/*
 * Copyright (c) 2026 Peter Nicolai Alexis Kyaw
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * The reference grammar (protocol.md section 4): parse and format.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

static const char RESERVED[] = "/#[],:%";

static tsm_error_kind malformed(const char *reason, const char *detail) {
    if (detail && *detail) {
        return tsm_set_error(TSM_ERR_MALFORMED, reason, -1, "the reference is malformed: %s (%s)", reason, detail);
    }
    return tsm_set_error(TSM_ERR_MALFORMED, reason, -1, "the reference is malformed: %s", reason);
}

static int is_name(const char *s, size_t n) {
    size_t i;
    if (n == 0 || s[0] < 'a' || s[0] > 'z') {
        return 0;
    }
    for (i = 1; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) {
            return 0;
        }
    }
    return 1;
}

static int is_store(const char *s, size_t n) {
    size_t i;
    if (n == 0 || !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= '0' && s[0] <= '9'))) {
        return 0;
    }
    for (i = 1; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) {
            return 0;
        }
    }
    return 1;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes one segment of n bytes into *out (malloc'd). */
static tsm_error_kind decode_segment(const char *raw, size_t n, char **out) {
    tsm_buf b = {NULL, 0, 0};
    size_t i = 0;
    char detail[16];
    if (n == 0) {
        return malformed("empty_segment", NULL);
    }
    while (i < n) {
        unsigned char c = (unsigned char)raw[i];
        if (c == '%') {
            if (i + 2 >= n) {
                snprintf(detail, sizeof detail, "%%%.*s", (int)(n - i - 1), raw + i + 1);
                tsm_buf_wipe(&b);
                return malformed("bad_escape", detail);
            }
            if (hexval(raw[i + 1]) < 0 || hexval(raw[i + 2]) < 0) {
                snprintf(detail, sizeof detail, "%%%.2s", raw + i + 1);
                tsm_buf_wipe(&b);
                return malformed("bad_escape", detail);
            }
            c = (unsigned char)(hexval(raw[i + 1]) * 16 + hexval(raw[i + 2]));
            if (!tsm_buf_add(&b, &c, 1)) {
                tsm_buf_wipe(&b);
                return tsm_no_memory();
            }
            i += 3;
            continue;
        }
        if (strchr(RESERVED, c) && c != 0) {
            snprintf(detail, sizeof detail, "%c", c);
            tsm_buf_wipe(&b);
            return malformed("reserved_character", detail);
        }
        if (c < 0x20 || c == 0x7F) {
            snprintf(detail, sizeof detail, "U+%04X", c);
            tsm_buf_wipe(&b);
            return malformed("control_character", detail);
        }
        if (!tsm_buf_add(&b, &c, 1)) {
            tsm_buf_wipe(&b);
            return tsm_no_memory();
        }
        i++;
    }
    if (!tsm_utf8_valid(b.data, b.len) || strlen((char *)b.data) != b.len) {
        tsm_buf_wipe(&b);
        return malformed("bad_utf8", NULL);
    }
    *out = (char *)b.data;
    return TSM_OK;
}

void tsm_reference_free(tsm_reference *r) {
    size_t i;
    if (!r) {
        return;
    }
    free(r->key);
    free(r->store);
    free(r->uuid);
    free(r->field);
    for (i = 0; i < r->segment_count; i++) {
        free(r->segments[i]);
    }
    free(r->segments);
    for (i = 0; i < r->qualifier_count; i++) {
        free(r->dimensions[i]);
        free(r->values[i]);
    }
    free(r->dimensions);
    free(r->values);
    free(r);
}

static int push_string(char ***list, size_t *count, char *s) {
    char **grown = (char **)realloc(*list, (*count + 1) * sizeof *grown);
    if (!grown) {
        free(s);
        return 0;
    }
    grown[(*count)++] = s;
    *list = grown;
    return 1;
}

tsm_error_kind tsm_reference_parse(const char *text, tsm_reference **out) {
    tsm_reference *r;
    const char *rest = text, *hash, *target, *end;
    size_t len, target_len;
    tsm_error_kind rc;
    *out = NULL;
    if (!text) {
        return tsm_set_error(TSM_ERR_INVALID_ARGUMENT, NULL, -1, "no reference");
    }
    len = strlen(text);
    if (len > TSM_MAX_REFERENCE_BYTES) {
        return malformed("too_long", NULL);
    }
    if (len == 0) {
        return malformed("empty", NULL);
    }
    r = (tsm_reference *)calloc(1, sizeof *r);
    if (!r) {
        return tsm_no_memory();
    }
    if (*rest == '[') {
        const char *close = strchr(rest, ']'), *p;
        if (!close) {
            tsm_reference_free(r);
            return malformed("unclosed_qualifiers", NULL);
        }
        if (close == rest + 1) {
            tsm_reference_free(r);
            return malformed("empty_segment", "[]");
        }
        p = rest + 1;
        while (p <= close) {
            const char *comma = memchr(p, ',', (size_t)(close - p));
            const char *stop = comma ? comma : close;
            const char *colon = memchr(p, ':', (size_t)(stop - p));
            char binding[256], *value = NULL;
            size_t i;
            snprintf(binding, sizeof binding, "%.*s", (int)(stop - p), p);
            if (!colon || memchr(colon + 1, ':', (size_t)(stop - colon - 1))) {
                tsm_reference_free(r);
                return malformed("bad_binding", binding);
            }
            if (!is_name(p, (size_t)(colon - p))) {
                snprintf(binding, sizeof binding, "%.*s", (int)(colon - p), p);
                tsm_reference_free(r);
                return malformed("bad_dimension", binding);
            }
            for (i = 0; i < r->qualifier_count; i++) {
                if (strlen(r->dimensions[i]) == (size_t)(colon - p) &&
                    memcmp(r->dimensions[i], p, (size_t)(colon - p)) == 0) {
                    snprintf(binding, sizeof binding, "%.*s", (int)(colon - p), p);
                    tsm_reference_free(r);
                    return malformed("duplicate_dimension", binding);
                }
            }
            rc = decode_segment(colon + 1, (size_t)(stop - colon - 1), &value);
            if (rc != TSM_OK) {
                tsm_reference_free(r);
                return rc;
            }
            {
                size_t count = r->qualifier_count;
                if (!push_string(&r->dimensions, &count, tsm_strndup(p, (size_t)(colon - p))) ||
                    !push_string(&r->values, &r->qualifier_count, value)) {
                    tsm_reference_free(r);
                    return tsm_no_memory();
                }
            }
            p = stop + 1;
        }
        rest = close + 1;
    }
    hash = strchr(rest, '#');
    if (hash && strchr(hash + 1, '#')) {
        tsm_reference_free(r);
        return malformed("reserved_character", "#");
    }
    target = rest;
    target_len = hash ? (size_t)(hash - rest) : strlen(rest);
    if (target_len == 0) {
        tsm_reference_free(r);
        return malformed("empty_target", NULL);
    }
    r->field_given = hash != NULL;
    if (hash) {
        rc = decode_segment(hash + 1, strlen(hash + 1), &r->field);
        if (rc != TSM_OK) {
            tsm_reference_free(r);
            return rc;
        }
    } else {
        r->field = tsm_strdup(TSM_DEFAULT_FIELD);
    }
    end = target + target_len;
    if (!memchr(target, '/', target_len)) {
        const char *p = target;
        char detail[TSM_MAX_REFERENCE_BYTES + 1];
        snprintf(detail, sizeof detail, "%.*s", (int)target_len, target);
        while (p <= end) {
            const char *dot = memchr(p, '.', (size_t)(end - p));
            const char *stop = dot ? dot : end;
            if (!is_name(p, (size_t)(stop - p))) {
                tsm_reference_free(r);
                return malformed("bad_key", detail);
            }
            p = stop + 1;
        }
        r->kind = TSM_TARGET_KEY;
        r->key = tsm_strndup(target, target_len);
    } else {
        const char *slash = memchr(target, '/', target_len);
        const char *first = slash + 1;
        const char *second_slash = memchr(first, '/', (size_t)(end - first));
        char detail[TSM_MAX_REFERENCE_BYTES + 1];
        if (!is_store(target, (size_t)(slash - target))) {
            snprintf(detail, sizeof detail, "%.*s", (int)(slash - target), target);
            tsm_reference_free(r);
            return malformed("bad_store", detail);
        }
        r->store = tsm_strndup(target, (size_t)(slash - target));
        if (!second_slash && first < end && *first == '~') {
            size_t n = (size_t)(end - first), i;
            int ok = n == 33;
            for (i = 1; ok && i < n; i++) {
                ok = hexval(first[i]) >= 0;
            }
            if (!ok) {
                snprintf(detail, sizeof detail, "%.*s", (int)n, first);
                tsm_reference_free(r);
                return malformed("bad_uuid", detail);
            }
            r->kind = TSM_TARGET_UUID;
            r->uuid = tsm_strndup(first + 1, 32);
            for (i = 0; r->uuid && i < 32; i++) {
                if (r->uuid[i] >= 'A' && r->uuid[i] <= 'F') {
                    r->uuid[i] = (char)(r->uuid[i] - 'A' + 'a');
                }
            }
        } else {
            const char *p = first;
            r->kind = TSM_TARGET_PATH;
            while (p <= end) {
                const char *s = memchr(p, '/', (size_t)(end - p));
                const char *stop = s ? s : end;
                char *segment = NULL;
                if (stop == p) {
                    tsm_reference_free(r);
                    return malformed("empty_segment", NULL);
                }
                if (*p == '@' || *p == '~') {
                    snprintf(detail, sizeof detail, "%c", *p);
                    tsm_reference_free(r);
                    return malformed("reserved_prefix", detail);
                }
                rc = decode_segment(p, (size_t)(stop - p), &segment);
                if (rc != TSM_OK) {
                    tsm_reference_free(r);
                    return rc;
                }
                if (!push_string(&r->segments, &r->segment_count, segment)) {
                    tsm_reference_free(r);
                    return tsm_no_memory();
                }
                p = stop + 1;
            }
        }
    }
    if (!r->field || (r->kind == TSM_TARGET_KEY && !r->key) || (r->kind != TSM_TARGET_KEY && !r->store)) {
        tsm_reference_free(r);
        return tsm_no_memory();
    }
    *out = r;
    return TSM_OK;
}

static int encode_segment(tsm_buf *b, const char *s, int path) {
    size_t i, n = strlen(s);
    if (n == 0) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        int escape = (strchr(RESERVED, c) && c != 0) || c < 0x20 || c == 0x7F || (path && i == 0 && (c == '@' || c == '~'));
        if (escape) {
            char e[4];
            snprintf(e, sizeof e, "%%%02X", c);
            if (!tsm_buf_adds(b, e)) {
                return 0;
            }
        } else if (!tsm_buf_add(b, &c, 1)) {
            return 0;
        }
    }
    return 1;
}

tsm_error_kind tsm_reference_format(const tsm_reference *r, char **out) {
    tsm_buf b = {NULL, 0, 0};
    size_t i, j;
    int ok = 1, e;
    size_t *order = NULL;
    *out = NULL;
    if (r->qualifier_count) {
        order = (size_t *)malloc(r->qualifier_count * sizeof *order);
        if (!order) {
            return tsm_no_memory();
        }
        for (i = 0; i < r->qualifier_count; i++) {
            order[i] = i;
        }
        /* Insertion sort by the dimension's UTF-8 bytes (strcmp). */
        for (i = 1; i < r->qualifier_count; i++) {
            size_t k = order[i];
            for (j = i; j > 0 && strcmp(r->dimensions[order[j - 1]], r->dimensions[k]) > 0; j--) {
                order[j] = order[j - 1];
            }
            order[j] = k;
        }
        ok = tsm_buf_addc(&b, '[');
        for (i = 0; ok && i < r->qualifier_count; i++) {
            if (i > 0 && strcmp(r->dimensions[order[i - 1]], r->dimensions[order[i]]) == 0) {
                free(order);
                tsm_buf_wipe(&b);
                return tsm_set_error(TSM_ERR_INVALID_ARGUMENT, NULL, -1, "a dimension is bound once");
            }
            ok = (i == 0 || tsm_buf_addc(&b, ',')) && tsm_buf_adds(&b, r->dimensions[order[i]]) &&
                 tsm_buf_addc(&b, ':');
            if (ok) {
                e = encode_segment(&b, r->values[order[i]], 0);
                if (e < 0) {
                    free(order);
                    tsm_buf_wipe(&b);
                    return tsm_set_error(TSM_ERR_INVALID_ARGUMENT, NULL, -1, "a segment is never empty");
                }
                ok = e;
            }
        }
        ok = ok && tsm_buf_addc(&b, ']');
        free(order);
    }
    if (ok) {
        switch (r->kind) {
        case TSM_TARGET_KEY:
            ok = r->key && tsm_buf_adds(&b, r->key);
            break;
        case TSM_TARGET_UUID:
            ok = r->store && r->uuid && tsm_buf_adds(&b, r->store) && tsm_buf_adds(&b, "/~");
            for (i = 0; ok && r->uuid[i]; i++) {
                char c = r->uuid[i];
                ok = tsm_buf_addc(&b, (char)(c >= 'A' && c <= 'F' ? c - 'A' + 'a' : c));
            }
            break;
        default:
            ok = r->store && tsm_buf_adds(&b, r->store);
            for (i = 0; ok && i < r->segment_count; i++) {
                ok = tsm_buf_addc(&b, '/');
                if (ok) {
                    e = encode_segment(&b, r->segments[i], 1);
                    if (e < 0) {
                        tsm_buf_wipe(&b);
                        return tsm_set_error(TSM_ERR_INVALID_ARGUMENT, NULL, -1, "a segment is never empty");
                    }
                    ok = e;
                }
            }
        }
    }
    if (ok && r->field && *r->field && strcmp(r->field, TSM_DEFAULT_FIELD) != 0) {
        ok = tsm_buf_addc(&b, '#');
        if (ok) {
            ok = encode_segment(&b, r->field, 0) > 0;
        }
    }
    if (!ok) {
        tsm_buf_wipe(&b);
        return tsm_set_error(TSM_ERR_INVALID_ARGUMENT, NULL, -1, "the reference has no canonical form");
    }
    if (!b.data && !tsm_buf_add(&b, "", 0)) {
        return tsm_no_memory();
    }
    *out = (char *)b.data;
    return TSM_OK;
}
