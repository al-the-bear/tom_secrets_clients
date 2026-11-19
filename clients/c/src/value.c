/*
 * Copyright (c) 2026 Peter Nicolai Alexis Kyaw
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * What a get answers (protocol.md 5.2) and what a getFile answers (5.5).
 */
#include <stdlib.h>
#include <string.h>

#include "internal.h"

struct tsm_value {
    char *reference;
    int binary;
    unsigned char *data; /* NUL-terminated beyond size */
    size_t size;
    char *store;
    char *uuid;
    char *source;
    long long fetched_at_ms;
    long long modified_ms;
    char *revision;
    int has_expires;
    long long expires_ms;
    char *client_token;
    char **bound_dimensions;
    char **bound_values;
    size_t bound_count;
};

struct tsm_file {
    char *reference;
    char *name;
    unsigned char *data;
    size_t size;
};

static tsm_error_kind bad_value(void) {
    return tsm_set_error(TSM_ERR_INTERNAL, NULL, -1, "the service sent a value message this library cannot read");
}

static int compare_index(const void *a, const void *b, const tsm_json *bound) {
    const size_t *x = (const size_t *)a, *y = (const size_t *)b;
    return strcmp(bound->keys[*x], bound->keys[*y]);
}

tsm_error_kind tsm_value_from_message(const char *ref, const tsm_json *m, tsm_value **out) {
    const tsm_json *raw = tsm_json_get(m, "value");
    const tsm_json *entry = tsm_json_get(m, "entry");
    const tsm_json *version = tsm_json_get(m, "version");
    const tsm_json *bound = tsm_json_get(m, "bound");
    const char *encoding = tsm_json_get_str(m, "encoding");
    const char *store, *uuid, *revision, *source, *expires, *token;
    tsm_value *v;
    size_t i;
    *out = NULL;
    if (!raw || raw->type != TSM_J_STRING || !entry || entry->type != TSM_J_OBJECT || !version ||
        version->type != TSM_J_OBJECT) {
        return bad_value();
    }
    store = tsm_json_get_str(entry, "store");
    uuid = tsm_json_get_str(entry, "uuid");
    revision = tsm_json_get_str(version, "revision");
    if (!store || !uuid || !revision) {
        return bad_value();
    }
    v = (tsm_value *)calloc(1, sizeof *v);
    if (!v) {
        return tsm_no_memory();
    }
    if (!tsm_parse_time(tsm_json_get_str(entry, "fetchedAt") ? tsm_json_get_str(entry, "fetchedAt") : "",
                        &v->fetched_at_ms) ||
        !tsm_parse_time(tsm_json_get_str(version, "modified") ? tsm_json_get_str(version, "modified") : "",
                        &v->modified_ms)) {
        tsm_value_free(v);
        return bad_value();
    }
    expires = tsm_json_get_str(m, "expires");
    if (expires) {
        if (!tsm_parse_time(expires, &v->expires_ms)) {
            tsm_value_free(v);
            return bad_value();
        }
        v->has_expires = 1;
    }
    if (encoding && strcmp(encoding, "base64") == 0) {
        unsigned char *data;
        size_t size;
        v->binary = 1;
        if (!tsm_base64_decode(raw->string, &data, &size)) {
            tsm_value_free(v);
            return bad_value();
        }
        v->data = (unsigned char *)malloc(size + 1);
        if (!v->data) {
            tsm_wipe(data, size);
            free(data);
            tsm_value_free(v);
            return tsm_no_memory();
        }
        memcpy(v->data, data, size);
        v->data[size] = 0;
        v->size = size;
        tsm_wipe(data, size);
        free(data);
    } else {
        v->data = (unsigned char *)malloc(raw->string_len + 1);
        if (!v->data) {
            tsm_value_free(v);
            return tsm_no_memory();
        }
        memcpy(v->data, raw->string, raw->string_len);
        v->data[raw->string_len] = 0;
        v->size = raw->string_len;
    }
    source = tsm_json_get_str(entry, "source");
    v->reference = tsm_strdup(ref);
    v->store = tsm_strdup(store);
    v->uuid = tsm_strdup(uuid);
    v->revision = tsm_strdup(revision);
    /* An unknown source is cache (section 8: no claim to be fresh). */
    v->source = tsm_strdup(source && (!strcmp(source, "github") || !strcmp(source, "file")) ? source : "cache");
    token = tsm_json_get_str(m, "clientToken");
    v->client_token = token ? tsm_strdup(token) : NULL;
    if (!v->reference || !v->store || !v->uuid || !v->revision || !v->source || (token && !v->client_token)) {
        tsm_value_free(v);
        return tsm_no_memory();
    }
    if (bound && bound->type == TSM_J_OBJECT && bound->count) {
        size_t *order = (size_t *)malloc(bound->count * sizeof *order), k, j;
        v->bound_dimensions = (char **)calloc(bound->count, sizeof(char *));
        v->bound_values = (char **)calloc(bound->count, sizeof(char *));
        if (!order || !v->bound_dimensions || !v->bound_values) {
            free(order);
            tsm_value_free(v);
            return tsm_no_memory();
        }
        for (i = 0; i < bound->count; i++) {
            order[i] = i;
        }
        for (i = 1; i < bound->count; i++) {
            k = order[i];
            for (j = i; j > 0 && compare_index(&order[j - 1], &k, bound) > 0; j--) {
                order[j] = order[j - 1];
            }
            order[j] = k;
        }
        for (i = 0; i < bound->count; i++) {
            const tsm_json *b = bound->items[order[i]];
            if (b->type != TSM_J_STRING) {
                free(order);
                tsm_value_free(v);
                return bad_value();
            }
            v->bound_dimensions[i] = tsm_strdup(bound->keys[order[i]]);
            v->bound_values[i] = tsm_strdup(b->string);
            v->bound_count = i + 1;
            if (!v->bound_dimensions[i] || !v->bound_values[i]) {
                free(order);
                tsm_value_free(v);
                return tsm_no_memory();
            }
        }
        free(order);
    }
    *out = v;
    return TSM_OK;
}

const char *tsm_value_text(const tsm_value *v) { return v->binary ? NULL : (const char *)v->data; }

const unsigned char *tsm_value_bytes(const tsm_value *v, size_t *size) {
    if (size) {
        *size = v->size;
    }
    return v->data;
}

const char *tsm_value_encoding(const tsm_value *v) { return v->binary ? "base64" : "utf8"; }
const char *tsm_value_reference(const tsm_value *v) { return v->reference; }
const char *tsm_value_entry_store(const tsm_value *v) { return v->store; }
const char *tsm_value_entry_uuid(const tsm_value *v) { return v->uuid; }
const char *tsm_value_entry_source(const tsm_value *v) { return v->source; }
long long tsm_value_entry_fetched_at_ms(const tsm_value *v) { return v->fetched_at_ms; }
long long tsm_value_version_modified_ms(const tsm_value *v) { return v->modified_ms; }
const char *tsm_value_version_revision(const tsm_value *v) { return v->revision; }

int tsm_value_expires_ms(const tsm_value *v, long long *expires_ms) {
    if (v->has_expires && expires_ms) {
        *expires_ms = v->expires_ms;
    }
    return v->has_expires;
}

const char *tsm_value_client_token(const tsm_value *v) { return v->client_token; }
size_t tsm_value_bound_count(const tsm_value *v) { return v->bound_count; }

const char *tsm_value_bound_dimension(const tsm_value *v, size_t i) {
    return i < v->bound_count ? v->bound_dimensions[i] : NULL;
}

const char *tsm_value_bound_value(const tsm_value *v, size_t i) {
    return i < v->bound_count ? v->bound_values[i] : NULL;
}

void tsm_value_free(tsm_value *v) {
    size_t i;
    if (!v) {
        return;
    }
    if (v->data) {
        tsm_wipe(v->data, v->size);
        free(v->data);
    }
    if (v->client_token) {
        tsm_wipe(v->client_token, strlen(v->client_token));
        free(v->client_token);
    }
    free(v->reference);
    free(v->store);
    free(v->uuid);
    free(v->source);
    free(v->revision);
    for (i = 0; i < v->bound_count; i++) {
        free(v->bound_dimensions[i]);
        free(v->bound_values[i]);
    }
    free(v->bound_dimensions);
    free(v->bound_values);
    free(v);
}

tsm_file *tsm_file_new(const char *ref, const char *name, unsigned char *data, size_t len) {
    tsm_file *f = (tsm_file *)calloc(1, sizeof *f);
    if (!f) {
        return NULL;
    }
    f->reference = tsm_strdup(ref);
    f->name = tsm_strdup(name);
    f->data = data;
    f->size = len;
    if (!f->reference || !f->name) {
        free(f->reference);
        free(f->name);
        free(f);
        return NULL;
    }
    return f;
}

const char *tsm_file_reference(const tsm_file *f) { return f->reference; }
const char *tsm_file_name(const tsm_file *f) { return f->name; }

const unsigned char *tsm_file_bytes(const tsm_file *f, size_t *size) {
    if (size) {
        *size = f->size;
    }
    return f->data;
}

void tsm_file_free(tsm_file *f) {
    if (!f) {
        return;
    }
    if (f->data) {
        tsm_wipe(f->data, f->size);
        free(f->data);
    }
    free(f->reference);
    free(f->name);
    free(f);
}
