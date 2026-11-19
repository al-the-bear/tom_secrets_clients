/*
 * Copyright (c) 2026 Peter Nicolai Alexis Kyaw
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * The JSON the protocol speaks (protocol.md 2.3): a strict parser and a
 * compact writer whose objects come out with their members sorted. Numbers
 * are read and written without the C locale's help (a program may have set
 * a decimal comma).
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

#define MAX_DEPTH 512

static tsm_json *node(tsm_jtype type) {
    tsm_json *j = (tsm_json *)calloc(1, sizeof *j);
    if (j) {
        j->type = type;
    }
    return j;
}

tsm_json *tsm_json_null(void) { return node(TSM_J_NULL); }

tsm_json *tsm_json_bool(int b) {
    tsm_json *j = node(TSM_J_BOOL);
    if (j) {
        j->boolean = b ? 1 : 0;
    }
    return j;
}

tsm_json *tsm_json_int(long long i) {
    tsm_json *j = node(TSM_J_NUMBER);
    if (j) {
        j->is_integer = 1;
        j->integer = i;
        j->number = (double)i;
    }
    return j;
}

tsm_json *tsm_json_strn(const char *s, size_t n) {
    tsm_json *j = node(TSM_J_STRING);
    if (j) {
        j->string = tsm_strndup(s, n);
        j->string_len = n;
        if (!j->string) {
            free(j);
            return NULL;
        }
    }
    return j;
}

tsm_json *tsm_json_str(const char *s) { return tsm_json_strn(s, strlen(s)); }

tsm_json *tsm_json_array(void) { return node(TSM_J_ARRAY); }

tsm_json *tsm_json_object(void) { return node(TSM_J_OBJECT); }

static int grow(tsm_json *j) {
    if (j->count < j->capacity) {
        return 1;
    }
    {
        size_t cap = j->capacity ? j->capacity * 2 : 8;
        tsm_json **items = (tsm_json **)realloc(j->items, cap * sizeof *items);
        if (!items) {
            return 0;
        }
        j->items = items;
        if (j->type == TSM_J_OBJECT) {
            char **keys = (char **)realloc(j->keys, cap * sizeof *keys);
            if (!keys) {
                return 0;
            }
            j->keys = keys;
        }
        j->capacity = cap;
    }
    return 1;
}

int tsm_json_push(tsm_json *array, tsm_json *value) {
    if (!value || !grow(array)) {
        tsm_json_free(value);
        return 0;
    }
    array->items[array->count++] = value;
    return 1;
}

int tsm_json_set(tsm_json *object, const char *key, tsm_json *value) {
    size_t i;
    if (!value) {
        return 0;
    }
    for (i = 0; i < object->count; i++) {
        if (strcmp(object->keys[i], key) == 0) {
            tsm_json_free(object->items[i]);
            object->items[i] = value;
            return 1;
        }
    }
    if (!grow(object)) {
        tsm_json_free(value);
        return 0;
    }
    object->keys[object->count] = tsm_strdup(key);
    if (!object->keys[object->count]) {
        tsm_json_free(value);
        return 0;
    }
    object->items[object->count++] = value;
    return 1;
}

const tsm_json *tsm_json_get(const tsm_json *object, const char *key) {
    size_t i;
    if (!object || object->type != TSM_J_OBJECT) {
        return NULL;
    }
    for (i = 0; i < object->count; i++) {
        if (strcmp(object->keys[i], key) == 0) {
            return object->items[i];
        }
    }
    return NULL;
}

const char *tsm_json_get_str(const tsm_json *object, const char *key) {
    const tsm_json *v = tsm_json_get(object, key);
    return v && v->type == TSM_J_STRING ? v->string : NULL;
}

int tsm_json_get_int(const tsm_json *object, const char *key, long long *out) {
    const tsm_json *v = tsm_json_get(object, key);
    if (!v || v->type != TSM_J_NUMBER) {
        return 0;
    }
    if (v->is_integer) {
        *out = v->integer;
        return 1;
    }
    if (v->number == floor(v->number) && fabs(v->number) <= 9007199254740992.0) {
        *out = (long long)v->number;
        return 1;
    }
    return 0;
}

static void free_node(tsm_json *j, int wipe) {
    size_t i;
    if (!j) {
        return;
    }
    if (j->string) {
        if (wipe) {
            tsm_wipe(j->string, j->string_len);
        }
        free(j->string);
    }
    for (i = 0; i < j->count; i++) {
        free_node(j->items[i], wipe);
        if (j->keys) {
            free(j->keys[i]);
        }
    }
    free(j->items);
    free(j->keys);
    free(j);
}

void tsm_json_free(tsm_json *j) { free_node(j, 0); }

void tsm_json_wipe_free(tsm_json *j) { free_node(j, 1); }

tsm_json *tsm_json_clone(const tsm_json *j) {
    tsm_json *c;
    size_t i;
    if (!j) {
        return NULL;
    }
    switch (j->type) {
    case TSM_J_NULL:
        return tsm_json_null();
    case TSM_J_BOOL:
        return tsm_json_bool(j->boolean);
    case TSM_J_NUMBER:
        c = node(TSM_J_NUMBER);
        if (c) {
            c->number = j->number;
            c->is_integer = j->is_integer;
            c->integer = j->integer;
        }
        return c;
    case TSM_J_STRING:
        return tsm_json_strn(j->string, j->string_len);
    case TSM_J_ARRAY:
        c = tsm_json_array();
        for (i = 0; c && i < j->count; i++) {
            if (!tsm_json_push(c, tsm_json_clone(j->items[i]))) {
                tsm_json_free(c);
                return NULL;
            }
        }
        return c;
    case TSM_J_OBJECT:
        c = tsm_json_object();
        for (i = 0; c && i < j->count; i++) {
            if (!tsm_json_set(c, j->keys[i], tsm_json_clone(j->items[i]))) {
                tsm_json_free(c);
                return NULL;
            }
        }
        return c;
    }
    return NULL;
}

/* ---- the parser ------------------------------------------------------ */

typedef struct parser {
    const char *s;
    size_t len;
    size_t at;
    char *why;
    size_t why_size;
} parser;

static tsm_json *fail(parser *p, const char *why) {
    if (p->why && p->why_size) {
        snprintf(p->why, p->why_size, "%s at %lu", why, (unsigned long)p->at);
    }
    return NULL;
}

static void skip_ws(parser *p) {
    while (p->at < p->len &&
           (p->s[p->at] == ' ' || p->s[p->at] == '\t' || p->s[p->at] == '\n' || p->s[p->at] == '\r')) {
        p->at++;
    }
}

static tsm_json *value(parser *p, int depth);

static int hex4(parser *p, unsigned *out) {
    unsigned v = 0;
    int i;
    if (p->at + 4 > p->len) {
        return 0;
    }
    for (i = 0; i < 4; i++) {
        char c = p->s[p->at + i];
        v <<= 4;
        if (c >= '0' && c <= '9') {
            v |= (unsigned)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            v |= (unsigned)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            v |= (unsigned)(c - 'A' + 10);
        } else {
            return 0;
        }
    }
    p->at += 4;
    *out = v;
    return 1;
}

static int add_utf8(tsm_buf *b, unsigned cp) {
    unsigned char u[4];
    size_t n;
    if (cp < 0x80) {
        u[0] = (unsigned char)cp;
        n = 1;
    } else if (cp < 0x800) {
        u[0] = (unsigned char)(0xC0 | (cp >> 6));
        u[1] = (unsigned char)(0x80 | (cp & 0x3F));
        n = 2;
    } else if (cp < 0x10000) {
        u[0] = (unsigned char)(0xE0 | (cp >> 12));
        u[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        u[2] = (unsigned char)(0x80 | (cp & 0x3F));
        n = 3;
    } else {
        u[0] = (unsigned char)(0xF0 | (cp >> 18));
        u[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
        u[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        u[3] = (unsigned char)(0x80 | (cp & 0x3F));
        n = 4;
    }
    return tsm_buf_add(b, u, n);
}

/* Reads a string at p->at (the opening quote) into b. */
static int string_into(parser *p, tsm_buf *b) {
    p->at++;
    for (;;) {
        unsigned char c;
        if (p->at >= p->len) {
            fail(p, "unterminated string");
            return 0;
        }
        c = (unsigned char)p->s[p->at++];
        if (c == '"') {
            if (!b->data && !tsm_buf_add(b, "", 0)) {
                return 0;
            }
            return 1;
        }
        if (c < 0x20) {
            p->at--;
            fail(p, "control character in a string");
            return 0;
        }
        if (c != '\\') {
            if (!tsm_buf_add(b, &c, 1)) {
                return 0;
            }
            continue;
        }
        if (p->at >= p->len) {
            fail(p, "unexpected end");
            return 0;
        }
        c = (unsigned char)p->s[p->at++];
        switch (c) {
        case '"': tsm_buf_addc(b, '"'); break;
        case '\\': tsm_buf_addc(b, '\\'); break;
        case '/': tsm_buf_addc(b, '/'); break;
        case 'b': tsm_buf_addc(b, '\b'); break;
        case 'f': tsm_buf_addc(b, '\f'); break;
        case 'n': tsm_buf_addc(b, '\n'); break;
        case 'r': tsm_buf_addc(b, '\r'); break;
        case 't': tsm_buf_addc(b, '\t'); break;
        case 'u': {
            unsigned first, second;
            if (!hex4(p, &first)) {
                fail(p, "bad \\u escape");
                return 0;
            }
            if (first >= 0xD800 && first < 0xDC00 && p->at + 1 < p->len && p->s[p->at] == '\\' &&
                p->s[p->at + 1] == 'u') {
                size_t save = p->at;
                p->at += 2;
                if (hex4(p, &second) && second >= 0xDC00 && second < 0xE000) {
                    add_utf8(b, 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00));
                    break;
                }
                p->at = save;
            }
            /* A lone surrogate becomes U+FFFD. */
            add_utf8(b, (first >= 0xD800 && first < 0xE000) ? 0xFFFD : first);
            break;
        }
        default:
            fail(p, "bad escape");
            return 0;
        }
    }
}

static tsm_json *string_value(parser *p) {
    tsm_buf b = {NULL, 0, 0};
    tsm_json *j;
    if (!string_into(p, &b)) {
        tsm_buf_wipe(&b);
        return NULL;
    }
    j = node(TSM_J_STRING);
    if (!j) {
        tsm_buf_wipe(&b);
        return NULL;
    }
    j->string = (char *)b.data;
    j->string_len = b.len;
    return j;
}

static tsm_json *number(parser *p) {
    size_t start = p->at;
    int negative = 0, whole = 1;
    double mantissa = 0;
    long long integer = 0, exponent = 0;
    int integer_ok = 1;
    tsm_json *j;
    if (p->s[p->at] == '-') {
        negative = 1;
        p->at++;
    }
    if (p->at < p->len && p->s[p->at] == '0') {
        p->at++;
    } else if (p->at < p->len && p->s[p->at] >= '1' && p->s[p->at] <= '9') {
        while (p->at < p->len && p->s[p->at] >= '0' && p->s[p->at] <= '9') {
            int d = p->s[p->at] - '0';
            mantissa = mantissa * 10 + d;
            if (integer > (9223372036854775807LL - d) / 10) {
                integer_ok = 0;
            } else {
                integer = integer * 10 + d;
            }
            p->at++;
        }
    } else {
        return fail(p, "bad number");
    }
    if (p->at < p->len && p->s[p->at] == '.') {
        whole = 0;
        p->at++;
        if (p->at >= p->len || p->s[p->at] < '0' || p->s[p->at] > '9') {
            return fail(p, "bad number");
        }
        while (p->at < p->len && p->s[p->at] >= '0' && p->s[p->at] <= '9') {
            mantissa = mantissa * 10 + (p->s[p->at] - '0');
            exponent--;
            p->at++;
        }
    }
    if (p->at < p->len && (p->s[p->at] == 'e' || p->s[p->at] == 'E')) {
        int sign = 1;
        long long e = 0;
        whole = 0;
        p->at++;
        if (p->at < p->len && (p->s[p->at] == '+' || p->s[p->at] == '-')) {
            sign = p->s[p->at] == '-' ? -1 : 1;
            p->at++;
        }
        if (p->at >= p->len || p->s[p->at] < '0' || p->s[p->at] > '9') {
            return fail(p, "bad number");
        }
        while (p->at < p->len && p->s[p->at] >= '0' && p->s[p->at] <= '9') {
            if (e < 100000) {
                e = e * 10 + (p->s[p->at] - '0');
            }
            p->at++;
        }
        exponent += sign * e;
    }
    j = node(TSM_J_NUMBER);
    if (!j) {
        return NULL;
    }
    j->number = mantissa * pow(10.0, (double)exponent);
    if (negative) {
        j->number = -j->number;
    }
    if (isinf(j->number)) {
        free(j);
        p->at = start;
        return fail(p, "number out of range");
    }
    if (whole && integer_ok) {
        j->is_integer = 1;
        j->integer = negative ? -integer : integer;
    }
    return j;
}

static tsm_json *object(parser *p, int depth) {
    tsm_json *o = tsm_json_object();
    if (!o) {
        return NULL;
    }
    p->at++;
    skip_ws(p);
    if (p->at < p->len && p->s[p->at] == '}') {
        p->at++;
        return o;
    }
    for (;;) {
        tsm_buf key = {NULL, 0, 0};
        tsm_json *v;
        skip_ws(p);
        if (p->at >= p->len || p->s[p->at] != '"') {
            tsm_json_free(o);
            return fail(p, "member name is no string");
        }
        if (!string_into(p, &key)) {
            tsm_buf_wipe(&key);
            tsm_json_free(o);
            return NULL;
        }
        skip_ws(p);
        if (p->at >= p->len || p->s[p->at] != ':') {
            tsm_buf_wipe(&key);
            tsm_json_free(o);
            return fail(p, "expected :");
        }
        p->at++;
        skip_ws(p);
        v = value(p, depth + 1);
        if (!v) {
            tsm_buf_wipe(&key);
            tsm_json_free(o);
            return NULL;
        }
        if (strlen((char *)key.data) != key.len || tsm_json_get(o, (char *)key.data)) {
            tsm_buf_wipe(&key);
            tsm_json_wipe_free(v);
            tsm_json_free(o);
            return fail(p, "duplicate member (or a NUL in a member name)");
        }
        if (!tsm_json_set(o, (char *)key.data, v)) {
            tsm_buf_wipe(&key);
            tsm_json_free(o);
            return NULL;
        }
        tsm_buf_wipe(&key);
        skip_ws(p);
        if (p->at < p->len && p->s[p->at] == ',') {
            p->at++;
            continue;
        }
        if (p->at < p->len && p->s[p->at] == '}') {
            p->at++;
            return o;
        }
        tsm_json_free(o);
        return fail(p, "expected , or }");
    }
}

static tsm_json *array(parser *p, int depth) {
    tsm_json *a = tsm_json_array();
    if (!a) {
        return NULL;
    }
    p->at++;
    skip_ws(p);
    if (p->at < p->len && p->s[p->at] == ']') {
        p->at++;
        return a;
    }
    for (;;) {
        tsm_json *v;
        skip_ws(p);
        v = value(p, depth + 1);
        if (!v || !tsm_json_push(a, v)) {
            tsm_json_free(a);
            return NULL;
        }
        skip_ws(p);
        if (p->at < p->len && p->s[p->at] == ',') {
            p->at++;
            continue;
        }
        if (p->at < p->len && p->s[p->at] == ']') {
            p->at++;
            return a;
        }
        tsm_json_free(a);
        return fail(p, "expected , or ]");
    }
}

static int word(parser *p, const char *w) {
    size_t n = strlen(w);
    if (p->at + n <= p->len && memcmp(p->s + p->at, w, n) == 0) {
        p->at += n;
        return 1;
    }
    return 0;
}

static tsm_json *value(parser *p, int depth) {
    char c;
    if (depth > MAX_DEPTH) {
        return fail(p, "nested too deeply");
    }
    if (p->at >= p->len) {
        return fail(p, "unexpected end");
    }
    c = p->s[p->at];
    if (c == '{') {
        return object(p, depth);
    }
    if (c == '[') {
        return array(p, depth);
    }
    if (c == '"') {
        return string_value(p);
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        return number(p);
    }
    if (word(p, "true")) {
        return tsm_json_bool(1);
    }
    if (word(p, "false")) {
        return tsm_json_bool(0);
    }
    if (word(p, "null")) {
        return tsm_json_null();
    }
    return fail(p, "unexpected character");
}

tsm_json *tsm_json_parse(const char *text, size_t len, char *why, size_t why_size) {
    parser p;
    tsm_json *j;
    p.s = text;
    p.len = len;
    p.at = 0;
    p.why = why;
    p.why_size = why_size;
    if (!tsm_utf8_valid((const unsigned char *)text, len)) {
        return fail(&p, "not UTF-8");
    }
    skip_ws(&p);
    j = value(&p, 0);
    if (!j) {
        return NULL;
    }
    skip_ws(&p);
    if (p.at != len) {
        tsm_json_free(j);
        return fail(&p, "data after the value");
    }
    return j;
}

/* ---- the writer ------------------------------------------------------ */

static int write_string(tsm_buf *b, const char *s, size_t n) {
    size_t i;
    if (!tsm_buf_addc(b, '"')) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        int ok;
        switch (c) {
        case '"': ok = tsm_buf_adds(b, "\\\""); break;
        case '\\': ok = tsm_buf_adds(b, "\\\\"); break;
        case '\n': ok = tsm_buf_adds(b, "\\n"); break;
        case '\r': ok = tsm_buf_adds(b, "\\r"); break;
        case '\t': ok = tsm_buf_adds(b, "\\t"); break;
        default:
            if (c < 0x20) {
                char esc[8];
                snprintf(esc, sizeof esc, "\\u%04x", c);
                ok = tsm_buf_adds(b, esc);
            } else {
                ok = tsm_buf_add(b, &c, 1);
            }
        }
        if (!ok) {
            return 0;
        }
    }
    return tsm_buf_addc(b, '"');
}

static int compare_keys(const void *a, const void *b) {
    const char *const *x = (const char *const *)a;
    const char *const *y = (const char *const *)b;
    return strcmp(*x, *y);
}

static int write_value(tsm_buf *b, const tsm_json *j) {
    size_t i;
    char number[64];
    switch (j->type) {
    case TSM_J_NULL:
        return tsm_buf_adds(b, "null");
    case TSM_J_BOOL:
        return tsm_buf_adds(b, j->boolean ? "true" : "false");
    case TSM_J_NUMBER:
        if (j->is_integer) {
            snprintf(number, sizeof number, "%lld", j->integer);
        } else if (j->number == floor(j->number) && fabs(j->number) < 1e16) {
            snprintf(number, sizeof number, "%lld", (long long)j->number);
        } else {
            char *comma;
            snprintf(number, sizeof number, "%.17g", j->number);
            /* A locale with a decimal comma: JSON has a point. */
            comma = strchr(number, ',');
            if (comma) {
                *comma = '.';
            }
        }
        return tsm_buf_adds(b, number);
    case TSM_J_STRING:
        return write_string(b, j->string, j->string_len);
    case TSM_J_ARRAY:
        if (!tsm_buf_addc(b, '[')) {
            return 0;
        }
        for (i = 0; i < j->count; i++) {
            if ((i && !tsm_buf_addc(b, ',')) || !write_value(b, j->items[i])) {
                return 0;
            }
        }
        return tsm_buf_addc(b, ']');
    case TSM_J_OBJECT: {
        char **keys;
        int ok = 1;
        if (!tsm_buf_addc(b, '{')) {
            return 0;
        }
        keys = (char **)malloc((j->count ? j->count : 1) * sizeof *keys);
        if (!keys) {
            return 0;
        }
        for (i = 0; i < j->count; i++) {
            keys[i] = j->keys[i];
        }
        qsort(keys, j->count, sizeof *keys, compare_keys);
        for (i = 0; ok && i < j->count; i++) {
            ok = (!i || tsm_buf_addc(b, ',')) && write_string(b, keys[i], strlen(keys[i])) &&
                 tsm_buf_addc(b, ':') && write_value(b, tsm_json_get(j, keys[i]));
        }
        free(keys);
        return ok && tsm_buf_addc(b, '}');
    }
    }
    return 0;
}

char *tsm_json_write(const tsm_json *j, size_t *len) {
    tsm_buf b = {NULL, 0, 0};
    if (!write_value(&b, j)) {
        tsm_buf_wipe(&b);
        return NULL;
    }
    if (len) {
        *len = b.len;
    }
    return (char *)b.data;
}
