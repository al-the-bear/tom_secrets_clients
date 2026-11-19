/*
 * Copyright (c) 2026 Peter Nicolai Alexis Kyaw
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Byte buffers, UTF-8, errors (the thread's last error), SHA-256, base64
 * and RFC 3339 times.
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

/* ---- buffers --------------------------------------------------------- */

int tsm_buf_add(tsm_buf *b, const void *data, size_t n) {
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 64;
        unsigned char *grown;
        while (cap < b->len + n + 1) {
            cap *= 2;
        }
        grown = (unsigned char *)malloc(cap);
        if (!grown) {
            return 0;
        }
        if (b->data) {
            memcpy(grown, b->data, b->len);
            /* The old block may hold a secret: overwritten before it is
             * freed. */
            tsm_wipe(b->data, b->cap);
            free(b->data);
        }
        b->data = grown;
        b->cap = cap;
    }
    if (n) {
        memcpy(b->data + b->len, data, n);
    }
    b->len += n;
    b->data[b->len] = 0;
    return 1;
}

int tsm_buf_addc(tsm_buf *b, char c) { return tsm_buf_add(b, &c, 1); }

int tsm_buf_adds(tsm_buf *b, const char *s) { return tsm_buf_add(b, s, strlen(s)); }

void tsm_wipe(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) {
        *v++ = 0;
    }
}

void tsm_buf_wipe(tsm_buf *b) {
    if (b->data) {
        tsm_wipe(b->data, b->cap);
        free(b->data);
    }
    b->data = NULL;
    b->len = b->cap = 0;
}

char *tsm_strndup(const char *s, size_t n) {
    char *out = (char *)malloc(n + 1);
    if (out) {
        memcpy(out, s, n);
        out[n] = 0;
    }
    return out;
}

char *tsm_strdup(const char *s) { return s ? tsm_strndup(s, strlen(s)) : NULL; }

void tsm_free(void *p) { free(p); }

int tsm_utf8_valid(const unsigned char *s, size_t n) {
    size_t i = 0;
    while (i < n) {
        unsigned char c = s[i];
        size_t extra;
        uint32_t cp;
        if (c < 0x80) {
            i++;
            continue;
        }
        if ((c & 0xE0) == 0xC0) {
            extra = 1;
            cp = c & 0x1F;
        } else if ((c & 0xF0) == 0xE0) {
            extra = 2;
            cp = c & 0x0F;
        } else if ((c & 0xF8) == 0xF0) {
            extra = 3;
            cp = c & 0x07;
        } else {
            return 0;
        }
        {
            size_t k;
            for (k = 1; k <= extra; k++) {
                if (i + k >= n || (s[i + k] & 0xC0) != 0x80) {
                    return 0;
                }
                cp = (cp << 6) | (s[i + k] & 0x3F);
            }
        }
        if ((extra == 1 && cp < 0x80) || (extra == 2 && cp < 0x800) || (extra == 3 && cp < 0x10000) ||
            cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            return 0;
        }
        i += extra + 1;
    }
    return 1;
}

/* ---- errors ---------------------------------------------------------- */

#if defined(_MSC_VER)
#define TSM_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
#define TSM_THREAD_LOCAL _Thread_local
#else
#define TSM_THREAD_LOCAL __thread
#endif

typedef struct last_error {
    tsm_error error;
    char message[512];
    char reason[96];
} last_error;

static TSM_THREAD_LOCAL last_error the_last_error;

const tsm_error *tsm_last_error(const struct tsm_client *c) {
    (void)c;
    last_error *e = &the_last_error;
    if (!e->error.message) {
        e->error.message = e->message;
        e->error.retry_after_ms = -1;
    }
    return &e->error;
}

tsm_error_kind tsm_set_error(tsm_error_kind kind, const char *reason, long long retry_after_ms,
                             const char *format, ...) {
    last_error *e = &the_last_error;
    va_list args;
    va_start(args, format);
    vsnprintf(e->message, sizeof e->message, format, args);
    va_end(args);
    e->error.kind = kind;
    e->error.message = e->message;
    if (reason) {
        snprintf(e->reason, sizeof e->reason, "%s", reason);
        e->error.reason = e->reason;
    } else {
        e->error.reason = NULL;
    }
    e->error.retry_after_ms = retry_after_ms;
    return kind;
}

tsm_error_kind tsm_set_error_from_message(const tsm_json *m) {
    const tsm_json *details = tsm_json_get(m, "details");
    const char *message = tsm_json_get_str(m, "message");
    const char *reason = NULL;
    long long retry = -1;
    if (details && details->type == TSM_J_OBJECT) {
        reason = tsm_json_get_str(details, "reason");
        if (!tsm_json_get_int(details, "retryAfterMs", &retry)) {
            retry = -1;
        }
    }
    return tsm_set_error(tsm_error_kind_from_wire(tsm_json_get_str(m, "kind")), reason, retry, "%s",
                         message ? message : "");
}

tsm_error_kind tsm_not_running(const char *why) {
    return tsm_set_error(TSM_ERR_NOT_RUNNING, NULL, -1, "the secrets service is not running: %s", why);
}

tsm_error_kind tsm_protocol_error(const char *why) {
    return tsm_set_error(TSM_ERR_INTERNAL, NULL, -1, "the service broke the protocol: %s", why);
}

tsm_error_kind tsm_no_memory(void) { return tsm_set_error(TSM_ERR_NO_MEMORY, NULL, -1, "out of memory"); }

static const char *const kind_names[] = {
    "ok",       "locked",   "denied",  "not_found",    "ambiguous",   "needs_unlock",
    "unavailable", "offline", "token_expired", "malformed", "timeout", "rate_limited",
    "unsupported", "internal", "not_running", "invalid_argument", "no_memory"};

const char *tsm_error_kind_name(tsm_error_kind kind) {
    if ((int)kind < 0 || (size_t)kind >= sizeof kind_names / sizeof kind_names[0]) {
        return "internal";
    }
    return kind_names[kind];
}

tsm_error_kind tsm_error_kind_from_wire(const char *name) {
    int k;
    if (!name) {
        return TSM_ERR_INTERNAL;
    }
    for (k = TSM_ERR_LOCKED; k <= TSM_ERR_INTERNAL; k++) {
        if (strcmp(kind_names[k], name) == 0) {
            return (tsm_error_kind)k;
        }
    }
    return TSM_ERR_INTERNAL;
}

/* ---- SHA-256 (FIPS 180-4) -------------------------------------------- */

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t h[8], const unsigned char *p) {
    uint32_t w[64], a, b, c, d, e, f, g, hh;
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) | ((uint32_t)p[4 * i + 2] << 8) |
               (uint32_t)p[4 * i + 3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (i = 0; i < 64; i++) {
        uint32_t s1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + s1 + ch + K[i] + w[i];
        uint32_t s0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    tsm_wipe(w, sizeof w);
}

void tsm_sha256(const unsigned char *data, size_t len, unsigned char out[32]) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    unsigned char block[64];
    size_t i, rest = len % 64;
    uint64_t bits = (uint64_t)len * 8;
    for (i = 0; i + 64 <= len; i += 64) {
        sha256_block(h, data + i);
    }
    memset(block, 0, sizeof block);
    if (rest) {
        memcpy(block, data + len - rest, rest);
    }
    block[rest] = 0x80;
    if (rest >= 56) {
        sha256_block(h, block);
        memset(block, 0, sizeof block);
    }
    for (i = 0; i < 8; i++) {
        block[56 + i] = (unsigned char)(bits >> (56 - 8 * i));
    }
    sha256_block(h, block);
    tsm_wipe(block, sizeof block);
    for (i = 0; i < 8; i++) {
        out[4 * i] = (unsigned char)(h[i] >> 24);
        out[4 * i + 1] = (unsigned char)(h[i] >> 16);
        out[4 * i + 2] = (unsigned char)(h[i] >> 8);
        out[4 * i + 3] = (unsigned char)h[i];
    }
}

/* ---- base64 ---------------------------------------------------------- */

int tsm_base64_decode(const char *text, unsigned char **out, size_t *out_len) {
    size_t n = strlen(text), pad = 0, i, o = 0;
    uint32_t buffer = 0;
    int bits = 0;
    unsigned char *data;
    while (n > 0 && text[n - 1] == '=') {
        n--;
        pad++;
    }
    if (pad > 2) {
        return 0;
    }
    data = (unsigned char *)malloc(n * 3 / 4 + 1);
    if (!data) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        char c = text[i];
        int v;
        if (c >= 'A' && c <= 'Z') {
            v = c - 'A';
        } else if (c >= 'a' && c <= 'z') {
            v = c - 'a' + 26;
        } else if (c >= '0' && c <= '9') {
            v = c - '0' + 52;
        } else if (c == '+') {
            v = 62;
        } else if (c == '/') {
            v = 63;
        } else {
            free(data);
            return 0;
        }
        buffer = (buffer << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            data[o++] = (unsigned char)(buffer >> bits);
        }
    }
    /* One leftover character carries fewer than 8 bits: not base64. */
    if (bits >= 6) {
        tsm_wipe(data, o);
        free(data);
        return 0;
    }
    *out = data;
    *out_len = o;
    return 1;
}

/* ---- RFC 3339 times -------------------------------------------------- */

static int digits(const char *s, size_t n, long long *out) {
    long long v = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return 0;
        }
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return 1;
}

static long long days_from_civil(long long y, long long m, long long d) {
    long long era, yoe, doy, doe;
    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

int tsm_parse_time(const char *s, long long *ms) {
    long long year, month, day, hour, minute, second, millis = 0, offset = 0, mdays;
    size_t at = 19, len = strlen(s);
    if (len < 20 || !digits(s, 4, &year) || s[4] != '-' || !digits(s + 5, 2, &month) || s[7] != '-' ||
        !digits(s + 8, 2, &day) || (s[10] != 'T' && s[10] != 't') || !digits(s + 11, 2, &hour) ||
        s[13] != ':' || !digits(s + 14, 2, &minute) || s[16] != ':' || !digits(s + 17, 2, &second)) {
        return 0;
    }
    if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) {
        return 0;
    }
    mdays = (month == 2) ? (((year % 4 == 0 && year % 100 != 0) || year % 400 == 0) ? 29 : 28)
            : (month == 4 || month == 6 || month == 9 || month == 11) ? 30 : 31;
    if (day < 1 || day > mdays) {
        return 0;
    }
    if (s[at] == '.') {
        size_t start = ++at, k;
        while (at < len && s[at] >= '0' && s[at] <= '9') {
            at++;
        }
        if (at == start) {
            return 0;
        }
        for (k = 0; k < 3; k++) {
            millis = millis * 10 + (start + k < at ? s[start + k] - '0' : 0);
        }
    }
    if ((s[at] == 'Z' || s[at] == 'z') && at + 1 == len) {
        offset = 0;
    } else if ((s[at] == '+' || s[at] == '-') && at + 6 == len && s[at + 3] == ':') {
        long long oh, om;
        if (!digits(s + at + 1, 2, &oh) || !digits(s + at + 4, 2, &om) || om > 59) {
            return 0;
        }
        offset = (oh * 3600 + om * 60) * (s[at] == '+' ? 1 : -1);
    } else {
        return 0;
    }
    *ms = ((days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second) - offset) * 1000 +
          millis;
    return 1;
}
