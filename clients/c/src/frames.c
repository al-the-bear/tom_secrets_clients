/*
 * Copyright (c) 2026 Peter Nicolai Alexis Kyaw
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Frames and JSON payloads (protocol.md section 2).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

unsigned char *tsm_frame_encode(int type, const unsigned char *payload, size_t len, size_t *out_len) {
    unsigned char *out = (unsigned char *)malloc(len + 5);
    if (!out) {
        return NULL;
    }
    out[0] = (unsigned char)(len >> 24);
    out[1] = (unsigned char)(len >> 16);
    out[2] = (unsigned char)(len >> 8);
    out[3] = (unsigned char)len;
    out[4] = (unsigned char)type;
    if (len) {
        memcpy(out + 5, payload, len);
    }
    *out_len = len + 5;
    return out;
}

void tsm_frames_free(tsm_frame *frames, size_t count) {
    size_t i;
    for (i = 0; i < count; i++) {
        tsm_wipe(frames[i].payload, frames[i].len);
        free(frames[i].payload);
    }
    free(frames);
}

void tsm_frame_reader_free(tsm_frame_reader *r) { tsm_buf_wipe(&r->pending); }

int tsm_frames_add(tsm_frame_reader *r, const unsigned char *data, size_t n, tsm_frame **frames,
                   size_t *count, char *why, size_t why_size) {
    size_t offset = 0, cap = 0;
    tsm_frame *out = NULL;
    *frames = NULL;
    *count = 0;
    if (n && !tsm_buf_add(&r->pending, data, n)) {
        snprintf(why, why_size, "out of memory");
        return -1;
    }
    while (r->pending.len - offset >= 5) {
        const unsigned char *h = r->pending.data + offset;
        unsigned long length = ((unsigned long)h[0] << 24) | ((unsigned long)h[1] << 16) |
                               ((unsigned long)h[2] << 8) | (unsigned long)h[3];
        int type = h[4];
        if (length > r->max_payload) {
            snprintf(why, why_size, "frame of %lu bytes over %lu", length, (unsigned long)r->max_payload);
            tsm_frames_free(out, *count);
            *count = 0;
            return -1;
        }
        if (type != TSM_FRAME_JSON && !(type == TSM_FRAME_BINARY && r->binary_allowed)) {
            snprintf(why, why_size, "frame type %d", type);
            tsm_frames_free(out, *count);
            *count = 0;
            return -1;
        }
        if (r->pending.len - offset - 5 < length) {
            break;
        }
        if (*count == cap) {
            tsm_frame *grown;
            cap = cap ? cap * 2 : 4;
            grown = (tsm_frame *)realloc(out, cap * sizeof *grown);
            if (!grown) {
                tsm_frames_free(out, *count);
                *count = 0;
                snprintf(why, why_size, "out of memory");
                return -1;
            }
            out = grown;
        }
        out[*count].type = type;
        out[*count].len = length;
        out[*count].payload = (unsigned char *)malloc(length + 1);
        if (!out[*count].payload) {
            tsm_frames_free(out, *count);
            *count = 0;
            snprintf(why, why_size, "out of memory");
            return -1;
        }
        memcpy(out[*count].payload, h + 5, length);
        out[*count].payload[length] = 0;
        (*count)++;
        offset += 5 + length;
    }
    if (offset) {
        /* The bytes handed out held frames (values among them): overwritten
         * as the buffer moves on. */
        memmove(r->pending.data, r->pending.data + offset, r->pending.len - offset);
        tsm_wipe(r->pending.data + r->pending.len - offset, offset);
        r->pending.len -= offset;
    }
    *frames = out;
    return 0;
}

tsm_json *tsm_payload_decode(const unsigned char *payload, size_t len, char *why, size_t why_size) {
    tsm_json *j;
    char reason[160];
    if (len == 0) {
        snprintf(why, why_size, "empty payload");
        return NULL;
    }
    if (!tsm_utf8_valid(payload, len)) {
        snprintf(why, why_size, "payload is not UTF-8");
        return NULL;
    }
    if (len >= 3 && payload[0] == 0xEF && payload[1] == 0xBB && payload[2] == 0xBF) {
        snprintf(why, why_size, "payload starts with a byte order mark");
        return NULL;
    }
    reason[0] = 0;
    j = tsm_json_parse((const char *)payload, len, reason, sizeof reason);
    if (!j) {
        snprintf(why, why_size, "payload is not JSON: %s", reason);
        return NULL;
    }
    if (j->type != TSM_J_OBJECT) {
        tsm_json_free(j);
        snprintf(why, why_size, "payload is not a JSON object");
        return NULL;
    }
    if (!tsm_json_get_str(j, "op")) {
        tsm_json_free(j);
        snprintf(why, why_size, "payload has no op");
        return NULL;
    }
    return j;
}
