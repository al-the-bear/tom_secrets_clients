/*
 * Copyright (c) 2026 Peter Nicolai Alexis Kyaw
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * The library's internals: JSON, byte buffers, the platform layer (sockets,
 * threads, files), errors and the small algorithms the protocol needs
 * (SHA-256, base64, RFC 3339 times).
 */
#ifndef TSM_INTERNAL_H
#define TSM_INTERNAL_H

#include <stddef.h>

#include "tsm/tsm.h"

/* ---- byte buffers ---------------------------------------------------- */

typedef struct tsm_buf {
    unsigned char *data;
    size_t len;
    size_t cap;
} tsm_buf;

int tsm_buf_add(tsm_buf *b, const void *data, size_t n);
int tsm_buf_addc(tsm_buf *b, char c);
int tsm_buf_adds(tsm_buf *b, const char *s);
/* Overwrites and frees the buffer's bytes. */
void tsm_buf_wipe(tsm_buf *b);
/* Overwrites n bytes in a way the optimiser keeps. */
void tsm_wipe(void *p, size_t n);
char *tsm_strdup(const char *s);
char *tsm_strndup(const char *s, size_t n);
int tsm_utf8_valid(const unsigned char *s, size_t n);

/* ---- JSON (protocol.md 2.3) ------------------------------------------ */

typedef enum { TSM_J_NULL, TSM_J_BOOL, TSM_J_NUMBER, TSM_J_STRING, TSM_J_ARRAY, TSM_J_OBJECT } tsm_jtype;

typedef struct tsm_json {
    tsm_jtype type;
    int boolean;
    double number;
    int is_integer; /* written without fraction or exponent, fits a long long */
    long long integer;
    char *string; /* NUL-terminated; string_len counts embedded NULs */
    size_t string_len;
    struct tsm_json **items; /* array items, or object values */
    char **keys;             /* object member names */
    size_t count;
    size_t capacity;
} tsm_json;

/* Parses strictly: one value, no duplicate member names, numbers in the JSON
 * grammar and inside a double, no unescaped control characters, valid UTF-8.
 * NULL on failure, with the reason in why (when given). */
tsm_json *tsm_json_parse(const char *text, size_t len, char *why, size_t why_size);
void tsm_json_free(tsm_json *j);
/* Overwrites the strings of j before freeing it (a value message). */
void tsm_json_wipe_free(tsm_json *j);
/* The compact text, members sorted by name; NULL when out of memory. */
char *tsm_json_write(const tsm_json *j, size_t *len);

tsm_json *tsm_json_null(void);
tsm_json *tsm_json_bool(int b);
tsm_json *tsm_json_int(long long i);
tsm_json *tsm_json_str(const char *s);
tsm_json *tsm_json_strn(const char *s, size_t n);
tsm_json *tsm_json_array(void);
tsm_json *tsm_json_object(void);
/* Takes ownership of value; replaces an existing member. 0 on failure. */
int tsm_json_set(tsm_json *object, const char *key, tsm_json *value);
int tsm_json_push(tsm_json *array, tsm_json *value);
const tsm_json *tsm_json_get(const tsm_json *object, const char *key);
const char *tsm_json_get_str(const tsm_json *object, const char *key);
/* The member as an integer: 1 when it is one. */
int tsm_json_get_int(const tsm_json *object, const char *key, long long *out);
tsm_json *tsm_json_clone(const tsm_json *j);

/* ---- frames (protocol.md 2) ------------------------------------------ */

#define TSM_FRAME_JSON 0
#define TSM_FRAME_BINARY 1
#define TSM_MAX_REQUEST_PAYLOAD (64 * 1024)
#define TSM_MAX_ANSWER_PAYLOAD (1024 * 1024)

typedef struct tsm_frame_reader {
    size_t max_payload;
    int binary_allowed;
    tsm_buf pending;
} tsm_frame_reader;

/* One frame read: its type and payload (malloc'd). */
typedef struct tsm_frame {
    int type;
    unsigned char *payload;
    size_t len;
} tsm_frame;

/* Adds data; *frames gets a malloc'd array of the frames now complete.
 * 0 on success; -1 with why for a frame that breaks section 2. */
int tsm_frames_add(tsm_frame_reader *r, const unsigned char *data, size_t n, tsm_frame **frames,
                   size_t *count, char *why, size_t why_size);
void tsm_frames_free(tsm_frame *frames, size_t count);
void tsm_frame_reader_free(tsm_frame_reader *r);
/* A frame: 4-byte big-endian length, the type, the payload. */
unsigned char *tsm_frame_encode(int type, const unsigned char *payload, size_t len, size_t *out_len);
/* The message of a JSON payload, or NULL with why (empty, not UTF-8, a byte
 * order mark, not strict JSON, not an object, no string op). */
tsm_json *tsm_payload_decode(const unsigned char *payload, size_t len, char *why, size_t why_size);

/* ---- errors ---------------------------------------------------------- */

/* Sets the calling thread's last error; returns kind. */
tsm_error_kind tsm_set_error(tsm_error_kind kind, const char *reason, long long retry_after_ms,
                             const char *format, ...);
tsm_error_kind tsm_set_error_from_message(const tsm_json *message);
tsm_error_kind tsm_not_running(const char *why);
tsm_error_kind tsm_protocol_error(const char *why);
tsm_error_kind tsm_no_memory(void);

/* ---- algorithms ------------------------------------------------------ */

void tsm_sha256(const unsigned char *data, size_t len, unsigned char out[32]);
/* Decodes standard base64, padding optional; 0 on bad input. */
int tsm_base64_decode(const char *text, unsigned char **out, size_t *out_len);
/* An RFC 3339 date-time as ms since the epoch; 0 when it is none. */
int tsm_parse_time(const char *text, long long *ms);

/* ---- platform -------------------------------------------------------- */

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
typedef SOCKET tsm_socket;
#define TSM_INVALID_SOCKET INVALID_SOCKET
typedef SRWLOCK tsm_mutex;
typedef CONDITION_VARIABLE tsm_cond;
#else
#include <pthread.h>
typedef int tsm_socket;
#define TSM_INVALID_SOCKET (-1)
typedef pthread_mutex_t tsm_mutex;
typedef pthread_cond_t tsm_cond;
#endif

int tsm_platform_init(void);
void tsm_mutex_init(tsm_mutex *m);
void tsm_mutex_destroy(tsm_mutex *m);
void tsm_mutex_lock(tsm_mutex *m);
void tsm_mutex_unlock(tsm_mutex *m);
void tsm_cond_init(tsm_cond *c);
void tsm_cond_destroy(tsm_cond *c);
void tsm_cond_wait(tsm_cond *c, tsm_mutex *m);
/* 0 when woken, 1 when timeout_ms passed. */
int tsm_cond_timedwait(tsm_cond *c, tsm_mutex *m, long long timeout_ms);
void tsm_cond_broadcast(tsm_cond *c);
/* Starts a detached thread; 0 on failure. */
int tsm_thread_start(void (*fn)(void *), void *arg);
long long tsm_monotonic_ms(void);
void tsm_sleep_ms(long long ms);
/* The file's bytes, NUL-terminated (malloc'd), or NULL. */
char *tsm_read_file(const char *path, size_t *len);
int tsm_file_exists(const char *path);
long long tsm_process_uid(void);

/* 0 on success. */
int tsm_socket_connect_unix(const char *path, tsm_socket *out);
int tsm_socket_connect_localhost(int port, int timeout_ms, tsm_socket *out);
int tsm_socket_send_all(tsm_socket s, const unsigned char *data, size_t len);
/* Bytes read, 0 at the end, -1 on an error. */
long tsm_socket_recv(tsm_socket s, unsigned char *buffer, size_t size);
void tsm_socket_shutdown(tsm_socket s);
void tsm_socket_close(tsm_socket s);

/* ---- values (value.c) ------------------------------------------------ */

tsm_error_kind tsm_value_from_message(const char *ref, const tsm_json *m, tsm_value **out);
tsm_file *tsm_file_new(const char *ref, const char *name, unsigned char *data, size_t len);

#endif /* TSM_INTERNAL_H */
