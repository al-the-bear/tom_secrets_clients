/*
 * Copyright (c) 2026 Peter Nicolai Alexis Kyaw
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * The C client of the Tom Secrets Manager's secrets service (C99; Winsock
 * on Windows). A program reads its secrets from the secrets service that
 * runs for its user on the same machine:
 *
 *     tsm_client *c;
 *     if (tsm_connect(&c, NULL) != TSM_OK) { ... tsm_last_error(NULL) ... }
 *     tsm_get_options opts = TSM_GET_OPTIONS_INIT;
 *     opts.field = "UserName";
 *     tsm_value *v;
 *     int rc = tsm_get(c, "[env:prod]db.main", &opts, &v);
 *     if (rc == TSM_OK) { use(tsm_value_text(v)); tsm_value_free(v); }
 *     tsm_client_free(c);
 *
 * Every call that can fail returns a tsm_error_kind (TSM_OK on success);
 * tsm_last_error gives the calling thread's last error with its message and
 * reason. A value never prints its secret (there is no printing function
 * that shows it), and tsm_value_free overwrites its buffer. The library is
 * written from the protocol document (protocol.md), links nothing but the C
 * library, threads and sockets, and logs nothing.
 */
#ifndef TSM_TSM_H
#define TSM_TSM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A client of the secrets service. */
typedef struct tsm_client tsm_client;

/* The protocol version this library speaks. */
#define TSM_PROTOCOL_VERSION 1
/* This library's version, sent in hello. */
#define TSM_CLIENT_VERSION "0.1.0"
/* The most references one tsm_get_many carries. */
#define TSM_MAX_GET_MANY 256
/* The field a reference without #field names. */
#define TSM_DEFAULT_FIELD "Password"
/* The longest reference, in bytes of UTF-8. */
#define TSM_MAX_REFERENCE_BYTES 1024

/*
 * What went wrong: TSM_OK, the protocol's kinds (protocol.md section 10),
 * TSM_ERR_NOT_RUNNING (no service found, or the connection lost), and two
 * of the library's own: TSM_ERR_INVALID_ARGUMENT (the program called it
 * wrongly) and TSM_ERR_NO_MEMORY.
 */
typedef enum tsm_error_kind {
    TSM_OK = 0,
    TSM_ERR_LOCKED,
    TSM_ERR_DENIED,
    TSM_ERR_NOT_FOUND,
    TSM_ERR_AMBIGUOUS,
    TSM_ERR_NEEDS_UNLOCK,
    TSM_ERR_UNAVAILABLE,
    TSM_ERR_OFFLINE,
    TSM_ERR_TOKEN_EXPIRED,
    TSM_ERR_MALFORMED,
    TSM_ERR_TIMEOUT,
    TSM_ERR_RATE_LIMITED,
    TSM_ERR_UNSUPPORTED,
    TSM_ERR_INTERNAL,
    TSM_ERR_NOT_RUNNING,
    TSM_ERR_INVALID_ARGUMENT,
    TSM_ERR_NO_MEMORY
} tsm_error_kind;

/* The protocol's name of a kind ("not_found"); "ok", "invalid_argument",
 * "no_memory" for the library's own. */
const char *tsm_error_kind_name(tsm_error_kind kind);

/* The kind an error message names: an unknown kind is TSM_ERR_INTERNAL, and
 * so is "not_running" (never the service's to send). */
tsm_error_kind tsm_error_kind_from_wire(const char *name);

/* An error: its kind, a message for people (never a value, token or key),
 * details.reason (or NULL) and details.retryAfterMs (or -1). */
typedef struct tsm_error {
    tsm_error_kind kind;
    const char *message;
    const char *reason;
    long long retry_after_ms;
} tsm_error;

/*
 * The calling thread's last error: of its last failed call of this library
 * (any client; c may be NULL). Valid until the thread's next call that
 * fails. Kind TSM_OK and an empty message before any failure.
 */
const tsm_error *tsm_last_error(const tsm_client *c);

/* --------------------------------------------------------------------- */
/* Values                                                                 */
/* --------------------------------------------------------------------- */

/* A secret. tsm_value_free overwrites its buffer. */
typedef struct tsm_value tsm_value;

/* The value as a NUL-terminated string; NULL for a binary value (encoding
 * "base64"), which is read with tsm_value_bytes rather than as a corrupt
 * string. A value holding a NUL byte reads up to it here. */
const char *tsm_value_text(const tsm_value *v);
/* The value's bytes (text as UTF-8) and their count. */
const unsigned char *tsm_value_bytes(const tsm_value *v, size_t *size);
/* "utf8" or "base64". */
const char *tsm_value_encoding(const tsm_value *v);
/* The reference the value was asked for, as given. */
const char *tsm_value_reference(const tsm_value *v);
/* The entry it was read from: store, KDBX UUID, source ("github", "file" or
 * "cache"), and the last successful fetch of the store (ms since the
 * epoch). */
const char *tsm_value_entry_store(const tsm_value *v);
const char *tsm_value_entry_uuid(const tsm_value *v);
const char *tsm_value_entry_source(const tsm_value *v);
long long tsm_value_entry_fetched_at_ms(const tsm_value *v);
/* The entry's version: its last modification (ms since the epoch) and the
 * store file revision; compare them to see a change. */
long long tsm_value_version_modified_ms(const tsm_value *v);
const char *tsm_value_version_revision(const tsm_value *v);
/* The entry's expiry (ms since the epoch); 0 when it has none. */
int tsm_value_expires_ms(const tsm_value *v, long long *expires_ms);
/* The client token the service granted, or NULL: the caller's to keep
 * (7.4); the library never stores it. */
const char *tsm_value_client_token(const tsm_value *v);
/* The bindings the winning entry carries: their count, and the i-th
 * dimension and value (sorted by dimension). */
size_t tsm_value_bound_count(const tsm_value *v);
const char *tsm_value_bound_dimension(const tsm_value *v, size_t i);
const char *tsm_value_bound_value(const tsm_value *v, size_t i);
/* Overwrites the buffer with zeros and frees the value. NULL is allowed. */
void tsm_value_free(tsm_value *v);

/* An attachment or a typed key read with tsm_get_file: its name and bytes.
 * tsm_file_free overwrites them. */
typedef struct tsm_file tsm_file;
const char *tsm_file_reference(const tsm_file *f);
const char *tsm_file_name(const tsm_file *f);
const unsigned char *tsm_file_bytes(const tsm_file *f, size_t *size);
void tsm_file_free(tsm_file *f);

/* A progress notice (5.4): pending is "unlock" or "approval"; approval_code
 * is the one-time approval code (7.5), or NULL. Valid during the callback
 * only. */
typedef struct tsm_progress {
    const char *pending;
    const char *approval_code;
} tsm_progress;

/* Receives the progress notices of a waiting request, on the connection's
 * reader thread: it must return quickly. */
typedef void (*tsm_progress_fn)(const tsm_progress *progress, void *context);

/* --------------------------------------------------------------------- */
/* The client                                                             */
/* --------------------------------------------------------------------- */

/* How a client finds and greets the service; every field may be 0/NULL. */
typedef struct tsm_client_options {
    /* Shown in approval prompts, never trusted. Default "c". */
    const char *client_name;
    /* A client token the program was granted before, sent in hello. */
    const char *client_token;
    /* The runtime directory instead of the environment's (as
     * TSM_RUNTIME_DIR names one). */
    const char *runtime_dir;
    /* "linux", "macos" or "windows". Default: this platform's. */
    const char *operating_system;
    /* How long connecting and the welcome may take, in ms. Default 10000. */
    int connect_timeout_ms;
} tsm_client_options;

#define TSM_CLIENT_OPTIONS_INIT {NULL, NULL, NULL, NULL, 0}

/*
 * The options of one tsm_get or tsm_get_file. Initialise with
 * TSM_GET_OPTIONS_INIT, then set what differs.
 */
typedef struct tsm_get_options {
    /* The field, when the reference names none. The same field in both is
     * sent once; two different ones are TSM_ERR_MALFORMED, reason
     * field_twice. */
    const char *field;
    /* Values for dimensions beside the reference: dimension, value,
     * dimension, value, ..., NULL. */
    const char *const *dimensions;
    /* Answer at once instead of waiting for an unlock or an approval. */
    int no_wait;
    /* How long the service may wait, in ms (capped by the service); -1:
     * not sent. */
    long long timeout_ms;
    tsm_progress_fn on_progress;
    void *progress_context;
    /* Ask for a client token with an "always" approval (tsm_get only). */
    int want_client_token;
    /* Wait out a rate_limited answer (its retryAfterMs, else 1 s) and send
     * the request again. */
    int wait_on_rate_limit;
} tsm_get_options;

#define TSM_GET_OPTIONS_INIT {NULL, NULL, 0, -1, NULL, NULL, 0, 0}

/* The options of one tsm_get_many (each tsm_request carries its field and
 * dimensions). */
typedef struct tsm_request_options {
    int no_wait;
    long long timeout_ms;
    tsm_progress_fn on_progress;
    void *progress_context;
    int wait_on_rate_limit;
} tsm_request_options;

#define TSM_REQUEST_OPTIONS_INIT {0, -1, NULL, NULL, 0}

/* One reference of a tsm_get_many. */
typedef struct tsm_request {
    const char *ref;
    const char *field;
    const char *const *dimensions;
} tsm_request;

/* One result of a tsm_get_many, in request order: a value (kind TSM_OK) or
 * an error. */
typedef struct tsm_result {
    tsm_value *value;
    tsm_error_kind kind;
    char *message;
    char *reason;
} tsm_result;

/* What the service said in welcome. */
typedef struct tsm_welcome {
    int protocol;
    const char *service_version;
    const char *host;
    const char *platform;
    /* The optional features it offers, sorted. */
    const char *const *features;
    size_t feature_count;
} tsm_welcome;

/* A client that connects on its first call. options may be NULL. */
tsm_error_kind tsm_client_new(tsm_client **out, const tsm_client_options *options);
/* A client connected at once, so a missing service shows right away. */
tsm_error_kind tsm_connect(tsm_client **out, const tsm_client_options *options);
/* Connects, unless a connection is open. */
tsm_error_kind tsm_open(tsm_client *c);
/* Closes the connection; a later call connects again. */
void tsm_close(tsm_client *c);
/* Closes and frees the client. No call may run on it then. NULL allowed. */
void tsm_client_free(tsm_client *c);
/* The welcome of the current connection; 0 when there is none. The strings
 * stay valid until the connection closes. */
int tsm_welcome_get(tsm_client *c, tsm_welcome *out);

/*
 * Reads one secret. The reference is parsed locally first: a malformed one
 * fails as TSM_ERR_MALFORMED without a round trip, and so does a request
 * over 64 KiB (reason frame). options may be NULL.
 */
tsm_error_kind tsm_get(tsm_client *c, const char *ref, const tsm_get_options *options, tsm_value **out);

/*
 * Reads 1 to TSM_MAX_GET_MANY secrets under one approval prompt; *out gets
 * an array of count results in request order (free with tsm_results_free).
 */
tsm_error_kind tsm_get_many(tsm_client *c, const tsm_request *requests, size_t count,
                            const tsm_request_options *options, tsm_result **out);
void tsm_results_free(tsm_result *results, size_t count);

/*
 * Reads an attachment or a typed key as bytes (5.5), checked against its
 * size and SHA-256. TSM_ERR_UNSUPPORTED when the service does not offer the
 * features binary and getFile.
 */
tsm_error_kind tsm_get_file(tsm_client *c, const char *ref, const tsm_get_options *options, tsm_file **out);

/* --------------------------------------------------------------------- */
/* References                                                             */
/* --------------------------------------------------------------------- */

typedef enum tsm_target_kind { TSM_TARGET_KEY, TSM_TARGET_PATH, TSM_TARGET_UUID } tsm_target_kind;

/* A parsed reference: the target (key; store and segments; store and
 * uuid), the bindings in the order written, the effective field and whether
 * one was written. */
typedef struct tsm_reference {
    tsm_target_kind kind;
    char *key;
    char *store;
    char **segments;
    size_t segment_count;
    char *uuid;
    char **dimensions;
    char **values;
    size_t qualifier_count;
    char *field;
    int field_given;
} tsm_reference;

/* Parses a reference (protocol.md 4); a malformed one is TSM_ERR_MALFORMED
 * whose reason names the rule it broke. */
tsm_error_kind tsm_reference_parse(const char *text, tsm_reference **out);
/* The canonical form (4.5), malloc'd; TSM_ERR_INVALID_ARGUMENT for a
 * reference that has none (a dimension bound twice, an empty segment).
 * field may be NULL for the default. */
tsm_error_kind tsm_reference_format(const tsm_reference *ref, char **out);
void tsm_reference_free(tsm_reference *ref);

/* Frees what the library allocated for the caller (tsm_reference_format's
 * text). */
void tsm_free(void *p);

/* --------------------------------------------------------------------- */
/* Finding the service                                                    */
/* --------------------------------------------------------------------- */

/* The runtime directory and its endpoint files (3.1); "" for the names a
 * platform does not use. */
typedef struct tsm_endpoints {
    char directory[1024];
    char client_socket[1100];
    char admin_socket[1100];
    char client_port_file[1100];
    char client_token_file[1100];
    char admin_port_file[1100];
} tsm_endpoints;

/* Reads one environment variable; NULL when unset. */
typedef const char *(*tsm_getenv_fn)(const char *name, void *context);

/*
 * The location of the service for operating_system ("linux", "macos",
 * "windows"), the environment and the numeric user id (only for the
 * /tmp/tsm-<uid> fallback). TSM_ERR_NOT_RUNNING when no runtime directory
 * can be named (Windows without LOCALAPPDATA and USERPROFILE).
 */
tsm_error_kind tsm_discover(const char *operating_system, tsm_getenv_fn getenv_fn, void *context,
                            long long uid, tsm_endpoints *out);

/* The port of a port file's text (decimal 1-65535, no sign or leading zero,
 * at most one trailing LF or CR LF), or 0 when unreadable. */
int tsm_read_port_file(const char *text);

/* "linux", "macos" or "windows" for this platform. */
const char *tsm_current_operating_system(void);

#ifdef __cplusplus
}
#endif

#endif /* TSM_TSM_H */
