/*
 * Copyright (c) 2026 Peter Nicolai Alexis Kyaw
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * The client (protocol.md section 5): the connection with its reader
 * thread, hello, get, getMany and getFile.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

/* ---- the connection -------------------------------------------------- */

typedef struct pending {
    long long id;
    int done;
    tsm_json *answer;
    tsm_json *file;
    int has_chunks;
    tsm_buf chunks;
    tsm_progress_fn on_progress;
    void *progress_context;
    struct pending *next;
} pending;

typedef struct connection {
    tsm_socket sock;
    tsm_mutex mu;
    tsm_cond cond;
    tsm_mutex write_mu;
    int refs;
    int closed;
    tsm_error_kind error_kind;
    char error_message[512];
    char error_reason[96];
    long long error_retry;
    int welcomed;
    char *service_version;
    char *host;
    char *platform;
    char **features;
    size_t feature_count;
    pending *pending;
    long long next_id;
    tsm_frame_reader frames;
} connection;

struct tsm_client {
    char *name;
    char *token;
    char *runtime_dir;
    char *os;
    int connect_timeout_ms;
    tsm_mutex mu;
    connection *conn;
};

static void connection_free(connection *c) {
    size_t i;
    tsm_socket_close(c->sock);
    while (c->pending) {
        pending *p = c->pending;
        c->pending = p->next;
        tsm_json_wipe_free(p->answer);
        tsm_json_free(p->file);
        tsm_buf_wipe(&p->chunks);
        free(p);
    }
    tsm_frame_reader_free(&c->frames);
    free(c->service_version);
    free(c->host);
    free(c->platform);
    for (i = 0; i < c->feature_count; i++) {
        free(c->features[i]);
    }
    free(c->features);
    tsm_cond_destroy(&c->cond);
    tsm_mutex_destroy(&c->mu);
    tsm_mutex_destroy(&c->write_mu);
    free(c);
}

static void connection_release(connection *c) {
    int last;
    tsm_mutex_lock(&c->mu);
    last = --c->refs == 0;
    tsm_mutex_unlock(&c->mu);
    if (last) {
        connection_free(c);
    }
}

/* Fails the connection with kind, reason and message: every waiting
 * request gets it, and the reader thread stops. */
static void connection_fail_with(connection *c, tsm_error_kind kind, const char *reason, long long retry,
                                 const char *message) {
    pending *p;
    tsm_mutex_lock(&c->mu);
    if (c->closed) {
        tsm_mutex_unlock(&c->mu);
        return;
    }
    c->closed = 1;
    c->error_kind = kind;
    snprintf(c->error_message, sizeof c->error_message, "%s", message);
    snprintf(c->error_reason, sizeof c->error_reason, "%s", reason ? reason : "");
    c->error_retry = retry;
    for (p = c->pending; p; p = p->next) {
        if (!p->done) {
            p->done = 1;
            tsm_buf_wipe(&p->chunks);
        }
    }
    tsm_cond_broadcast(&c->cond);
    tsm_mutex_unlock(&c->mu);
    /* Unblocks the reader thread, which then ends. */
    tsm_socket_shutdown(c->sock);
}

/* Fails the connection with the calling thread's last error. */
static void connection_fail(connection *c) {
    const tsm_error *e = tsm_last_error(NULL);
    connection_fail_with(c, e->kind, e->reason, e->retry_after_ms, e->message);
}

/* Copies the connection's failure into the calling thread's last error. */
static tsm_error_kind connection_error(connection *c) {
    tsm_error_kind kind;
    tsm_mutex_lock(&c->mu);
    kind = tsm_set_error(c->error_kind, c->error_reason[0] ? c->error_reason : NULL, c->error_retry, "%s",
                         c->error_message);
    tsm_mutex_unlock(&c->mu);
    return kind;
}

static tsm_error_kind dropped(void) { return tsm_not_running("the connection to the service dropped"); }

/* The pending request of id that still waits; the lock is held. */
static pending *find_pending(connection *c, long long id) {
    pending *p;
    for (p = c->pending; p; p = p->next) {
        if (p->id == id && !p->done) {
            return p;
        }
    }
    return NULL;
}

static int welcome_of(connection *c, const tsm_json *m) {
    long long protocol;
    const tsm_json *service = tsm_json_get(m, "service");
    const tsm_json *features = tsm_json_get(m, "features");
    const tsm_json *version = service ? tsm_json_get(service, "version") : NULL;
    const tsm_json *p = tsm_json_get(m, "protocol");
    const char *host = tsm_json_get_str(m, "host"), *platform = tsm_json_get_str(m, "platform");
    size_t i, j;
    if (!p || p->type != TSM_J_NUMBER || !p->is_integer || !tsm_json_get_int(m, "protocol", &protocol) ||
        protocol != TSM_PROTOCOL_VERSION) {
        char shown[64] = "none";
        if (p) {
            char *text = tsm_json_write(p, NULL);
            snprintf(shown, sizeof shown, "%s", text ? text : "?");
            free(text);
        }
        tsm_set_error(TSM_ERR_UNSUPPORTED, NULL, -1, "the service speaks protocol %s", shown);
        return 0;
    }
    if (version && version->type == TSM_J_STRING) {
        c->service_version = tsm_strdup(version->string);
    } else {
        c->service_version = version ? tsm_json_write(version, NULL) : tsm_strdup("");
    }
    c->host = tsm_strdup(host ? host : "");
    c->platform = tsm_strdup(platform ? platform : "");
    if (features && features->type == TSM_J_ARRAY && features->count) {
        c->features = (char **)calloc(features->count, sizeof(char *));
        for (i = 0; c->features && i < features->count; i++) {
            if (features->items[i]->type == TSM_J_STRING) {
                c->features[c->feature_count++] = tsm_strdup(features->items[i]->string);
            }
        }
        /* Sorted, by insertion. */
        for (i = 1; c->features && i < c->feature_count; i++) {
            char *k = c->features[i];
            for (j = i; j > 0 && strcmp(c->features[j - 1], k) > 0; j--) {
                c->features[j] = c->features[j - 1];
            }
            c->features[j] = k;
        }
    }
    return 1;
}

static int offers(connection *c, const char *feature) {
    size_t i;
    for (i = 0; i < c->feature_count; i++) {
        if (c->features[i] && strcmp(c->features[i], feature) == 0) {
            return 1;
        }
    }
    return 0;
}

/* One message from the service; 0 when it fails the connection. */
static int on_message(connection *c, tsm_json *m) {
    const char *op = tsm_json_get_str(m, "op");
    const tsm_json *id_value = tsm_json_get(m, "id");
    long long id;
    pending *p;
    if (!c->welcomed) {
        if (strcmp(op, "welcome") == 0) {
            int ok;
            tsm_mutex_lock(&c->mu);
            ok = welcome_of(c, m);
            if (ok) {
                c->welcomed = 1;
                c->frames.binary_allowed = offers(c, "binary");
                tsm_cond_broadcast(&c->cond);
            }
            tsm_mutex_unlock(&c->mu);
            tsm_json_free(m);
            return ok;
        }
        if (strcmp(op, "error") == 0 && !id_value) {
            tsm_set_error_from_message(m);
        } else {
            char why[128];
            snprintf(why, sizeof why, "the first frame is %.64s, not welcome", op);
            tsm_protocol_error(why);
        }
        tsm_json_free(m);
        return 0;
    }
    if (strcmp(op, "error") == 0 && !id_value) {
        tsm_set_error_from_message(m);
        tsm_json_free(m);
        return 0;
    }
    if (!tsm_json_get_int(m, "id", &id)) {
        tsm_json_wipe_free(m); /* an answer nobody waits for; ignored */
        return 1;
    }
    if (strcmp(op, "progress") == 0) {
        tsm_progress_fn fn = NULL;
        void *context = NULL;
        tsm_mutex_lock(&c->mu);
        p = find_pending(c, id);
        if (p) {
            fn = p->on_progress;
            context = p->progress_context;
        }
        tsm_mutex_unlock(&c->mu);
        if (fn) {
            const char *pending_text = tsm_json_get_str(m, "pending");
            tsm_progress progress;
            progress.pending = pending_text && strcmp(pending_text, "unlock") == 0 ? "unlock" : "approval";
            progress.approval_code = tsm_json_get_str(m, "approvalCode");
            fn(&progress, context);
        }
        tsm_json_free(m);
        return 1;
    }
    tsm_mutex_lock(&c->mu);
    p = find_pending(c, id);
    if (!p) {
        tsm_mutex_unlock(&c->mu);
        tsm_json_wipe_free(m);
        return 1;
    }
    if (strcmp(op, "file") == 0) {
        tsm_json_free(p->file);
        p->file = m;
        tsm_buf_wipe(&p->chunks);
        p->has_chunks = 1;
        tsm_mutex_unlock(&c->mu);
        return 1;
    }
    if (strcmp(op, "end") == 0) {
        if (!p->file) {
            tsm_mutex_unlock(&c->mu);
            tsm_json_free(m);
            tsm_protocol_error("end without file");
            return 0;
        }
        p->answer = m;
        p->done = 1;
        tsm_cond_broadcast(&c->cond);
        tsm_mutex_unlock(&c->mu);
        return 1;
    }
    if (strcmp(op, "value") == 0 || strcmp(op, "values") == 0 || strcmp(op, "error") == 0) {
        p->answer = m;
        p->done = 1;
        tsm_cond_broadcast(&c->cond);
        tsm_mutex_unlock(&c->mu);
        return 1;
    }
    /* Any other answer is one this library does not know: section 8 says
     * ignore it. */
    tsm_mutex_unlock(&c->mu);
    tsm_json_wipe_free(m);
    return 1;
}

static int on_chunk(connection *c, const unsigned char *payload, size_t len) {
    long long id = 0;
    int i, ok;
    pending *p;
    if (len < 8) {
        tsm_protocol_error("a binary chunk without id");
        return 0;
    }
    for (i = 0; i < 8; i++) {
        id = (id << 8) | payload[i];
    }
    tsm_mutex_lock(&c->mu);
    p = find_pending(c, id);
    ok = p && p->has_chunks && tsm_buf_add(&p->chunks, payload + 8, len - 8);
    tsm_mutex_unlock(&c->mu);
    if (!ok) {
        tsm_protocol_error("a chunk without file");
    }
    return ok;
}

static void reader(void *arg) {
    connection *c = (connection *)arg;
    unsigned char buffer[65536];
    for (;;) {
        long n = tsm_socket_recv(c->sock, buffer, sizeof buffer);
        tsm_frame *frames;
        size_t count, i;
        char why[192];
        int ok = 1;
        if (n <= 0) {
            dropped();
            connection_fail(c);
            break;
        }
        if (tsm_frames_add(&c->frames, buffer, (size_t)n, &frames, &count, why, sizeof why) != 0) {
            tsm_wipe(buffer, (size_t)n);
            tsm_protocol_error(why);
            connection_fail(c);
            break;
        }
        tsm_wipe(buffer, (size_t)n);
        for (i = 0; ok && i < count; i++) {
            if (frames[i].type == TSM_FRAME_BINARY) {
                ok = on_chunk(c, frames[i].payload, frames[i].len);
            } else {
                tsm_json *m = tsm_payload_decode(frames[i].payload, frames[i].len, why, sizeof why);
                if (!m) {
                    tsm_protocol_error(why);
                    ok = 0;
                } else {
                    ok = on_message(c, m);
                }
            }
        }
        tsm_frames_free(frames, count);
        if (!ok) {
            connection_fail(c);
            break;
        }
        tsm_mutex_lock(&c->mu);
        ok = !c->closed;
        tsm_mutex_unlock(&c->mu);
        if (!ok) {
            break;
        }
    }
    connection_release(c);
}

static tsm_error_kind connection_write(connection *c, const tsm_json *m) {
    size_t len, frame_len;
    char *payload = tsm_json_write(m, &len);
    unsigned char *frame;
    int ok;
    if (!payload) {
        return tsm_no_memory();
    }
    if (len > TSM_MAX_REQUEST_PAYLOAD) {
        tsm_wipe(payload, len);
        free(payload);
        return tsm_set_error(TSM_ERR_MALFORMED, "frame", -1, "the request is %lu bytes, over %d",
                             (unsigned long)len, TSM_MAX_REQUEST_PAYLOAD);
    }
    frame = tsm_frame_encode(TSM_FRAME_JSON, (const unsigned char *)payload, len, &frame_len);
    tsm_wipe(payload, len);
    free(payload);
    if (!frame) {
        return tsm_no_memory();
    }
    tsm_mutex_lock(&c->write_mu);
    ok = tsm_socket_send_all(c->sock, frame, frame_len) == 0;
    tsm_mutex_unlock(&c->write_mu);
    tsm_wipe(frame, frame_len);
    free(frame);
    return ok ? TSM_OK : dropped();
}

/* Sends request (an "id" is added) and waits for its last message. */
static tsm_error_kind connection_send(connection *c, tsm_json *request, tsm_progress_fn fn, void *context,
                                      pending **out) {
    pending *p = (pending *)calloc(1, sizeof *p), **link;
    tsm_error_kind rc;
    *out = NULL;
    if (!p) {
        return tsm_no_memory();
    }
    p->on_progress = fn;
    p->progress_context = context;
    tsm_mutex_lock(&c->mu);
    if (c->closed) {
        tsm_mutex_unlock(&c->mu);
        free(p);
        return dropped();
    }
    p->id = c->next_id++;
    p->next = c->pending;
    c->pending = p;
    tsm_mutex_unlock(&c->mu);
    if (!tsm_json_set(request, "id", tsm_json_int(p->id))) {
        rc = tsm_no_memory();
    } else {
        rc = connection_write(c, request);
    }
    tsm_mutex_lock(&c->mu);
    if (rc == TSM_OK) {
        while (!p->done) {
            tsm_cond_wait(&c->cond, &c->mu);
        }
    }
    for (link = &c->pending; *link; link = &(*link)->next) {
        if (*link == p) {
            *link = p->next;
            break;
        }
    }
    tsm_mutex_unlock(&c->mu);
    if (rc != TSM_OK) {
        if (rc == TSM_ERR_NOT_RUNNING) {
            connection_fail(c);
        }
        tsm_json_wipe_free(p->answer);
        tsm_json_free(p->file);
        tsm_buf_wipe(&p->chunks);
        free(p);
        return rc;
    }
    if (!p->answer) {
        tsm_buf_wipe(&p->chunks);
        tsm_json_free(p->file);
        free(p);
        return connection_error(c);
    }
    *out = p;
    return TSM_OK;
}

static void pending_free(pending *p) {
    if (p) {
        tsm_json_wipe_free(p->answer);
        tsm_json_free(p->file);
        tsm_buf_wipe(&p->chunks);
        free(p);
    }
}

/* ---- the client ------------------------------------------------------ */

static const char *process_getenv(const char *name, void *context) {
    const tsm_client *c = (const tsm_client *)context;
    if (c->runtime_dir && strcmp(name, "TSM_RUNTIME_DIR") == 0) {
        return c->runtime_dir;
    }
    return getenv(name);
}

static char *program_name(void) {
    char buffer[256] = "";
#ifdef _WIN32
    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, path, sizeof path);
    if (n > 0 && n < sizeof path) {
        char *base = strrchr(path, '\\');
        char *dot;
        snprintf(buffer, sizeof buffer, "%s", base ? base + 1 : path);
        dot = strrchr(buffer, '.');
        if (dot && (!strcmp(dot, ".exe") || !strcmp(dot, ".EXE"))) {
            *dot = 0;
        }
    }
#elif defined(__linux__)
    char *comm = tsm_read_file("/proc/self/comm", NULL);
    if (comm) {
        snprintf(buffer, sizeof buffer, "%s", comm);
        buffer[strcspn(buffer, "\n")] = 0;
        free(comm);
    }
#elif defined(__APPLE__)
    const char *name = getprogname();
    snprintf(buffer, sizeof buffer, "%s", name ? name : "");
#endif
    return tsm_strdup(buffer[0] ? buffer : "c");
}

tsm_error_kind tsm_client_new(tsm_client **out, const tsm_client_options *options) {
    tsm_client *c = (tsm_client *)calloc(1, sizeof *c);
    *out = NULL;
    if (!c) {
        return tsm_no_memory();
    }
    c->name = options && options->client_name ? tsm_strdup(options->client_name) : program_name();
    c->token = options && options->client_token ? tsm_strdup(options->client_token) : NULL;
    c->runtime_dir = options && options->runtime_dir ? tsm_strdup(options->runtime_dir) : NULL;
    c->os = tsm_strdup(options && options->operating_system ? options->operating_system
                                                            : tsm_current_operating_system());
    c->connect_timeout_ms = options && options->connect_timeout_ms > 0 ? options->connect_timeout_ms : 10000;
    if (!c->name || !c->os || (options && options->client_token && !c->token) ||
        (options && options->runtime_dir && !c->runtime_dir)) {
        tsm_client_free(c);
        return tsm_no_memory();
    }
    tsm_mutex_init(&c->mu);
    *out = c;
    return TSM_OK;
}

tsm_error_kind tsm_connect(tsm_client **out, const tsm_client_options *options) {
    tsm_error_kind rc = tsm_client_new(out, options);
    if (rc != TSM_OK) {
        return rc;
    }
    rc = tsm_open(*out);
    if (rc != TSM_OK) {
        tsm_client_free(*out);
        *out = NULL;
    }
    return rc;
}

static tsm_error_kind connect_once(tsm_client *client, connection **out) {
    tsm_endpoints location;
    tsm_socket sock = TSM_INVALID_SOCKET;
    char *token = NULL;
    connection *c;
    tsm_json *hello, *info, *features;
    tsm_error_kind rc;
    long long deadline;
    *out = NULL;
    if (tsm_discover(client->os, process_getenv, client, tsm_process_uid(), &location) != TSM_OK) {
        return tsm_not_running("no runtime directory can be named");
    }
    if (strcmp(client->os, "windows") == 0) {
        char *text = tsm_read_file(location.client_port_file, NULL);
        int port = text ? tsm_read_port_file(text) : 0;
        free(text);
        if (!port) {
            return tsm_not_running("no readable client.port");
        }
        token = tsm_read_file(location.client_token_file, NULL);
        if (!token) {
            return tsm_not_running("no client.token");
        }
        {
            size_t n = strlen(token);
            if (n >= 2 && token[n - 2] == '\r' && token[n - 1] == '\n') {
                token[n - 2] = 0;
            } else if (n >= 1 && token[n - 1] == '\n') {
                token[n - 1] = 0;
            }
        }
        if (tsm_socket_connect_localhost(port, client->connect_timeout_ms, &sock) != 0) {
            tsm_wipe(token, strlen(token));
            free(token);
            return tsm_not_running("the connection was refused");
        }
    } else {
        char why[1200];
        if (!tsm_file_exists(location.client_socket)) {
            snprintf(why, sizeof why, "no client.sock in %s", location.directory);
            return tsm_not_running(why);
        }
        if (tsm_socket_connect_unix(location.client_socket, &sock) != 0) {
            return tsm_not_running("the connection was refused");
        }
    }
    c = (connection *)calloc(1, sizeof *c);
    if (!c) {
        tsm_socket_close(sock);
        free(token);
        return tsm_no_memory();
    }
    c->sock = sock;
    c->next_id = 1;
    c->frames.max_payload = TSM_MAX_ANSWER_PAYLOAD;
    c->refs = 2; /* the reader thread's and the caller's */
    tsm_mutex_init(&c->mu);
    tsm_mutex_init(&c->write_mu);
    tsm_cond_init(&c->cond);
    if (!tsm_thread_start(reader, c)) {
        free(token);
        connection_free(c);
        return tsm_not_running("the reader thread could not start");
    }
    hello = tsm_json_object();
    info = tsm_json_object();
    features = tsm_json_array();
    rc = hello && info && features && tsm_json_set(hello, "op", tsm_json_str("hello")) &&
                 tsm_json_set(hello, "protocol", tsm_json_int(TSM_PROTOCOL_VERSION)) &&
                 tsm_json_set(info, "name", tsm_json_str(client->name)) &&
                 tsm_json_set(info, "version", tsm_json_str(TSM_CLIENT_VERSION)) &&
                 tsm_json_set(info, "language", tsm_json_str("c")) &&
                 tsm_json_push(features, tsm_json_str("binary")) &&
                 tsm_json_push(features, tsm_json_str("getFile")) && tsm_json_set(hello, "client", info) &&
                 tsm_json_set(hello, "features", features) &&
                 (!token || tsm_json_set(hello, "token", tsm_json_str(token))) &&
                 (!client->token || tsm_json_set(hello, "clientToken", tsm_json_str(client->token)))
             ? TSM_OK
             : tsm_no_memory();
    if (token) {
        tsm_wipe(token, strlen(token));
        free(token);
    }
    if (rc == TSM_OK) {
        rc = connection_write(c, hello);
    } else if (hello) {
        /* info and features belong to hello once set; free what is not. */
        if (!tsm_json_get(hello, "client")) {
            tsm_json_free(info);
        }
        if (!tsm_json_get(hello, "features")) {
            tsm_json_free(features);
        }
    } else {
        tsm_json_free(info);
        tsm_json_free(features);
    }
    tsm_json_wipe_free(hello);
    if (rc != TSM_OK) {
        connection_fail(c);
        connection_release(c);
        return rc;
    }
    deadline = tsm_monotonic_ms() + client->connect_timeout_ms;
    tsm_mutex_lock(&c->mu);
    while (!c->welcomed && !c->closed) {
        long long left = deadline - tsm_monotonic_ms();
        if (left <= 0) {
            break;
        }
        tsm_cond_timedwait(&c->cond, &c->mu, left);
    }
    if (c->welcomed && !c->closed) {
        tsm_mutex_unlock(&c->mu);
        *out = c;
        return TSM_OK;
    }
    if (c->closed) {
        tsm_mutex_unlock(&c->mu);
        rc = connection_error(c);
        connection_release(c);
        return rc;
    }
    tsm_mutex_unlock(&c->mu);
    tsm_not_running("no welcome");
    connection_fail(c);
    connection_release(c);
    return tsm_set_error(TSM_ERR_NOT_RUNNING, NULL, -1,
                         "the secrets service is not running: no welcome within %d ms", client->connect_timeout_ms);
}

/* The open connection, with a reference for the caller. */
static tsm_error_kind ensure(tsm_client *client, connection **out) {
    connection *c;
    tsm_error_kind rc;
    tsm_mutex_lock(&client->mu);
    c = client->conn;
    if (c) {
        int closed;
        tsm_mutex_lock(&c->mu);
        closed = c->closed;
        if (!closed) {
            c->refs++;
        }
        tsm_mutex_unlock(&c->mu);
        if (!closed) {
            tsm_mutex_unlock(&client->mu);
            *out = c;
            return TSM_OK;
        }
        client->conn = NULL;
        connection_release(c);
    }
    rc = connect_once(client, &c);
    if (rc == TSM_OK) {
        tsm_mutex_lock(&c->mu);
        c->refs++; /* the client's own */
        tsm_mutex_unlock(&c->mu);
        client->conn = c;
        *out = c;
    }
    tsm_mutex_unlock(&client->mu);
    return rc;
}

tsm_error_kind tsm_open(tsm_client *client) {
    connection *c;
    tsm_error_kind rc = ensure(client, &c);
    if (rc == TSM_OK) {
        connection_release(c);
    }
    return rc;
}

void tsm_close(tsm_client *client) {
    connection *c;
    if (!client) {
        return;
    }
    tsm_mutex_lock(&client->mu);
    c = client->conn;
    client->conn = NULL;
    tsm_mutex_unlock(&client->mu);
    if (c) {
        /* The caller's last error stays as it was. */
        connection_fail_with(c, TSM_ERR_NOT_RUNNING, NULL, -1,
                             "the secrets service is not running: the client closed the connection");
        connection_release(c);
    }
}

void tsm_client_free(tsm_client *client) {
    if (!client) {
        return;
    }
    tsm_close(client);
    if (client->token) {
        tsm_wipe(client->token, strlen(client->token));
    }
    free(client->name);
    free(client->token);
    free(client->runtime_dir);
    free(client->os);
    tsm_mutex_destroy(&client->mu);
    free(client);
}

int tsm_welcome_get(tsm_client *client, tsm_welcome *out) {
    connection *c;
    int ok = 0;
    tsm_mutex_lock(&client->mu);
    c = client->conn;
    if (c) {
        tsm_mutex_lock(&c->mu);
        if (c->welcomed && !c->closed) {
            out->protocol = TSM_PROTOCOL_VERSION;
            out->service_version = c->service_version ? c->service_version : "";
            out->host = c->host ? c->host : "";
            out->platform = c->platform ? c->platform : "";
            out->features = (const char *const *)c->features;
            out->feature_count = c->feature_count;
            ok = 1;
        }
        tsm_mutex_unlock(&c->mu);
    }
    tsm_mutex_unlock(&client->mu);
    return ok;
}

/* ---- requests -------------------------------------------------------- */

static tsm_error_kind request_item(const char *ref, const char *field, const char *const *dimensions,
                                   tsm_json **out) {
    tsm_reference *parsed;
    tsm_json *item;
    tsm_error_kind rc;
    *out = NULL;
    rc = tsm_reference_parse(ref, &parsed);
    if (rc != TSM_OK) {
        return rc;
    }
    if (field && parsed->field_given && strcmp(field, parsed->field) != 0) {
        tsm_reference_free(parsed);
        return tsm_set_error(TSM_ERR_MALFORMED, "field_twice", -1, "the field is named in the reference and as field");
    }
    item = tsm_json_object();
    if (!item || !tsm_json_set(item, "ref", tsm_json_str(ref))) {
        tsm_json_free(item);
        tsm_reference_free(parsed);
        return tsm_no_memory();
    }
    if (dimensions && dimensions[0]) {
        tsm_json *d = tsm_json_object();
        size_t i;
        for (i = 0; d && dimensions[i] && dimensions[i + 1]; i += 2) {
            if (!tsm_json_set(d, dimensions[i], tsm_json_str(dimensions[i + 1]))) {
                tsm_json_free(d);
                d = NULL;
            }
        }
        if (!d || !tsm_json_set(item, "dimensions", d)) {
            tsm_json_free(item);
            tsm_reference_free(parsed);
            return tsm_no_memory();
        }
    }
    if (field && !parsed->field_given && !tsm_json_set(item, "field", tsm_json_str(field))) {
        tsm_json_free(item);
        tsm_reference_free(parsed);
        return tsm_no_memory();
    }
    tsm_reference_free(parsed);
    *out = item;
    return TSM_OK;
}

static int add_waiting(tsm_json *request, int no_wait, long long timeout_ms) {
    return (!no_wait || tsm_json_set(request, "wait", tsm_json_bool(0))) &&
           (timeout_ms < 0 || tsm_json_set(request, "timeoutMs", tsm_json_int(timeout_ms)));
}

/* Sends request, waiting out rate limits when asked; *out the answer. */
static tsm_error_kind run_request(tsm_client *client, tsm_json *request, tsm_progress_fn fn, void *context,
                                  int wait_on_rate_limit, pending **out) {
    for (;;) {
        connection *c;
        pending *p;
        const char *op;
        tsm_error_kind rc = ensure(client, &c);
        if (rc != TSM_OK) {
            return rc;
        }
        rc = connection_send(c, request, fn, context, &p);
        connection_release(c);
        if (rc != TSM_OK) {
            return rc;
        }
        op = tsm_json_get_str(p->answer, "op");
        if (strcmp(op, "error") != 0) {
            *out = p;
            return TSM_OK;
        }
        rc = tsm_set_error_from_message(p->answer);
        pending_free(p);
        if (rc == TSM_ERR_RATE_LIMITED && wait_on_rate_limit) {
            long long ms = tsm_last_error(NULL)->retry_after_ms;
            tsm_sleep_ms(ms > 0 ? ms : 1000);
            continue;
        }
        return rc;
    }
}

tsm_error_kind tsm_get(tsm_client *client, const char *ref, const tsm_get_options *options, tsm_value **out) {
    tsm_get_options defaults = TSM_GET_OPTIONS_INIT;
    tsm_json *request;
    pending *p;
    tsm_error_kind rc;
    *out = NULL;
    if (!options) {
        options = &defaults;
    }
    rc = request_item(ref, options->field, options->dimensions, &request);
    if (rc != TSM_OK) {
        return rc;
    }
    if (!tsm_json_set(request, "op", tsm_json_str("get")) ||
        !add_waiting(request, options->no_wait, options->timeout_ms) ||
        (options->want_client_token && !tsm_json_set(request, "wantClientToken", tsm_json_bool(1)))) {
        tsm_json_free(request);
        return tsm_no_memory();
    }
    rc = run_request(client, request, options->on_progress, options->progress_context, options->wait_on_rate_limit, &p);
    tsm_json_free(request);
    if (rc != TSM_OK) {
        return rc;
    }
    if (strcmp(tsm_json_get_str(p->answer, "op"), "value") != 0) {
        char why[128];
        snprintf(why, sizeof why, "get was answered %.64s", tsm_json_get_str(p->answer, "op"));
        pending_free(p);
        return tsm_protocol_error(why);
    }
    rc = tsm_value_from_message(ref, p->answer, out);
    pending_free(p);
    return rc;
}

void tsm_results_free(tsm_result *results, size_t count) {
    size_t i;
    if (!results) {
        return;
    }
    for (i = 0; i < count; i++) {
        tsm_value_free(results[i].value);
        free(results[i].message);
        free(results[i].reason);
    }
    free(results);
}

tsm_error_kind tsm_get_many(tsm_client *client, const tsm_request *requests, size_t count,
                            const tsm_request_options *options, tsm_result **out) {
    tsm_request_options defaults = TSM_REQUEST_OPTIONS_INIT;
    tsm_json *request, *refs;
    const tsm_json *results;
    tsm_result *list;
    pending *p;
    tsm_error_kind rc;
    size_t i;
    *out = NULL;
    if (!options) {
        options = &defaults;
    }
    if (count == 0 || count > TSM_MAX_GET_MANY) {
        return tsm_set_error(TSM_ERR_INVALID_ARGUMENT, NULL, -1, "a get_many carries 1 to %d references, not %lu",
                             TSM_MAX_GET_MANY, (unsigned long)count);
    }
    request = tsm_json_object();
    refs = tsm_json_array();
    if (!request || !refs) {
        tsm_json_free(request);
        tsm_json_free(refs);
        return tsm_no_memory();
    }
    for (i = 0; i < count; i++) {
        tsm_json *item;
        rc = request_item(requests[i].ref, requests[i].field, requests[i].dimensions, &item);
        if (rc != TSM_OK || !tsm_json_push(refs, item)) {
            tsm_json_free(request);
            tsm_json_free(refs);
            return rc != TSM_OK ? rc : tsm_no_memory();
        }
    }
    if (!tsm_json_set(request, "op", tsm_json_str("getMany")) || !tsm_json_set(request, "refs", refs) ||
        !add_waiting(request, options->no_wait, options->timeout_ms)) {
        tsm_json_free(request);
        return tsm_no_memory();
    }
    rc = run_request(client, request, options->on_progress, options->progress_context, options->wait_on_rate_limit, &p);
    tsm_json_free(request);
    if (rc != TSM_OK) {
        return rc;
    }
    results = tsm_json_get(p->answer, "results");
    if (strcmp(tsm_json_get_str(p->answer, "op"), "values") != 0 || !results || results->type != TSM_J_ARRAY) {
        char why[128];
        snprintf(why, sizeof why, "getMany was answered %.64s", tsm_json_get_str(p->answer, "op"));
        pending_free(p);
        return tsm_protocol_error(why);
    }
    if (results->count != count) {
        char why[64];
        snprintf(why, sizeof why, "getMany got %lu results", (unsigned long)results->count);
        pending_free(p);
        return tsm_protocol_error(why);
    }
    list = (tsm_result *)calloc(count, sizeof *list);
    if (!list) {
        pending_free(p);
        return tsm_no_memory();
    }
    for (i = 0; i < count; i++) {
        const tsm_json *r = results->items[i];
        const char *op = tsm_json_get_str(r, "op");
        if (r->type != TSM_J_OBJECT) {
            tsm_results_free(list, count);
            pending_free(p);
            return tsm_protocol_error("a getMany result is no object");
        }
        if (op && strcmp(op, "error") == 0) {
            const tsm_json *details = tsm_json_get(r, "details");
            const char *message = tsm_json_get_str(r, "message");
            const char *reason = details ? tsm_json_get_str(details, "reason") : NULL;
            list[i].kind = tsm_error_kind_from_wire(tsm_json_get_str(r, "kind"));
            list[i].message = tsm_strdup(message ? message : "");
            list[i].reason = reason ? tsm_strdup(reason) : NULL;
        } else {
            rc = tsm_value_from_message(requests[i].ref, r, &list[i].value);
            if (rc != TSM_OK) {
                tsm_results_free(list, count);
                pending_free(p);
                return rc;
            }
            list[i].kind = TSM_OK;
        }
    }
    pending_free(p);
    *out = list;
    return TSM_OK;
}

tsm_error_kind tsm_get_file(tsm_client *client, const char *ref, const tsm_get_options *options, tsm_file **out) {
    tsm_get_options defaults = TSM_GET_OPTIONS_INIT;
    tsm_json *request;
    connection *c;
    pending *p;
    tsm_error_kind rc;
    int has_binary, has_get_file;
    const char *name, *sum;
    long long size;
    unsigned char digest[32];
    char hex[65];
    size_t i;
    *out = NULL;
    if (!options) {
        options = &defaults;
    }
    rc = request_item(ref, options->field, options->dimensions, &request);
    if (rc != TSM_OK) {
        return rc;
    }
    rc = ensure(client, &c);
    if (rc != TSM_OK) {
        tsm_json_free(request);
        return rc;
    }
    tsm_mutex_lock(&c->mu);
    has_binary = offers(c, "binary");
    has_get_file = offers(c, "getFile");
    tsm_mutex_unlock(&c->mu);
    connection_release(c);
    if (!has_binary || !has_get_file) {
        tsm_json_free(request);
        return tsm_set_error(TSM_ERR_UNSUPPORTED, NULL, -1, "the service does not offer getFile (features %s%s%s)",
                             has_binary ? "" : "binary", !has_binary && !has_get_file ? ", " : "",
                             has_get_file ? "" : "getFile");
    }
    if (!tsm_json_set(request, "op", tsm_json_str("getFile")) ||
        !add_waiting(request, options->no_wait, options->timeout_ms)) {
        tsm_json_free(request);
        return tsm_no_memory();
    }
    rc = run_request(client, request, options->on_progress, options->progress_context, options->wait_on_rate_limit, &p);
    tsm_json_free(request);
    if (rc != TSM_OK) {
        return rc;
    }
    if (strcmp(tsm_json_get_str(p->answer, "op"), "end") != 0 || !p->file) {
        char why[128];
        snprintf(why, sizeof why, "getFile was answered %.64s", tsm_json_get_str(p->answer, "op"));
        pending_free(p);
        return tsm_protocol_error(why);
    }
    name = tsm_json_get_str(p->file, "name");
    sum = tsm_json_get_str(p->answer, "sha256");
    tsm_sha256(p->chunks.data ? p->chunks.data : (const unsigned char *)"", p->chunks.len, digest);
    for (i = 0; i < 32; i++) {
        snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    }
    if (!name || !sum || !tsm_json_get_int(p->file, "size", &size) || size != (long long)p->chunks.len ||
        strcmp(sum, hex) != 0) {
        pending_free(p);
        return tsm_protocol_error("the file does not match its size or sha256");
    }
    {
        unsigned char *data = (unsigned char *)malloc(p->chunks.len + 1);
        if (!data) {
            pending_free(p);
            return tsm_no_memory();
        }
        if (p->chunks.len) {
            memcpy(data, p->chunks.data, p->chunks.len);
        }
        *out = tsm_file_new(ref, name, data, p->chunks.len);
        if (!*out) {
            tsm_wipe(data, p->chunks.len);
            free(data);
            pending_free(p);
            return tsm_no_memory();
        }
    }
    pending_free(p);
    return TSM_OK;
}
