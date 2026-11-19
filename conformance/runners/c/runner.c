/*
 * Copyright (c) 2026 Peter Nicolai Alexis Kyaw
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * The conformance runner of the C client (clients/c).
 *
 * It reads one case per line on standard input,
 *   {"case": name, "runtimeDir": dir, "action": {...}}
 * runs its action with the library against the service in runtimeDir, and
 * writes one canonical result line per case on standard output,
 *   {"case": name, "result": {...}}
 * (keys sorted, compact). conformance/README.md defines the actions and the
 * result shapes every runner writes. concurrent actions run on threads,
 * overlapping on the client's one connection. It uses the library's JSON
 * and platform layer (its internal header), as built from the repository.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "tsm/tsm.h"

static tsm_json *run(tsm_client *c, const tsm_json *action);

static tsm_json *obj(void) { return tsm_json_object(); }

static void set(tsm_json *o, const char *key, tsm_json *value) {
    if (!tsm_json_set(o, key, value)) {
        fprintf(stderr, "runner: out of memory\n");
        exit(2);
    }
}

static tsm_json *error_shape(tsm_error_kind kind, const char *reason) {
    tsm_json *e = obj();
    set(e, "kind", tsm_json_str(tsm_error_kind_name(kind)));
    if (reason) {
        set(e, "reason", tsm_json_str(reason));
    }
    return e;
}

static tsm_json *error_result(void) {
    const tsm_error *e = tsm_last_error(NULL);
    tsm_json *r = obj();
    set(r, "error", error_shape(e->kind, e->reason));
    return r;
}

static char *base64(const unsigned char *data, size_t n) {
    static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *out = (char *)malloc(4 * ((n + 2) / 3) + 1);
    size_t i, o = 0;
    for (i = 0; i < n; i += 3) {
        unsigned v = (unsigned)data[i] << 16 | (i + 1 < n ? (unsigned)data[i + 1] << 8 : 0) | (i + 2 < n ? data[i + 2] : 0);
        out[o++] = a[(v >> 18) & 63];
        out[o++] = a[(v >> 12) & 63];
        out[o++] = i + 1 < n ? a[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? a[v & 63] : '=';
    }
    out[o] = 0;
    return out;
}

static tsm_json *value_shape(tsm_value *v) {
    tsm_json *out = obj(), *entry = obj(), *version = obj(), *bound = obj();
    size_t size, i;
    const unsigned char *bytes = tsm_value_bytes(v, &size);
    char *b64 = base64(bytes, size);
    long long expires;
    const char *text = tsm_value_text(v);
    set(out, "encoding", tsm_json_str(tsm_value_encoding(v)));
    set(out, "base64", tsm_json_str(b64));
    free(b64);
    set(entry, "store", tsm_json_str(tsm_value_entry_store(v)));
    set(entry, "uuid", tsm_json_str(tsm_value_entry_uuid(v)));
    set(entry, "source", tsm_json_str(tsm_value_entry_source(v)));
    set(entry, "fetchedAtMs", tsm_json_int(tsm_value_entry_fetched_at_ms(v)));
    set(out, "entry", entry);
    for (i = 0; i < tsm_value_bound_count(v); i++) {
        set(bound, tsm_value_bound_dimension(v, i), tsm_json_str(tsm_value_bound_value(v, i)));
    }
    set(out, "bound", bound);
    set(version, "modifiedMs", tsm_json_int(tsm_value_version_modified_ms(v)));
    set(version, "revision", tsm_json_str(tsm_value_version_revision(v)));
    set(out, "version", version);
    /* C has no printable form of a value at all: nothing can show it. */
    set(out, "masked", tsm_json_bool(1));
    if (text) {
        set(out, "text", tsm_json_strn(text, size));
    } else {
        set(out, "textRefused", tsm_json_bool(1));
    }
    if (tsm_value_expires_ms(v, &expires)) {
        set(out, "expiresMs", tsm_json_int(expires));
    }
    if (tsm_value_client_token(v)) {
        set(out, "clientToken", tsm_json_str(tsm_value_client_token(v)));
    }
    tsm_value_free(v);
    return out;
}

typedef struct progress_log {
    tsm_mutex mu;
    tsm_json *entries;
} progress_log;

static void log_progress(const tsm_progress *p, void *context) {
    progress_log *log = (progress_log *)context;
    tsm_json *entry = obj();
    set(entry, "pending", tsm_json_str(p->pending));
    if (p->approval_code) {
        set(entry, "approvalCode", tsm_json_str(p->approval_code));
    }
    tsm_mutex_lock(&log->mu);
    tsm_json_push(log->entries, entry);
    tsm_mutex_unlock(&log->mu);
}

static tsm_json *with_progress(tsm_json *result, progress_log *log) {
    if (log->entries->count) {
        set(result, "progress", log->entries);
    } else {
        tsm_json_free(log->entries);
    }
    tsm_mutex_destroy(&log->mu);
    return result;
}

/* "dimension, value, ..., NULL" of a JSON object (pointers into it). */
static const char **dimensions_of(const tsm_json *d) {
    const char **out;
    size_t i;
    if (!d || d->type != TSM_J_OBJECT) {
        return NULL;
    }
    out = (const char **)calloc(2 * d->count + 1, sizeof *out);
    for (i = 0; i < d->count; i++) {
        out[2 * i] = d->keys[i];
        out[2 * i + 1] = d->items[i]->string;
    }
    return out;
}

static tsm_json *shape(const tsm_reference *r) {
    tsm_json *out = obj(), *target = obj(), *qualifiers = tsm_json_array();
    size_t i;
    switch (r->kind) {
    case TSM_TARGET_KEY:
        set(target, "kind", tsm_json_str("key"));
        set(target, "key", tsm_json_str(r->key));
        break;
    case TSM_TARGET_UUID:
        set(target, "kind", tsm_json_str("uuid"));
        set(target, "store", tsm_json_str(r->store));
        set(target, "uuid", tsm_json_str(r->uuid));
        break;
    default: {
        tsm_json *segments = tsm_json_array();
        set(target, "kind", tsm_json_str("path"));
        set(target, "store", tsm_json_str(r->store));
        for (i = 0; i < r->segment_count; i++) {
            tsm_json_push(segments, tsm_json_str(r->segments[i]));
        }
        set(target, "segments", segments);
    }
    }
    for (i = 0; i < r->qualifier_count; i++) {
        tsm_json *q = obj();
        set(q, "dimension", tsm_json_str(r->dimensions[i]));
        set(q, "value", tsm_json_str(r->values[i]));
        tsm_json_push(qualifiers, q);
    }
    set(out, "qualifiers", qualifiers);
    set(out, "target", target);
    set(out, "field", tsm_json_str(r->field));
    set(out, "fieldGiven", tsm_json_bool(r->field_given));
    return out;
}

/* A reference of the action's parsed shape (pointers into m). */
static void from_shape(const tsm_json *m, tsm_reference *r, char ***owned) {
    const tsm_json *t = tsm_json_get(m, "target"), *q = tsm_json_get(m, "qualifiers");
    const char *kind = tsm_json_get_str(t, "kind");
    size_t i;
    memset(r, 0, sizeof *r);
    if (strcmp(kind, "key") == 0) {
        r->kind = TSM_TARGET_KEY;
        r->key = (char *)tsm_json_get_str(t, "key");
    } else if (strcmp(kind, "uuid") == 0) {
        r->kind = TSM_TARGET_UUID;
        r->store = (char *)tsm_json_get_str(t, "store");
        r->uuid = (char *)tsm_json_get_str(t, "uuid");
    } else {
        const tsm_json *segments = tsm_json_get(t, "segments");
        r->kind = TSM_TARGET_PATH;
        r->store = (char *)tsm_json_get_str(t, "store");
        r->segment_count = segments->count;
        r->segments = (char **)calloc(segments->count + 1, sizeof(char *));
        for (i = 0; i < segments->count; i++) {
            r->segments[i] = segments->items[i]->string;
        }
    }
    r->qualifier_count = q->count;
    r->dimensions = (char **)calloc(q->count + 1, sizeof(char *));
    r->values = (char **)calloc(q->count + 1, sizeof(char *));
    for (i = 0; i < q->count; i++) {
        r->dimensions[i] = (char *)tsm_json_get_str(q->items[i], "dimension");
        r->values[i] = (char *)tsm_json_get_str(q->items[i], "value");
    }
    r->field = (char *)tsm_json_get_str(m, "field");
    owned[0] = r->segments;
    owned[1] = r->dimensions;
    owned[2] = r->values;
}

typedef struct concurrent_job {
    tsm_client *client;
    const tsm_json *action;
    tsm_json *result;
    tsm_mutex *mu;
    tsm_cond *cond;
    size_t *left;
} concurrent_job;

static void run_job(void *arg) {
    concurrent_job *job = (concurrent_job *)arg;
    tsm_json *result = run(job->client, job->action);
    tsm_mutex_lock(job->mu);
    job->result = result;
    (*job->left)--;
    tsm_cond_broadcast(job->cond);
    tsm_mutex_unlock(job->mu);
}

static tsm_json *run(tsm_client *c, const tsm_json *action) {
    const char *op = tsm_json_get_str(action, "do");
    const char *ref = tsm_json_get_str(action, "ref");
    const tsm_json *wait = tsm_json_get(action, "wait");
    int no_wait = wait && wait->type == TSM_J_BOOL && !wait->boolean;
    long long timeout_ms = -1;
    tsm_json *result;
    if (!tsm_json_get_int(action, "timeoutMs", &timeout_ms)) {
        timeout_ms = -1;
    }
    if (strcmp(op, "parse") == 0) {
        tsm_reference *r;
        char *canonical;
        if (tsm_reference_parse(ref, &r) != TSM_OK) {
            return error_result();
        }
        result = obj();
        set(result, "parsed", shape(r));
        tsm_reference_format(r, &canonical);
        set(result, "canonical", tsm_json_str(canonical ? canonical : ""));
        tsm_free(canonical);
        tsm_reference_free(r);
        return result;
    }
    if (strcmp(op, "format") == 0) {
        tsm_reference r;
        char **owned[3];
        char *formatted;
        tsm_error_kind rc;
        from_shape(tsm_json_get(action, "parsed"), &r, owned);
        rc = tsm_reference_format(&r, &formatted);
        free(owned[0]);
        free(owned[1]);
        free(owned[2]);
        if (rc != TSM_OK) {
            return error_result();
        }
        result = obj();
        set(result, "formatted", tsm_json_str(formatted));
        tsm_free(formatted);
        return result;
    }
    if (strcmp(op, "connect") == 0) {
        tsm_welcome w;
        tsm_json *welcome, *features;
        size_t i;
        if (tsm_open(c) != TSM_OK) {
            return error_result();
        }
        tsm_welcome_get(c, &w);
        welcome = obj();
        features = tsm_json_array();
        for (i = 0; i < w.feature_count; i++) {
            tsm_json_push(features, tsm_json_str(w.features[i]));
        }
        set(welcome, "host", tsm_json_str(w.host));
        set(welcome, "platform", tsm_json_str(w.platform));
        set(welcome, "features", features);
        result = obj();
        set(result, "welcome", welcome);
        return result;
    }
    if (strcmp(op, "get") == 0) {
        tsm_get_options options = TSM_GET_OPTIONS_INIT;
        const tsm_json *flag;
        const char **dimensions = dimensions_of(tsm_json_get(action, "dimensions"));
        progress_log log;
        tsm_value *v;
        tsm_mutex_init(&log.mu);
        log.entries = tsm_json_array();
        options.field = tsm_json_get_str(action, "field");
        options.dimensions = dimensions;
        options.no_wait = no_wait;
        options.timeout_ms = timeout_ms;
        options.on_progress = log_progress;
        options.progress_context = &log;
        flag = tsm_json_get(action, "wantClientToken");
        options.want_client_token = flag && flag->type == TSM_J_BOOL && flag->boolean;
        flag = tsm_json_get(action, "waitOnRateLimit");
        options.wait_on_rate_limit = flag && flag->type == TSM_J_BOOL && flag->boolean;
        if (tsm_get(c, ref, &options, &v) == TSM_OK) {
            result = obj();
            set(result, "value", value_shape(v));
        } else {
            result = error_result();
        }
        free((void *)dimensions);
        return with_progress(result, &log);
    }
    if (strcmp(op, "getMany") == 0) {
        const tsm_json *refs = tsm_json_get(action, "refs");
        tsm_request *requests = (tsm_request *)calloc(refs->count, sizeof *requests);
        tsm_request_options options = TSM_REQUEST_OPTIONS_INIT;
        tsm_result *results;
        progress_log log;
        size_t i;
        tsm_mutex_init(&log.mu);
        log.entries = tsm_json_array();
        for (i = 0; i < refs->count; i++) {
            requests[i].ref = tsm_json_get_str(refs->items[i], "ref");
            requests[i].field = tsm_json_get_str(refs->items[i], "field");
            requests[i].dimensions = dimensions_of(tsm_json_get(refs->items[i], "dimensions"));
        }
        options.no_wait = no_wait;
        options.timeout_ms = timeout_ms;
        options.on_progress = log_progress;
        options.progress_context = &log;
        if (tsm_get_many(c, requests, refs->count, &options, &results) == TSM_OK) {
            tsm_json *list = tsm_json_array();
            for (i = 0; i < refs->count; i++) {
                tsm_json *item = obj();
                if (results[i].kind == TSM_OK) {
                    set(item, "value", value_shape(results[i].value));
                    results[i].value = NULL;
                } else {
                    set(item, "error", error_shape(results[i].kind, results[i].reason));
                }
                tsm_json_push(list, item);
            }
            tsm_results_free(results, refs->count);
            result = obj();
            set(result, "results", list);
        } else {
            result = error_result();
        }
        for (i = 0; i < refs->count; i++) {
            free((void *)requests[i].dimensions);
        }
        free(requests);
        return with_progress(result, &log);
    }
    if (strcmp(op, "getFile") == 0) {
        tsm_get_options options = TSM_GET_OPTIONS_INIT;
        tsm_file *f;
        tsm_json *file;
        size_t size;
        const unsigned char *bytes;
        char *b64;
        options.field = tsm_json_get_str(action, "field");
        if (tsm_get_file(c, ref, &options, &f) != TSM_OK) {
            return error_result();
        }
        bytes = tsm_file_bytes(f, &size);
        b64 = base64(bytes, size);
        file = obj();
        set(file, "name", tsm_json_str(tsm_file_name(f)));
        set(file, "size", tsm_json_int((long long)size));
        set(file, "base64", tsm_json_str(b64));
        free(b64);
        tsm_file_free(f);
        result = obj();
        set(result, "file", file);
        return result;
    }
    if (strcmp(op, "concurrent") == 0) {
        const tsm_json *actions = tsm_json_get(action, "actions");
        concurrent_job *jobs = (concurrent_job *)calloc(actions->count + 1, sizeof *jobs);
        tsm_mutex mu;
        tsm_cond cond;
        size_t left = actions->count, i;
        tsm_json *list = tsm_json_array();
        tsm_mutex_init(&mu);
        tsm_cond_init(&cond);
        for (i = 0; i < actions->count; i++) {
            jobs[i].client = c;
            jobs[i].action = actions->items[i];
            jobs[i].mu = &mu;
            jobs[i].cond = &cond;
            jobs[i].left = &left;
            if (!tsm_thread_start(run_job, &jobs[i])) {
                fprintf(stderr, "runner: no thread\n");
                exit(2);
            }
        }
        tsm_mutex_lock(&mu);
        while (left > 0) {
            tsm_cond_wait(&cond, &mu);
        }
        tsm_mutex_unlock(&mu);
        for (i = 0; i < actions->count; i++) {
            tsm_json_push(list, jobs[i].result);
        }
        free(jobs);
        tsm_cond_destroy(&cond);
        tsm_mutex_destroy(&mu);
        result = obj();
        set(result, "results", list);
        return result;
    }
    if (strcmp(op, "sequence") == 0) {
        const tsm_json *actions = tsm_json_get(action, "actions");
        tsm_json *steps = tsm_json_array();
        size_t i;
        for (i = 0; i < actions->count; i++) {
            const tsm_json *step = actions->items[i];
            if (strcmp(tsm_json_get_str(step, "do"), "pause") == 0) {
                long long ms = 0;
                tsm_json_get_int(step, "ms", &ms);
                tsm_sleep_ms(ms);
                continue;
            }
            tsm_json_push(steps, run(c, step));
        }
        result = obj();
        set(result, "steps", steps);
        return result;
    }
    result = obj();
    set(result, "unsupportedAction", tsm_json_str(op));
    return result;
}

static char *read_line(void) {
    tsm_buf b = {NULL, 0, 0};
    int ch;
    while ((ch = getchar()) != EOF && ch != '\n') {
        tsm_buf_addc(&b, (char)ch);
    }
    if (ch == EOF && b.len == 0) {
        tsm_buf_wipe(&b);
        return NULL;
    }
    if (!b.data) {
        tsm_buf_add(&b, "", 0);
    }
    return (char *)b.data;
}

int main(void) {
    char *line;
    while ((line = read_line()) != NULL) {
        tsm_json *request, *action, *answer, *client_options;
        tsm_client_options options = TSM_CLIENT_OPTIONS_INIT;
        tsm_client *c;
        char why[256], *text;
        if (strspn(line, " \t\r") == strlen(line)) {
            free(line);
            continue;
        }
        request = tsm_json_parse(line, strlen(line), why, sizeof why);
        free(line);
        if (!request) {
            fprintf(stderr, "runner: bad case line: %s\n", why);
            return 2;
        }
        action = (tsm_json *)tsm_json_get(request, "action");
        client_options = (tsm_json *)tsm_json_get(action, "client");
        options.client_name = "conformance-runner";
        options.runtime_dir = tsm_json_get_str(request, "runtimeDir");
        options.connect_timeout_ms = 5000;
        options.client_token = client_options ? tsm_json_get_str(client_options, "clientToken") : NULL;
        if (tsm_client_new(&c, &options) != TSM_OK) {
            fprintf(stderr, "runner: no client\n");
            return 2;
        }
        answer = obj();
        set(answer, "case", tsm_json_clone(tsm_json_get(request, "case")));
        set(answer, "result", run(c, action));
        tsm_client_free(c);
        text = tsm_json_write(answer, NULL);
        printf("%s\n", text);
        fflush(stdout);
        free(text);
        tsm_json_free(answer);
        tsm_json_free(request);
    }
    return 0;
}
