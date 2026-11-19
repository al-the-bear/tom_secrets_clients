/*
 * Copyright (c) 2026 Peter Nicolai Alexis Kyaw
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * The library's tests (ctest; run from the module's folder): every vector
 * of protocol/vectors/ that a client computes (references, discovery, port
 * files, frames), JSON, values, SHA-256, times, and the client against a
 * small service on a Unix socket (not on Windows). The full behaviour is the
 * conformance suite's. Exits 1 when a check fails.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "tsm/tsm.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

static int failures;
static int checks;

#define CHECK(cond, ...)                                                                                     \
    do {                                                                                                     \
        checks++;                                                                                            \
        if (!(cond)) {                                                                                       \
            failures++;                                                                                      \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                                                      \
            printf(__VA_ARGS__);                                                                             \
            printf("\n");                                                                                    \
        }                                                                                                    \
    } while (0)

static tsm_json *vectors(const char *name) {
    char path[256], why[128];
    size_t len;
    char *text;
    tsm_json *j;
    snprintf(path, sizeof path, "../../protocol/vectors/%s", name);
    text = tsm_read_file(path, &len);
    if (!text) {
        printf("FAIL cannot read %s (run from clients/c)\n", path);
        exit(1);
    }
    j = tsm_json_parse(text, len, why, sizeof why);
    free(text);
    if (!j) {
        printf("FAIL %s: %s\n", name, why);
        exit(1);
    }
    return j;
}

static int json_equal(const tsm_json *a, const tsm_json *b) {
    size_t i;
    if (!a || !b) {
        return a == b;
    }
    if (a->type != b->type) {
        return 0;
    }
    switch (a->type) {
    case TSM_J_NULL:
        return 1;
    case TSM_J_BOOL:
        return a->boolean == b->boolean;
    case TSM_J_NUMBER:
        return a->number == b->number;
    case TSM_J_STRING:
        return a->string_len == b->string_len && memcmp(a->string, b->string, a->string_len) == 0;
    case TSM_J_ARRAY:
        if (a->count != b->count) {
            return 0;
        }
        for (i = 0; i < a->count; i++) {
            if (!json_equal(a->items[i], b->items[i])) {
                return 0;
            }
        }
        return 1;
    case TSM_J_OBJECT:
        if (a->count != b->count) {
            return 0;
        }
        for (i = 0; i < a->count; i++) {
            if (!json_equal(a->items[i], tsm_json_get(b, a->keys[i]))) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

static tsm_json *shape(const tsm_reference *r) {
    tsm_json *out = tsm_json_object(), *target = tsm_json_object(), *q = tsm_json_array();
    size_t i;
    if (r->kind == TSM_TARGET_KEY) {
        tsm_json_set(target, "kind", tsm_json_str("key"));
        tsm_json_set(target, "key", tsm_json_str(r->key));
    } else if (r->kind == TSM_TARGET_UUID) {
        tsm_json_set(target, "kind", tsm_json_str("uuid"));
        tsm_json_set(target, "store", tsm_json_str(r->store));
        tsm_json_set(target, "uuid", tsm_json_str(r->uuid));
    } else {
        tsm_json *segments = tsm_json_array();
        tsm_json_set(target, "kind", tsm_json_str("path"));
        tsm_json_set(target, "store", tsm_json_str(r->store));
        for (i = 0; i < r->segment_count; i++) {
            tsm_json_push(segments, tsm_json_str(r->segments[i]));
        }
        tsm_json_set(target, "segments", segments);
    }
    for (i = 0; i < r->qualifier_count; i++) {
        tsm_json *b = tsm_json_object();
        tsm_json_set(b, "dimension", tsm_json_str(r->dimensions[i]));
        tsm_json_set(b, "value", tsm_json_str(r->values[i]));
        tsm_json_push(q, b);
    }
    tsm_json_set(out, "qualifiers", q);
    tsm_json_set(out, "target", target);
    tsm_json_set(out, "field", tsm_json_str(r->field));
    tsm_json_set(out, "fieldGiven", tsm_json_bool(r->field_given));
    return out;
}

static void test_references(void) {
    tsm_json *v = vectors("references.json");
    const tsm_json *list;
    long long max;
    size_t i;
    CHECK(tsm_json_get_int(v, "maxReferenceBytes", &max) && max == TSM_MAX_REFERENCE_BYTES, "maxReferenceBytes");
    list = tsm_json_get(v, "valid");
    for (i = 0; i < list->count; i++) {
        const char *input = tsm_json_get_str(list->items[i], "input");
        tsm_reference *r, *again;
        char *canonical = NULL, *twice = NULL;
        tsm_json *s;
        if (tsm_reference_parse(input, &r) != TSM_OK) {
            CHECK(0, "valid %s: %s", input, tsm_last_error(NULL)->message);
            continue;
        }
        s = shape(r);
        CHECK(json_equal(s, tsm_json_get(list->items[i], "parsed")), "parsed %s", input);
        tsm_json_free(s);
        CHECK(tsm_reference_format(r, &canonical) == TSM_OK &&
                  strcmp(canonical, tsm_json_get_str(list->items[i], "canonical")) == 0,
              "canonical %s: %s", input, canonical ? canonical : "(none)");
        CHECK(tsm_reference_parse(canonical, &again) == TSM_OK && tsm_reference_format(again, &twice) == TSM_OK &&
                  strcmp(twice, canonical) == 0,
              "reparse %s", input);
        tsm_reference_free(again);
        tsm_free(twice);
        tsm_free(canonical);
        tsm_reference_free(r);
    }
    list = tsm_json_get(v, "invalid");
    for (i = 0; i < list->count; i++) {
        const char *input = tsm_json_get_str(list->items[i], "input");
        const char *reason = tsm_json_get_str(list->items[i], "reason");
        tsm_reference *r = NULL;
        tsm_error_kind rc = tsm_reference_parse(input, &r);
        const tsm_error *e = tsm_last_error(NULL);
        CHECK(rc == TSM_ERR_MALFORMED && e->reason && strcmp(e->reason, reason) == 0, "invalid %s: %s, want %s",
              input, e->reason ? e->reason : "(none)", reason);
        tsm_reference_free(r);
    }
    list = tsm_json_get(v, "format");
    for (i = 0; i < list->count; i++) {
        const tsm_json *parsed = tsm_json_get(list->items[i], "parsed");
        const tsm_json *t = tsm_json_get(parsed, "target"), *q = tsm_json_get(parsed, "qualifiers");
        const char *kind = tsm_json_get_str(t, "kind");
        tsm_reference r;
        char *formatted = NULL;
        size_t k;
        memset(&r, 0, sizeof r);
        if (!strcmp(kind, "key")) {
            r.kind = TSM_TARGET_KEY;
            r.key = (char *)tsm_json_get_str(t, "key");
        } else if (!strcmp(kind, "uuid")) {
            r.kind = TSM_TARGET_UUID;
            r.store = (char *)tsm_json_get_str(t, "store");
            r.uuid = (char *)tsm_json_get_str(t, "uuid");
        } else {
            const tsm_json *segments = tsm_json_get(t, "segments");
            r.kind = TSM_TARGET_PATH;
            r.store = (char *)tsm_json_get_str(t, "store");
            r.segment_count = segments->count;
            r.segments = (char **)calloc(segments->count + 1, sizeof(char *));
            for (k = 0; k < segments->count; k++) {
                r.segments[k] = segments->items[k]->string;
            }
        }
        r.qualifier_count = q->count;
        r.dimensions = (char **)calloc(q->count + 1, sizeof(char *));
        r.values = (char **)calloc(q->count + 1, sizeof(char *));
        for (k = 0; k < q->count; k++) {
            r.dimensions[k] = (char *)tsm_json_get_str(q->items[k], "dimension");
            r.values[k] = (char *)tsm_json_get_str(q->items[k], "value");
        }
        r.field = (char *)tsm_json_get_str(parsed, "field");
        CHECK(tsm_reference_format(&r, &formatted) == TSM_OK &&
                  strcmp(formatted, tsm_json_get_str(list->items[i], "formatted")) == 0,
              "format %s", formatted ? formatted : "(none)");
        if (formatted) {
            tsm_reference *back;
            if (tsm_reference_parse(formatted, &back) == TSM_OK) {
                tsm_json *s = shape(back);
                CHECK(json_equal(s, tsm_json_get(list->items[i], "reparsed")), "reparsed %s", formatted);
                tsm_json_free(s);
                tsm_reference_free(back);
            } else {
                CHECK(0, "reparse %s", formatted);
            }
        }
        tsm_free(formatted);
        free(r.segments);
        free(r.dimensions);
        free(r.values);
    }
    tsm_json_free(v);
}

static const char *json_env(const char *name, void *context) {
    return tsm_json_get_str((const tsm_json *)context, name);
}

static void test_discovery(void) {
    tsm_json *v = vectors("discovery.json");
    const tsm_json *cases = tsm_json_get(v, "cases"), *ports = tsm_json_get(v, "portFiles");
    size_t i;
    for (i = 0; i < cases->count; i++) {
        const tsm_json *c = cases->items[i], *expect = tsm_json_get(c, "expect");
        long long uid = 0;
        tsm_endpoints e;
        tsm_json_get_int(c, "uid", &uid);
        if (tsm_discover(tsm_json_get_str(c, "os"), json_env, (void *)tsm_json_get(c, "env"), uid, &e) != TSM_OK) {
            CHECK(tsm_json_get_str(expect, "notRunning") &&
                      strcmp(tsm_json_get_str(expect, "notRunning"), "no_runtime_directory") == 0,
                  "discovery case %lu: not running", (unsigned long)i);
            continue;
        }
        {
            const tsm_json *client = tsm_json_get(expect, "client"), *admin = tsm_json_get(expect, "admin");
            const char *s;
#define SAME(field, m, key) (s = tsm_json_get_str(m, key), strcmp(e.field, s ? s : "") == 0)
            CHECK(strcmp(e.directory, tsm_json_get_str(expect, "directory")) == 0, "directory %s", e.directory);
            CHECK(SAME(client_socket, client, "socket") && SAME(client_port_file, client, "portFile") &&
                      SAME(client_token_file, client, "tokenFile") && SAME(admin_socket, admin, "socket") &&
                      SAME(admin_port_file, admin, "portFile"),
                  "discovery case %lu endpoints", (unsigned long)i);
#undef SAME
        }
    }
    for (i = 0; i < ports->count; i++) {
        long long port = 0;
        int want = tsm_json_get_int(ports->items[i], "port", &port) ? (int)port : 0;
        CHECK(tsm_read_port_file(tsm_json_get_str(ports->items[i], "text")) == want, "port file %lu",
              (unsigned long)i);
    }
    tsm_json_free(v);
}

static unsigned char *hex(const char *text, size_t *len) {
    size_t n = strlen(text) / 2, i;
    unsigned char *out = (unsigned char *)malloc(n + 1);
    for (i = 0; i < n; i++) {
        unsigned b;
        sscanf(text + 2 * i, "%2x", &b);
        out[i] = (unsigned char)b;
    }
    *len = n;
    return out;
}

static void test_frames(void) {
    tsm_json *v = vectors("frames.json");
    const tsm_json *frames = tsm_json_get(v, "frames"), *invalid = tsm_json_get(v, "invalid");
    long long protocol;
    size_t i;
    char why[256];
    CHECK(tsm_json_get_int(v, "protocol", &protocol) && protocol == TSM_PROTOCOL_VERSION, "protocol");
    for (i = 0; i < frames->count; i++) {
        const tsm_json *c = frames->items[i];
        const char *name = tsm_json_get_str(c, "name");
        long long type;
        size_t len, count;
        unsigned char *data = hex(tsm_json_get_str(c, "hex"), &len);
        tsm_frame *read;
        tsm_frame_reader r;
        memset(&r, 0, sizeof r);
        r.max_payload = TSM_MAX_ANSWER_PAYLOAD;
        tsm_json_get_int(c, "type", &type);
        if (type == TSM_FRAME_JSON) {
            tsm_json *m, *back;
            char *written;
            size_t wlen;
            CHECK(tsm_frames_add(&r, data, len, &read, &count, why, sizeof why) == 0 && count == 1, "%s", name);
            m = tsm_payload_decode(read[0].payload, read[0].len, why, sizeof why);
            CHECK(m && json_equal(m, tsm_json_get(c, "json")), "%s decodes", name);
            written = tsm_json_write(m, &wlen);
            back = tsm_json_parse(written, wlen, why, sizeof why);
            CHECK(back && json_equal(back, tsm_json_get(c, "json")), "%s written again", name);
            tsm_json_free(back);
            free(written);
            tsm_json_free(m);
            tsm_frames_free(read, count);
        } else {
            long long id;
            unsigned long long got = 0;
            size_t chunk_len, k;
            unsigned char *chunk = hex(tsm_json_get_str(c, "chunkHex"), &chunk_len);
            CHECK(tsm_frames_add(&r, data, len, &read, &count, why, sizeof why) == -1, "%s before binary", name);
            tsm_frame_reader_free(&r);
            memset(&r, 0, sizeof r);
            r.max_payload = TSM_MAX_ANSWER_PAYLOAD;
            r.binary_allowed = 1;
            CHECK(tsm_frames_add(&r, data, len, &read, &count, why, sizeof why) == 0 && count == 1, "%s", name);
            for (k = 0; k < 8; k++) {
                got = got << 8 | read[0].payload[k];
            }
            tsm_json_get_int(c, "requestId", &id);
            CHECK(got == (unsigned long long)id && read[0].len - 8 == chunk_len &&
                      memcmp(read[0].payload + 8, chunk, chunk_len) == 0,
                  "%s chunk", name);
            tsm_frames_free(read, count);
            free(chunk);
        }
        tsm_frame_reader_free(&r);
        free(data);
    }
    for (i = 0; i < invalid->count; i++) {
        const tsm_json *c = invalid->items[i];
        const char *name = tsm_json_get_str(c, "name"), *outcome = tsm_json_get_str(c, "outcome");
        size_t len, count = 0;
        unsigned char *data = hex(tsm_json_get_str(c, "hex"), &len);
        tsm_frame *read = NULL;
        tsm_frame_reader r;
        int rc;
        memset(&r, 0, sizeof r);
        r.max_payload = strcmp(tsm_json_get_str(c, "direction"), "to service") == 0 ? TSM_MAX_REQUEST_PAYLOAD
                                                                                    : TSM_MAX_ANSWER_PAYLOAD;
        rc = tsm_frames_add(&r, data, len, &read, &count, why, sizeof why);
        if (!strcmp(outcome, "close")) {
            CHECK(rc == -1, "%s closes", name);
        } else if (!strcmp(outcome, "read")) {
            CHECK(rc == 0 && count == 0, "%s reads on", name);
        } else {
            tsm_json *m;
            CHECK(rc == 0 && count == 1, "%s one frame", name);
            m = count ? tsm_payload_decode(read[0].payload, read[0].len, why, sizeof why) : NULL;
            if (!strcmp(name, "a first frame that is not hello")) {
                /* Well-formed JSON: the order of frames is wrong, which the
                 * service checks. */
                CHECK(m != NULL, "%s decodes", name);
            } else {
                CHECK(m == NULL, "%s malformed", name);
            }
            tsm_json_free(m);
        }
        tsm_frames_free(read, count);
        tsm_frame_reader_free(&r);
        free(data);
    }
    tsm_json_free(v);
}

static void test_json(void) {
    static const char *const bad[] = {
        "\xEF\xBB\xBF{\"op\":\"x\"}", "{\"op\":\"x\",\"op\":\"y\"}", "{\"op\":\"x\"} {}", "{\"op\":\"x\",\"n\":1e999}",
        "{\"op\":1}", "[]", "{\"op\":\"x\",\"n\":01}", "{\"op\":\"a\x01\"}", "{\"op\":\"\xff\"}"};
    size_t i;
    char why[128];
    tsm_json *j;
    char *out;
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        tsm_json *m = tsm_payload_decode((const unsigned char *)bad[i], strlen(bad[i]), why, sizeof why);
        CHECK(m == NULL, "bad payload %lu decoded", (unsigned long)i);
        tsm_json_free(m);
    }
    {
        static const char text[] = "{\"b\":[1,2.5,-3e2,true,null],\"a\":\"\\u00e9\\ud83d\\ude00\\ud800\\n\"}";
        j = tsm_json_parse(text, sizeof text - 1, why, sizeof why);
    }
    out = j ? tsm_json_write(j, NULL) : NULL;
    CHECK(out && strcmp(out, "{\"a\":\"\xc3\xa9\xf0\x9f\x98\x80\xef\xbf\xbd\\n\",\"b\":[1,2.5,-300,true,null]}") == 0,
          "round trip: %s", out ? out : why);
    free(out);
    tsm_json_free(j);
}

static void test_algorithms(void) {
    unsigned char d[32], *million, *data;
    char h[65];
    size_t i, n;
    long long ms;
    static const struct {
        const char *text;
        const char *sum;
    } v[] = {{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
             {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
             {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"}};
    for (i = 0; i < 3; i++) {
        tsm_sha256((const unsigned char *)v[i].text, strlen(v[i].text), d);
        for (n = 0; n < 32; n++) {
            snprintf(h + 2 * n, 3, "%02x", d[n]);
        }
        CHECK(strcmp(h, v[i].sum) == 0, "sha256 %lu", (unsigned long)i);
    }
    million = (unsigned char *)malloc(1000000);
    memset(million, 'a', 1000000);
    tsm_sha256(million, 1000000, d);
    free(million);
    for (n = 0; n < 32; n++) {
        snprintf(h + 2 * n, 3, "%02x", d[n]);
    }
    CHECK(strcmp(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0, "sha256 million");
    CHECK(tsm_base64_decode("AAEC/w==", &data, &n) && n == 4 && data[3] == 0xff, "base64");
    free(data);
    CHECK(!tsm_base64_decode("A", &data, &n) && !tsm_base64_decode("AA===", &data, &n), "base64 refused");
    CHECK(tsm_parse_time("2026-11-19T11:00:00.250+01:00", &ms) && ms == 1795082400250LL, "time");
    CHECK(tsm_parse_time("2024-02-29t23:59:59.999999999-00:30", &ms) && ms == 1709252999999LL, "time 2");
    CHECK(!tsm_parse_time("2026-02-29T00:00:00Z", &ms) && !tsm_parse_time("2026-11-19T24:00:00Z", &ms) &&
              !tsm_parse_time("2026-11-19T10:00:00", &ms),
          "times refused");
    CHECK(tsm_error_kind_from_wire("brand_new") == TSM_ERR_INTERNAL &&
              tsm_error_kind_from_wire("not_running") == TSM_ERR_INTERNAL &&
              tsm_error_kind_from_wire("denied") == TSM_ERR_DENIED,
          "kinds from the wire");
}

static tsm_json *value_message(long long id, const char *value) {
    char text[512], why[64];
    snprintf(text, sizeof text,
             "{\"op\":\"value\",\"id\":%lld,\"value\":\"%s\",\"entry\":{\"store\":\"demo\",\"uuid\":"
             "\"8f1c0f0e000040008000000000000002\",\"source\":\"file\",\"fetchedAt\":\"2026-11-19T10:00:00Z\"},"
             "\"bound\":{\"env\":\"prod\"},\"version\":{\"modified\":\"2026-11-19T09:00:00.250+01:00\","
             "\"revision\":\"r1\"}}",
             id, value);
    return tsm_json_parse(text, strlen(text), why, sizeof why);
}

static void test_values(void) {
    tsm_json *m = value_message(1, "demo-password");
    tsm_value *v;
    size_t size;
    long long expires;
    CHECK(tsm_value_from_message("db.main", m, &v) == TSM_OK, "value");
    CHECK(strcmp(tsm_value_text(v), "demo-password") == 0, "text");
    CHECK(strcmp(tsm_value_entry_source(v), "file") == 0, "source");
    CHECK(tsm_value_version_modified_ms(v) == 1795075200250LL, "modified");
    CHECK(tsm_value_bound_count(v) == 1 && strcmp(tsm_value_bound_value(v, 0), "prod") == 0, "bound");
    CHECK(!tsm_value_expires_ms(v, &expires) && !tsm_value_client_token(v), "no expiry, no token");
    tsm_value_bytes(v, &size);
    CHECK(size == 13, "size");
    tsm_value_free(v);
    tsm_json_set(m, "encoding", tsm_json_str("base64"));
    tsm_json_set(m, "value", tsm_json_str("AAEC/w=="));
    CHECK(tsm_value_from_message("x", m, &v) == TSM_OK && tsm_value_text(v) == NULL, "binary refuses text");
    tsm_value_free(v);
    tsm_json_set(m, "version", tsm_json_null());
    CHECK(tsm_value_from_message("x", m, &v) == TSM_ERR_INTERNAL, "a bad value message is internal");
    tsm_json_free(m);
}

/* ---- a service in the test ------------------------------------------- */
#ifndef _WIN32

typedef struct service {
    char dir[256];
    char path[300];
    int listener;
    const char *features;
    tsm_mutex mu;
    int hellos;
    int limited;
    int peers[64];
    int peer_count;
} service;

static void send_text(int fd, tsm_mutex *write_mu, int type, const unsigned char *payload, size_t len) {
    size_t frame_len;
    unsigned char *frame = tsm_frame_encode(type, payload, len, &frame_len);
    tsm_mutex_lock(write_mu);
    tsm_socket_send_all(fd, frame, frame_len);
    tsm_mutex_unlock(write_mu);
    free(frame);
}

static void send_json(int fd, tsm_mutex *write_mu, const tsm_json *m) {
    size_t len;
    char *text = tsm_json_write(m, &len);
    send_text(fd, write_mu, TSM_FRAME_JSON, (const unsigned char *)text, len);
    free(text);
}

static void send_raw(int fd, tsm_mutex *write_mu, const char *json) {
    send_text(fd, write_mu, TSM_FRAME_JSON, (const unsigned char *)json, strlen(json));
}

typedef struct peer {
    service *s;
    int fd;
} peer;

static void drop_all(service *s) {
    int i;
    tsm_mutex_lock(&s->mu);
    for (i = 0; i < s->peer_count; i++) {
        shutdown(s->peers[i], SHUT_RDWR);
    }
    tsm_mutex_unlock(&s->mu);
}

static void serve(void *arg) {
    peer p = *(peer *)arg;
    tsm_mutex write_mu;
    tsm_frame_reader r;
    unsigned char buffer[65536];
    char why[256], text[512];
    free(arg);
    tsm_mutex_init(&write_mu);
    memset(&r, 0, sizeof r);
    r.max_payload = TSM_MAX_REQUEST_PAYLOAD;
    for (;;) {
        long n = tsm_socket_recv(p.fd, buffer, sizeof buffer);
        tsm_frame *frames;
        size_t count, i;
        if (n <= 0 || tsm_frames_add(&r, buffer, (size_t)n, &frames, &count, why, sizeof why) != 0) {
            break;
        }
        for (i = 0; i < count; i++) {
            tsm_json *m = tsm_payload_decode(frames[i].payload, frames[i].len, why, sizeof why);
            const char *op = m ? tsm_json_get_str(m, "op") : "";
            long long id = 0;
            tsm_json_get_int(m, "id", &id);
            if (!strcmp(op, "hello")) {
                tsm_mutex_lock(&p.s->mu);
                p.s->hellos++;
                tsm_mutex_unlock(&p.s->mu);
                CHECK(!strcmp(tsm_json_get_str(tsm_json_get(m, "client"), "language"), "c") &&
                          !strcmp(tsm_json_get_str(tsm_json_get(m, "client"), "version"), TSM_CLIENT_VERSION) &&
                          !strcmp(tsm_json_get_str(tsm_json_get(m, "client"), "name"), "unit-test"),
                      "hello");
                snprintf(text, sizeof text,
                         "{\"op\":\"welcome\",\"protocol\":1,\"service\":{\"version\":\"0.0.0-test\"},\"features\":%s,"
                         "\"host\":\"testhost\",\"platform\":\"macos\"}",
                         p.s->features);
                send_raw(p.fd, &write_mu, text);
            } else if (!strcmp(op, "get")) {
                const char *ref = tsm_json_get_str(m, "ref");
                if (!strcmp(ref, "missing.entry")) {
                    snprintf(text, sizeof text,
                             "{\"op\":\"error\",\"id\":%lld,\"kind\":\"not_found\",\"message\":\"no entry\","
                             "\"details\":{\"reason\":\"no_entry\"}}",
                             id);
                    send_raw(p.fd, &write_mu, text);
                } else if (!strcmp(ref, "slow.entry")) {
                    tsm_json *v = value_message(id, "slow-secret");
                    snprintf(text, sizeof text,
                             "{\"op\":\"progress\",\"id\":%lld,\"pending\":\"approval\",\"approvalCode\":\"123-456\"}", id);
                    send_raw(p.fd, &write_mu, text);
                    tsm_sleep_ms(20);
                    send_json(p.fd, &write_mu, v);
                    tsm_json_free(v);
                } else if (!strcmp(ref, "limited.entry")) {
                    int first;
                    tsm_mutex_lock(&p.s->mu);
                    first = ++p.s->limited == 1;
                    tsm_mutex_unlock(&p.s->mu);
                    if (first) {
                        snprintf(text, sizeof text,
                                 "{\"op\":\"error\",\"id\":%lld,\"kind\":\"rate_limited\",\"message\":\"slow down\","
                                 "\"details\":{\"retryAfterMs\":10}}",
                                 id);
                        send_raw(p.fd, &write_mu, text);
                    } else {
                        tsm_json *v = value_message(id, "limited-secret");
                        send_json(p.fd, &write_mu, v);
                        tsm_json_free(v);
                    }
                } else if (!strcmp(ref, "drop.entry")) {
                    drop_all(p.s);
                } else {
                    char value[300];
                    tsm_json *v;
                    const char *field = tsm_json_get_str(m, "field");
                    snprintf(value, sizeof value, "secret-of-%s%s%s", ref, field ? "#" : "", field ? field : "");
                    v = value_message(id, value);
                    send_json(p.fd, &write_mu, v);
                    tsm_json_free(v);
                }
            } else if (!strcmp(op, "getMany")) {
                const tsm_json *refs = tsm_json_get(m, "refs");
                tsm_json *answer = tsm_json_object(), *results = tsm_json_array();
                size_t k;
                for (k = 0; k < refs->count; k++) {
                    const char *ref = tsm_json_get_str(refs->items[k], "ref");
                    if (!strcmp(ref, "missing.entry")) {
                        tsm_json *e = tsm_json_object();
                        tsm_json_set(e, "op", tsm_json_str("error"));
                        tsm_json_set(e, "kind", tsm_json_str("not_found"));
                        tsm_json_set(e, "message", tsm_json_str("no entry"));
                        tsm_json_push(results, e);
                    } else {
                        char value[300];
                        snprintf(value, sizeof value, "secret-of-%s", ref);
                        tsm_json_push(results, value_message(0, value));
                    }
                }
                tsm_json_set(answer, "op", tsm_json_str("values"));
                tsm_json_set(answer, "id", tsm_json_int(id));
                tsm_json_set(answer, "results", results);
                send_json(p.fd, &write_mu, answer);
                tsm_json_free(answer);
            } else if (!strcmp(op, "getFile")) {
                static const char content[] = "-----BEGIN DEMO KEY-----\nnot a real key\n-----END DEMO KEY-----\n";
                size_t len = sizeof content - 1, start, k;
                unsigned char digest[32], chunk[24];
                char sum[65];
                snprintf(text, sizeof text, "{\"op\":\"file\",\"id\":%lld,\"name\":\"demo.pem\",\"size\":%lu}", id,
                         (unsigned long)len);
                send_raw(p.fd, &write_mu, text);
                for (start = 0; start < len; start += 16) {
                    size_t n2 = len - start < 16 ? len - start : 16;
                    for (k = 0; k < 8; k++) {
                        chunk[k] = (unsigned char)(id >> (56 - 8 * k));
                    }
                    memcpy(chunk + 8, content + start, n2);
                    send_text(p.fd, &write_mu, TSM_FRAME_BINARY, chunk, 8 + n2);
                }
                tsm_sha256((const unsigned char *)content, len, digest);
                for (k = 0; k < 32; k++) {
                    snprintf(sum + 2 * k, 3, "%02x", digest[k]);
                }
                snprintf(text, sizeof text, "{\"op\":\"end\",\"id\":%lld,\"sha256\":\"%s\"}", id, sum);
                send_raw(p.fd, &write_mu, text);
            }
            tsm_json_free(m);
        }
        tsm_frames_free(frames, count);
    }
    tsm_frame_reader_free(&r);
    close(p.fd);
    tsm_mutex_destroy(&write_mu);
}

static void accept_loop(void *arg) {
    service *s = (service *)arg;
    for (;;) {
        int fd = accept(s->listener, NULL, NULL);
        peer *p;
        if (fd < 0) {
            return;
        }
        tsm_mutex_lock(&s->mu);
        if (s->peer_count < 64) {
            s->peers[s->peer_count++] = fd;
        }
        tsm_mutex_unlock(&s->mu);
        p = (peer *)malloc(sizeof *p);
        p->s = s;
        p->fd = fd;
        tsm_thread_start(serve, p);
    }
}

/* The services of the run: static, as their detached threads may still be
 * ending when a test moves on. */
static service services[4];

static service *service_start(const char *features) {
    static int counter;
    service *s;
    struct sockaddr_un a;
    const char *tmp = getenv("TMPDIR");
    if (counter >= (int)(sizeof services / sizeof services[0])) {
        printf("FAIL too many services\n");
        exit(1);
    }
    s = &services[counter];
    /* The system's temporary folder: a Unix socket's path is short. */
    {
        /* Both names from a local buffer: s->dir and s->path are parts of
         * one static object. */
        char dir[200];
        snprintf(dir, sizeof dir, "%.150s/tsm-c-test-%d-%d", tmp && *tmp ? tmp : "/tmp", (int)getpid(), ++counter);
        snprintf(s->dir, sizeof s->dir, "%s", dir);
        snprintf(s->path, sizeof s->path, "%s/client.sock", dir);
    }
    if (mkdir(s->dir, 0700) != 0) {
        printf("FAIL mkdir %s\n", s->dir);
        exit(1);
    }
    s->features = features;
    tsm_mutex_init(&s->mu);
    s->listener = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    if (strlen(s->path) >= sizeof a.sun_path) {
        printf("FAIL socket path too long: %s\n", s->path);
        exit(1);
    }
    memcpy(a.sun_path, s->path, strlen(s->path) + 1);
    if (bind(s->listener, (struct sockaddr *)&a, sizeof a) != 0 || listen(s->listener, 16) != 0) {
        printf("FAIL bind %s\n", s->path);
        exit(1);
    }
    tsm_thread_start(accept_loop, s);
    return s;
}

static void service_stop(service *s) {
    shutdown(s->listener, SHUT_RDWR);
    close(s->listener);
    drop_all(s);
    unlink(s->path);
    rmdir(s->dir);
}

static tsm_client *client_of(service *s) {
    tsm_client_options o = TSM_CLIENT_OPTIONS_INIT;
    tsm_client *c;
    o.client_name = "unit-test";
    o.runtime_dir = s->dir;
    o.operating_system = "linux";
    tsm_client_new(&c, &o);
    return c;
}

typedef struct seen {
    int count;
    char code[32];
} seen;

static void record(const tsm_progress *p, void *context) {
    seen *s = (seen *)context;
    s->count++;
    snprintf(s->code, sizeof s->code, "%s", p->approval_code ? p->approval_code : "");
}

typedef struct job {
    tsm_client *c;
    int i;
    int ok;
} job;

static void get_job(void *arg) {
    job *j = (job *)arg;
    char ref[32], want[64];
    tsm_value *v;
    snprintf(ref, sizeof ref, "k%d.entry", j->i);
    snprintf(want, sizeof want, "secret-of-%s", ref);
    j->ok = tsm_get(j->c, ref, NULL, &v) == TSM_OK && strcmp(tsm_value_text(v), want) == 0 ? 1 : -1;
    tsm_value_free(v);
}

static void test_client(void) {
    service *s = service_start("[]");
    tsm_client *c = client_of(s);
    tsm_get_options o = TSM_GET_OPTIONS_INIT;
    tsm_value *v = NULL;
    tsm_welcome w;
    seen progress;
    tsm_result *results;
    tsm_request requests[2];
    tsm_file *f;
    job jobs[20];
    int i, done;
    static const char *const big_dimensions[] = {"env", NULL, NULL};
    char *big;

    o.field = "UserName";
    CHECK(tsm_get(c, "db.main", &o, &v) == TSM_OK && strcmp(tsm_value_text(v), "secret-of-db.main#UserName") == 0,
          "get: %s", tsm_last_error(NULL)->message);
    tsm_value_free(v);
    CHECK(tsm_welcome_get(c, &w) && !strcmp(w.host, "testhost") && !strcmp(w.service_version, "0.0.0-test"),
          "welcome");

    for (i = 0; i < 20; i++) {
        jobs[i].c = c;
        jobs[i].i = i;
        jobs[i].ok = 0;
        tsm_thread_start(get_job, &jobs[i]);
    }
    do {
        tsm_sleep_ms(5);
        for (done = 1, i = 0; i < 20; i++) {
            done = done && jobs[i].ok != 0;
        }
    } while (!done);
    for (i = 0; i < 20; i++) {
        CHECK(jobs[i].ok == 1, "concurrent get %d", i);
    }
    CHECK(s->hellos == 1, "one connection: %d", s->hellos);

    memset(&progress, 0, sizeof progress);
    o = (tsm_get_options)TSM_GET_OPTIONS_INIT;
    o.on_progress = record;
    o.progress_context = &progress;
    CHECK(tsm_get(c, "slow.entry", &o, &v) == TSM_OK && progress.count == 1 && !strcmp(progress.code, "123-456"),
          "progress");
    tsm_value_free(v);
    CHECK(tsm_get(c, "limited.entry", NULL, &v) == TSM_ERR_RATE_LIMITED &&
              tsm_last_error(c)->retry_after_ms == 10,
          "rate limited");
    o = (tsm_get_options)TSM_GET_OPTIONS_INIT;
    o.wait_on_rate_limit = 1;
    CHECK(tsm_get(c, "limited.entry", &o, &v) == TSM_OK && !strcmp(tsm_value_text(v), "limited-secret"),
          "rate limit waited out");
    tsm_value_free(v);

    CHECK(tsm_get(c, "missing.entry", NULL, &v) == TSM_ERR_NOT_FOUND &&
              !strcmp(tsm_last_error(c)->reason, "no_entry") && !strcmp(tsm_last_error(c)->message, "no entry"),
          "not found");
    CHECK(tsm_get(c, "Bad Key", NULL, &v) == TSM_ERR_MALFORMED, "malformed locally");
    o = (tsm_get_options)TSM_GET_OPTIONS_INIT;
    o.field = "Password";
    CHECK(tsm_get(c, "fleet/Db/Main#UserName", &o, &v) == TSM_ERR_MALFORMED &&
              !strcmp(tsm_last_error(c)->reason, "field_twice"),
          "field twice");
    big = (char *)malloc(TSM_MAX_REQUEST_PAYLOAD + 1);
    memset(big, 'x', TSM_MAX_REQUEST_PAYLOAD);
    big[TSM_MAX_REQUEST_PAYLOAD] = 0;
    {
        const char *dims[3];
        dims[0] = big_dimensions[0];
        dims[1] = big;
        dims[2] = NULL;
        o = (tsm_get_options)TSM_GET_OPTIONS_INIT;
        o.dimensions = dims;
        CHECK(tsm_get(c, "db.main", &o, &v) == TSM_ERR_MALFORMED && !strcmp(tsm_last_error(c)->reason, "frame"),
              "frame too big");
    }
    free(big);

    requests[0].ref = "a.entry";
    requests[0].field = NULL;
    requests[0].dimensions = NULL;
    requests[1].ref = "missing.entry";
    requests[1].field = NULL;
    requests[1].dimensions = NULL;
    CHECK(tsm_get_many(c, requests, 2, NULL, &results) == TSM_OK &&
              !strcmp(tsm_value_text(results[0].value), "secret-of-a.entry") && results[1].kind == TSM_ERR_NOT_FOUND,
          "get many");
    tsm_results_free(results, 2);
    CHECK(tsm_get_many(c, requests, 0, NULL, &results) == TSM_ERR_INVALID_ARGUMENT, "get many of none");
    CHECK(tsm_get_file(c, "fleet/Ssh/Deploy#demo.pem", NULL, &f) == TSM_ERR_UNSUPPORTED, "no getFile");

    CHECK(tsm_get(c, "drop.entry", NULL, &v) == TSM_ERR_NOT_RUNNING, "dropped");
    CHECK(tsm_get(c, "again.entry", NULL, &v) == TSM_OK, "connects again");
    tsm_value_free(v);
    CHECK(s->hellos == 2, "two connections: %d", s->hellos);
    tsm_client_free(c);
    service_stop(s);

    s = service_start("[\"binary\",\"getFile\"]");
    c = client_of(s);
    CHECK(tsm_get_file(c, "fleet/Ssh/Deploy#demo.pem", NULL, &f) == TSM_OK, "get file: %s",
          tsm_last_error(NULL)->message);
    if (f) {
        size_t size;
        const unsigned char *bytes = tsm_file_bytes(f, &size);
        CHECK(!strcmp(tsm_file_name(f), "demo.pem") &&
                  size == strlen("-----BEGIN DEMO KEY-----\nnot a real key\n-----END DEMO KEY-----\n") &&
                  memcmp(bytes, "-----BEGIN", 10) == 0,
              "file: %lu bytes", (unsigned long)size);
        tsm_file_free(f);
    }
    tsm_client_free(c);
    service_stop(s);

    {
        tsm_client_options o2 = TSM_CLIENT_OPTIONS_INIT;
        o2.runtime_dir = "/nonexistent/tsm-c-test";
        o2.operating_system = "linux";
        CHECK(tsm_connect(&c, &o2) == TSM_ERR_NOT_RUNNING && c == NULL, "not running");
    }
}
#endif

int main(void) {
    test_references();
    test_discovery();
    test_frames();
    test_json();
    test_algorithms();
    test_values();
#ifndef _WIN32
    test_client();
#endif
    printf("%d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
