// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause
//
// The conformance runner of the C++ client (clients/cpp, tsm/tsm.hpp).
//
// It reads one case per line on standard input,
//   {"case": name, "runtimeDir": dir, "action": {...}}
// runs its action with the C++ library against the service in runtimeDir,
// and writes one canonical result line per case on standard output,
//   {"case": name, "result": {...}}
// (keys sorted, compact). conformance/README.md defines the actions and the
// result shapes every runner writes. concurrent actions run on threads,
// overlapping on the client's one connection. The JSON in and out is the C
// library's (its internal header).
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "tsm/tsm.hpp"

extern "C" {
#include "internal.h"
}

namespace {

using Json = tsm_json *;

Json obj() { return tsm_json_object(); }

void set(Json o, const char *key, Json value) {
    if (!tsm_json_set(o, key, value)) {
        std::fprintf(stderr, "runner: out of memory\n");
        std::exit(2);
    }
}

Json str(const std::string &s) { return tsm_json_strn(s.data(), s.size()); }

std::string get_str(const tsm_json *m, const char *key) {
    const char *s = tsm_json_get_str(m, key);
    return s ? s : "";
}

std::optional<std::string> opt_str(const tsm_json *m, const char *key) {
    const char *s = tsm_json_get_str(m, key);
    return s ? std::optional<std::string>(s) : std::nullopt;
}

bool flag(const tsm_json *m, const char *key) {
    const tsm_json *v = tsm_json_get(m, key);
    return v && v->type == TSM_J_BOOL && v->boolean;
}

Json error_shape(const tsm::Error &e) {
    Json out = obj();
    set(out, "kind", tsm_json_str(tsm::to_string(e.kind())));
    if (e.reason()) set(out, "reason", str(*e.reason()));
    return out;
}

Json error_result(const tsm::Error &e) {
    Json r = obj();
    set(r, "error", error_shape(e));
    return r;
}

std::string base64(const unsigned char *data, size_t n) {
    static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = static_cast<unsigned>(data[i]) << 16 | (i + 1 < n ? static_cast<unsigned>(data[i + 1]) << 8 : 0u) |
                     (i + 2 < n ? data[i + 2] : 0u);
        out += a[(v >> 18) & 63];
        out += a[(v >> 12) & 63];
        out += i + 1 < n ? a[(v >> 6) & 63] : '=';
        out += i + 2 < n ? a[v & 63] : '=';
    }
    return out;
}

long long ms(std::chrono::system_clock::time_point t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count();
}

Json value_shape(const tsm::Value &v) {
    Json out = obj(), entry = obj(), version = obj(), bound = obj();
    auto e = v.entry();
    auto ver = v.version();
    std::ostringstream printed;
    printed << v;
    auto text = v.text();
    set(out, "encoding", str(v.encoding()));
    set(out, "base64", str(base64(v.data(), v.size())));
    set(entry, "store", str(e.store));
    set(entry, "uuid", str(e.uuid));
    set(entry, "source", str(e.source));
    set(entry, "fetchedAtMs", tsm_json_int(ms(e.fetched_at)));
    set(out, "entry", entry);
    for (const auto &kv : v.bound()) set(bound, kv.first.c_str(), str(kv.second));
    set(out, "bound", bound);
    set(version, "modifiedMs", tsm_json_int(ms(ver.modified)));
    set(version, "revision", str(ver.revision));
    set(out, "version", version);
    // The printable form shows *** and never the value; a value that occurs
    // in the reference cannot be told apart.
    bool masked = printed.str().find("***") != std::string::npos &&
                  (!text || v.reference().find(*text) != std::string::npos || printed.str().find(*text) == std::string::npos);
    set(out, "masked", tsm_json_bool(masked));
    if (text) {
        set(out, "text", tsm_json_strn(text->data(), text->size()));
    } else {
        set(out, "textRefused", tsm_json_bool(1));
    }
    if (auto x = v.expires()) set(out, "expiresMs", tsm_json_int(ms(*x)));
    if (auto t = v.client_token()) set(out, "clientToken", str(*t));
    return out;
}

std::map<std::string, std::string> dimensions_of(const tsm_json *d) {
    std::map<std::string, std::string> out;
    if (d && d->type == TSM_J_OBJECT) {
        for (size_t i = 0; i < d->count; i++) out.emplace(d->keys[i], d->items[i]->string);
    }
    return out;
}

struct ProgressLog {
    std::mutex mu;
    Json entries = tsm_json_array();
    tsm::ProgressCallback callback() {
        return [this](const tsm::Progress &p) {
            Json entry = obj();
            set(entry, "pending", str(p.pending));
            if (p.approval_code) set(entry, "approvalCode", str(*p.approval_code));
            std::lock_guard<std::mutex> lock(mu);
            tsm_json_push(entries, entry);
        };
    }
    Json add_to(Json result) {
        if (entries->count) {
            set(result, "progress", entries);
        } else {
            tsm_json_free(entries);
        }
        entries = nullptr;
        return result;
    }
};

Json shape(const tsm::Reference &r) {
    Json out = obj(), target = obj(), qualifiers = tsm_json_array();
    switch (r.kind) {
    case tsm::TargetKind::Key:
        set(target, "kind", tsm_json_str("key"));
        set(target, "key", str(r.key));
        break;
    case tsm::TargetKind::Uuid:
        set(target, "kind", tsm_json_str("uuid"));
        set(target, "store", str(r.store));
        set(target, "uuid", str(r.uuid));
        break;
    case tsm::TargetKind::Path: {
        Json segments = tsm_json_array();
        set(target, "kind", tsm_json_str("path"));
        set(target, "store", str(r.store));
        for (const auto &s : r.segments) tsm_json_push(segments, str(s));
        set(target, "segments", segments);
    }
    }
    for (const auto &q : r.qualifiers) {
        Json b = obj();
        set(b, "dimension", str(q.dimension));
        set(b, "value", str(q.value));
        tsm_json_push(qualifiers, b);
    }
    set(out, "qualifiers", qualifiers);
    set(out, "target", target);
    set(out, "field", str(r.field));
    set(out, "fieldGiven", tsm_json_bool(r.field_given));
    return out;
}

tsm::Reference from_shape(const tsm_json *m) {
    const tsm_json *t = tsm_json_get(m, "target");
    tsm::Reference r;
    std::string kind = get_str(t, "kind");
    if (kind == "key") {
        r.kind = tsm::TargetKind::Key;
        r.key = get_str(t, "key");
    } else if (kind == "uuid") {
        r.kind = tsm::TargetKind::Uuid;
        r.store = get_str(t, "store");
        r.uuid = get_str(t, "uuid");
    } else {
        r.kind = tsm::TargetKind::Path;
        r.store = get_str(t, "store");
        const tsm_json *segments = tsm_json_get(t, "segments");
        for (size_t i = 0; i < segments->count; i++) r.segments.emplace_back(segments->items[i]->string);
    }
    const tsm_json *q = tsm_json_get(m, "qualifiers");
    for (size_t i = 0; i < q->count; i++) r.qualifiers.push_back({get_str(q->items[i], "dimension"), get_str(q->items[i], "value")});
    if (auto f = opt_str(m, "field")) r.field = *f;
    return r;
}

Json run(tsm::Client &c, const tsm_json *action) {
    std::string op = get_str(action, "do");
    std::string ref = get_str(action, "ref");
    const tsm_json *wait = tsm_json_get(action, "wait");
    bool no_wait = wait && wait->type == TSM_J_BOOL && !wait->boolean;
    std::optional<std::chrono::milliseconds> timeout;
    long long t = 0;
    if (tsm_json_get_int(action, "timeoutMs", &t)) timeout = std::chrono::milliseconds(t);
    try {
        if (op == "parse") {
            tsm::Reference r = tsm::Reference::parse(ref);
            Json out = obj();
            set(out, "parsed", shape(r));
            set(out, "canonical", str(r.canonical()));
            return out;
        }
        if (op == "format") {
            Json out = obj();
            set(out, "formatted", str(from_shape(tsm_json_get(action, "parsed")).format()));
            return out;
        }
        if (op == "connect") {
            c.open();
            auto w = c.welcome();
            Json welcome = obj(), features = tsm_json_array();
            for (const auto &f : w->features) tsm_json_push(features, str(f));
            set(welcome, "host", str(w->host));
            set(welcome, "platform", str(w->platform));
            set(welcome, "features", features);
            Json out = obj();
            set(out, "welcome", welcome);
            return out;
        }
        if (op == "get") {
            ProgressLog log;
            tsm::GetOptions o;
            o.field = opt_str(action, "field");
            o.dimensions = dimensions_of(tsm_json_get(action, "dimensions"));
            o.no_wait = no_wait;
            o.timeout = timeout;
            o.on_progress = log.callback();
            o.want_client_token = flag(action, "wantClientToken");
            o.wait_on_rate_limit = flag(action, "waitOnRateLimit");
            Json result;
            try {
                tsm::Value v = c.get(ref, o);
                result = obj();
                set(result, "value", value_shape(v));
            } catch (const tsm::Error &e) {
                result = error_result(e);
            }
            return log.add_to(result);
        }
        if (op == "getMany") {
            ProgressLog log;
            const tsm_json *refs = tsm_json_get(action, "refs");
            std::vector<tsm::Request> requests;
            for (size_t i = 0; i < refs->count; i++) {
                requests.push_back({get_str(refs->items[i], "ref"), opt_str(refs->items[i], "field"),
                                    dimensions_of(tsm_json_get(refs->items[i], "dimensions"))});
            }
            tsm::RequestOptions o;
            o.no_wait = no_wait;
            o.timeout = timeout;
            o.on_progress = log.callback();
            Json result;
            try {
                Json list = tsm_json_array();
                for (const auto &r : c.get_many(requests, o)) {
                    Json item = obj();
                    if (r.value) {
                        set(item, "value", value_shape(*r.value));
                    } else {
                        set(item, "error", error_shape(*r.error));
                    }
                    tsm_json_push(list, item);
                }
                result = obj();
                set(result, "results", list);
            } catch (const tsm::Error &e) {
                result = error_result(e);
            }
            return log.add_to(result);
        }
        if (op == "getFile") {
            tsm::GetOptions o;
            o.field = opt_str(action, "field");
            tsm::File f = c.get_file(ref, o);
            Json file = obj();
            set(file, "name", str(f.name()));
            set(file, "size", tsm_json_int(static_cast<long long>(f.size())));
            set(file, "base64", str(base64(f.data(), f.size())));
            Json out = obj();
            set(out, "file", file);
            return out;
        }
        if (op == "concurrent") {
            const tsm_json *actions = tsm_json_get(action, "actions");
            std::vector<Json> results(actions->count, nullptr);
            std::vector<std::thread> threads;
            for (size_t i = 0; i < actions->count; i++) {
                threads.emplace_back([&c, &results, actions, i] { results[i] = run(c, actions->items[i]); });
            }
            for (auto &th : threads) th.join();
            Json list = tsm_json_array();
            for (Json r : results) tsm_json_push(list, r);
            Json out = obj();
            set(out, "results", list);
            return out;
        }
        if (op == "sequence") {
            const tsm_json *actions = tsm_json_get(action, "actions");
            Json steps = tsm_json_array();
            for (size_t i = 0; i < actions->count; i++) {
                const tsm_json *step = actions->items[i];
                if (get_str(step, "do") == "pause") {
                    long long pause = 0;
                    tsm_json_get_int(step, "ms", &pause);
                    std::this_thread::sleep_for(std::chrono::milliseconds(pause));
                    continue;
                }
                tsm_json_push(steps, run(c, step));
            }
            Json out = obj();
            set(out, "steps", steps);
            return out;
        }
    } catch (const tsm::Error &e) {
        return error_result(e);
    }
    Json out = obj();
    set(out, "unsupportedAction", str(op));
    return out;
}

}  // namespace

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.find_first_not_of(" \t\r") == std::string::npos) continue;
        char why[256];
        Json request = tsm_json_parse(line.data(), line.size(), why, sizeof why);
        if (!request) {
            std::fprintf(stderr, "runner: bad case line: %s\n", why);
            return 2;
        }
        const tsm_json *action = tsm_json_get(request, "action");
        const tsm_json *client = tsm_json_get(action, "client");
        tsm::ClientOptions options;
        options.client_name = "conformance-runner";
        options.runtime_dir = get_str(request, "runtimeDir");
        options.connect_timeout = std::chrono::milliseconds(5000);
        if (client) options.client_token = opt_str(client, "clientToken");
        Json answer = obj();
        set(answer, "case", tsm_json_clone(tsm_json_get(request, "case")));
        {
            tsm::Client c(options);
            set(answer, "result", run(c, action));
        }
        char *text = tsm_json_write(answer, nullptr);
        std::printf("%s\n", text);
        std::fflush(stdout);
        std::free(text);
        tsm_json_free(answer);
        tsm_json_free(request);
    }
    return 0;
}
