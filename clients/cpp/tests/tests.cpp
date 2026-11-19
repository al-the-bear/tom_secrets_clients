// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause
//
// The C++ client's tests (ctest; run from the module's folder): the
// reference vectors through tsm::Reference, the error mapping, and the
// client against a small service on a Unix socket (not on Windows): values,
// get_many, get_file, progress, rate limits, errors as exceptions, RAII and
// moves. The protocol itself is the C library's tests' and the conformance
// suite's.
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "tsm/tsm.hpp"

extern "C" {
#include "internal.h"
}

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

static int failures;
static int checks;

#define CHECK(cond, what)                                                       \
    do {                                                                        \
        checks++;                                                               \
        if (!(cond)) {                                                          \
            failures++;                                                         \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, std::string(what).c_str()); \
        }                                                                       \
    } while (0)

template <typename F>
static std::optional<tsm::Error> raises(F &&f) {
    try {
        f();
    } catch (const tsm::Error &e) {
        return e;
    }
    return std::nullopt;
}

static tsm_json *vectors(const char *name) {
    std::string path = std::string("../../protocol/vectors/") + name;
    size_t len = 0;
    char why[128];
    char *text = tsm_read_file(path.c_str(), &len);
    if (!text) {
        std::printf("FAIL cannot read %s (run from clients/cpp)\n", path.c_str());
        std::exit(1);
    }
    tsm_json *j = tsm_json_parse(text, len, why, sizeof why);
    std::free(text);
    if (!j) {
        std::printf("FAIL %s: %s\n", name, why);
        std::exit(1);
    }
    return j;
}

static std::string str(const tsm_json *m, const char *key) {
    const char *s = tsm_json_get_str(m, key);
    return s ? s : "";
}

static tsm::Reference from_shape(const tsm_json *m) {
    const tsm_json *t = tsm_json_get(m, "target");
    tsm::Reference r;
    std::string kind = str(t, "kind");
    if (kind == "key") {
        r.kind = tsm::TargetKind::Key;
        r.key = str(t, "key");
    } else if (kind == "uuid") {
        r.kind = tsm::TargetKind::Uuid;
        r.store = str(t, "store");
        r.uuid = str(t, "uuid");
    } else {
        r.kind = tsm::TargetKind::Path;
        r.store = str(t, "store");
        const tsm_json *segments = tsm_json_get(t, "segments");
        for (size_t i = 0; i < segments->count; i++) r.segments.emplace_back(segments->items[i]->string);
    }
    const tsm_json *q = tsm_json_get(m, "qualifiers");
    for (size_t i = 0; i < q->count; i++) r.qualifiers.push_back({str(q->items[i], "dimension"), str(q->items[i], "value")});
    if (tsm_json_get_str(m, "field")) r.field = str(m, "field");
    return r;
}

static bool same_shape(const tsm::Reference &r, const tsm_json *shape) {
    tsm::Reference want = from_shape(shape);
    bool ok = r.kind == want.kind && r.field == want.field && r.qualifiers.size() == want.qualifiers.size();
    const tsm_json *given = tsm_json_get(shape, "fieldGiven");
    ok = ok && given && (given->boolean != 0) == r.field_given;
    if (r.kind == tsm::TargetKind::Key) ok = ok && r.key == want.key;
    if (r.kind == tsm::TargetKind::Uuid) ok = ok && r.store == want.store && r.uuid == want.uuid;
    if (r.kind == tsm::TargetKind::Path) ok = ok && r.store == want.store && r.segments == want.segments;
    for (size_t i = 0; ok && i < r.qualifiers.size(); i++) {
        ok = r.qualifiers[i].dimension == want.qualifiers[i].dimension && r.qualifiers[i].value == want.qualifiers[i].value;
    }
    return ok;
}

static void test_references() {
    tsm_json *v = vectors("references.json");
    const tsm_json *valid = tsm_json_get(v, "valid");
    for (size_t i = 0; i < valid->count; i++) {
        std::string input = str(valid->items[i], "input");
        try {
            tsm::Reference r = tsm::Reference::parse(input);
            CHECK(same_shape(r, tsm_json_get(valid->items[i], "parsed")), "parsed " + input);
            CHECK(r.format() == str(valid->items[i], "canonical"), "canonical " + input);
        } catch (const tsm::Error &e) {
            CHECK(false, "valid " + input + ": " + e.what());
        }
    }
    const tsm_json *invalid = tsm_json_get(v, "invalid");
    for (size_t i = 0; i < invalid->count; i++) {
        std::string input = str(invalid->items[i], "input");
        auto e = raises([&] { tsm::Reference::parse(input); });
        CHECK(e && e->kind() == tsm::ErrorKind::Malformed && e->reason() == str(invalid->items[i], "reason"),
              "invalid " + input);
    }
    const tsm_json *format = tsm_json_get(v, "format");
    for (size_t i = 0; i < format->count; i++) {
        tsm::Reference r = from_shape(tsm_json_get(format->items[i], "parsed"));
        CHECK(r.format() == str(format->items[i], "formatted"), "format " + r.canonical());
        CHECK(same_shape(tsm::Reference::parse(r.format()), tsm_json_get(format->items[i], "reparsed")),
              "reparsed " + r.canonical());
    }
    tsm::Reference twice = tsm::Reference::parse("[env:prod]db.main");
    twice.qualifiers.push_back({"env", "dev"});
    auto e = raises([&] { (void)twice.format(); });
    CHECK(e && e->kind() == tsm::ErrorKind::InvalidArgument, "a dimension bound twice");
    CHECK(twice.canonical().empty(), "no canonical form");
    tsm_json_free(v);
}

static void test_errors() {
    CHECK(std::string(tsm::to_string(tsm::ErrorKind::NotFound)) == "not_found", "kind names");
    tsm::Client c(tsm::ClientOptions{std::nullopt, std::nullopt, std::string("/nonexistent/tsm-cpp"), std::string("linux")});
    auto e = raises([&] { (void)c.get("db.main"); });
    CHECK(e && e->kind() == tsm::ErrorKind::NotRunning, "not running");
    auto m = raises([&] { (void)c.get("Bad Key"); });
    CHECK(m && m->kind() == tsm::ErrorKind::Malformed && m->reason() == std::string("bad_key"), "malformed locally");
    auto none = raises([&] { (void)c.get_many({}); });
    CHECK(none && none->kind() == tsm::ErrorKind::InvalidArgument, "get_many of none");
    CHECK(!c.welcome(), "no welcome without a connection");
    auto conn = raises([] { (void)tsm::Client::connect({std::nullopt, std::nullopt, std::string("/nonexistent/x"), std::string("linux")}); });
    CHECK(conn && conn->kind() == tsm::ErrorKind::NotRunning, "connect");
}

#ifndef _WIN32
// ---- a service in the test ----------------------------------------------

struct Service {
    std::string dir;
    std::string path;
    int listener = -1;
    std::string features;
    std::mutex mu;
    int hellos = 0;
    std::string language;
    std::atomic<int> limited{0};
    std::vector<int> peers;
    std::vector<std::thread> threads;

    explicit Service(std::string feature_list) : features(std::move(feature_list)) {
        static int counter;
        const char *tmp = std::getenv("TMPDIR");
        dir = std::string(tmp && *tmp ? tmp : "/tmp") + "/tsm-cpp-test-" + std::to_string(getpid()) + "-" +
              std::to_string(++counter);
        path = dir + "/client.sock";
        mkdir(dir.c_str(), 0700);
        listener = socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un a{};
        a.sun_family = AF_UNIX;
        if (path.size() >= sizeof a.sun_path) {
            std::printf("FAIL socket path too long\n");
            std::exit(1);
        }
        std::memcpy(a.sun_path, path.c_str(), path.size() + 1);
        if (bind(listener, reinterpret_cast<sockaddr *>(&a), sizeof a) != 0 || listen(listener, 16) != 0) {
            std::printf("FAIL bind %s\n", path.c_str());
            std::exit(1);
        }
        threads.emplace_back([this] { accept_loop(); });
    }

    ~Service() {
        shutdown(listener, SHUT_RDWR);
        close(listener);
        drop_all();
        for (auto &t : threads) t.join();
        unlink(path.c_str());
        rmdir(dir.c_str());
    }

    void drop_all() {
        std::lock_guard<std::mutex> lock(mu);
        for (int p : peers) shutdown(p, SHUT_RDWR);
    }

    tsm::ClientOptions options() {
        tsm::ClientOptions o;
        o.client_name = "unit-test";
        o.runtime_dir = dir;
        o.operating_system = "linux";
        return o;
    }

    void accept_loop() {
        for (;;) {
            int fd = accept(listener, nullptr, nullptr);
            if (fd < 0) return;
            std::lock_guard<std::mutex> lock(mu);
            peers.push_back(fd);
            threads.emplace_back([this, fd] { serve(fd); });
        }
    }

    static void send_raw(int fd, std::mutex &w, const std::string &json, int type = TSM_FRAME_JSON) {
        size_t n = 0;
        unsigned char *frame = tsm_frame_encode(type, reinterpret_cast<const unsigned char *>(json.data()), json.size(), &n);
        std::lock_guard<std::mutex> lock(w);
        tsm_socket_send_all(fd, frame, n);
        std::free(frame);
    }

    static std::string value_json(long long id, const std::string &value) {
        return "{\"op\":\"value\",\"id\":" + std::to_string(id) + ",\"value\":\"" + value +
               "\",\"entry\":{\"store\":\"demo\",\"uuid\":\"8f1c0f0e000040008000000000000002\",\"source\":\"file\","
               "\"fetchedAt\":\"2026-11-19T10:00:00Z\"},\"bound\":{\"env\":\"prod\"},\"version\":{\"modified\":"
               "\"2026-11-19T09:00:00.250+01:00\",\"revision\":\"r1\"},\"clientToken\":\"demo-token\"}";
    }

    void serve(int fd) {
        std::mutex w;
        tsm_frame_reader r{};
        r.max_payload = TSM_MAX_REQUEST_PAYLOAD;
        unsigned char buffer[65536];
        char why[256];
        for (;;) {
            long n = tsm_socket_recv(fd, buffer, sizeof buffer);
            tsm_frame *frames = nullptr;
            size_t count = 0;
            if (n <= 0 || tsm_frames_add(&r, buffer, static_cast<size_t>(n), &frames, &count, why, sizeof why) != 0) break;
            for (size_t i = 0; i < count; i++) {
                tsm_json *m = tsm_payload_decode(frames[i].payload, frames[i].len, why, sizeof why);
                std::string op = m ? str(m, "op") : "";
                long long id = 0;
                tsm_json_get_int(m, "id", &id);
                if (op == "hello") {
                    {
                        std::lock_guard<std::mutex> lock(mu);
                        hellos++;
                        language = str(tsm_json_get(m, "client"), "language");
                    }
                    send_raw(fd, w, "{\"op\":\"welcome\",\"protocol\":1,\"service\":{\"version\":\"0.0.0-test\"},\"features\":" +
                                        features + ",\"host\":\"testhost\",\"platform\":\"linux\"}");
                } else if (op == "get") {
                    std::string ref = str(m, "ref");
                    if (ref == "missing.entry") {
                        send_raw(fd, w, "{\"op\":\"error\",\"id\":" + std::to_string(id) +
                                            ",\"kind\":\"not_found\",\"message\":\"no entry\",\"details\":{\"reason\":\"no_entry\"}}");
                    } else if (ref == "slow.entry") {
                        send_raw(fd, w, "{\"op\":\"progress\",\"id\":" + std::to_string(id) +
                                            ",\"pending\":\"approval\",\"approvalCode\":\"123-456\"}");
                        send_raw(fd, w, value_json(id, "slow-secret"));
                    } else if (ref == "limited.entry") {
                        if (++limited == 1) {
                            send_raw(fd, w, "{\"op\":\"error\",\"id\":" + std::to_string(id) +
                                                ",\"kind\":\"rate_limited\",\"message\":\"slow down\",\"details\":{\"retryAfterMs\":10}}");
                        } else {
                            send_raw(fd, w, value_json(id, "limited-secret"));
                        }
                    } else {
                        std::string field = str(m, "field");
                        send_raw(fd, w, value_json(id, "secret-of-" + ref + (field.empty() ? "" : "#" + field)));
                    }
                } else if (op == "getMany") {
                    const tsm_json *refs = tsm_json_get(m, "refs");
                    std::string results;
                    for (size_t k = 0; k < refs->count; k++) {
                        std::string ref = str(refs->items[k], "ref");
                        if (k) results += ",";
                        results += ref == "missing.entry" ? "{\"op\":\"error\",\"kind\":\"not_found\",\"message\":\"no entry\"}"
                                                          : value_json(0, "secret-of-" + ref);
                    }
                    send_raw(fd, w, "{\"op\":\"values\",\"id\":" + std::to_string(id) + ",\"results\":[" + results + "]}");
                } else if (op == "getFile") {
                    static const std::string content = "-----BEGIN DEMO KEY-----\nnot a real key\n-----END DEMO KEY-----\n";
                    send_raw(fd, w, "{\"op\":\"file\",\"id\":" + std::to_string(id) + ",\"name\":\"demo.pem\",\"size\":" +
                                        std::to_string(content.size()) + "}");
                    std::string chunk;
                    for (int k = 0; k < 8; k++) chunk += static_cast<char>((id >> (56 - 8 * k)) & 0xff);
                    send_raw(fd, w, chunk + content, TSM_FRAME_BINARY);
                    unsigned char digest[32];
                    tsm_sha256(reinterpret_cast<const unsigned char *>(content.data()), content.size(), digest);
                    char sum[65];
                    for (int k = 0; k < 32; k++) std::snprintf(sum + 2 * k, 3, "%02x", digest[k]);
                    send_raw(fd, w, "{\"op\":\"end\",\"id\":" + std::to_string(id) + ",\"sha256\":\"" + sum + "\"}");
                }
                tsm_json_free(m);
            }
            tsm_frames_free(frames, count);
        }
        tsm_frame_reader_free(&r);
        close(fd);
    }
};

static void test_client() {
    {
        Service s("[]");
        tsm::Client c(s.options());
        tsm::GetOptions o;
        o.field = "UserName";
        tsm::Value v = c.get("db.main", o);
        CHECK(v.text() == std::string_view("secret-of-db.main#UserName"), "get");
        CHECK(v.entry().source == "file" && v.bound().at("env") == "prod" && v.version().revision == "r1", "metadata");
        CHECK(v.client_token() == std::string("demo-token") && !v.expires(), "token, no expiry");
        CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(v.version().modified.time_since_epoch()).count() ==
                  1795075200250LL,
              "modified");
        std::ostringstream printed;
        printed << v;
        CHECK(printed.str() == "SecretValue(db.main: ***)", "printed masked: " + printed.str());
        {
            std::lock_guard<std::mutex> lock(s.mu);
            CHECK(s.language == "cpp", "hello names cpp: " + s.language);
        }
        auto w = c.welcome();
        CHECK(w && w->host == "testhost" && w->service_version == "0.0.0-test", "welcome");

        tsm::Value moved = std::move(v);
        CHECK(moved.text() == std::string_view("secret-of-db.main#UserName"), "moved value");

        std::vector<std::string> seen;
        tsm::GetOptions slow;
        slow.on_progress = [&](const tsm::Progress &p) { seen.push_back(p.pending + ":" + p.approval_code.value_or("")); };
        CHECK(c.get("slow.entry", slow).text() == std::string_view("slow-secret") && seen.size() == 1 &&
                  seen[0] == "approval:123-456",
              "progress");
        tsm::GetOptions throwing;
        throwing.on_progress = [](const tsm::Progress &) { throw std::runtime_error("from the callback"); };
        CHECK(c.get("slow.entry", throwing).text() == std::string_view("slow-secret"), "a throwing callback is dropped");

        auto limited = raises([&] { (void)c.get("limited.entry"); });
        CHECK(limited && limited->kind() == tsm::ErrorKind::RateLimited &&
                  limited->retry_after() == std::chrono::milliseconds(10),
              "rate limited");
        tsm::GetOptions wait;
        wait.wait_on_rate_limit = true;
        CHECK(c.get("limited.entry", wait).text() == std::string_view("limited-secret"), "rate limit waited out");

        auto missing = raises([&] { (void)c.get("missing.entry"); });
        CHECK(missing && missing->kind() == tsm::ErrorKind::NotFound && missing->reason() == std::string("no_entry") &&
                  std::string(missing->what()) == "no entry",
              "not found");

        auto results = c.get_many({{"a.entry", std::nullopt, {}}, {"missing.entry", std::nullopt, {}}});
        CHECK(results.size() == 2 && results[0].value && results[0].value->text() == std::string_view("secret-of-a.entry") &&
                  results[1].error && results[1].error->kind() == tsm::ErrorKind::NotFound,
              "get_many");

        auto unsupported = raises([&] { (void)c.get_file("fleet/Ssh/Deploy#demo.pem"); });
        CHECK(unsupported && unsupported->kind() == tsm::ErrorKind::Unsupported, "no getFile");

        std::vector<std::thread> threads;
        std::atomic<int> ok{0};
        for (int i = 0; i < 16; i++) {
            threads.emplace_back([&c, &ok, i] {
                std::string ref = "k" + std::to_string(i) + ".entry";
                if (c.get(ref).text() == std::string_view("secret-of-" + ref)) ok++;
            });
        }
        for (auto &t : threads) t.join();
        CHECK(ok == 16, "concurrent gets");
        std::lock_guard<std::mutex> lock(s.mu);
        CHECK(s.hellos == 1, "one connection");
    }
    {
        Service s("[\"binary\",\"getFile\"]");
        tsm::Client c = tsm::Client::connect(s.options());
        tsm::File f = c.get_file("fleet/Ssh/Deploy#demo.pem");
        std::string bytes(reinterpret_cast<const char *>(f.data()), f.size());
        CHECK(f.name() == "demo.pem" && bytes.find("not a real key") != std::string::npos, "get_file");
        std::ostringstream printed;
        printed << f;
        CHECK(printed.str().find("real key") == std::string::npos, "file printed masked");
        tsm::Client other = std::move(c);
        CHECK(other.get("after.move").text() == std::string_view("secret-of-after.move"), "moved client");
    }
}
#endif

int main() {
    test_references();
    test_errors();
#ifndef _WIN32
    test_client();
#endif
    std::printf("%d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
