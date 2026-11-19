// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause
//
// The C++ client of the Tom Secrets Manager's secrets service: C++17 RAII
// over the C client (tsm/tsm.h). A program reads its secrets from the
// secrets service that runs for its user on the same machine:
//
//     auto c = tsm::Client::connect();
//     tsm::GetOptions o;
//     o.field = "UserName";
//     auto v = c.get("[env:prod]db.main", o);   // C++20: c.get(ref, {.field = "UserName"})
//     use(*v.text());
//
// Every failure is a tsm::Error (an exception) with kind(). A Value never
// prints its secret (operator<< writes "SecretValue(<ref>: ***)"), and its
// destructor overwrites its buffer. Header-only: link tsm::cpp (CMake),
// which brings the C library.
#ifndef TSM_TSM_HPP
#define TSM_TSM_HPP

#include <chrono>
#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "tsm/tsm.h"

namespace tsm {

/// The protocol version this library speaks.
inline constexpr int protocol_version = TSM_PROTOCOL_VERSION;
/// This library's version (the C library's, which it is built on).
inline constexpr const char *client_version = TSM_CLIENT_VERSION;
/// The most references one get_many carries.
inline constexpr std::size_t max_get_many = TSM_MAX_GET_MANY;
/// The field a reference without #field names.
inline constexpr const char *default_field = TSM_DEFAULT_FIELD;

/// What went wrong: the protocol's kinds (protocol.md section 10),
/// NotRunning (no service found, or the connection lost), and the library's
/// own InvalidArgument and NoMemory.
enum class ErrorKind {
    Locked = TSM_ERR_LOCKED,
    Denied = TSM_ERR_DENIED,
    NotFound = TSM_ERR_NOT_FOUND,
    Ambiguous = TSM_ERR_AMBIGUOUS,
    NeedsUnlock = TSM_ERR_NEEDS_UNLOCK,
    Unavailable = TSM_ERR_UNAVAILABLE,
    Offline = TSM_ERR_OFFLINE,
    TokenExpired = TSM_ERR_TOKEN_EXPIRED,
    Malformed = TSM_ERR_MALFORMED,
    Timeout = TSM_ERR_TIMEOUT,
    RateLimited = TSM_ERR_RATE_LIMITED,
    Unsupported = TSM_ERR_UNSUPPORTED,
    Internal = TSM_ERR_INTERNAL,
    NotRunning = TSM_ERR_NOT_RUNNING,
    InvalidArgument = TSM_ERR_INVALID_ARGUMENT,
    NoMemory = TSM_ERR_NO_MEMORY,
};

/// The protocol's name of a kind ("not_found").
inline const char *to_string(ErrorKind kind) { return tsm_error_kind_name(static_cast<tsm_error_kind>(kind)); }

/// Every failure of the library: kind(), what() (for people; never a value,
/// token or key), reason() (details.reason) and retry_after() (details.
/// retryAfterMs).
class Error : public std::runtime_error {
public:
    Error(ErrorKind kind, const std::string &message, std::optional<std::string> reason = std::nullopt,
          std::optional<std::chrono::milliseconds> retry_after = std::nullopt)
        : std::runtime_error(message), kind_(kind), reason_(std::move(reason)), retry_after_(retry_after) {}

    /// What went wrong.
    ErrorKind kind() const noexcept { return kind_; }
    /// details.reason, when there is one.
    const std::optional<std::string> &reason() const noexcept { return reason_; }
    /// details.retryAfterMs of a rate limit, when there is one.
    std::optional<std::chrono::milliseconds> retry_after() const noexcept { return retry_after_; }

private:
    ErrorKind kind_;
    std::optional<std::string> reason_;
    std::optional<std::chrono::milliseconds> retry_after_;
};

namespace detail {

/// Throws the calling thread's last error of the C library.
[[noreturn]] inline void throw_last() {
    const tsm_error *e = tsm_last_error(nullptr);
    std::optional<std::string> reason;
    if (e->reason) {
        reason = e->reason;
    }
    std::optional<std::chrono::milliseconds> retry;
    if (e->retry_after_ms >= 0) {
        retry = std::chrono::milliseconds(e->retry_after_ms);
    }
    throw Error(static_cast<ErrorKind>(e->kind), e->message ? e->message : "", std::move(reason), retry);
}

inline void check(tsm_error_kind rc) {
    if (rc != TSM_OK) {
        throw_last();
    }
}

inline std::chrono::system_clock::time_point from_ms(long long ms) {
    return std::chrono::system_clock::time_point(std::chrono::milliseconds(ms));
}

/// "dimension, value, ..., NULL" over a map, valid while the map lives.
inline std::vector<const char *> c_dimensions(const std::map<std::string, std::string> &dimensions) {
    std::vector<const char *> out;
    out.reserve(2 * dimensions.size() + 1);
    for (const auto &kv : dimensions) {
        out.push_back(kv.first.c_str());
        out.push_back(kv.second.c_str());
    }
    out.push_back(nullptr);
    return out;
}

}  // namespace detail

/// A progress notice (5.4): why a request waits, "unlock" or "approval",
/// with the one-time approval code on a host with no approver connected.
struct Progress {
    std::string pending;
    std::optional<std::string> approval_code;
};

/// Receives the progress notices of a waiting request, on the connection's
/// reader thread: it must return quickly. An exception it throws is caught
/// and dropped (it cannot cross the C library's thread).
using ProgressCallback = std::function<void(const Progress &)>;

/// The options of one get or get_file. An aggregate: C++20 code writes
/// c.get(ref, {.field = "UserName"}); C++17 code sets the members. Every
/// member has a default initializer, so leaving members out of a designated
/// initializer raises no -Wmissing-field-initializers.
struct GetOptions {
    /// The field, when the reference names none. The same field in both is
    /// sent once; two different ones are Malformed, reason field_twice.
    std::optional<std::string> field{};
    /// Values for dimensions beside the reference ({"env", "prod"}).
    std::map<std::string, std::string> dimensions{};
    /// Answer at once instead of waiting for an unlock or an approval.
    bool no_wait = false;
    /// How long the service may wait, capped by the service.
    std::optional<std::chrono::milliseconds> timeout{};
    /// Receives the progress notices while the request waits.
    ProgressCallback on_progress{};
    /// Ask for a client token with an "always" approval (get only).
    bool want_client_token = false;
    /// Wait out a rate_limited answer and send the request again.
    bool wait_on_rate_limit = false;
};

/// The options of one get_many (each Request carries its field and
/// dimensions).
struct RequestOptions {
    bool no_wait = false;
    std::optional<std::chrono::milliseconds> timeout{};
    ProgressCallback on_progress{};
    bool wait_on_rate_limit = false;
};

/// One reference of a get_many.
struct Request {
    std::string ref{};
    std::optional<std::string> field{};
    std::map<std::string, std::string> dimensions{};
};

/// How a Client finds and greets the service; every member is optional.
struct ClientOptions {
    /// Shown in approval prompts, never trusted. Default: the program's name.
    std::optional<std::string> client_name{};
    /// A client token the program was granted before, sent in hello.
    std::optional<std::string> client_token{};
    /// The runtime directory instead of the environment's.
    std::optional<std::string> runtime_dir{};
    /// "linux", "macos" or "windows". Default: this platform's.
    std::optional<std::string> operating_system{};
    /// How long connecting and the welcome may take.
    std::chrono::milliseconds connect_timeout{10000};
};

/// The entry a value was read from.
struct Entry {
    std::string store;
    std::string uuid;
    /// "github", "file" or "cache".
    std::string source;
    std::chrono::system_clock::time_point fetched_at;
};

/// The entry's version: compare it to see a change.
struct Version {
    std::chrono::system_clock::time_point modified;
    std::string revision;
};

/// A secret. Move-only; the destructor overwrites its buffer. operator<<
/// writes "SecretValue(<ref>: ***)", never the secret.
class Value {
public:
    explicit Value(tsm_value *v) noexcept : v_(v) {}
    Value(Value &&other) noexcept : v_(std::exchange(other.v_, nullptr)) {}
    Value &operator=(Value &&other) noexcept {
        if (this != &other) {
            tsm_value_free(v_);
            v_ = std::exchange(other.v_, nullptr);
        }
        return *this;
    }
    Value(const Value &) = delete;
    Value &operator=(const Value &) = delete;
    ~Value() { tsm_value_free(v_); }

    /// The value as text; nullopt for a binary value (read it with data()).
    std::optional<std::string_view> text() const {
        const char *t = tsm_value_text(v_);
        if (!t) {
            return std::nullopt;
        }
        return std::string_view(t, size());
    }
    /// The value's bytes (text as UTF-8).
    const unsigned char *data() const { return tsm_value_bytes(v_, nullptr); }
    std::size_t size() const {
        std::size_t n = 0;
        tsm_value_bytes(v_, &n);
        return n;
    }
    /// "utf8" or "base64".
    std::string encoding() const { return tsm_value_encoding(v_); }
    /// The reference the value was asked for, as given.
    std::string reference() const { return tsm_value_reference(v_); }
    Entry entry() const {
        return {tsm_value_entry_store(v_), tsm_value_entry_uuid(v_), tsm_value_entry_source(v_),
                detail::from_ms(tsm_value_entry_fetched_at_ms(v_))};
    }
    Version version() const {
        return {detail::from_ms(tsm_value_version_modified_ms(v_)), tsm_value_version_revision(v_)};
    }
    /// The bindings the winning entry carries.
    std::map<std::string, std::string> bound() const {
        std::map<std::string, std::string> out;
        for (std::size_t i = 0; i < tsm_value_bound_count(v_); i++) {
            out.emplace(tsm_value_bound_dimension(v_, i), tsm_value_bound_value(v_, i));
        }
        return out;
    }
    /// The entry's expiry, when it has one.
    std::optional<std::chrono::system_clock::time_point> expires() const {
        long long ms = 0;
        if (!tsm_value_expires_ms(v_, &ms)) {
            return std::nullopt;
        }
        return detail::from_ms(ms);
    }
    /// The client token the service granted, when one was asked for: the
    /// caller's to keep; the library never stores it.
    std::optional<std::string> client_token() const {
        const char *t = tsm_value_client_token(v_);
        return t ? std::optional<std::string>(t) : std::nullopt;
    }

    friend std::ostream &operator<<(std::ostream &os, const Value &v) {
        return os << "SecretValue(" << tsm_value_reference(v.v_) << ": ***)";
    }

private:
    tsm_value *v_;
};

/// An attachment or a typed key read with get_file. Move-only; the
/// destructor overwrites its bytes.
class File {
public:
    explicit File(tsm_file *f) noexcept : f_(f) {}
    File(File &&other) noexcept : f_(std::exchange(other.f_, nullptr)) {}
    File &operator=(File &&other) noexcept {
        if (this != &other) {
            tsm_file_free(f_);
            f_ = std::exchange(other.f_, nullptr);
        }
        return *this;
    }
    File(const File &) = delete;
    File &operator=(const File &) = delete;
    ~File() { tsm_file_free(f_); }

    std::string name() const { return tsm_file_name(f_); }
    std::string reference() const { return tsm_file_reference(f_); }
    const unsigned char *data() const { return tsm_file_bytes(f_, nullptr); }
    std::size_t size() const {
        std::size_t n = 0;
        tsm_file_bytes(f_, &n);
        return n;
    }

    friend std::ostream &operator<<(std::ostream &os, const File &f) {
        return os << "SecretFile(" << tsm_file_reference(f.f_) << ": " << tsm_file_name(f.f_) << ", " << f.size()
                  << " bytes)";
    }

private:
    tsm_file *f_;
};

/// One result of a get_many, in request order: a value or an error.
struct Result {
    std::optional<Value> value;
    std::optional<Error> error;
};

/// What the service said in welcome.
struct Welcome {
    int protocol;
    std::string service_version;
    std::string host;
    std::string platform;
    /// The optional features it offers, sorted.
    std::vector<std::string> features;
};

/// What a reference names.
enum class TargetKind { Key = TSM_TARGET_KEY, Path = TSM_TARGET_PATH, Uuid = TSM_TARGET_UUID };

/// One binding <dimension>:<value> of a reference's qualifiers.
struct Binding {
    std::string dimension;
    std::string value;
};

/// A parsed reference (protocol.md 4): parse() refuses a malformed one with
/// an Error of kind Malformed whose reason() names the rule it broke;
/// format() gives the canonical form.
struct Reference {
    TargetKind kind = TargetKind::Key;
    std::string key;
    std::string store;
    std::vector<std::string> segments;
    std::string uuid;
    std::vector<Binding> qualifiers;
    std::string field = default_field;
    bool field_given = false;

    static Reference parse(const std::string &text) {
        tsm_reference *r = nullptr;
        detail::check(tsm_reference_parse(text.c_str(), &r));
        std::unique_ptr<tsm_reference, decltype(&tsm_reference_free)> owned(r, &tsm_reference_free);
        Reference out;
        out.kind = static_cast<TargetKind>(r->kind);
        if (r->key) out.key = r->key;
        if (r->store) out.store = r->store;
        if (r->uuid) out.uuid = r->uuid;
        for (std::size_t i = 0; i < r->segment_count; i++) out.segments.emplace_back(r->segments[i]);
        for (std::size_t i = 0; i < r->qualifier_count; i++) out.qualifiers.push_back({r->dimensions[i], r->values[i]});
        out.field = r->field;
        out.field_given = r->field_given != 0;
        return out;
    }

    /// The canonical form; Error InvalidArgument for a reference that has
    /// none (a dimension bound twice, an empty segment).
    std::string format() const {
        std::vector<char *> segs, dims, vals;
        for (const auto &s : segments) segs.push_back(const_cast<char *>(s.c_str()));
        for (const auto &q : qualifiers) {
            dims.push_back(const_cast<char *>(q.dimension.c_str()));
            vals.push_back(const_cast<char *>(q.value.c_str()));
        }
        tsm_reference r{};
        r.kind = static_cast<tsm_target_kind>(kind);
        r.key = const_cast<char *>(key.c_str());
        r.store = const_cast<char *>(store.c_str());
        r.uuid = const_cast<char *>(uuid.c_str());
        r.segments = segs.data();
        r.segment_count = segs.size();
        r.dimensions = dims.data();
        r.values = vals.data();
        r.qualifier_count = qualifiers.size();
        r.field = const_cast<char *>(field.c_str());
        char *text = nullptr;
        detail::check(tsm_reference_format(&r, &text));
        std::string out(text);
        tsm_free(text);
        return out;
    }

    /// The canonical form, or "" when it has none.
    std::string canonical() const {
        try {
            return format();
        } catch (const Error &) {
            return "";
        }
    }
};

/// A client of the secrets service: one connection, opened by the first
/// call (or open()); after NotRunning or a dropped connection the next call
/// connects again. Thread-safe: calls from several threads overlap on the one
/// connection. Move-only; the destructor closes it. Logs nothing.
class Client {
public:
    /// A client that connects on its first call.
    explicit Client(const ClientOptions &options = {}) {
        tsm_client_options o = TSM_CLIENT_OPTIONS_INIT;
        o.client_name = options.client_name ? options.client_name->c_str() : nullptr;
        o.client_token = options.client_token ? options.client_token->c_str() : nullptr;
        o.runtime_dir = options.runtime_dir ? options.runtime_dir->c_str() : nullptr;
        o.operating_system = options.operating_system ? options.operating_system->c_str() : nullptr;
        o.connect_timeout_ms = static_cast<int>(options.connect_timeout.count());
        o.client_language = "cpp";
        tsm_client *c = nullptr;
        detail::check(tsm_client_new(&c, &o));
        c_ = c;
    }

    /// A client connected at once, so a missing service shows right away.
    static Client connect(const ClientOptions &options = {}) {
        Client c(options);
        c.open();
        return c;
    }

    Client(Client &&other) noexcept : c_(std::exchange(other.c_, nullptr)) {}
    Client &operator=(Client &&other) noexcept {
        if (this != &other) {
            tsm_client_free(c_);
            c_ = std::exchange(other.c_, nullptr);
        }
        return *this;
    }
    Client(const Client &) = delete;
    Client &operator=(const Client &) = delete;
    ~Client() { tsm_client_free(c_); }

    /// Connects, unless a connection is open.
    void open() { detail::check(tsm_open(c_)); }
    /// Closes the connection; a later call connects again.
    void close() { tsm_close(c_); }

    /// The welcome of the current connection, when there is one.
    std::optional<Welcome> welcome() const {
        tsm_welcome w;
        if (!tsm_welcome_get(c_, &w)) {
            return std::nullopt;
        }
        Welcome out{w.protocol, w.service_version, w.host, w.platform, {}};
        for (std::size_t i = 0; i < w.feature_count; i++) out.features.emplace_back(w.features[i]);
        return out;
    }

    /// Reads one secret. The reference is parsed locally first: a malformed
    /// one fails as Malformed without a round trip, and so does a request
    /// over 64 KiB (reason frame).
    Value get(const std::string &ref, const GetOptions &options = {}) const {
        auto dims = detail::c_dimensions(options.dimensions);
        tsm_get_options o = TSM_GET_OPTIONS_INIT;
        fill(o, options, dims);
        tsm_value *v = nullptr;
        detail::check(tsm_get(c_, ref.c_str(), &o, &v));
        return Value(v);
    }

    /// Reads 1 to max_get_many secrets under one approval prompt; the
    /// results come in request order, each a value or an error.
    std::vector<Result> get_many(const std::vector<Request> &requests, const RequestOptions &options = {}) const {
        std::vector<std::vector<const char *>> dims;
        std::vector<tsm_request> c_requests;
        dims.reserve(requests.size());
        c_requests.reserve(requests.size());
        for (const auto &r : requests) {
            dims.push_back(detail::c_dimensions(r.dimensions));
            c_requests.push_back({r.ref.c_str(), r.field ? r.field->c_str() : nullptr, dims.back().data()});
        }
        tsm_request_options o = TSM_REQUEST_OPTIONS_INIT;
        o.no_wait = options.no_wait;
        o.timeout_ms = options.timeout ? options.timeout->count() : -1;
        o.wait_on_rate_limit = options.wait_on_rate_limit;
        if (options.on_progress) {
            o.on_progress = &progress_trampoline;
            o.progress_context = const_cast<ProgressCallback *>(&options.on_progress);
        }
        tsm_result *results = nullptr;
        detail::check(tsm_get_many(c_, c_requests.data(), c_requests.size(), &o, &results));
        std::vector<Result> out;
        out.reserve(requests.size());
        for (std::size_t i = 0; i < requests.size(); i++) {
            Result r;
            if (results[i].kind == TSM_OK) {
                r.value.emplace(std::exchange(results[i].value, nullptr));
            } else {
                std::optional<std::string> reason;
                if (results[i].reason) reason = results[i].reason;
                r.error.emplace(static_cast<ErrorKind>(results[i].kind), results[i].message ? results[i].message : "",
                                std::move(reason));
            }
            out.push_back(std::move(r));
        }
        tsm_results_free(results, requests.size());
        return out;
    }

    /// Reads an attachment or a typed key as bytes, checked against its size
    /// and SHA-256; Unsupported when the service does not offer the
    /// features binary and getFile.
    File get_file(const std::string &ref, const GetOptions &options = {}) const {
        auto dims = detail::c_dimensions(options.dimensions);
        tsm_get_options o = TSM_GET_OPTIONS_INIT;
        fill(o, options, dims);
        tsm_file *f = nullptr;
        detail::check(tsm_get_file(c_, ref.c_str(), &o, &f));
        return File(f);
    }

private:
    static void progress_trampoline(const tsm_progress *p, void *context) {
        try {
            Progress progress{p->pending, std::nullopt};
            if (p->approval_code) progress.approval_code = p->approval_code;
            (*static_cast<const ProgressCallback *>(context))(progress);
        } catch (...) {
            // It cannot cross the C library's reader thread.
        }
    }

    static void fill(tsm_get_options &o, const GetOptions &options, const std::vector<const char *> &dims) {
        o.field = options.field ? options.field->c_str() : nullptr;
        o.dimensions = dims.data();
        o.no_wait = options.no_wait;
        o.timeout_ms = options.timeout ? options.timeout->count() : -1;
        o.want_client_token = options.want_client_token;
        o.wait_on_rate_limit = options.wait_on_rate_limit;
        if (options.on_progress) {
            o.on_progress = &progress_trampoline;
            o.progress_context = const_cast<ProgressCallback *>(&options.on_progress);
        }
    }

    tsm_client *c_ = nullptr;
};

}  // namespace tsm

#endif  // TSM_TSM_HPP
