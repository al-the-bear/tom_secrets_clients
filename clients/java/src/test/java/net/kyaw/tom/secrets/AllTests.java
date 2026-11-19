// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The library's tests, run without a test framework (the library has no
 * dependencies, test or other): {@code java -cp build/test-classes
 * net.kyaw.tom.secrets.AllTests} from the module's folder, after compiling
 * main and test sources together. Exits 1 when a test fails.
 *
 * <p>They check the library against every vector of protocol/vectors/ that
 * a client computes (references, discovery, port files, frames), values,
 * and the client against a small service on a Unix socket. The full
 * behaviour is the conformance suite's.
 */
public final class AllTests {
    private AllTests() {}

    interface Body {
        void run() throws Exception;
    }

    private static int failed;
    private static int passed;

    static void test(String name, Body body) {
        try {
            body.run();
            passed++;
            System.out.println("ok   " + name);
        } catch (Throwable e) {
            failed++;
            System.out.println("FAIL " + name + ": " + e);
        }
    }

    static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    static void equal(Object actual, Object expected, String what) {
        if (!Objects.equals(actual, expected)) {
            throw new AssertionError(what + ": " + actual + ", expected " + expected);
        }
    }

    interface Thrower {
        void run() throws Exception;
    }

    static <T extends Throwable> T raises(Class<T> type, Thrower body) {
        try {
            body.run();
        } catch (Throwable e) {
            if (type.isInstance(e)) {
                return type.cast(e);
            }
            throw new AssertionError("raised " + e + ", expected " + type.getSimpleName());
        }
        throw new AssertionError("nothing raised, expected " + type.getSimpleName());
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> vectors(String name) throws Exception {
        return (Map<String, Object>) Json.parse(Files.readString(Path.of("..", "..", "protocol", "vectors", name)));
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> list(Map<String, Object> m, String key) {
        return (List<Map<String, Object>>) m.get(key);
    }

    static Map<String, Object> map(Object... pairs) {
        Map<String, Object> m = new TreeMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            m.put((String) pairs[i], pairs[i + 1]);
        }
        return m;
    }

    static Map<String, Object> shape(SecretReference r) {
        SecretReference.Target t = r.target();
        Map<String, Object> target;
        switch (t.kind()) {
            case KEY:
                target = map("kind", "key", "key", t.key());
                break;
            case UUID:
                target = map("kind", "uuid", "store", t.store(), "uuid", t.uuid());
                break;
            default:
                target = map("kind", "path", "store", t.store(), "segments", new ArrayList<Object>(t.segments()));
        }
        List<Object> qualifiers = new ArrayList<>();
        for (SecretReference.Binding b : r.qualifiers()) {
            qualifiers.add(map("dimension", b.dimension(), "value", b.value()));
        }
        return map("qualifiers", qualifiers, "target", target, "field", r.field(), "fieldGiven", r.fieldGiven());
    }

    @SuppressWarnings("unchecked")
    static SecretReference referenceOf(Map<String, Object> m) {
        Map<String, Object> t = (Map<String, Object>) m.get("target");
        SecretReference.Target target;
        if ("key".equals(t.get("kind"))) {
            target = SecretReference.Target.key((String) t.get("key"));
        } else if ("uuid".equals(t.get("kind"))) {
            target = SecretReference.Target.uuid((String) t.get("store"), (String) t.get("uuid"));
        } else {
            target = SecretReference.Target.path((String) t.get("store"), (List<String>) (List<?>) t.get("segments"));
        }
        List<SecretReference.Binding> qualifiers = new ArrayList<>();
        for (Map<String, Object> q : list(m, "qualifiers")) {
            qualifiers.add(new SecretReference.Binding((String) q.get("dimension"), (String) q.get("value")));
        }
        return new SecretReference(target, qualifiers, (String) m.get("field"), false);
    }

    static byte[] hex(String text) {
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(text.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    public static void main(String[] args) throws Exception {
        vectorTests();
        valueTests();
        if (!"windows".equals(Discovery.currentOperatingSystem())) {
            clientTests();
        }
        System.out.println(passed + " passed, " + failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }

    @SuppressWarnings("unchecked")
    static void vectorTests() throws Exception {
        Map<String, Object> refs = vectors("references.json");
        test("references: the limit", () -> equal(refs.get("maxReferenceBytes"),
                (long) SecretReference.MAX_REFERENCE_BYTES, "maxReferenceBytes"));
        test("references: valid ones parse to their shape and canonical form", () -> {
            for (Map<String, Object> c : list(refs, "valid")) {
                SecretReference r = SecretReference.parse((String) c.get("input"));
                equal(shape(r), c.get("parsed"), (String) c.get("input"));
                equal(r.canonical(), c.get("canonical"), (String) c.get("input"));
                equal(SecretReference.parse(r.canonical()).canonical(), r.canonical(), "reparse");
            }
        });
        test("references: invalid ones are malformed with their reason", () -> {
            for (Map<String, Object> c : list(refs, "invalid")) {
                SecretsException e = raises(SecretsException.class, () -> SecretReference.parse((String) c.get("input")));
                equal(e.kind(), SecretsException.Kind.MALFORMED, (String) c.get("input"));
                equal(e.reason(), c.get("reason"), (String) c.get("input"));
            }
        });
        test("references: formatted and reparsed", () -> {
            for (Map<String, Object> c : list(refs, "format")) {
                String formatted = SecretReference.format(referenceOf((Map<String, Object>) c.get("parsed")));
                equal(formatted, c.get("formatted"), "formatted");
                equal(shape(SecretReference.parse(formatted)), c.get("reparsed"), formatted);
            }
        });

        Map<String, Object> discovery = vectors("discovery.json");
        test("discovery: every case", () -> {
            for (Map<String, Object> c : list(discovery, "cases")) {
                Map<String, String> env = new HashMap<>();
                ((Map<String, Object>) c.get("env")).forEach((k, v) -> env.put(k, (String) v));
                int uid = c.get("uid") instanceof Long ? ((Long) c.get("uid")).intValue() : 0;
                var found = Discovery.discover((String) c.get("os"), env, () -> uid);
                Map<String, Object> expect = (Map<String, Object>) c.get("expect");
                if (found.isEmpty()) {
                    equal(expect.get("notRunning"), "no_runtime_directory", c.toString());
                    continue;
                }
                var e = found.get();
                Map<String, Object> client = (Map<String, Object>) expect.get("client");
                Map<String, Object> admin = (Map<String, Object>) expect.get("admin");
                equal(e.directory(), expect.get("directory"), c.toString());
                equal(e.clientSocket(), client.get("socket"), c.toString());
                equal(e.clientPortFile(), client.get("portFile"), c.toString());
                equal(e.clientTokenFile(), client.get("tokenFile"), c.toString());
                equal(e.adminSocket(), admin.get("socket"), c.toString());
                equal(e.adminPortFile(), admin.get("portFile"), c.toString());
            }
        });
        test("discovery: port files", () -> {
            for (Map<String, Object> c : list(discovery, "portFiles")) {
                OptionalInt port = Discovery.readPortFile((String) c.get("text"));
                Object expected = c.get("port");
                equal(port.isPresent() ? (Object) (long) port.getAsInt() : null, expected, (String) c.get("text"));
            }
        });

        Map<String, Object> frames = vectors("frames.json");
        test("frames: the protocol", () -> equal(frames.get("protocol"), (long) SecretsClient.PROTOCOL_VERSION, "protocol"));
        test("frames: JSON frames decode to their message and write back to it", () -> {
            for (Map<String, Object> c : list(frames, "frames")) {
                if (!Long.valueOf(Frames.JSON).equals(c.get("type"))) {
                    continue;
                }
                byte[] data = hex((String) c.get("hex"));
                List<Frames.Frame> read = new Frames.Reader(Frames.MAX_ANSWER_PAYLOAD).add(data, data.length);
                equal(read.size(), 1, (String) c.get("name"));
                Map<String, Object> m = Frames.decode(read.get(0).payload);
                equal(m, c.get("json"), (String) c.get("name"));
                equal(Json.parse(Json.write(m)), c.get("json"), (String) c.get("name"));
            }
        });
        test("frames: binary frames only once negotiated", () -> {
            for (Map<String, Object> c : list(frames, "frames")) {
                if (!Long.valueOf(Frames.BINARY).equals(c.get("type"))) {
                    continue;
                }
                byte[] data = hex((String) c.get("hex"));
                raises(Frames.FrameException.class, () -> new Frames.Reader(Frames.MAX_ANSWER_PAYLOAD).add(data, data.length));
                Frames.Reader negotiated = new Frames.Reader(Frames.MAX_ANSWER_PAYLOAD);
                negotiated.binaryAllowed = true;
                byte[] payload = negotiated.add(data, data.length).get(0).payload;
                equal(ByteBuffer.wrap(payload, 0, 8).getLong(), c.get("requestId"), (String) c.get("name"));
                check(Arrays.equals(Arrays.copyOfRange(payload, 8, payload.length), hex((String) c.get("chunkHex"))),
                        (String) c.get("name"));
            }
        });
        test("frames: invalid frames", () -> {
            for (Map<String, Object> c : list(frames, "invalid")) {
                String name = (String) c.get("name");
                byte[] data = hex((String) c.get("hex"));
                int max = "to service".equals(c.get("direction")) ? Frames.MAX_REQUEST_PAYLOAD : Frames.MAX_ANSWER_PAYLOAD;
                Frames.Reader reader = new Frames.Reader(max);
                switch ((String) c.get("outcome")) {
                    case "close":
                        raises(Frames.FrameException.class, () -> reader.add(data, data.length));
                        break;
                    case "read":
                        equal(reader.add(data, data.length).size(), 0, name);
                        break;
                    default:
                        List<Frames.Frame> read = reader.add(data, data.length);
                        equal(read.size(), 1, name);
                        if (name.equals("a first frame that is not hello")) {
                            // Well-formed JSON: the order of frames is wrong,
                            // which the service checks.
                            Frames.decode(read.get(0).payload);
                        } else {
                            raises(Frames.FrameException.class, () -> Frames.decode(read.get(0).payload));
                        }
                }
            }
        });
        test("frames: split reads", () -> {
            byte[] frame = Frames.encode(Frames.JSON, "{\"op\":\"x\"}".getBytes(StandardCharsets.UTF_8));
            Frames.Reader reader = new Frames.Reader(Frames.MAX_REQUEST_PAYLOAD);
            equal(reader.add(Arrays.copyOfRange(frame, 0, 3), 3).size(), 0, "3 bytes");
            equal(reader.add(Arrays.copyOfRange(frame, 3, 8), 5).size(), 0, "8 bytes");
            byte[] rest = new byte[frame.length - 8 + frame.length];
            System.arraycopy(frame, 8, rest, 0, frame.length - 8);
            System.arraycopy(frame, 0, rest, frame.length - 8, frame.length);
            equal(reader.add(rest, rest.length).size(), 2, "two frames");
        });
        test("JSON: strict", () -> {
            for (String bad : List.of("﻿{\"op\":\"x\"}", "{\"op\":\"x\",\"op\":\"y\"}", "{\"op\":\"x\"} {}",
                    "{\"op\":\"x\",\"n\":1e999}", "{\"op\":1}", "[]", "{\"op\":\"x\",\"n\":01}", "{\"op\":\"a\u0001\"}")) {
                raises(Frames.FrameException.class, () -> Frames.decode(bad.getBytes(StandardCharsets.UTF_8)));
            }
            raises(Frames.FrameException.class, () -> Frames.decode(new byte[] {(byte) 0xff, (byte) 0xfe}));
            equal(Json.parse("\"\\ud83d\\ude00\\ud800\""), "😀�", "surrogates");
        });
    }

    static Map<String, Object> valueMessage(Object id, String value) {
        Map<String, Object> m = map("op", "value", "value", value,
                "entry", map("store", "demo", "uuid", "8f1c0f0e000040008000000000000002", "source", "file",
                        "fetchedAt", "2026-11-19T10:00:00Z"),
                "bound", map("env", "prod"),
                "version", map("modified", "2026-11-19T09:00:00.250+01:00", "revision", "r1"));
        if (id != null) {
            m.put("id", id);
        }
        return m;
    }

    @SuppressWarnings("unchecked")
    static void valueTests() {
        test("values: read from a value message", () -> {
            SecretValue v = SecretValue.fromMessage("db.main", valueMessage(null, "demo-password"));
            equal(v.text(), "demo-password", "text");
            equal(v.entry().source(), "file", "source");
            equal(v.bound().get("env"), "prod", "bound");
            equal(v.version().modified().toEpochMilli(), 1795075200250L, "modified");
            equal(v.expires(), null, "expires");
        });
        test("values: never printed", () -> {
            SecretValue v = SecretValue.fromMessage("db.main", valueMessage(null, "demo-password"));
            for (String p : List.of(v.toString(), String.valueOf(v), String.format("%s", v), "" + List.of(v))) {
                check(p.contains("***") && !p.contains("demo-password"), p);
            }
        });
        test("values: close overwrites the buffer", () -> {
            SecretValue v = SecretValue.fromMessage("db.main", valueMessage(null, "demo-password"));
            byte[] data = v.bytes();
            v.close();
            check(v.isClosed(), "closed");
            check(Arrays.equals(data, new byte[data.length]), "zeros");
            raises(IllegalStateException.class, v::text);
        });
        test("values: binary ones refuse text", () -> {
            Map<String, Object> m = valueMessage(null, "AAEC/w==");
            m.put("encoding", "base64");
            SecretValue v = SecretValue.fromMessage("x", m);
            check(Arrays.equals(v.bytes(), new byte[] {0, 1, 2, (byte) 0xff}), "bytes");
            raises(IllegalStateException.class, v::text);
        });
        test("values: an unknown source is cache; a bad message is internal", () -> {
            Map<String, Object> m = valueMessage(null, "x");
            ((Map<String, Object>) m.get("entry")).put("source", "relay");
            equal(SecretValue.fromMessage("x", m).entry().source(), "cache", "source");
            m.put("version", null);
            SecretsException e = raises(SecretsException.class, () -> SecretValue.fromMessage("x", m));
            equal(e.kind(), SecretsException.Kind.INTERNAL, "kind");
            equal(e.details().get("code"), "bad_value", "code");
        });
        test("values: times", () -> {
            equal(SecretValue.parseTime("2024-02-29t23:59:59.999999999-00:30").toEpochMilli(), 1709252999999L, "time");
            for (String bad : List.of("2026-02-29T00:00:00Z", "2026-11-19 10:00:00Z", "2026-11-19T24:00:00Z",
                    "2026-11-19T10:00:00")) {
                equal(SecretValue.parseTime(bad), null, bad);
            }
        });
        test("errors: kinds from the wire", () -> {
            equal(SecretsException.Kind.fromWire("brand_new"), SecretsException.Kind.INTERNAL, "unknown");
            equal(SecretsException.Kind.fromWire("not_running"), SecretsException.Kind.INTERNAL, "not_running");
            equal(SecretsException.Kind.fromWire("denied"), SecretsException.Kind.DENIED, "denied");
        });
    }

    /** Answers hello with welcome and get, getMany and getFile as the tests need. */
    static final class FakeService implements AutoCloseable {
        final Path dir;
        final ServerSocketChannel server;
        final List<Map<String, Object>> hellos = new ArrayList<>();
        final List<SocketChannel> peers = new ArrayList<>();
        final List<String> features;
        final AtomicInteger limited = new AtomicInteger();

        FakeService(String... features) throws IOException {
            // The system's temporary folder: a Unix socket's path is short.
            dir = Files.createTempDirectory("tsm-java-");
            this.features = List.of(features);
            server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
            server.bind(UnixDomainSocketAddress.of(dir.resolve("client.sock")));
            Thread t = new Thread(this::accept);
            t.setDaemon(true);
            t.start();
        }

        SecretsClient client() {
            return new SecretsClient(ClientOptions.builder()
                    .clientName("unit-test")
                    .environment(Map.of("TSM_RUNTIME_DIR", dir.toString()))
                    .build());
        }

        void accept() {
            while (true) {
                try {
                    SocketChannel peer = server.accept();
                    synchronized (peers) {
                        peers.add(peer);
                    }
                    Thread t = new Thread(() -> serve(peer));
                    t.setDaemon(true);
                    t.start();
                } catch (IOException e) {
                    return;
                }
            }
        }

        void dropAll() {
            synchronized (peers) {
                for (SocketChannel p : peers) {
                    try {
                        p.close();
                    } catch (IOException e) {
                        // closed already
                    }
                }
            }
        }

        void send(SocketChannel peer, int type, byte[] payload) {
            synchronized (peer) {
                try {
                    ByteBuffer b = ByteBuffer.wrap(Frames.encode(type, payload));
                    while (b.hasRemaining()) {
                        peer.write(b);
                    }
                } catch (IOException e) {
                    // the client went away
                }
            }
        }

        void sendJson(SocketChannel peer, Map<String, Object> m) {
            send(peer, Frames.JSON, Json.write(m).getBytes(StandardCharsets.UTF_8));
        }

        @SuppressWarnings("unchecked")
        void serve(SocketChannel peer) {
            Frames.Reader reader = new Frames.Reader(Frames.MAX_REQUEST_PAYLOAD);
            ByteBuffer buffer = ByteBuffer.allocate(65536);
            while (true) {
                int n;
                try {
                    n = peer.read(buffer);
                } catch (IOException e) {
                    return;
                }
                if (n < 0) {
                    return;
                }
                List<Frames.Frame> frames;
                try {
                    frames = reader.add(buffer.array(), n);
                } catch (Frames.FrameException e) {
                    return;
                }
                buffer.clear();
                for (Frames.Frame f : frames) {
                    Map<String, Object> m;
                    try {
                        m = Frames.decode(f.payload);
                    } catch (Frames.FrameException e) {
                        return;
                    }
                    Thread t = new Thread(() -> answer(peer, m));
                    t.setDaemon(true);
                    t.start();
                }
            }
        }

        @SuppressWarnings("unchecked")
        void answer(SocketChannel peer, Map<String, Object> m) {
            Object id = m.get("id");
            switch ((String) m.get("op")) {
                case "hello":
                    synchronized (hellos) {
                        hellos.add(m);
                    }
                    sendJson(peer, map("op", "welcome", "protocol", 1L, "service", map("version", "0.0.0-test"),
                            "features", new ArrayList<Object>(features), "host", "testhost", "platform", "macos"));
                    break;
                case "get": {
                    String ref = (String) m.get("ref");
                    switch (ref) {
                        case "missing.entry":
                            sendJson(peer, map("op", "error", "id", id, "kind", "not_found", "message", "no entry",
                                    "details", map("reason", "no_entry")));
                            break;
                        case "slow.entry":
                            sendJson(peer, map("op", "progress", "id", id, "pending", "approval", "approvalCode", "123-456"));
                            sleep(20);
                            sendJson(peer, valueMessage(id, "slow-secret"));
                            break;
                        case "limited.entry":
                            if (limited.incrementAndGet() == 1) {
                                sendJson(peer, map("op", "error", "id", id, "kind", "rate_limited", "message", "slow down",
                                        "details", map("retryAfterMs", 10L)));
                            } else {
                                sendJson(peer, valueMessage(id, "limited-secret"));
                            }
                            break;
                        case "drop.entry":
                            dropAll();
                            break;
                        default:
                            String value = "secret-of-" + ref + (m.get("field") instanceof String ? "#" + m.get("field") : "");
                            sendJson(peer, valueMessage(id, value));
                    }
                    break;
                }
                case "getMany": {
                    List<Object> results = new ArrayList<>();
                    for (Object raw : (List<Object>) m.get("refs")) {
                        String ref = (String) ((Map<String, Object>) raw).get("ref");
                        results.add(ref.equals("missing.entry")
                                ? map("op", "error", "kind", "not_found", "message", "no entry")
                                : valueMessage(null, "secret-of-" + ref));
                    }
                    sendJson(peer, map("op", "values", "id", id, "results", results));
                    break;
                }
                case "getFile": {
                    byte[] content = "-----BEGIN DEMO KEY-----\nnot a real key\n-----END DEMO KEY-----\n"
                            .getBytes(StandardCharsets.UTF_8);
                    sendJson(peer, map("op", "file", "id", id, "name", "demo.pem", "size", (long) content.length));
                    for (int start = 0; start < content.length; start += 16) {
                        int end = Math.min(start + 16, content.length);
                        ByteBuffer chunk = ByteBuffer.allocate(8 + end - start);
                        chunk.putLong((Long) id).put(content, start, end - start);
                        send(peer, Frames.BINARY, chunk.array());
                    }
                    try {
                        StringBuilder sum = new StringBuilder();
                        for (byte b : MessageDigest.getInstance("SHA-256").digest(content)) {
                            sum.append(String.format("%02x", b & 0xFF));
                        }
                        sendJson(peer, map("op", "end", "id", id, "sha256", sum.toString()));
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                    break;
                }
                default:
                    break;
            }
        }

        static void sleep(long ms) {
            try {
                Thread.sleep(ms);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        @Override
        public void close() throws IOException {
            server.close();
            dropAll();
            Files.deleteIfExists(dir.resolve("client.sock"));
            Files.deleteIfExists(dir);
        }
    }

    @SuppressWarnings("unchecked")
    static void clientTests() {
        test("client: get and hello", () -> {
            try (FakeService s = new FakeService(); SecretsClient c = s.client()) {
                try (SecretValue v = c.get("db.main", GetOptions.builder().field("UserName").build())) {
                    equal(v.text(), "secret-of-db.main#UserName", "text");
                }
                equal(c.welcome().host(), "testhost", "host");
                equal(c.welcome().serviceVersion(), "0.0.0-test", "service version");
                Map<String, Object> hello = s.hellos.get(0);
                Map<String, Object> client = (Map<String, Object>) hello.get("client");
                equal(client.get("name"), "unit-test", "name");
                equal(client.get("language"), "java", "language");
                equal(client.get("version"), SecretsClient.CLIENT_VERSION, "version");
                equal(hello.get("features"), List.of("binary", "getFile"), "features");
            }
        });
        test("client: concurrent gets share one connection", () -> {
            try (FakeService s = new FakeService(); SecretsClient c = s.client()) {
                ExecutorService pool = Executors.newFixedThreadPool(20);
                try {
                    List<Future<String>> futures = new ArrayList<>();
                    for (int i = 0; i < 20; i++) {
                        String ref = "k" + i + ".entry";
                        futures.add(pool.submit(() -> {
                            try (SecretValue v = c.get(ref)) {
                                return v.text();
                            }
                        }));
                    }
                    for (int i = 0; i < 20; i++) {
                        equal(futures.get(i).get(), "secret-of-k" + i + ".entry", "value " + i);
                    }
                } finally {
                    pool.shutdownNow();
                }
                equal(s.hellos.size(), 1, "connections");
            }
        });
        test("client: progress and a rate limit", () -> {
            try (FakeService s = new FakeService(); SecretsClient c = s.client()) {
                List<Progress> seen = new ArrayList<>();
                try (SecretValue v = c.get("slow.entry", GetOptions.builder().onProgress(seen::add).build())) {
                    equal(v.text(), "slow-secret", "text");
                }
                equal(seen, List.of(new Progress("approval", "123-456")), "progress");
                SecretsException e = raises(SecretsException.class, () -> c.get("limited.entry"));
                equal(e.kind(), SecretsException.Kind.RATE_LIMITED, "kind");
                try (SecretValue v = c.get("limited.entry", GetOptions.builder().waitOnRateLimit().build())) {
                    equal(v.text(), "limited-secret", "text");
                }
            }
        });
        test("client: errors", () -> {
            try (FakeService s = new FakeService(); SecretsClient c = s.client()) {
                SecretsException e = raises(SecretsException.class, () -> c.get("missing.entry"));
                equal(e.kind(), SecretsException.Kind.NOT_FOUND, "kind");
                equal(e.reason(), "no_entry", "reason");
                equal(raises(SecretsException.class, () -> c.get("Bad Key")).kind(), SecretsException.Kind.MALFORMED, "local");
                equal(raises(SecretsException.class,
                        () -> c.get("fleet/Db/Main#UserName", GetOptions.builder().field("Password").build())).reason(),
                        "field_twice", "field twice");
                equal(raises(SecretsException.class,
                        () -> c.get("db.main", GetOptions.builder().dimension("env", "x".repeat(Frames.MAX_REQUEST_PAYLOAD)).build()))
                        .reason(), "frame", "frame");
            }
        });
        test("client: getMany", () -> {
            try (FakeService s = new FakeService(); SecretsClient c = s.client()) {
                List<SecretResult> results = c.getMany(
                        List.of(SecretRequest.of("a.entry"), SecretRequest.of("missing.entry")), RequestOptions.defaults());
                equal(results.get(0).value().text(), "secret-of-a.entry", "value");
                equal(results.get(1).error().kind(), SecretsException.Kind.NOT_FOUND, "error");
                raises(IllegalArgumentException.class, () -> c.getMany(List.of(), RequestOptions.defaults()));
            }
        });
        test("client: getFile", () -> {
            try (FakeService s = new FakeService("binary", "getFile"); SecretsClient c = s.client()) {
                try (SecretFile f = c.getFile("fleet/Ssh/Deploy#demo.pem", GetOptions.defaults())) {
                    equal(f.name(), "demo.pem", "name");
                    check(new String(f.bytes(), StandardCharsets.UTF_8).contains("not a real key"), "bytes");
                    check(!f.toString().contains("real key"), "masked");
                }
            }
            try (FakeService s = new FakeService(); SecretsClient c = s.client()) {
                SecretsException e = raises(SecretsException.class,
                        () -> c.getFile("fleet/Ssh/Deploy#demo.pem", GetOptions.defaults()));
                equal(e.kind(), SecretsException.Kind.UNSUPPORTED, "kind");
                equal(e.details().get("features"), List.of("binary", "getFile"), "features");
            }
        });
        test("client: a dropped connection, then a new one", () -> {
            try (FakeService s = new FakeService(); SecretsClient c = s.client()) {
                equal(raises(SecretsException.class, () -> c.get("drop.entry")).kind(),
                        SecretsException.Kind.NOT_RUNNING, "dropped");
                c.get("again.entry").close();
                equal(s.hellos.size(), 2, "hellos");
            }
        });
        test("client: not running", () -> {
            Path empty = Files.createTempDirectory("tsm-java-empty-");
            try {
                SecretsException e = raises(SecretsException.class, () -> SecretsClient.connect(ClientOptions.builder()
                        .environment(Map.of("TSM_RUNTIME_DIR", empty.toString())).operatingSystem("linux").build()));
                equal(e.kind(), SecretsException.Kind.NOT_RUNNING, "kind");
                SecretsClient windows = new SecretsClient(ClientOptions.builder()
                        .environment(Map.of()).operatingSystem("windows").build());
                equal(raises(SecretsException.class, windows::open).kind(), SecretsException.Kind.NOT_RUNNING, "windows");
            } finally {
                Files.deleteIfExists(empty);
            }
        });
    }
}
