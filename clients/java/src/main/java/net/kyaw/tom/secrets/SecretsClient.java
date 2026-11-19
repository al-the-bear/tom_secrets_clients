// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

/**
 * A client of the Tom Secrets Manager's secrets service (protocol.md section
 * 5):
 *
 * <pre>{@code
 * try (var c = SecretsClient.connect()) {
 *     try (var v = c.get("[env:prod]db.main", GetOptions.builder().field("UserName").build())) {
 *         connect(v.text());
 *     }
 * }
 * }</pre>
 *
 * <p>One connection, opened by the first call (or {@link #open}); after
 * {@code NOT_RUNNING} or a dropped connection the next call connects again.
 * It is thread-safe: calls from several threads overlap on the one
 * connection. The library logs nothing: no value, token or payload.
 */
public final class SecretsClient implements AutoCloseable {
    /** The protocol version this library speaks. */
    public static final int PROTOCOL_VERSION = 1;
    /** The most references one {@code getMany} carries. */
    public static final int MAX_GET_MANY = 256;
    /** This library's version, sent in {@code hello}. */
    public static final String CLIENT_VERSION = "0.1.0";
    /** The optional features (section 8) this library takes: binary frames and {@code getFile}. */
    public static final List<String> CLIENT_FEATURES = List.of("binary", "getFile");

    private final String clientName;
    private final String clientToken;
    private final Map<String, String> environment;
    private final String operatingSystem;
    private final Duration connectTimeout;
    private final Object connecting = new Object();
    private volatile Connection connection;

    /** A client with {@code options} that connects on its first call. */
    public SecretsClient(ClientOptions options) {
        clientName = options.clientName != null ? options.clientName : defaultName();
        clientToken = options.clientToken;
        environment = options.environment != null ? options.environment : System.getenv();
        operatingSystem = options.operatingSystem != null ? options.operatingSystem : Discovery.currentOperatingSystem();
        connectTimeout = options.connectTimeout != null ? options.connectTimeout : Duration.ofSeconds(10);
    }

    /** A client with the defaults, connected at once, so a missing service shows right away. */
    public static SecretsClient connect() throws SecretsException {
        return connect(ClientOptions.defaults());
    }

    /** A client with {@code options}, connected at once. */
    public static SecretsClient connect(ClientOptions options) throws SecretsException {
        SecretsClient client = new SecretsClient(options);
        client.open();
        return client;
    }

    private static String defaultName() {
        String command = System.getProperty("sun.java.command", "");
        String main = command.split(" ", 2)[0];
        if (main.isEmpty()) {
            return "java";
        }
        if (main.endsWith(".jar")) {
            String file = Path.of(main).getFileName().toString();
            return file.substring(0, file.length() - 4);
        }
        return main.substring(main.lastIndexOf('.') + 1);
    }

    /** The name {@code hello} gives the program. */
    public String clientName() {
        return clientName;
    }

    /** The service's {@code welcome} on the current connection, or null. */
    public Welcome welcome() {
        Connection c = connection;
        return c == null || c.isClosed() ? null : c.welcome;
    }

    /** Connects, unless a connection is open. */
    public void open() throws SecretsException {
        ensure();
    }

    /** Closes the connection; a later call connects again. */
    @Override
    public void close() {
        Connection c;
        synchronized (connecting) {
            c = connection;
            connection = null;
        }
        if (c != null) {
            c.fail(SecretsException.notRunning("the client closed the connection"));
        }
    }

    /** Reads one secret with the default options. */
    public SecretValue get(String ref) throws SecretsException {
        return get(ref, GetOptions.defaults());
    }

    /**
     * Reads one secret. The reference is parsed locally first: a malformed
     * one fails as {@code MALFORMED} without a round trip, and so does a
     * request over 64 KiB (reason {@code frame}).
     */
    public SecretValue get(String ref, GetOptions options) throws SecretsException {
        Map<String, Object> request = requestItem(ref, options.field, options.dimensions);
        request.put("op", "get");
        addWaiting(request, options.waiting);
        if (options.wantClientToken) {
            request.put("wantClientToken", true);
        }
        Answer answer = request(request, options.waiting);
        if (!"value".equals(answer.message.get("op"))) {
            throw SecretsException.protocol("get was answered " + answer.message.get("op"));
        }
        return SecretValue.fromMessage(ref, answer.message);
    }

    /**
     * Reads 1 to {@link #MAX_GET_MANY} secrets under one approval prompt; the
     * results come in request order, each a value or an error. Every
     * reference is parsed locally first.
     *
     * @throws IllegalArgumentException for no or more than 256 references
     */
    public List<SecretResult> getMany(List<SecretRequest> requests, RequestOptions options) throws SecretsException {
        if (requests.isEmpty() || requests.size() > MAX_GET_MANY) {
            throw new IllegalArgumentException(
                    "a getMany carries 1 to " + MAX_GET_MANY + " references, not " + requests.size());
        }
        List<Object> items = new ArrayList<>();
        for (SecretRequest r : requests) {
            items.add(requestItem(r.ref(), r.field(), r.dimensions()));
        }
        Map<String, Object> request = new TreeMap<>();
        request.put("op", "getMany");
        request.put("refs", items);
        addWaiting(request, options);
        Answer answer = request(request, options);
        Object results = answer.message.get("results");
        if (!"values".equals(answer.message.get("op")) || !(results instanceof List)) {
            throw SecretsException.protocol("getMany was answered " + answer.message.get("op"));
        }
        List<?> list = (List<?>) results;
        if (list.size() != requests.size()) {
            throw SecretsException.protocol("getMany got " + list.size() + " results");
        }
        List<SecretResult> out = new ArrayList<>();
        for (int i = 0; i < list.size(); i++) {
            if (!(list.get(i) instanceof Map)) {
                throw SecretsException.protocol("a getMany result is no object");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> result = (Map<String, Object>) list.get(i);
            if ("error".equals(result.get("op"))) {
                out.add(new SecretResult(null, SecretsException.fromMessage(result)));
            } else {
                out.add(new SecretResult(SecretValue.fromMessage(requests.get(i).ref(), result), null));
            }
        }
        return out;
    }

    /**
     * Reads an attachment or a typed key as bytes (5.5), over binary frames,
     * checked against its size and SHA-256. Fails as {@code UNSUPPORTED}
     * when the service does not offer the features {@code binary} and {@code
     * getFile} ({@code details.features} names the missing ones).
     */
    public SecretFile getFile(String ref, GetOptions options) throws SecretsException {
        Map<String, Object> request = requestItem(ref, options.field, options.dimensions);
        Connection c = ensure();
        List<Object> missing = new ArrayList<>();
        for (String f : CLIENT_FEATURES) {
            if (c.welcome == null || !c.welcome.offers(f)) {
                missing.add(f);
            }
        }
        if (!missing.isEmpty()) {
            throw new SecretsException(SecretsException.Kind.UNSUPPORTED,
                    "the service does not offer getFile (features " + String.join(", ", missing.stream().map(Object::toString).toList()) + ")",
                    Map.of("features", missing));
        }
        request.put("op", "getFile");
        addWaiting(request, options.waiting);
        Answer answer = request(request, options.waiting);
        if (!"end".equals(answer.message.get("op")) || answer.file == null) {
            throw SecretsException.protocol("getFile was answered " + answer.message.get("op"));
        }
        String name = Json.string(answer.file, "name");
        Long size = Json.whole(answer.file.get("size"));
        byte[] data = answer.data;
        if (name == null || size == null || size != data.length
                || !sha256Hex(data).equals(answer.message.get("sha256"))) {
            Arrays.fill(data, (byte) 0);
            throw SecretsException.protocol("the file does not match its size or sha256");
        }
        return new SecretFile(ref, name, data);
    }

    private static String sha256Hex(byte[] data) {
        try {
            StringBuilder hex = new StringBuilder();
            for (byte b : MessageDigest.getInstance("SHA-256").digest(data)) {
                hex.append(String.format("%02x", b & 0xFF));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("every Java platform has SHA-256", e);
        }
    }

    private static void addWaiting(Map<String, Object> request, RequestOptions options) {
        if (options.noWait) {
            request.put("wait", false);
        }
        if (options.timeout != null) {
            request.put("timeoutMs", options.timeout.toMillis());
        }
    }

    private static Map<String, Object> requestItem(String ref, String field, Map<String, String> dimensions)
            throws SecretsException {
        SecretReference parsed = SecretReference.parse(ref);
        if (field != null && parsed.fieldGiven() && !field.equals(parsed.field())) {
            throw SecretsException.malformed("field_twice", "the field is named in the reference and as field");
        }
        Map<String, Object> item = new TreeMap<>();
        item.put("ref", ref);
        if (dimensions != null && !dimensions.isEmpty()) {
            item.put("dimensions", new TreeMap<String, Object>(dimensions));
        }
        if (field != null && !parsed.fieldGiven()) {
            item.put("field", field);
        }
        return item;
    }

    private Answer request(Map<String, Object> request, RequestOptions options) throws SecretsException {
        while (true) {
            Connection c = ensure();
            Answer answer = c.send(new TreeMap<>(request), options.onProgress);
            if (!"error".equals(answer.message.get("op"))) {
                return answer;
            }
            SecretsException error = SecretsException.fromMessage(answer.message);
            if (error.kind() != SecretsException.Kind.RATE_LIMITED || !options.waitOnRateLimit) {
                throw error;
            }
            Long ms = Json.whole(error.details().get("retryAfterMs"));
            try {
                Thread.sleep(ms != null && ms > 0 ? ms : 1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw SecretsException.notRunning("interrupted while waiting out a rate limit");
            }
        }
    }

    private Connection ensure() throws SecretsException {
        Connection c = connection;
        if (c != null && !c.isClosed()) {
            return c;
        }
        synchronized (connecting) {
            c = connection;
            if (c != null && !c.isClosed()) {
                return c;
            }
            c = connectOnce();
            connection = c;
            return c;
        }
    }

    private static String read(String path) {
        try {
            return path == null ? null : Files.readString(Path.of(path), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    private Connection connectOnce() throws SecretsException {
        Discovery.Endpoints location = Discovery.discover(operatingSystem, environment, Discovery::processUid)
                .orElseThrow(() -> SecretsException.notRunning("no runtime directory can be named"));
        String token = null;
        SocketChannel channel;
        try {
            if ("windows".equals(operatingSystem)) {
                String text = read(location.clientPortFile());
                OptionalInt port = text == null ? OptionalInt.empty() : Discovery.readPortFile(text);
                if (port.isEmpty()) {
                    throw SecretsException.notRunning("no readable client.port");
                }
                String raw = read(location.clientTokenFile());
                if (raw == null) {
                    throw SecretsException.notRunning("no client.token");
                }
                token = Discovery.stripLineEnd(raw);
                channel = SocketChannel.open(new InetSocketAddress("127.0.0.1", port.getAsInt()));
            } else {
                if (!Files.exists(Path.of(location.clientSocket()))) {
                    throw SecretsException.notRunning("no client.sock in " + location.directory());
                }
                channel = SocketChannel.open(StandardProtocolFamily.UNIX);
                channel.connect(UnixDomainSocketAddress.of(location.clientSocket()));
            }
        } catch (IOException e) {
            throw SecretsException.notRunning("the connection was refused");
        }
        Connection c = new Connection(channel);
        Map<String, Object> client = new TreeMap<>();
        client.put("name", clientName);
        client.put("version", CLIENT_VERSION);
        client.put("language", "java");
        Map<String, Object> hello = new LinkedHashMap<>();
        hello.put("op", "hello");
        hello.put("protocol", (long) PROTOCOL_VERSION);
        hello.put("client", client);
        hello.put("features", new ArrayList<Object>(CLIENT_FEATURES));
        if (token != null) {
            hello.put("token", token);
        }
        if (clientToken != null) {
            hello.put("clientToken", clientToken);
        }
        try {
            c.write(hello);
        } catch (SecretsException e) {
            c.fail(dropped());
            throw e;
        }
        try {
            c.welcomed.get(connectTimeout.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
        } catch (java.util.concurrent.TimeoutException e) {
            c.fail(SecretsException.notRunning("no welcome"));
            throw SecretsException.notRunning("no welcome within " + connectTimeout.toMillis() + " ms");
        } catch (ExecutionException e) {
            throw (SecretsException) e.getCause();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            c.fail(SecretsException.notRunning("interrupted"));
            throw SecretsException.notRunning("interrupted while connecting");
        }
        return c;
    }

    static SecretsException dropped() {
        return SecretsException.notRunning("the connection to the service dropped");
    }

    /** A request's last message; for {@code getFile} also the file message and its bytes. */
    private static final class Answer {
        final Map<String, Object> message;
        final Map<String, Object> file;
        final byte[] data;

        Answer(Map<String, Object> message, Map<String, Object> file, byte[] data) {
            this.message = message;
            this.file = file;
            this.data = data;
        }
    }

    private static final class Pending {
        final CompletableFuture<Answer> future = new CompletableFuture<>();
        final Consumer<Progress> onProgress;
        Map<String, Object> file;
        java.io.ByteArrayOutputStream chunks;

        Pending(Consumer<Progress> onProgress) {
            this.onProgress = onProgress;
        }

        void wipe() {
            if (chunks != null) {
                // ByteArrayOutputStream keeps its buffer: overwrite it in place.
                byte[] zeros = new byte[chunks.size()];
                chunks.reset();
                chunks.write(zeros, 0, zeros.length);
            }
        }
    }

    /** One connection: frames in and out, the open requests by id. */
    private static final class Connection {
        private final SocketChannel channel;
        private final Object writeLock = new Object();
        private final Map<Long, Pending> pending = new HashMap<>();
        private final Frames.Reader frames = new Frames.Reader(Frames.MAX_ANSWER_PAYLOAD);
        final CompletableFuture<Void> welcomed = new CompletableFuture<>();
        volatile Welcome welcome;
        private boolean closed;
        private long nextId = 1;

        Connection(SocketChannel channel) {
            this.channel = channel;
            Thread reader = new Thread(this::read, "tsm-client");
            reader.setDaemon(true);
            reader.start();
        }

        synchronized boolean isClosed() {
            return closed;
        }

        void write(Map<String, Object> message) throws SecretsException {
            byte[] payload = Json.write(message).getBytes(StandardCharsets.UTF_8);
            if (payload.length > Frames.MAX_REQUEST_PAYLOAD) {
                throw SecretsException.malformed("frame",
                        "the request is " + payload.length + " bytes, over " + Frames.MAX_REQUEST_PAYLOAD);
            }
            ByteBuffer frame = ByteBuffer.wrap(Frames.encode(Frames.JSON, payload));
            synchronized (writeLock) {
                try {
                    while (frame.hasRemaining()) {
                        channel.write(frame);
                    }
                } catch (IOException e) {
                    throw dropped();
                }
            }
        }

        Answer send(Map<String, Object> request, Consumer<Progress> onProgress) throws SecretsException {
            Pending p = new Pending(onProgress);
            long id;
            synchronized (this) {
                if (closed) {
                    throw dropped();
                }
                id = nextId++;
                pending.put(id, p);
            }
            request.put("id", id);
            try {
                write(request);
            } catch (SecretsException e) {
                synchronized (this) {
                    pending.remove(id);
                }
                if (e.kind() == SecretsException.Kind.NOT_RUNNING) {
                    fail(dropped());
                }
                throw e;
            }
            try {
                return p.future.get();
            } catch (ExecutionException e) {
                throw (SecretsException) e.getCause();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                synchronized (this) {
                    pending.remove(id);
                }
                throw SecretsException.notRunning("interrupted while waiting for the answer");
            }
        }

        private void read() {
            ByteBuffer buffer = ByteBuffer.allocate(64 * 1024);
            while (true) {
                int n;
                try {
                    n = channel.read(buffer);
                } catch (IOException e) {
                    fail(dropped());
                    return;
                }
                if (n < 0) {
                    fail(dropped());
                    return;
                }
                List<Frames.Frame> read;
                try {
                    read = frames.add(buffer.array(), n);
                } catch (Frames.FrameException e) {
                    fail(SecretsException.protocol(e.getMessage()));
                    return;
                } finally {
                    Arrays.fill(buffer.array(), 0, Math.max(n, 0), (byte) 0);
                    buffer.clear();
                }
                for (Frames.Frame f : read) {
                    try {
                        if (f.type == Frames.BINARY) {
                            onChunk(f.payload);
                        } else {
                            onMessage(Frames.decode(f.payload));
                        }
                    } catch (Frames.FrameException e) {
                        fail(SecretsException.protocol(e.getMessage()));
                        return;
                    } catch (SecretsException e) {
                        fail(e);
                        return;
                    } finally {
                        Arrays.fill(f.payload, (byte) 0);
                    }
                    if (isClosed()) {
                        return;
                    }
                }
            }
        }

        private void onMessage(Map<String, Object> m) throws SecretsException {
            Object op = m.get("op");
            boolean hasId = m.containsKey("id");
            if (welcome == null) {
                if ("welcome".equals(op)) {
                    welcome = welcomeOf(m);
                    frames.binaryAllowed = welcome.offers("binary");
                    welcomed.complete(null);
                    return;
                }
                if ("error".equals(op) && !hasId) {
                    throw SecretsException.fromMessage(m);
                }
                throw SecretsException.protocol("the first frame is " + op + ", not welcome");
            }
            if ("error".equals(op) && !hasId) {
                throw SecretsException.fromMessage(m);
            }
            Long id = Json.whole(m.get("id"));
            if (id == null) {
                return; // an answer nobody waits for; ignored
            }
            Pending p;
            synchronized (this) {
                p = pending.get(id);
            }
            if (p == null) {
                return;
            }
            if ("progress".equals(op)) {
                if (p.onProgress != null) {
                    p.onProgress.accept(new Progress("unlock".equals(m.get("pending")) ? "unlock" : "approval",
                            Json.string(m, "approvalCode")));
                }
            } else if ("file".equals(op)) {
                synchronized (this) {
                    p.file = m;
                    p.chunks = new java.io.ByteArrayOutputStream();
                }
            } else if ("end".equals(op)) {
                Map<String, Object> file;
                byte[] data;
                synchronized (this) {
                    file = p.file;
                    if (file == null) {
                        throw SecretsException.protocol("end without file");
                    }
                    data = p.chunks.toByteArray();
                    p.wipe();
                    pending.remove(id);
                }
                p.future.complete(new Answer(m, file, data));
            } else if ("value".equals(op) || "values".equals(op) || "error".equals(op)) {
                synchronized (this) {
                    pending.remove(id);
                }
                p.future.complete(new Answer(m, null, null));
            }
            // Any other answer is one this library does not know: section 8
            // says ignore it.
        }

        private void onChunk(byte[] payload) throws SecretsException {
            if (payload.length < 8) {
                throw SecretsException.protocol("a binary chunk without id");
            }
            long id = ByteBuffer.wrap(payload, 0, 8).getLong();
            synchronized (this) {
                Pending p = pending.get(id);
                if (p == null || p.file == null) {
                    throw SecretsException.protocol("a chunk without file");
                }
                p.chunks.write(payload, 8, payload.length - 8);
            }
        }

        void fail(SecretsException error) {
            List<Pending> waiting;
            synchronized (this) {
                if (closed) {
                    return;
                }
                closed = true;
                waiting = new ArrayList<>(pending.values());
                pending.clear();
            }
            welcomed.completeExceptionally(error);
            for (Pending p : waiting) {
                p.wipe();
                p.future.completeExceptionally(error);
            }
            try {
                // Unblocks the reader thread, which then ends.
                channel.close();
            } catch (IOException e) {
                // closed already
            }
        }

        private static Welcome welcomeOf(Map<String, Object> m) throws SecretsException {
            Long protocol = Json.whole(m.get("protocol"));
            if (!(m.get("protocol") instanceof Long) || protocol != PROTOCOL_VERSION) {
                List<Object> protocols = new ArrayList<>();
                protocols.add(m.get("protocol"));
                throw new SecretsException(SecretsException.Kind.UNSUPPORTED,
                        "the service speaks protocol " + m.get("protocol"), Map.of("protocols", protocols));
            }
            Map<String, Object> service = Json.object(m, "service");
            Object version = service == null ? null : service.get("version");
            List<String> features = new ArrayList<>();
            if (m.get("features") instanceof List) {
                for (Object f : (List<?>) m.get("features")) {
                    if (f instanceof String) {
                        features.add((String) f);
                    }
                }
            }
            features.sort(null);
            String host = Json.string(m, "host");
            String platform = Json.string(m, "platform");
            return new Welcome(PROTOCOL_VERSION,
                    version instanceof String ? (String) version : version == null ? "" : Json.write(version),
                    features, host == null ? "" : host, platform == null ? "" : platform);
        }
    }
}
