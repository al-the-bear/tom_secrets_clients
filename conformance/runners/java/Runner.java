// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import net.kyaw.tom.secrets.ClientOptions;
import net.kyaw.tom.secrets.GetOptions;
import net.kyaw.tom.secrets.Json;
import net.kyaw.tom.secrets.Progress;
import net.kyaw.tom.secrets.RequestOptions;
import net.kyaw.tom.secrets.SecretReference;
import net.kyaw.tom.secrets.SecretRequest;
import net.kyaw.tom.secrets.SecretResult;
import net.kyaw.tom.secrets.SecretValue;
import net.kyaw.tom.secrets.SecretsClient;
import net.kyaw.tom.secrets.SecretsException;

/**
 * The conformance runner of the Java client (net.kyaw.tom:tom-secrets-client).
 *
 * <p>It reads one case per line on standard input, {@code {"case": name,
 * "runtimeDir": dir, "action": {...}}}, runs its action with the library
 * against the service in {@code runtimeDir}, and writes one canonical result
 * line per case on standard output, {@code {"case": name, "result": {...}}}
 * (keys sorted, compact). conformance/README.md defines the actions and the
 * result shapes every runner writes. {@code concurrent} actions run on
 * threads, overlapping on the client's one connection.
 *
 * <p>runner.json compiles it with the library's sources ({@code javac
 * --source-path ../clients/java/src/main/java}), so it uses the library as it
 * is in the repository.
 */
public final class Runner {
    private Runner() {}

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        String line;
        while ((line = in.readLine()) != null) {
            if (line.isBlank()) {
                continue;
            }
            Map<String, Object> request = (Map<String, Object>) Json.parse(line);
            Map<String, Object> result = runCase((String) request.get("runtimeDir"),
                    (Map<String, Object>) request.get("action"));
            Map<String, Object> answer = new TreeMap<>();
            answer.put("case", request.get("case"));
            answer.put("result", result);
            out.println(Json.write(answer));
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> runCase(String runtimeDir, Map<String, Object> action) throws Exception {
        Map<String, String> environment = new HashMap<>(System.getenv());
        environment.put("TSM_RUNTIME_DIR", runtimeDir);
        ClientOptions.Builder options = ClientOptions.builder()
                .clientName("conformance-runner")
                .environment(environment)
                .connectTimeout(Duration.ofSeconds(5));
        Object client = action.get("client");
        if (client instanceof Map && ((Map<String, Object>) client).get("clientToken") instanceof String) {
            options.clientToken((String) ((Map<String, Object>) client).get("clientToken"));
        }
        try (SecretsClient c = new SecretsClient(options.build())) {
            return run(c, action);
        }
    }

    static Map<String, Object> map(Object... pairs) {
        Map<String, Object> m = new TreeMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            m.put((String) pairs[i], pairs[i + 1]);
        }
        return m;
    }

    @SuppressWarnings("unchecked")
    static Map<String, String> strings(Object value) {
        Map<String, String> out = new TreeMap<>();
        if (value instanceof Map) {
            for (Map.Entry<String, Object> e : ((Map<String, Object>) value).entrySet()) {
                out.put(e.getKey(), (String) e.getValue());
            }
        }
        return out;
    }

    static Consumer<Progress> log(List<Object> progress) {
        return p -> {
            synchronized (progress) {
                Map<String, Object> entry = map("pending", p.pending());
                if (p.approvalCode() != null) {
                    entry.put("approvalCode", p.approvalCode());
                }
                progress.add(entry);
            }
        };
    }

    static Map<String, Object> withProgress(Map<String, Object> result, List<Object> progress) {
        synchronized (progress) {
            if (!progress.isEmpty()) {
                result.put("progress", new ArrayList<>(progress));
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> run(SecretsClient c, Map<String, Object> action) throws Exception {
        String ref = (String) action.get("ref");
        boolean noWait = Boolean.FALSE.equals(action.get("wait"));
        Duration timeout = action.get("timeoutMs") instanceof Number
                ? Duration.ofMillis(((Number) action.get("timeoutMs")).longValue())
                : null;
        try {
            switch ((String) action.get("do")) {
                case "parse": {
                    SecretReference r = SecretReference.parse(ref);
                    return map("parsed", shape(r), "canonical", r.canonical());
                }
                case "format":
                    return map("formatted", SecretReference.format(fromShape((Map<String, Object>) action.get("parsed"))));
                case "connect": {
                    c.open();
                    var w = c.welcome();
                    return map("welcome", map("host", w.host(), "platform", w.platform(),
                            "features", new ArrayList<Object>(w.features())));
                }
                case "get": {
                    List<Object> progress = Collections.synchronizedList(new ArrayList<>());
                    GetOptions.Builder options = GetOptions.builder().onProgress(log(progress));
                    if (action.get("field") instanceof String) {
                        options.field((String) action.get("field"));
                    }
                    options.dimensions(strings(action.get("dimensions")));
                    if (noWait) {
                        options.noWait();
                    }
                    if (timeout != null) {
                        options.timeout(timeout);
                    }
                    if (Boolean.TRUE.equals(action.get("wantClientToken"))) {
                        options.wantClientToken();
                    }
                    if (Boolean.TRUE.equals(action.get("waitOnRateLimit"))) {
                        options.waitOnRateLimit();
                    }
                    Map<String, Object> result;
                    try {
                        result = map("value", valueShape(c.get(ref, options.build())));
                    } catch (SecretsException e) {
                        result = map("error", errorShape(e));
                    }
                    return withProgress(result, progress);
                }
                case "getMany": {
                    List<Object> progress = Collections.synchronizedList(new ArrayList<>());
                    List<SecretRequest> requests = new ArrayList<>();
                    for (Object raw : (List<Object>) action.get("refs")) {
                        Map<String, Object> r = (Map<String, Object>) raw;
                        requests.add(new SecretRequest((String) r.get("ref"),
                                r.get("field") instanceof String ? (String) r.get("field") : null,
                                strings(r.get("dimensions"))));
                    }
                    RequestOptions.Builder options = RequestOptions.builder().onProgress(log(progress));
                    if (noWait) {
                        options.noWait();
                    }
                    if (timeout != null) {
                        options.timeout(timeout);
                    }
                    Map<String, Object> result;
                    try {
                        List<Object> list = new ArrayList<>();
                        for (SecretResult r : c.getMany(requests, options.build())) {
                            list.add(r.isValue() ? map("value", valueShape(r.value())) : map("error", errorShape(r.error())));
                        }
                        result = map("results", list);
                    } catch (SecretsException e) {
                        result = map("error", errorShape(e));
                    }
                    return withProgress(result, progress);
                }
                case "getFile": {
                    GetOptions.Builder options = GetOptions.builder();
                    if (action.get("field") instanceof String) {
                        options.field((String) action.get("field"));
                    }
                    try (var f = c.getFile(ref, options.build())) {
                        return map("file", map("name", f.name(), "size", (long) f.size(),
                                "base64", Base64.getEncoder().encodeToString(f.bytes())));
                    }
                }
                case "concurrent": {
                    List<Object> actions = (List<Object>) action.get("actions");
                    ExecutorService pool = Executors.newFixedThreadPool(Math.max(1, actions.size()));
                    try {
                        List<Future<Map<String, Object>>> futures = new ArrayList<>();
                        for (Object a : actions) {
                            futures.add(pool.submit(() -> run(c, (Map<String, Object>) a)));
                        }
                        List<Object> results = new ArrayList<>();
                        for (Future<Map<String, Object>> f : futures) {
                            results.add(f.get());
                        }
                        return map("results", results);
                    } finally {
                        pool.shutdownNow();
                    }
                }
                case "sequence": {
                    List<Object> steps = new ArrayList<>();
                    for (Object raw : (List<Object>) action.get("actions")) {
                        Map<String, Object> step = (Map<String, Object>) raw;
                        if ("pause".equals(step.get("do"))) {
                            Thread.sleep(((Number) step.get("ms")).longValue());
                            continue;
                        }
                        steps.add(run(c, step));
                    }
                    return map("steps", steps);
                }
                default:
                    return map("unsupportedAction", action.get("do"));
            }
        } catch (SecretsException e) {
            return map("error", errorShape(e));
        }
    }

    static Map<String, Object> errorShape(SecretsException e) {
        Map<String, Object> out = map("kind", e.kind().wireName());
        if (e.reason() != null) {
            out.put("reason", e.reason());
        }
        return out;
    }

    static Map<String, Object> valueShape(SecretValue v) {
        try (v) {
            String text = v.isBinary() ? null : v.text();
            List<String> printed = List.of(v.toString(), String.valueOf(v), "" + v, String.format("%s", v));
            // Every printable form shows *** and never the value (README,
            // Results); a value that occurs in the reference cannot be told
            // apart.
            boolean masked = printed.stream().allMatch(p -> p.contains("***")
                    && (text == null || v.reference().contains(text) || !p.contains(text)));
            Map<String, Object> out = map(
                    "encoding", v.encoding(),
                    "base64", Base64.getEncoder().encodeToString(v.bytes()),
                    "entry", map("store", v.entry().store(), "uuid", v.entry().uuid(), "source", v.entry().source(),
                            "fetchedAtMs", v.entry().fetchedAt().toEpochMilli()),
                    "bound", new TreeMap<String, Object>(v.bound()),
                    "version", map("modifiedMs", v.version().modified().toEpochMilli(),
                            "revision", v.version().revision()),
                    "masked", masked);
            if (text != null) {
                out.put("text", text);
            } else {
                out.put("textRefused", true);
            }
            if (v.expires() != null) {
                out.put("expiresMs", v.expires().toEpochMilli());
            }
            if (v.clientToken() != null) {
                out.put("clientToken", v.clientToken());
            }
            return out;
        }
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
    static SecretReference fromShape(Map<String, Object> m) {
        Map<String, Object> t = (Map<String, Object>) m.get("target");
        SecretReference.Target target;
        switch ((String) t.get("kind")) {
            case "key":
                target = SecretReference.Target.key((String) t.get("key"));
                break;
            case "uuid":
                target = SecretReference.Target.uuid((String) t.get("store"), (String) t.get("uuid"));
                break;
            default:
                List<String> segments = new ArrayList<>();
                for (Object s : (List<Object>) t.get("segments")) {
                    segments.add((String) s);
                }
                target = SecretReference.Target.path((String) t.get("store"), segments);
        }
        List<SecretReference.Binding> qualifiers = new ArrayList<>();
        for (Object raw : (List<Object>) m.get("qualifiers")) {
            Map<String, Object> q = (Map<String, Object>) raw;
            qualifiers.add(new SecretReference.Binding((String) q.get("dimension"), (String) q.get("value")));
        }
        Object field = m.get("field");
        return new SecretReference(target, qualifiers, field instanceof String ? (String) field : null, false);
    }
}
