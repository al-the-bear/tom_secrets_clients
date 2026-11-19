// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

/**
 * A secret (protocol.md 5.2). Its {@code toString} never shows it: it gives
 * {@code SecretValue(<ref>: ***)}. {@link #close} (also the end of a
 * try-with-resources block) overwrites its buffer. A {@code String} the
 * caller takes out with {@link #text} is an immutable Java string the
 * library cannot overwrite: the caller handles it.
 */
public final class SecretValue implements AutoCloseable {
    private final String reference;
    private final String encoding;
    private final SecretEntry entry;
    private final Map<String, String> bound;
    private final SecretVersion version;
    private final Instant expires;
    private final String clientToken;
    private final byte[] data;
    private volatile boolean closed;

    private SecretValue(String reference, String encoding, SecretEntry entry, Map<String, String> bound,
            SecretVersion version, Instant expires, String clientToken, byte[] data) {
        this.reference = reference;
        this.encoding = encoding;
        this.entry = entry;
        this.bound = bound;
        this.version = version;
        this.expires = expires;
        this.clientToken = clientToken;
        this.data = data;
    }

    private static final String DATE =
            "\\d{4}-\\d{2}-\\d{2}[Tt]\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?([Zz]|[+-]\\d{2}:\\d{2})";

    /** An RFC 3339 time (fractions and offsets allowed), or null when it is none. */
    static Instant parseTime(Object v) {
        if (!(v instanceof String) || !((String) v).matches(DATE)) {
            return null;
        }
        try {
            String s = ((String) v).replace('t', 'T').replace('z', 'Z');
            return OffsetDateTime.parse(s).toInstant();
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    /** The source a protocol {@code source} names; an unknown one is {@code cache}. */
    static String sourceFromWire(Object name) {
        return "github".equals(name) || "file".equals(name) ? (String) name : "cache";
    }

    private static SecretsException badValue() {
        return new SecretsException(SecretsException.Kind.INTERNAL,
                "the service sent a value message this library cannot read", Map.of("code", "bad_value"));
    }

    /** The value of a {@code value} message (or a {@code values} result). */
    static SecretValue fromMessage(String reference, Map<String, Object> m) throws SecretsException {
        String raw = Json.string(m, "value");
        Map<String, Object> entry = Json.object(m, "entry");
        Map<String, Object> version = Json.object(m, "version");
        if (raw == null || entry == null || version == null) {
            throw badValue();
        }
        Map<String, String> bound = new TreeMap<>();
        Map<String, Object> b = Json.object(m, "bound");
        if (b != null) {
            for (Map.Entry<String, Object> e : b.entrySet()) {
                if (!(e.getValue() instanceof String)) {
                    throw badValue();
                }
                bound.put(e.getKey(), (String) e.getValue());
            }
        }
        String encoding = "base64".equals(m.get("encoding")) ? "base64" : "utf8";
        byte[] data;
        if (encoding.equals("base64")) {
            if (!raw.matches("[A-Za-z0-9+/]*={0,2}")) {
                throw badValue();
            }
            String unpadded = raw.replaceAll("=+$", "");
            try {
                data = Base64.getDecoder().decode(unpadded + "==".substring(0, (4 - unpadded.length() % 4) % 4));
            } catch (IllegalArgumentException e) {
                throw badValue();
            }
        } else {
            data = raw.getBytes(StandardCharsets.UTF_8);
        }
        String store = Json.string(entry, "store");
        String uuid = Json.string(entry, "uuid");
        String revision = Json.string(version, "revision");
        Instant fetched = parseTime(entry.get("fetchedAt"));
        Instant modified = parseTime(version.get("modified"));
        if (store == null || uuid == null || revision == null || fetched == null || modified == null) {
            throw badValue();
        }
        Instant expires = null;
        if (m.get("expires") instanceof String) {
            expires = parseTime(m.get("expires"));
            if (expires == null) {
                throw badValue();
            }
        }
        return new SecretValue(reference, encoding,
                new SecretEntry(store, uuid, sourceFromWire(entry.get("source")), fetched),
                Collections.unmodifiableMap(bound), new SecretVersion(modified, revision), expires,
                Json.string(m, "clientToken"), data);
    }

    /** The reference the value was asked for, as given. */
    public String reference() {
        return reference;
    }

    /** How the service sent it: {@code utf8} (text) or {@code base64} (bytes). */
    public String encoding() {
        return encoding;
    }

    /** Whether the value is binary ({@code base64}): read it with {@link #bytes}. */
    public boolean isBinary() {
        return encoding.equals("base64");
    }

    /** The entry it was read from. */
    public SecretEntry entry() {
        return entry;
    }

    /** The bindings the winning entry carries, dimension to value. */
    public Map<String, String> bound() {
        return bound;
    }

    /** The entry's version. */
    public SecretVersion version() {
        return version;
    }

    /** The entry's expiry, or null. */
    public Instant expires() {
        return expires;
    }

    /**
     * The client token the service granted when one was asked for, or null:
     * the caller's to keep (7.4); the library never stores it.
     */
    public String clientToken() {
        return clientToken;
    }

    /**
     * The value as text.
     *
     * @throws IllegalStateException for a binary value (read it with {@link
     *     #bytes} rather than decode it into a corrupt string), and after
     *     {@link #close}
     */
    public String text() {
        check();
        if (isBinary()) {
            throw new IllegalStateException("the value of " + reference + " is binary: read it with bytes(), not text()");
        }
        return new String(data, StandardCharsets.UTF_8);
    }

    /**
     * The value as bytes (text as its UTF-8): the buffer itself, which {@link
     * #close} overwrites; copy it to keep it.
     *
     * @throws IllegalStateException after {@link #close}
     */
    public byte[] bytes() {
        check();
        return data;
    }

    /** Overwrites the buffer with zeros; the value cannot be read afterwards. */
    @Override
    public void close() {
        Arrays.fill(data, (byte) 0);
        closed = true;
    }

    /** Whether {@link #close} was called. */
    public boolean isClosed() {
        return closed;
    }

    private void check() {
        if (closed) {
            throw new IllegalStateException("the value of " + reference + " was closed");
        }
    }

    /** {@code SecretValue(<ref>: ***)}, never the secret. */
    @Override
    public String toString() {
        return "SecretValue(" + reference + ": ***)";
    }
}
