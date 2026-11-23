// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

/**
 * Every failure of the library (protocol.md section 10): a {@link Kind}, a
 * message for people (never a value, token or key) and the details
 * ({@code reason}, {@code candidates}, {@code retryAfterMs}, ...). A call the
 * program gets wrong (a {@code getMany} of no references) is an {@link
 * IllegalArgumentException} instead.
 */
public final class SecretsException extends Exception {
    private static final long serialVersionUID = 1L;

    /**
     * What went wrong: the protocol's kinds plus {@link #NOT_RUNNING}, which
     * the library reports when it finds no service or loses the connection.
     */
    public enum Kind {
        /** {@code locked} */
        LOCKED("locked"),
        /** {@code denied} */
        DENIED("denied"),
        /** {@code not_found} */
        NOT_FOUND("not_found"),
        /** {@code ambiguous} */
        AMBIGUOUS("ambiguous"),
        /** {@code needs_unlock} */
        NEEDS_UNLOCK("needs_unlock"),
        /** {@code unavailable} */
        UNAVAILABLE("unavailable"),
        /** {@code offline} */
        OFFLINE("offline"),
        /** {@code token_expired} */
        TOKEN_EXPIRED("token_expired"),
        /** {@code malformed} */
        MALFORMED("malformed"),
        /** {@code timeout} */
        TIMEOUT("timeout"),
        /** {@code rate_limited} */
        RATE_LIMITED("rate_limited"),
        /** {@code unsupported} */
        UNSUPPORTED("unsupported"),
        /** {@code internal} */
        INTERNAL("internal"),
        /** {@code not_running}: no service found, or the connection lost. */
        NOT_RUNNING("not_running");

        private final String wire;

        Kind(String wire) {
            this.wire = wire;
        }

        /** The protocol's name ({@code not_found}). */
        public String wireName() {
            return wire;
        }

        /**
         * The kind an error message names: an unknown kind (from a later
         * service) is {@link #INTERNAL}; {@code not_running} is never the
         * service's to send.
         */
        public static Kind fromWire(Object name) {
            for (Kind k : values()) {
                if (k != NOT_RUNNING && k.wire.equals(name)) {
                    return k;
                }
            }
            return INTERNAL;
        }
    }

    private final Kind kind;
    // Not serialized: a deserialized exception answers no details (the
    // values in them need not be serializable).
    private final transient Map<String, Object> details;

    /** An error of {@code kind} with {@code message} and {@code details}. */
    public SecretsException(Kind kind, String message, Map<String, Object> details) {
        super(message);
        this.kind = kind;
        this.details = Collections.unmodifiableMap(new TreeMap<>(details == null ? Map.of() : details));
    }

    /** What went wrong. */
    public Kind kind() {
        return kind;
    }

    /** The error's details; numbers are {@link Long} or {@link Double}. */
    public Map<String, Object> details() {
        return details == null ? Map.of() : details;
    }

    /** {@code details.reason}, or null when there is none. */
    public String reason() {
        Object r = details().get("reason");
        return r instanceof String ? (String) r : null;
    }

    @Override
    public String toString() {
        String reason = reason();
        return "SecretsException(" + kind.wire + (reason == null ? "" : ", " + reason) + "): " + getMessage();
    }

    static SecretsException fromMessage(Map<String, Object> m) {
        Map<String, Object> details = Json.object(m, "details");
        String message = Json.string(m, "message");
        return new SecretsException(Kind.fromWire(m.get("kind")), message == null ? "" : message, details);
    }

    static SecretsException notRunning(String why) {
        return new SecretsException(Kind.NOT_RUNNING, "the secrets service is not running: " + why, null);
    }

    static SecretsException protocol(String why) {
        return new SecretsException(Kind.INTERNAL, "the service broke the protocol: " + why, Map.of("code", "protocol"));
    }

    static SecretsException malformed(String reason, String message) {
        return new SecretsException(Kind.MALFORMED, message, Map.of("reason", reason));
    }
}
