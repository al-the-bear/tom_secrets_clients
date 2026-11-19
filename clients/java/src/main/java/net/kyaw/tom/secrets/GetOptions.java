// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * The options of one {@code get} or {@code getFile}; build them with {@link
 * #builder()}: {@code GetOptions.builder().field("UserName").build()}.
 */
public final class GetOptions {
    final String field;
    final Map<String, String> dimensions;
    final boolean wantClientToken;
    final RequestOptions waiting;

    private GetOptions(Builder b) {
        field = b.field;
        dimensions = Map.copyOf(b.dimensions);
        wantClientToken = b.wantClientToken;
        waiting = new RequestOptions(b.noWait, b.timeout, b.onProgress, b.waitOnRateLimit);
    }

    /** The defaults. */
    public static GetOptions defaults() {
        return builder().build();
    }

    /** A builder with the defaults. */
    public static Builder builder() {
        return new Builder();
    }

    /** Builds {@link GetOptions}. */
    public static final class Builder {
        private String field;
        private final Map<String, String> dimensions = new LinkedHashMap<>();
        private boolean noWait;
        private Duration timeout;
        private Consumer<Progress> onProgress;
        private boolean wantClientToken;
        private boolean waitOnRateLimit;

        private Builder() {}

        /**
         * The field, when the reference names none. The same field in both
         * is sent once; two different ones are {@code MALFORMED}, reason
         * {@code field_twice}.
         */
        public Builder field(String field) {
            this.field = field;
            return this;
        }

        /** A value for a dimension beside the reference ({@code env} = {@code prod}). */
        public Builder dimension(String dimension, String value) {
            dimensions.put(dimension, value);
            return this;
        }

        /** Values for dimensions beside the reference. */
        public Builder dimensions(Map<String, String> values) {
            dimensions.putAll(values);
            return this;
        }

        /** Answer at once instead of waiting for an unlock or an approval. */
        public Builder noWait() {
            noWait = true;
            return this;
        }

        /** How long the service may wait, in whole milliseconds, capped by the service. */
        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        /**
         * Receives the progress notices while the request waits; called on
         * the connection's reader thread, so it must return quickly.
         */
        public Builder onProgress(Consumer<Progress> onProgress) {
            this.onProgress = onProgress;
            return this;
        }

        /** Asks for a client token with an "always" approval ({@code get} only; {@code getFile} does not send it). */
        public Builder wantClientToken() {
            wantClientToken = true;
            return this;
        }

        /** Waits out a {@code RATE_LIMITED} answer and sends the request again. */
        public Builder waitOnRateLimit() {
            waitOnRateLimit = true;
            return this;
        }

        /** The options. */
        public GetOptions build() {
            return new GetOptions(this);
        }
    }
}
