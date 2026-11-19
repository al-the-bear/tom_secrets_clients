// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.time.Duration;
import java.util.function.Consumer;

/**
 * The options of one {@code getMany} (each {@link SecretRequest} carries its
 * field and dimensions); build them with {@link #builder()}.
 */
public final class RequestOptions {
    final boolean noWait;
    final Duration timeout;
    final Consumer<Progress> onProgress;
    final boolean waitOnRateLimit;

    RequestOptions(boolean noWait, Duration timeout, Consumer<Progress> onProgress, boolean waitOnRateLimit) {
        this.noWait = noWait;
        this.timeout = timeout;
        this.onProgress = onProgress;
        this.waitOnRateLimit = waitOnRateLimit;
    }

    /** The defaults: wait, no timeout, no progress, no waiting on rate limits. */
    public static RequestOptions defaults() {
        return builder().build();
    }

    /** A builder with the defaults. */
    public static Builder builder() {
        return new Builder();
    }

    /** Builds {@link RequestOptions}. */
    public static final class Builder {
        private boolean noWait;
        private Duration timeout;
        private Consumer<Progress> onProgress;
        private boolean waitOnRateLimit;

        private Builder() {}

        /** Answer at once instead of waiting for an unlock or an approval ({@code LOCKED} when locked). */
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

        /**
         * Waits out a {@code RATE_LIMITED} answer (its {@code retryAfterMs},
         * else one second) and sends the request again.
         */
        public Builder waitOnRateLimit() {
            waitOnRateLimit = true;
            return this;
        }

        /** The options. */
        public RequestOptions build() {
            return new RequestOptions(noWait, timeout, onProgress, waitOnRateLimit);
        }
    }
}
