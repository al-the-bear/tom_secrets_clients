// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.time.Duration;
import java.util.Map;

/**
 * How a {@link SecretsClient} finds and greets the service; build it with
 * {@link #builder()}. Every setting is optional.
 */
public final class ClientOptions {
    final String clientName;
    final String clientToken;
    final Map<String, String> environment;
    final String operatingSystem;
    final Duration connectTimeout;

    private ClientOptions(Builder b) {
        clientName = b.clientName;
        clientToken = b.clientToken;
        environment = b.environment == null ? null : Map.copyOf(b.environment);
        operatingSystem = b.operatingSystem;
        connectTimeout = b.connectTimeout;
    }

    /** The defaults. */
    public static ClientOptions defaults() {
        return builder().build();
    }

    /** A builder with the defaults. */
    public static Builder builder() {
        return new Builder();
    }

    /** Builds {@link ClientOptions}. */
    public static final class Builder {
        private String clientName;
        private String clientToken;
        private Map<String, String> environment;
        private String operatingSystem;
        private Duration connectTimeout = Duration.ofSeconds(10);

        private Builder() {}

        /**
         * The name {@code hello} gives the program, shown in approval
         * prompts and never trusted (the service measures the process).
         * Default: the main class's simple name, else {@code java}.
         */
        public Builder clientName(String name) {
            clientName = name;
            return this;
        }

        /** A client token the program was granted before (7.4), sent with every connection. */
        public Builder clientToken(String token) {
            clientToken = token;
            return this;
        }

        /**
         * Where {@code TSM_RUNTIME_DIR} and the OS variables are read from.
         * Default: the process's environment.
         */
        public Builder environment(Map<String, String> environment) {
            this.environment = environment;
            return this;
        }

        /** {@code linux}, {@code macos} or {@code windows}. Default: this process's. */
        public Builder operatingSystem(String name) {
            operatingSystem = name;
            return this;
        }

        /** How long connecting and the service's {@code welcome} may take. Default 10 seconds. */
        public Builder connectTimeout(Duration timeout) {
            connectTimeout = timeout;
            return this;
        }

        /** The options. */
        public ClientOptions build() {
            return new ClientOptions(this);
        }
    }
}
