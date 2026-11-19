// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.util.List;

/**
 * What the service said in {@code welcome}: the protocol, its version, the
 * optional features it offers (sorted), its host name (the current value of
 * the {@code host} dimension) and platform.
 *
 * @param protocol the protocol version (1)
 * @param serviceVersion the service's version
 * @param features the optional features the service offers, sorted
 * @param host the service's host name
 * @param platform the service's platform
 */
public record Welcome(int protocol, String serviceVersion, List<String> features, String host, String platform) {
    /** Keeps the features as an unmodifiable list. */
    public Welcome {
        features = List.copyOf(features);
    }

    /** Whether the service offers {@code feature}. */
    public boolean offers(String feature) {
        return features.contains(feature);
    }
}
