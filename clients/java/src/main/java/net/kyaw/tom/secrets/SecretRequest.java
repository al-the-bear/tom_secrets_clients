// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.util.Map;

/**
 * One reference of a {@code getMany}: the reference, the field when the
 * reference names none (or null), and values for dimensions beside it.
 *
 * @param ref the reference
 * @param field the field, or null
 * @param dimensions values for dimensions, never null
 */
public record SecretRequest(String ref, String field, Map<String, String> dimensions) {
    /** Keeps the dimensions as an unmodifiable map. */
    public SecretRequest {
        dimensions = dimensions == null ? Map.of() : Map.copyOf(dimensions);
    }

    /** A request for {@code ref}, without field or dimensions. */
    public static SecretRequest of(String ref) {
        return new SecretRequest(ref, null, Map.of());
    }
}
