// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

/**
 * One result of a {@code getMany}, in request order: a value or an error.
 *
 * @param value the value, or null
 * @param error the error, or null
 */
public record SecretResult(SecretValue value, SecretsException error) {
    /** Whether this result holds a value. */
    public boolean isValue() {
        return value != null;
    }
}
