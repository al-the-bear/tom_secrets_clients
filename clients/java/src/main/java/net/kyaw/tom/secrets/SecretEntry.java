// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.time.Instant;

/**
 * The entry a value was read from: its store and KDBX UUID, where the
 * service read it ({@code github}, {@code file} or {@code cache}), and the
 * last successful fetch of the store.
 *
 * @param store the store
 * @param uuid the entry's KDBX UUID
 * @param source {@code github}, {@code file} or {@code cache}
 * @param fetchedAt the last successful fetch of the store
 */
public record SecretEntry(String store, String uuid, String source, Instant fetchedAt) {}
