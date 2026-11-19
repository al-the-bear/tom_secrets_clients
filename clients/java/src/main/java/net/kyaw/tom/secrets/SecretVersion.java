// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.time.Instant;

/**
 * The entry's last modification and the store file revision it was read
 * from; a caller caching a value compares it to see a change.
 *
 * @param modified the entry's last modification
 * @param revision the store file revision
 */
public record SecretVersion(Instant modified, String revision) {}
