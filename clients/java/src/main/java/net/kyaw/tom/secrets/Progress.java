// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

/**
 * A progress notice (protocol.md 5.4): why a request waits, {@code unlock}
 * (the service is locked and an admin was told) or {@code approval} (the
 * request went to approval), with the one-time approval code on a host with
 * no approver connected (7.5), else null.
 *
 * @param pending {@code unlock} or {@code approval}
 * @param approvalCode the approval code, or null
 */
public record Progress(String pending, String approvalCode) {}
