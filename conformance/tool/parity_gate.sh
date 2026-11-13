#!/usr/bin/env bash
# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
#
# parity_gate.sh — prove that every runner runs the case tables.
#
# A runner that never reaches a table passes as loudly as one that runs it.
# So: break one expectation, then one input of a case (the value the fake
# service sends), and require every runner to go red each time. The table is
# restored unconditionally.
#
#   conformance/tool/parity_gate.sh [--runner LANG]...
#   conformance/tool/parity_gate.sh --table get --from '<regex>' --to '<text>'
#
# The regex must match exactly once in the table.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "${PYTHON:-python3}" "$HERE/conformance.py" parity "$@"
