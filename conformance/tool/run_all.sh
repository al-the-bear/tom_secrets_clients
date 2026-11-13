#!/usr/bin/env bash
# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
#
# run_all.sh — every runner against every case table, after the driver's
# self-test, the reference table check and the coverage gate.
#
#   conformance/tool/run_all.sh [--runner LANG]... [--strict]
#
# A runner whose toolchain is missing is reported NOT MEASURED, never passed;
# --strict turns that into a failure. Exit 0 only when everything holds.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${PYTHON:-python3}"
cd "$HERE"
"$PY" test_conformance.py -q
"$PY" conformance.py gen --check
"$PY" conformance.py coverage
"$PY" conformance.py run "$@"
