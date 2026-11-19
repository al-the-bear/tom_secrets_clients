// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause
//
// The design's call, c.get(ref, {.field = "UserName"}), compiles with C++20
// designated initializers; with no service it fails as NotRunning.
#include <cstdio>

#include "tsm/tsm.hpp"

int main() {
    tsm::Client c({.runtime_dir = "/nonexistent/tsm-cpp-test", .operating_system = "linux"});
    try {
        auto v = c.get("[env:prod]db.main", {.field = "UserName"});
        std::printf("FAIL a value without a service\n");
        return 1;
    } catch (const tsm::Error &e) {
        if (e.kind() != tsm::ErrorKind::NotRunning) {
            std::printf("FAIL %s: %s\n", tsm::to_string(e.kind()), e.what());
            return 1;
        }
    }
    std::printf("designated initializers: ok\n");
    return 0;
}
