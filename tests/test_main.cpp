// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <privacy_pass/privacy_pass.hpp>

// Global setup for tests
struct GlobalSetup {
    GlobalSetup() {
        privacy_pass::initialize();
    }
    ~GlobalSetup() {
        privacy_pass::shutdown();
    }
};

static GlobalSetup global_setup;
