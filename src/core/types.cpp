// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/core/types.hpp>
#include <privacy_pass/privacy_pass.hpp>

#include <spdlog/spdlog.h>

// Backend-specific init/shutdown are defined in src/crypto/{openssl,boringssl}/init.cpp
namespace privacy_pass::crypto::detail {
void backend_init();
void backend_shutdown();
}  // namespace privacy_pass::crypto::detail

namespace privacy_pass {

namespace {
    bool g_initialized = false;
}

Result<void> initialize() {
    if (g_initialized) {
        return {};
    }

    crypto::detail::backend_init();

    g_initialized = true;
    spdlog::debug("Privacy Pass library initialized");

    return {};
}

void shutdown() {
    if (!g_initialized) {
        return;
    }

    crypto::detail::backend_shutdown();

    g_initialized = false;
    spdlog::debug("Privacy Pass library shut down");
}

}  // namespace privacy_pass
