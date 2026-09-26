// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/core/types.hpp>
#include <privacy_pass/privacy_pass.hpp>

#include <spdlog/spdlog.h>
#include <atomic>
#include <mutex>  // for std::once_flag, std::call_once

// Backend-specific init/shutdown are defined in src/crypto/{openssl,boringssl}/init.cpp
namespace privacy_pass::crypto::detail {
void backend_init();
void backend_shutdown();
}  // namespace privacy_pass::crypto::detail

namespace privacy_pass {

bool constant_time_equal(ByteView a, ByteView b) noexcept {
    if (a.size() != b.size()) return false;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

namespace {
    std::atomic<bool> g_initialized{false};
}

Result<void> initialize() {
    // Double-checked locking with call_once via function-local static
    // to avoid static destruction order issues
    static std::once_flag flag;
    std::call_once(flag, []() {
        crypto::detail::backend_init();
        g_initialized.store(true, std::memory_order_release);
        spdlog::debug("Privacy Pass library initialized");
    });
    return {};
}

void shutdown() {
    bool expected = true;
    if (!g_initialized.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
        return;
    }

    crypto::detail::backend_shutdown();
    spdlog::debug("Privacy Pass library shut down");
}

}  // namespace privacy_pass
