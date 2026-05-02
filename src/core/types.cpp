// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/core/types.hpp>
#include <privacy_pass/privacy_pass.hpp>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <spdlog/spdlog.h>

namespace privacy_pass {

namespace {
    bool g_initialized = false;
}

Result<void> initialize() {
    if (g_initialized) {
        return {};
    }

    // Initialize OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    g_initialized = true;
    spdlog::debug("Privacy Pass library initialized");

    return {};
}

void shutdown() {
    if (!g_initialized) {
        return;
    }

    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    g_initialized = false;
    spdlog::debug("Privacy Pass library shut down");
}

}  // namespace privacy_pass
