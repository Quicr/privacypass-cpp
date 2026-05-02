// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

// Core types and utilities
#include <privacy_pass/core/types.hpp>
#include <privacy_pass/core/serialization.hpp>

// Protocol structures
#include <privacy_pass/core/token_challenge.hpp>
#include <privacy_pass/core/token_request.hpp>
#include <privacy_pass/core/token_response.hpp>
#include <privacy_pass/core/token.hpp>

// Participants
#include <privacy_pass/core/client.hpp>
#include <privacy_pass/core/issuer.hpp>
#include <privacy_pass/core/origin.hpp>

// Cryptographic primitives
#include <privacy_pass/crypto/hash.hpp>
#include <privacy_pass/crypto/random.hpp>
#include <privacy_pass/crypto/blind_rsa.hpp>
#include <privacy_pass/crypto/voprf.hpp>

// HTTP authentication scheme
#include <privacy_pass/http/auth_scheme.hpp>

// MOQ extension
#include <privacy_pass/moq/types.hpp>
#include <privacy_pass/moq/auth_scope.hpp>
#include <privacy_pass/moq/authorization_info.hpp>
#include <privacy_pass/moq/client.hpp>
#include <privacy_pass/moq/relay.hpp>

namespace privacy_pass {

// Library version
constexpr int VERSION_MAJOR = 1;
constexpr int VERSION_MINOR = 0;
constexpr int VERSION_PATCH = 0;
constexpr std::string_view VERSION_STRING = "1.0.0";

// Initialize the library (call once at startup)
// Sets up OpenSSL and logging
Result<void> initialize();

// Shutdown the library (call before exit)
void shutdown();

}  // namespace privacy_pass
