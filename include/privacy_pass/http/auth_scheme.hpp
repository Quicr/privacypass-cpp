// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/serialization.hpp>
#include <privacy_pass/core/token.hpp>
#include <privacy_pass/core/token_challenge.hpp>
#include <privacy_pass/core/types.hpp>

#include <optional>
#include <string>
#include <vector>

namespace privacy_pass::http {

// WWW-Authenticate header parameters
struct ChallengeHeader {
    std::string challenge;      // Base64url-encoded TokenChallenge
    std::optional<std::string> token_key;  // Base64url-encoded issuer public key
    std::optional<uint32_t> max_age;  // Optional max-age in seconds

    // Format as WWW-Authenticate header value
    [[nodiscard]] std::string format() const;

    // Parse from WWW-Authenticate header value
    [[nodiscard]] static Result<ChallengeHeader> parse(std::string_view header);

    // Parse all PrivateToken challenges from a WWW-Authenticate header value
    [[nodiscard]] static Result<std::vector<ChallengeHeader>> parse_all(std::string_view header);

    // Decode the challenge
    [[nodiscard]] Result<TokenChallenge> decode_challenge() const;

    // Decode the token key
    [[nodiscard]] Result<Bytes> decode_token_key() const;
};

// Authorization header with PrivateToken
struct AuthorizationHeader {
    std::string token;  // Base64url-encoded Token

    // Format as Authorization header value
    [[nodiscard]] std::string format() const;

    // Parse from Authorization header value
    [[nodiscard]] static Result<AuthorizationHeader> parse(std::string_view header);

    // Decode the token
    [[nodiscard]] Result<Token> decode_token() const;
};

// Build a WWW-Authenticate header
[[nodiscard]] Result<std::string> build_www_authenticate(
    const TokenChallenge& challenge,
    ByteView token_key,
    std::optional<uint32_t> max_age = std::nullopt);

// Build an Authorization header
[[nodiscard]] Result<std::string> build_authorization(const Token& token);

// Parse and extract token from Authorization header
[[nodiscard]] Result<Token> parse_authorization(std::string_view header);

// Media types
constexpr std::string_view MEDIA_TYPE_ISSUER_DIRECTORY =
    "application/private-token-issuer-directory";
constexpr std::string_view MEDIA_TYPE_TOKEN_REQUEST =
    "application/private-token-request";
constexpr std::string_view MEDIA_TYPE_TOKEN_RESPONSE =
    "application/private-token-response";
constexpr std::string_view MEDIA_TYPE_BATCHED_REQUEST =
    "application/private-token-request-batched";
constexpr std::string_view MEDIA_TYPE_BATCHED_RESPONSE =
    "application/private-token-response-batched";

}  // namespace privacy_pass::http
