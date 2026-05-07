// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/origin.hpp>
#include <privacy_pass/core/token.hpp>
#include <privacy_pass/core/token_challenge.hpp>
#include <privacy_pass/core/types.hpp>
#include <privacy_pass/crypto/blind_rsa.hpp>
#include <privacy_pass/crypto/voprf.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace privacy_pass {

// Result of token validation
struct ValidationResult {
    bool valid{false};
    std::optional<ErrorCode> error_code;
    std::optional<std::string> error_message;
    std::optional<ChallengeDigest> challenge_digest;

    [[nodiscard]] static ValidationResult success(ChallengeDigest digest);
    [[nodiscard]] static ValidationResult failure(ErrorCode code, std::string message = {});

    [[nodiscard]] explicit operator bool() const { return valid; }
};

// Configuration for token authenticator
struct TokenAuthenticatorConfig {
    std::string issuer_name;
    std::vector<std::string> origin_names;
    std::chrono::seconds redemption_window{3600};
    std::chrono::seconds replay_window{3600};
    bool require_redemption_context{true};
    size_t max_replay_cache_size{100000};  // Maximum entries in replay cache (conservative default)
};

// TokenAuthenticator - entity that validates tokens
//
// This abstraction handles:
// - Creating challenges for token providers
// - Validating token signatures
// - Verifying challenge digest matches
// - Managing replay protection
// - Tracking token redemption
//
// Usage:
//   TokenAuthenticator auth(config);
//   auth.add_trusted_key(issuer_name, public_key);
//
//   // Create challenge for client:
//   auto challenge = auth.create_challenge(TokenType::BLIND_RSA);
//
//   // When receiving a token:
//   auto result = auth.validate(token, challenge);
//   if (result.valid) {
//       auto redeem_result = auth.redeem(token, challenge);
//   }
class TokenAuthenticator {
public:
    explicit TokenAuthenticator(TokenAuthenticatorConfig config);
    ~TokenAuthenticator();

    TokenAuthenticator(const TokenAuthenticator&) = delete;
    TokenAuthenticator& operator=(const TokenAuthenticator&) = delete;
    TokenAuthenticator(TokenAuthenticator&&) noexcept;
    TokenAuthenticator& operator=(TokenAuthenticator&&) noexcept;

    // Add a trusted issuer's public key (Blind RSA)
    void add_trusted_key(std::string_view issuer_name, crypto::BlindRsaPublicKey key);

    // Add a trusted issuer's public key (VOPRF)
    void add_trusted_key(std::string_view issuer_name, crypto::VoprfPublicKey key);

    // Remove a trusted issuer
    void remove_trusted_issuer(std::string_view issuer_name);

    // Check if issuer is trusted
    [[nodiscard]] bool is_trusted(std::string_view issuer_name) const;

    // Create a token challenge
    // The challenge can include optional origin_info for application-specific data
    [[nodiscard]] Result<TokenChallenge> create_challenge(
        TokenType type,
        std::optional<ChallengeDigest> redemption_context = std::nullopt,
        std::vector<std::string> additional_origin_info = {}) const;

    // Validate a token without marking it as redeemed
    // Use this for checking token validity before committing to an action
    [[nodiscard]] ValidationResult validate(
        const Token& token,
        const TokenChallenge& expected_challenge) const;

    // Validate and redeem a token (marks it as used, preventing replay)
    // Use this when the token is being consumed for an action
    [[nodiscard]] ValidationResult validate_and_redeem(
        const Token& token,
        const TokenChallenge& expected_challenge);

    // Check if a token would be considered a replay
    [[nodiscard]] bool would_be_replay(const Token& token) const;

    // Manually mark a token as redeemed
    // Useful when validation and redemption are separate steps
    void mark_redeemed(const Token& token);

    // Get the number of redeemed tokens in cache
    [[nodiscard]] size_t redemption_cache_size() const;

    // Prune expired entries from redemption cache
    void prune_redemption_cache();

    // Get configuration
    [[nodiscard]] const TokenAuthenticatorConfig& config() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace privacy_pass
