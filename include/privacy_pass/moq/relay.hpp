// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/issuer.hpp>
#include <privacy_pass/core/origin.hpp>
#include <privacy_pass/moq/authorization_info.hpp>

#include <chrono>
#include <memory>
#include <optional>

namespace privacy_pass::moq {

// Verification result with detailed information
struct VerificationResult {
    bool valid;
    std::optional<MoqErrorCode> error_code;
    std::optional<std::string> error_message;
    std::optional<AuthorizationInfo> authorization_info;

    [[nodiscard]] static VerificationResult success(AuthorizationInfo auth_info);
    [[nodiscard]] static VerificationResult failure(
        MoqErrorCode code,
        std::string message = {});
};

// MoQ Relay configuration
struct RelayConfig {
    std::string relay_name;
    std::string issuer_name;
    std::chrono::seconds token_validity_window{3600};
    std::chrono::seconds replay_window{3600};
    bool strict_scope_matching{true};
};

// MoQ Relay - combines Origin and optional Issuer functionality
// Handles token verification and scope matching for MoQ operations
class MoqRelay {
public:
    explicit MoqRelay(RelayConfig config);
    ~MoqRelay();

    MoqRelay(const MoqRelay&) = delete;
    MoqRelay& operator=(const MoqRelay&) = delete;
    MoqRelay(MoqRelay&&) noexcept;
    MoqRelay& operator=(MoqRelay&&) noexcept;

    // Add trusted issuer keys
    void add_trusted_issuer(
        std::string_view issuer_name,
        crypto::BlindRsaPublicKey key);

    void add_trusted_issuer(
        std::string_view issuer_name,
        crypto::VoprfPublicKey key);

    // Create a token challenge for a client
    [[nodiscard]] Result<TokenChallenge> create_challenge(
        TokenType type,
        const AuthorizationInfo& required_auth,
        std::optional<ChallengeDigest> redemption_context = std::nullopt) const;

    // Verify a token and check authorization
    [[nodiscard]] VerificationResult verify_token(
        const Token& token,
        const TokenChallenge& expected_challenge) const;

    // Verify and authorize a specific action
    [[nodiscard]] VerificationResult verify_and_authorize(
        const Token& token,
        const TokenChallenge& expected_challenge,
        Action action,
        const Namespace& ns,
        const TrackName& track);

    // Check if a token has already been redeemed
    [[nodiscard]] bool is_replayed(const Token& token) const;

    // Mark a token as redeemed
    void mark_redeemed(const Token& token);

    // Get relay configuration
    [[nodiscard]] const RelayConfig& config() const;

    // Enable issuer mode (relay can also issue tokens)
    void enable_issuer_mode(crypto::BlindRsaPrivateKey key);
    void enable_issuer_mode(crypto::VoprfPrivateKey key);

    // Issue a token (when in issuer mode)
    [[nodiscard]] Result<TokenResponse> issue(const TokenRequest& request) const;

    // Get issuer public keys (when in issuer mode)
    [[nodiscard]] std::vector<PublicKey> issuer_public_keys() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace privacy_pass::moq
