// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/token.hpp>
#include <privacy_pass/core/token_challenge.hpp>
#include <privacy_pass/core/types.hpp>
#include <privacy_pass/crypto/blind_rsa.hpp>
#include <privacy_pass/crypto/voprf.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace privacy_pass {

// Replay protection using nonce tracking
class ReplayCache {
public:
    explicit ReplayCache(
        std::chrono::seconds window = std::chrono::seconds(3600));
    ~ReplayCache();

    ReplayCache(const ReplayCache&) = delete;
    ReplayCache& operator=(const ReplayCache&) = delete;
    ReplayCache(ReplayCache&&) noexcept;
    ReplayCache& operator=(ReplayCache&&) noexcept;

    // Check if a nonce has been seen and add it if not
    // Returns true if the nonce is new (not a replay)
    [[nodiscard]] bool check_and_add(const Nonce& nonce);

    // Prune expired entries
    void prune();

    // Get the number of tracked nonces
    [[nodiscard]] size_t size() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Origin configuration
struct OriginConfig {
    std::string issuer_name;
    std::vector<std::string> origin_names;
    std::chrono::seconds redemption_window{3600};
    bool require_redemption_context{true};
};

// Privacy Pass Origin for publicly verifiable tokens (Blind RSA)
class PublicOrigin {
public:
    PublicOrigin(
        OriginConfig config,
        std::vector<crypto::BlindRsaPublicKey> issuer_keys);
    ~PublicOrigin();

    PublicOrigin(const PublicOrigin&) = delete;
    PublicOrigin& operator=(const PublicOrigin&) = delete;
    PublicOrigin(PublicOrigin&&) noexcept;
    PublicOrigin& operator=(PublicOrigin&&) noexcept;

    // Create a token challenge
    [[nodiscard]] Result<TokenChallenge> create_challenge(
        std::optional<ChallengeDigest> redemption_context = std::nullopt) const;

    // Verify a token
    [[nodiscard]] Result<bool> verify(
        const Token& token,
        const TokenChallenge& expected_challenge) const;

    // Verify a token with replay protection
    [[nodiscard]] Result<bool> verify_and_redeem(
        const Token& token,
        const TokenChallenge& expected_challenge);

    // Add an issuer key
    void add_issuer_key(crypto::BlindRsaPublicKey key);

    // Remove an issuer key by key ID
    void remove_issuer_key(const TokenKeyId& key_id);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Privacy Pass Origin for privately verifiable tokens (VOPRF)
// Note: Requires issuer cooperation to verify tokens
class PrivateOrigin {
public:
    PrivateOrigin(
        OriginConfig config,
        std::vector<crypto::VoprfPublicKey> issuer_keys);
    ~PrivateOrigin();

    PrivateOrigin(const PrivateOrigin&) = delete;
    PrivateOrigin& operator=(const PrivateOrigin&) = delete;
    PrivateOrigin(PrivateOrigin&&) noexcept;
    PrivateOrigin& operator=(PrivateOrigin&&) noexcept;

    // Create a token challenge
    [[nodiscard]] Result<TokenChallenge> create_challenge(
        std::optional<ChallengeDigest> redemption_context = std::nullopt) const;

    // Validate token structure (cannot verify signature without issuer)
    [[nodiscard]] Result<bool> validate_structure(
        const Token& token,
        const TokenChallenge& expected_challenge) const;

    // Check if a token would be a replay (without full verification)
    [[nodiscard]] bool would_be_replay(const Token& token) const;

    // Mark a token as redeemed (after issuer verification)
    void mark_redeemed(const Token& token);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Unified origin that handles both token types
class Origin {
public:
    Origin(OriginConfig config);
    ~Origin();

    Origin(const Origin&) = delete;
    Origin& operator=(const Origin&) = delete;
    Origin(Origin&&) noexcept;
    Origin& operator=(Origin&&) noexcept;

    // Add issuer keys
    void add_blind_rsa_key(crypto::BlindRsaPublicKey key);
    void add_voprf_key(crypto::VoprfPublicKey key);

    // Create a challenge for a specific token type
    [[nodiscard]] Result<TokenChallenge> create_challenge(
        TokenType type,
        std::optional<ChallengeDigest> redemption_context = std::nullopt) const;

    // Verify a token (publicly verifiable types only)
    [[nodiscard]] Result<bool> verify(
        const Token& token,
        const TokenChallenge& expected_challenge) const;

    // Verify and redeem with replay protection
    [[nodiscard]] Result<bool> verify_and_redeem(
        const Token& token,
        const TokenChallenge& expected_challenge);

    // Get config
    [[nodiscard]] const OriginConfig& config() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace privacy_pass
