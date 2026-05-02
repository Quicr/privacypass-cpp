// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/token.hpp>
#include <privacy_pass/core/token_challenge.hpp>
#include <privacy_pass/core/token_request.hpp>
#include <privacy_pass/core/token_response.hpp>
#include <privacy_pass/core/types.hpp>
#include <privacy_pass/crypto/blind_rsa.hpp>
#include <privacy_pass/crypto/voprf.hpp>

#include <memory>
#include <variant>

namespace privacy_pass {

// Data needed to finalize a token after receiving issuer response
struct FinalizationData {
    TokenType token_type;
    Nonce nonce;
    ChallengeDigest challenge_digest;
    TokenKeyId token_key_id;

    // Type-specific finalization data
    std::variant<crypto::BlindingData, crypto::VoprfFinalizationData> data;

    FinalizationData() = default;
    FinalizationData(FinalizationData&&) noexcept = default;
    FinalizationData& operator=(FinalizationData&&) noexcept = default;
};

// Result of creating a token request
struct TokenRequestResult {
    TokenRequest request;
    FinalizationData finalization_data;
};

// Privacy Pass Client for publicly verifiable tokens (Blind RSA)
class PublicClient {
public:
    PublicClient();
    ~PublicClient();

    PublicClient(const PublicClient&) = delete;
    PublicClient& operator=(const PublicClient&) = delete;
    PublicClient(PublicClient&&) noexcept;
    PublicClient& operator=(PublicClient&&) noexcept;

    // Create a token request from a challenge
    [[nodiscard]] Result<TokenRequestResult> create_token_request(
        const TokenChallenge& challenge,
        const crypto::BlindRsaPublicKey& issuer_key) const;

    // Finalize a token from the issuer's response
    [[nodiscard]] Result<Token> finalize(
        const TokenResponse& response,
        FinalizationData finalization_data,
        const crypto::BlindRsaPublicKey& issuer_key) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Privacy Pass Client for privately verifiable tokens (VOPRF)
class PrivateClient {
public:
    PrivateClient();
    ~PrivateClient();

    PrivateClient(const PrivateClient&) = delete;
    PrivateClient& operator=(const PrivateClient&) = delete;
    PrivateClient(PrivateClient&&) noexcept;
    PrivateClient& operator=(PrivateClient&&) noexcept;

    // Create a token request from a challenge
    [[nodiscard]] Result<TokenRequestResult> create_token_request(
        const TokenChallenge& challenge,
        const crypto::VoprfPublicKey& issuer_key) const;

    // Finalize a token from the issuer's response
    [[nodiscard]] Result<Token> finalize(
        const TokenResponse& response,
        FinalizationData finalization_data,
        const crypto::VoprfPublicKey& issuer_key) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Unified client that handles both token types
class Client {
public:
    Client();
    ~Client();

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) noexcept;
    Client& operator=(Client&&) noexcept;

    // Create a token request (automatically selects based on challenge type)
    [[nodiscard]] Result<TokenRequestResult> create_token_request(
        const TokenChallenge& challenge,
        const PublicKey& issuer_key) const;

    // Finalize a token
    [[nodiscard]] Result<Token> finalize(
        const TokenResponse& response,
        FinalizationData finalization_data,
        const PublicKey& issuer_key) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace privacy_pass
