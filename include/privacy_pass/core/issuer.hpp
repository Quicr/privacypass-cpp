// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/token.hpp>
#include <privacy_pass/core/token_request.hpp>
#include <privacy_pass/core/token_response.hpp>
#include <privacy_pass/core/types.hpp>
#include <privacy_pass/crypto/blind_rsa.hpp>
#include <privacy_pass/crypto/voprf.hpp>

#include <memory>
#include <unordered_map>
#include <vector>

namespace privacy_pass {

// Issuer configuration
struct IssuerConfig {
    std::string issuer_request_uri;
    std::vector<PublicKey> token_keys;
    std::optional<uint64_t> not_before;  // Unix timestamp
};

// Privacy Pass Issuer for publicly verifiable tokens (Blind RSA)
class PublicIssuer {
public:
    explicit PublicIssuer(crypto::BlindRsaPrivateKey private_key);
    ~PublicIssuer();

    PublicIssuer(const PublicIssuer&) = delete;
    PublicIssuer& operator=(const PublicIssuer&) = delete;
    PublicIssuer(PublicIssuer&&) noexcept;
    PublicIssuer& operator=(PublicIssuer&&) noexcept;

    // Generate a new issuer with fresh keys
    [[nodiscard]] static Result<PublicIssuer> generate();

    // Issue a token response for a request
    [[nodiscard]] Result<TokenResponse> issue(const TokenRequest& request) const;

    // Issue multiple tokens (batched)
    [[nodiscard]] Result<BatchedTokenResponse> issue_batch(
        const BatchedTokenRequest& requests) const;

    // Get the public key
    [[nodiscard]] Result<crypto::BlindRsaPublicKey> public_key() const;

    // Get truncated key ID
    [[nodiscard]] uint8_t truncated_key_id() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Privacy Pass Issuer for privately verifiable tokens (VOPRF)
class PrivateIssuer {
public:
    explicit PrivateIssuer(crypto::VoprfPrivateKey private_key);
    ~PrivateIssuer();

    PrivateIssuer(const PrivateIssuer&) = delete;
    PrivateIssuer& operator=(const PrivateIssuer&) = delete;
    PrivateIssuer(PrivateIssuer&&) noexcept;
    PrivateIssuer& operator=(PrivateIssuer&&) noexcept;

    // Generate a new issuer with fresh keys
    [[nodiscard]] static Result<PrivateIssuer> generate();

    // Issue a token response for a request
    [[nodiscard]] Result<TokenResponse> issue(const TokenRequest& request) const;

    // Issue multiple tokens (batched)
    [[nodiscard]] Result<BatchedTokenResponse> issue_batch(
        const BatchedTokenRequest& requests) const;

    // Get the public key
    [[nodiscard]] Result<crypto::VoprfPublicKey> public_key() const;

    // Get truncated key ID
    [[nodiscard]] uint8_t truncated_key_id() const;

    // Verify a token (only possible for private issuers)
    [[nodiscard]] Result<bool> verify(const Token& token) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Multi-key issuer that can handle multiple active keys
class MultiKeyIssuer {
public:
    MultiKeyIssuer();
    ~MultiKeyIssuer();

    MultiKeyIssuer(const MultiKeyIssuer&) = delete;
    MultiKeyIssuer& operator=(const MultiKeyIssuer&) = delete;
    MultiKeyIssuer(MultiKeyIssuer&&) noexcept;
    MultiKeyIssuer& operator=(MultiKeyIssuer&&) noexcept;

    // Add a Blind RSA key
    Result<void> add_blind_rsa_key(crypto::BlindRsaPrivateKey key);

    // Add a VOPRF key
    Result<void> add_voprf_key(crypto::VoprfPrivateKey key);

    // Remove a key by truncated ID
    void remove_key(uint8_t truncated_key_id);

    // Issue a token (selects key based on request)
    [[nodiscard]] Result<TokenResponse> issue(const TokenRequest& request) const;

    // Get all public keys
    [[nodiscard]] std::vector<PublicKey> public_keys() const;

    // Get issuer configuration for directory endpoint
    [[nodiscard]] IssuerConfig config(std::string_view request_uri) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace privacy_pass
