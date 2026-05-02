// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/serialization.hpp>
#include <privacy_pass/core/types.hpp>

namespace privacy_pass {

// AuthenticatorInput - internal structure for computing authenticator
struct AuthenticatorInput {
    TokenType token_type;
    Nonce nonce;
    ChallengeDigest challenge_digest;
    TokenKeyId token_key_id;

    [[nodiscard]] Result<Bytes> serialize() const;
    [[nodiscard]] static Result<AuthenticatorInput> deserialize(ByteView data);
    [[nodiscard]] size_t serialized_size() const noexcept;
};

// Token structure (RFC 9578)
// Final token presented by Client to Origin for redemption
struct Token {
    TokenType token_type;
    Nonce nonce;
    ChallengeDigest challenge_digest;
    TokenKeyId token_key_id;
    Bytes authenticator;  // Nk bytes (256 for RSA, 48 for VOPRF P-384)

    // Create a token
    static Token create(
        TokenType type,
        Nonce nonce,
        ChallengeDigest digest,
        TokenKeyId key_id,
        Bytes auth);

    // Serialize to wire format
    [[nodiscard]] Result<Bytes> serialize() const;

    // Deserialize from wire format
    [[nodiscard]] static Result<Token> deserialize(ByteView data);

    // Get the authenticator input portion
    [[nodiscard]] AuthenticatorInput authenticator_input() const;

    // Serialized size
    [[nodiscard]] size_t serialized_size() const noexcept;

    // Validate structure (not cryptographic validation)
    [[nodiscard]] Result<void> validate() const;
};

}  // namespace privacy_pass
