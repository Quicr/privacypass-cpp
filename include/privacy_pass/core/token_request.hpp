// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/serialization.hpp>
#include <privacy_pass/core/types.hpp>

#include <vector>

namespace privacy_pass {

// TokenRequest structure (RFC 9578)
// Sent by Client to Issuer to request a blind signature
struct TokenRequest {
    TokenType token_type;
    uint8_t truncated_token_key_id;  // LSB of full key ID
    Bytes blinded_msg;               // Nk bytes for RSA, 49 bytes for VOPRF P-384

    // Create a token request
    static TokenRequest create(
        TokenType type,
        uint8_t truncated_key_id,
        Bytes blinded_message);

    // Serialize to wire format
    [[nodiscard]] Result<Bytes> serialize() const;

    // Deserialize from wire format
    [[nodiscard]] static Result<TokenRequest> deserialize(ByteView data);

    // Serialized size
    [[nodiscard]] size_t serialized_size() const noexcept;
};

// BatchedTokenRequest for requesting multiple tokens
struct BatchedTokenRequest {
    std::vector<TokenRequest> requests;

    [[nodiscard]] Result<Bytes> serialize() const;
    [[nodiscard]] static Result<BatchedTokenRequest> deserialize(ByteView data);
    [[nodiscard]] size_t serialized_size() const noexcept;
};

}  // namespace privacy_pass
