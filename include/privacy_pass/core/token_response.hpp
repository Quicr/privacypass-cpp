// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/serialization.hpp>
#include <privacy_pass/core/types.hpp>

#include <optional>
#include <variant>
#include <vector>

namespace privacy_pass {

// Blind RSA token response
struct BlindRsaTokenResponse {
    Bytes blind_sig;  // Nk = 256 bytes

    [[nodiscard]] Result<Bytes> serialize() const;
    [[nodiscard]] static Result<BlindRsaTokenResponse> deserialize(ByteView data);
    [[nodiscard]] size_t serialized_size() const noexcept { return blind_sig.size(); }
};

// VOPRF token response (P-384)
struct VoprfTokenResponse {
    Bytes evaluate_msg;   // Ne = 49 bytes (compressed P-384 point)
    Bytes evaluate_proof; // 2*Ns = 96 bytes (DLEQ proof)

    [[nodiscard]] Result<Bytes> serialize() const;
    [[nodiscard]] static Result<VoprfTokenResponse> deserialize(ByteView data);
    [[nodiscard]] size_t serialized_size() const noexcept {
        return evaluate_msg.size() + evaluate_proof.size();
    }
};

// Generic token response that can hold any type
using TokenResponseVariant = std::variant<BlindRsaTokenResponse, VoprfTokenResponse>;

struct TokenResponse {
    TokenType token_type;
    TokenResponseVariant response;

    // Create responses for specific types
    static TokenResponse create_blind_rsa(Bytes blind_sig);
    static TokenResponse create_voprf(Bytes evaluate_msg, Bytes evaluate_proof);

    [[nodiscard]] Result<Bytes> serialize() const;
    [[nodiscard]] static Result<TokenResponse> deserialize(TokenType type, ByteView data);
    [[nodiscard]] size_t serialized_size() const noexcept;

    // Accessors
    [[nodiscard]] const BlindRsaTokenResponse* as_blind_rsa() const noexcept {
        return std::get_if<BlindRsaTokenResponse>(&response);
    }

    [[nodiscard]] const VoprfTokenResponse* as_voprf() const noexcept {
        return std::get_if<VoprfTokenResponse>(&response);
    }
};

// Optional token response for batched responses
struct OptionalTokenResponse {
    bool present;
    std::optional<TokenResponse> response;

    [[nodiscard]] Result<Bytes> serialize() const;
    [[nodiscard]] static Result<OptionalTokenResponse> deserialize(ByteView data);
};

// Batched token response
struct BatchedTokenResponse {
    std::vector<OptionalTokenResponse> responses;

    [[nodiscard]] Result<Bytes> serialize() const;
    [[nodiscard]] static Result<BatchedTokenResponse> deserialize(ByteView data);
};

}  // namespace privacy_pass
