// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/serialization.hpp>
#include <privacy_pass/core/types.hpp>

#include <optional>
#include <string>
#include <vector>

namespace privacy_pass {

// TokenChallenge structure (RFC 9578)
// Sent by Origin to Client to initiate token request
struct TokenChallenge {
    TokenType token_type;
    std::string issuer_name;                    // 1..2^16-1 bytes
    std::optional<ChallengeDigest> redemption_context;  // 0 or 32 bytes
    std::vector<std::string> origin_info;       // Comma-separated in wire format

    // Create a challenge
    static TokenChallenge create(
        TokenType type,
        std::string issuer,
        std::optional<ChallengeDigest> context = std::nullopt,
        std::vector<std::string> origins = {});

    // Serialize to wire format
    [[nodiscard]] Result<Bytes> serialize() const;

    // Deserialize from wire format (zero-copy where possible)
    [[nodiscard]] static Result<TokenChallenge> deserialize(ByteView data);

    // Compute SHA-256 digest of serialized challenge
    [[nodiscard]] Result<ChallengeDigest> digest() const;

    // Get origin_info as comma-separated string
    [[nodiscard]] std::string origin_info_string() const;

    // Serialized size
    [[nodiscard]] size_t serialized_size() const noexcept;
};

}  // namespace privacy_pass
