// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/core/token_challenge.hpp>
#include <privacy_pass/crypto/hash.hpp>

#include <spdlog/spdlog.h>

namespace privacy_pass {

TokenChallenge TokenChallenge::create(
    TokenType type,
    std::string issuer,
    std::optional<ChallengeDigest> context,
    std::vector<std::string> origins) {

    return TokenChallenge{
        .token_type = type,
        .issuer_name = std::move(issuer),
        .redemption_context = context,
        .origin_info = std::move(origins),
    };
}

std::string TokenChallenge::origin_info_string() const {
    std::string result;
    for (size_t i = 0; i < origin_info.size(); ++i) {
        if (i > 0) result += ',';
        result += origin_info[i];
    }
    return result;
}

size_t TokenChallenge::serialized_size() const noexcept {
    size_t size = 2;  // token_type
    size += 2 + issuer_name.size();  // length-prefixed issuer_name
    size += 1;  // redemption_context length
    if (redemption_context) {
        size += 32;  // Fixed 32 bytes
    }

    std::string origin_str = origin_info_string();
    size += 2 + origin_str.size();  // length-prefixed origin_info

    return size;
}

Result<Bytes> TokenChallenge::serialize() const {
    if (issuer_name.empty() || issuer_name.size() > 0xFFFF) {
        return std::unexpected(Error{ErrorCode::INVALID_LENGTH,
            "issuer_name length must be 1..65535"});
    }

    std::string origin_str = origin_info_string();
    if (origin_str.size() > 0xFFFF) {
        return std::unexpected(Error{ErrorCode::INVALID_LENGTH,
            "origin_info length must be <= 65535"});
    }

    ByteWriter writer(serialized_size());

    // token_type (2 bytes)
    writer.write_u16(static_cast<uint16_t>(token_type));

    // issuer_name (length-prefixed, 2 bytes)
    writer.write_u16(static_cast<uint16_t>(issuer_name.size()));
    writer.write_bytes(ByteView(
        reinterpret_cast<const uint8_t*>(issuer_name.data()),
        issuer_name.size()));

    // redemption_context (length-prefixed, 0 or 32 bytes)
    if (redemption_context) {
        writer.write_u8(32);
        writer.write_array(*redemption_context);
    } else {
        writer.write_u8(0);
    }

    // origin_info (length-prefixed, 2 bytes)
    writer.write_u16(static_cast<uint16_t>(origin_str.size()));
    if (!origin_str.empty()) {
        writer.write_bytes(ByteView(
            reinterpret_cast<const uint8_t*>(origin_str.data()),
            origin_str.size()));
    }

    return writer.take();
}

Result<TokenChallenge> TokenChallenge::deserialize(ByteView data) {
    ByteReader reader(data);

    // token_type
    auto type = reader.read_u16();
    if (!type) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read token_type"});
    }

    // issuer_name
    auto issuer_len = reader.read_u16();
    if (!issuer_len) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read issuer_name length"});
    }

    auto issuer_bytes = reader.read_bytes(*issuer_len);
    if (!issuer_bytes) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read issuer_name"});
    }

    TokenChallenge challenge;
    challenge.token_type = static_cast<TokenType>(*type);
    challenge.issuer_name = std::string(
        reinterpret_cast<const char*>(issuer_bytes->data()),
        issuer_bytes->size());

    auto context_len = reader.read_u8();
    if (!context_len) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read redemption_context length"});
    }

    if (*context_len != 0 && *context_len != 32) {
        return std::unexpected(Error{ErrorCode::INVALID_LENGTH,
            "redemption_context length must be 0 or 32"});
    }

    if (*context_len == 32) {
        auto context = reader.read_array<32>();
        if (!context) {
            return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read redemption_context"});
        }
        challenge.redemption_context = *context;
    }

    auto origin_len = reader.read_u16();
    if (!origin_len) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read origin_info length"});
    }

    if (*origin_len > 0) {
        auto origin_bytes = reader.read_bytes(*origin_len);
        if (!origin_bytes) {
            return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read origin_info"});
        }

        std::string origin_str(
            reinterpret_cast<const char*>(origin_bytes->data()),
            origin_bytes->size());

        size_t pos = 0;
        while (pos < origin_str.size()) {
            size_t comma = origin_str.find(',', pos);
            if (comma == std::string::npos) {
                challenge.origin_info.push_back(origin_str.substr(pos));
                break;
            }
            challenge.origin_info.push_back(origin_str.substr(pos, comma - pos));
            pos = comma + 1;
        }
    }

    if (!reader.empty()) {
        return std::unexpected(Error{ErrorCode::MALFORMED_DATA, "Trailing TokenChallenge data"});
    }

    return challenge;
}

Result<ChallengeDigest> TokenChallenge::digest() const {
    auto serialized = serialize();
    if (!serialized) {
        return std::unexpected(serialized.error());
    }

    return crypto::sha256(ByteView(serialized->data(), serialized->size()));
}

}  // namespace privacy_pass
