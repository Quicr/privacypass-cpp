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

    if (redemption_context) {
        size += 32;  // Fixed 32 bytes
    }

    std::string origin_str = origin_info_string();
    size += 2 + origin_str.size();  // length-prefixed origin_info

    return size;
}

Result<Bytes> TokenChallenge::serialize() const {
    ByteWriter writer(serialized_size());

    // token_type (2 bytes)
    writer.write_u16(static_cast<uint16_t>(token_type));

    // issuer_name (length-prefixed, 2 bytes)
    writer.write_u16(static_cast<uint16_t>(issuer_name.size()));
    writer.write_bytes(ByteView(
        reinterpret_cast<const uint8_t*>(issuer_name.data()),
        issuer_name.size()));

    // redemption_context (0 or 32 bytes)
    if (redemption_context) {
        writer.write_array(*redemption_context);
    }

    // origin_info (length-prefixed, 2 bytes)
    std::string origin_str = origin_info_string();
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

    // Per RFC 9578: The format is:
    // struct {
    //   uint16 token_type;
    //   opaque issuer_name<1..2^16-1>;
    //   opaque redemption_context<0..32>;  // 0 or 32 bytes
    //   opaque origin_info<0..2^16-1>;
    // }
    //
    // redemption_context is either 0 or 32 bytes.
    // We need to parse based on token type semantics and remaining data.
    //
    // Strategy: Calculate expected remaining size with and without context.
    // If remaining >= 34 (32 context + 2 origin_len), try to read context first.
    // If remaining == 2 (just origin_len of 0), no context.

    size_t remaining = reader.remaining();

    if (remaining < 2) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Missing origin_info length"});
    }

    // Peek at what would be origin_len if there's no redemption_context
    size_t saved_pos = reader.position();

    // First, try parsing WITHOUT redemption_context
    auto potential_origin_len = reader.read_u16();
    if (!potential_origin_len) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read potential origin_len"});
    }

    // Check if remaining data (after this u16) matches the length we just read
    size_t remaining_after_len = reader.remaining();

    if (remaining_after_len == *potential_origin_len) {
        // This looks like the correct interpretation: no redemption_context
        // Read origin_info
        if (*potential_origin_len > 0) {
            auto origin_bytes = reader.read_bytes(*potential_origin_len);
            if (!origin_bytes) {
                return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read origin_info"});
            }

            std::string origin_str(
                reinterpret_cast<const char*>(origin_bytes->data()),
                origin_bytes->size());

            // Parse comma-separated origins
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
        return challenge;
    }

    // Reset and try WITH redemption_context
    // We need to re-read from the saved position
    // Unfortunately ByteReader doesn't have seek, so we recreate from remaining
    ByteReader reader2(data.subspan(saved_pos));

    if (reader2.remaining() >= 34) {  // 32 (context) + 2 (origin_len min)
        auto context = reader2.read_array<32>();
        if (context) {
            challenge.redemption_context = *context;
        }

        auto origin_len = reader2.read_u16();
        if (!origin_len) {
            return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read origin_info length"});
        }

        if (*origin_len > 0) {
            auto origin_bytes = reader2.read_bytes(*origin_len);
            if (!origin_bytes) {
                return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read origin_info"});
            }

            std::string origin_str(
                reinterpret_cast<const char*>(origin_bytes->data()),
                origin_bytes->size());

            // Parse comma-separated origins
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
        return challenge;
    }

    return std::unexpected(Error{ErrorCode::MALFORMED_DATA, "Could not determine redemption_context presence"});
}

Result<ChallengeDigest> TokenChallenge::digest() const {
    auto serialized = serialize();
    if (!serialized) {
        return std::unexpected(serialized.error());
    }

    return crypto::sha256(ByteView(serialized->data(), serialized->size()));
}

}  // namespace privacy_pass
