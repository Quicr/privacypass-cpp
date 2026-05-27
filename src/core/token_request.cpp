// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/core/token_request.hpp>

#include <spdlog/spdlog.h>

namespace privacy_pass {

TokenRequest TokenRequest::create(
    TokenType type,
    uint8_t truncated_key_id,
    Bytes blinded_message) {

    return TokenRequest{
        .token_type = type,
        .truncated_token_key_id = truncated_key_id,
        .blinded_msg = std::move(blinded_message),
    };
}

size_t TokenRequest::serialized_size() const noexcept {
    return 2 + 1 + blinded_msg.size();  // type + key_id + blinded_msg
}

Result<Bytes> TokenRequest::serialize() const {
    ByteWriter writer(serialized_size());

    writer.write_u16(static_cast<uint16_t>(token_type));
    writer.write_u8(truncated_token_key_id);
    writer.write_bytes(ByteView(blinded_msg.data(), blinded_msg.size()));

    return writer.take();
}

Result<TokenRequest> TokenRequest::deserialize(ByteView data) {
    ByteReader reader(data);

    auto type = reader.read_u16();
    if (!type) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read token_type"});
    }

    auto key_id = reader.read_u8();
    if (!key_id) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read key_id"});
    }

    TokenRequest request;
    request.token_type = static_cast<TokenType>(*type);
    request.truncated_token_key_id = *key_id;

    // Determine blinded message size based on token type
    auto info = TokenTypeInfo::for_type(request.token_type);
    size_t blinded_size = info.blinded_element_size;

    if (reader.remaining() < blinded_size) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Insufficient data for blinded_msg"});
    }

    auto blinded = reader.read_bytes(blinded_size);
    if (!blinded) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read blinded_msg"});
    }

    request.blinded_msg.assign(blinded->begin(), blinded->end());

    if (!reader.empty()) {
        return std::unexpected(Error{ErrorCode::MALFORMED_DATA, "Trailing TokenRequest data"});
    }

    return request;
}

// BatchedTokenRequest implementation
size_t BatchedTokenRequest::serialized_size() const noexcept {
    size_t payload_size = 0;
    for (const auto& req : requests) {
        payload_size += req.serialized_size();
    }
    return varint_size(payload_size) + payload_size;
}

Result<Bytes> BatchedTokenRequest::serialize() const {
    ByteWriter writer(serialized_size());

    size_t payload_size = 0;
    for (const auto& req : requests) {
        payload_size += req.serialized_size();
    }
    writer.write_varint(payload_size);

    for (const auto& req : requests) {
        auto serialized = req.serialize();
        if (!serialized) {
            return std::unexpected(serialized.error());
        }
        writer.write_bytes(ByteView(serialized->data(), serialized->size()));
    }

    return writer.take();
}

// Maximum batch size to prevent memory exhaustion
constexpr size_t MAX_BATCH_SIZE = 10000;
constexpr uint64_t MAX_BATCH_PAYLOAD_SIZE = 65535;

Result<BatchedTokenRequest> BatchedTokenRequest::deserialize(ByteView data) {
    ByteReader reader(data);

    auto payload_size_value = reader.read_varint();
    if (!payload_size_value) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read batch size"});
    }
    if (*payload_size_value > MAX_BATCH_PAYLOAD_SIZE) {
        return std::unexpected(Error{ErrorCode::MALFORMED_DATA, "Batch payload too large"});
    }

    auto payload = reader.read_bytes(static_cast<size_t>(*payload_size_value));
    if (!payload) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read batch payload"});
    }
    if (!reader.empty()) {
        return std::unexpected(Error{ErrorCode::MALFORMED_DATA, "Trailing BatchedTokenRequest data"});
    }

    ByteReader payload_reader(*payload);

    BatchedTokenRequest result;

    while (!payload_reader.empty()) {
        if (result.requests.size() >= MAX_BATCH_SIZE) {
            return std::unexpected(Error{ErrorCode::MALFORMED_DATA,
                "Batch size exceeds maximum"});
        }

        auto remaining = payload_reader.remaining_data();
        if (remaining.size() < 3) {
            return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read request header"});
        }

        const auto type = static_cast<TokenType>(
            (static_cast<uint16_t>(remaining[0]) << 8) | remaining[1]);
        const auto info = TokenTypeInfo::for_type(type);
        if (info.blinded_element_size == 0) {
            return std::unexpected(Error{ErrorCode::UNSUPPORTED_TOKEN_TYPE,
                "Unsupported batched request token type"});
        }

        const size_t request_size = 2 + 1 + info.blinded_element_size;
        auto request_bytes = payload_reader.read_bytes(request_size);
        if (!request_bytes) {
            return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read request"});
        }

        auto req = TokenRequest::deserialize(*request_bytes);
        if (!req) {
            return std::unexpected(req.error());
        }

        result.requests.push_back(std::move(*req));
    }

    return result;
}

}  // namespace privacy_pass
