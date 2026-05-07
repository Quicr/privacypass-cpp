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

    return request;
}

// BatchedTokenRequest implementation
size_t BatchedTokenRequest::serialized_size() const noexcept {
    size_t size = varint_size(requests.size());
    for (const auto& req : requests) {
        size += req.serialized_size();
    }
    return size;
}

Result<Bytes> BatchedTokenRequest::serialize() const {
    ByteWriter writer(serialized_size());

    writer.write_varint(requests.size());
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
constexpr uint64_t MAX_BATCH_SIZE = 10000;

Result<BatchedTokenRequest> BatchedTokenRequest::deserialize(ByteView data) {
    ByteReader reader(data);

    auto count = reader.read_varint();
    if (!count) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read request count"});
    }

    // Enforce maximum batch size
    if (*count > MAX_BATCH_SIZE) {
        return std::unexpected(Error{ErrorCode::MALFORMED_DATA,
            "Batch size exceeds maximum: " + std::to_string(*count)});
    }

    BatchedTokenRequest result;
    result.requests.reserve(static_cast<size_t>(*count));

    for (uint64_t i = 0; i < *count; ++i) {
        // Read type to determine size
        auto type_peek = reader.peek_u8();
        if (!type_peek) {
            return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to peek token_type"});
        }

        // Parse individual request from remaining data
        auto req = TokenRequest::deserialize(reader.remaining_data());
        if (!req) {
            return std::unexpected(req.error());
        }

        // Skip past the request we just parsed
        reader.skip(req->serialized_size());

        result.requests.push_back(std::move(*req));
    }

    return result;
}

}  // namespace privacy_pass
