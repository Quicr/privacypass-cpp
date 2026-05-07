// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/core/token_response.hpp>

#include <spdlog/spdlog.h>

namespace privacy_pass {

// BlindRsaTokenResponse implementation
Result<Bytes> BlindRsaTokenResponse::serialize() const {
    return Bytes(blind_sig.begin(), blind_sig.end());
}

Result<BlindRsaTokenResponse> BlindRsaTokenResponse::deserialize(ByteView data) {
    if (data.size() != 256) {
        return std::unexpected(Error{ErrorCode::INVALID_LENGTH,
            "Blind RSA signature must be 256 bytes"});
    }

    BlindRsaTokenResponse response;
    response.blind_sig.assign(data.begin(), data.end());
    return response;
}

// VoprfTokenResponse implementation
Result<Bytes> VoprfTokenResponse::serialize() const {
    Bytes result;
    result.reserve(evaluate_msg.size() + evaluate_proof.size());
    result.insert(result.end(), evaluate_msg.begin(), evaluate_msg.end());
    result.insert(result.end(), evaluate_proof.begin(), evaluate_proof.end());
    return result;
}

Result<VoprfTokenResponse> VoprfTokenResponse::deserialize(ByteView data) {
    constexpr size_t EXPECTED_SIZE = 97 + 96;  // Ne + 2*Ns for P-384

    if (data.size() != EXPECTED_SIZE) {
        return std::unexpected(Error{ErrorCode::INVALID_LENGTH,
            "VOPRF response must be 193 bytes"});
    }

    VoprfTokenResponse response;
    response.evaluate_msg.assign(data.begin(), data.begin() + 97);
    response.evaluate_proof.assign(data.begin() + 97, data.end());
    return response;
}

// TokenResponse implementation
TokenResponse TokenResponse::create_blind_rsa(Bytes blind_sig) {
    TokenResponse response;
    response.token_type = TokenType::BLIND_RSA;
    response.response = BlindRsaTokenResponse{.blind_sig = std::move(blind_sig)};
    return response;
}

TokenResponse TokenResponse::create_voprf(Bytes evaluate_msg, Bytes evaluate_proof) {
    TokenResponse response;
    response.token_type = TokenType::VOPRF_P384_SHA384;
    response.response = VoprfTokenResponse{
        .evaluate_msg = std::move(evaluate_msg),
        .evaluate_proof = std::move(evaluate_proof),
    };
    return response;
}

size_t TokenResponse::serialized_size() const noexcept {
    return std::visit([](const auto& r) { return r.serialized_size(); }, response);
}

Result<Bytes> TokenResponse::serialize() const {
    return std::visit([](const auto& r) { return r.serialize(); }, response);
}

Result<TokenResponse> TokenResponse::deserialize(TokenType type, ByteView data) {
    TokenResponse response;
    response.token_type = type;

    switch (type) {
        case TokenType::BLIND_RSA:
        case TokenType::PARTIALLY_BLIND_RSA: {
            auto rsa_response = BlindRsaTokenResponse::deserialize(data);
            if (!rsa_response) {
                return std::unexpected(rsa_response.error());
            }
            response.response = std::move(*rsa_response);
            break;
        }
        case TokenType::VOPRF_P384_SHA384: {
            auto voprf_response = VoprfTokenResponse::deserialize(data);
            if (!voprf_response) {
                return std::unexpected(voprf_response.error());
            }
            response.response = std::move(*voprf_response);
            break;
        }
        default:
            return std::unexpected(Error{ErrorCode::UNSUPPORTED_TOKEN_TYPE,
                "Unsupported token type"});
    }

    return response;
}

// OptionalTokenResponse implementation
Result<Bytes> OptionalTokenResponse::serialize() const {
    ByteWriter writer;

    if (!present || !response) {
        writer.write_u8(0x00);
    } else {
        writer.write_u8(0x01);
        writer.write_u16(static_cast<uint16_t>(response->token_type));
        auto resp_bytes = response->serialize();
        if (!resp_bytes) {
            return std::unexpected(resp_bytes.error());
        }
        writer.write_bytes(ByteView(resp_bytes->data(), resp_bytes->size()));
    }

    return writer.take();
}

Result<OptionalTokenResponse> OptionalTokenResponse::deserialize(ByteView data) {
    ByteReader reader(data);

    auto status = reader.read_u8();
    if (!status) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read status"});
    }

    OptionalTokenResponse result;
    result.present = (*status == 0x01);

    if (result.present) {
        auto type = reader.read_u16();
        if (!type) {
            return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read token_type"});
        }

        auto resp = TokenResponse::deserialize(
            static_cast<TokenType>(*type),
            reader.remaining_data());
        if (!resp) {
            return std::unexpected(resp.error());
        }
        result.response = std::move(*resp);
    }

    return result;
}

// BatchedTokenResponse implementation
Result<Bytes> BatchedTokenResponse::serialize() const {
    ByteWriter writer;

    writer.write_varint(responses.size());
    for (const auto& resp : responses) {
        auto serialized = resp.serialize();
        if (!serialized) {
            return std::unexpected(serialized.error());
        }
        writer.write_bytes(ByteView(serialized->data(), serialized->size()));
    }

    return writer.take();
}

// Maximum batch size to prevent memory exhaustion
constexpr uint64_t MAX_RESPONSE_BATCH_SIZE = 10000;

Result<BatchedTokenResponse> BatchedTokenResponse::deserialize(ByteView data) {
    ByteReader reader(data);

    auto count = reader.read_varint();
    if (!count) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read response count"});
    }

    // Enforce maximum batch size
    if (*count > MAX_RESPONSE_BATCH_SIZE) {
        return std::unexpected(Error{ErrorCode::MALFORMED_DATA,
            "Response batch size exceeds maximum: " + std::to_string(*count)});
    }

    BatchedTokenResponse result;
    result.responses.reserve(static_cast<size_t>(*count));

    for (uint64_t i = 0; i < *count; ++i) {
        auto resp = OptionalTokenResponse::deserialize(reader.remaining_data());
        if (!resp) {
            return std::unexpected(resp.error());
        }

        // Calculate how much to skip (simplified - real implementation needs proper length handling)
        size_t skip = 1;  // status byte
        if (resp->present && resp->response) {
            skip += 2 + resp->response->serialized_size();
        }
        reader.skip(skip);

        result.responses.push_back(std::move(*resp));
    }

    return result;
}

}  // namespace privacy_pass
