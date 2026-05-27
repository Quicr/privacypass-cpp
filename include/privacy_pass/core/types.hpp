// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <openssl/crypto.h>

namespace privacy_pass {

// Token type constants (RFC 9578)
enum class TokenType : uint16_t {
    VOPRF_P384_SHA384 = 0x0001,
    BLIND_RSA = 0x0002,
    VOPRF_RISTRETTO255_SHA512 = 0x0005,
    PARTIALLY_BLIND_RSA = 0xDA7A,
    ARC_P256 = 0xE5AC,
};

// Error codes for Privacy Pass operations
enum class ErrorCode : uint16_t {
    OK = 0,

    // Serialization errors
    BUFFER_TOO_SMALL = 0x0010,
    INVALID_LENGTH = 0x0011,
    MALFORMED_DATA = 0x0012,
    UNEXPECTED_END = 0x0013,

    // Crypto errors
    CRYPTO_ERROR = 0x0020,
    INVALID_KEY = 0x0021,
    INVALID_SIGNATURE = 0x0022,
    BLINDING_FAILED = 0x0023,
    UNBLINDING_FAILED = 0x0024,
    VERIFICATION_FAILED = 0x0025,
    RANDOM_GENERATION_FAILED = 0x0026,

    // Token errors
    TOKEN_MISSING = 0x0100,
    TOKEN_INVALID = 0x0101,
    TOKEN_EXPIRED = 0x0102,
    TOKEN_REPLAYED = 0x0103,
    SCOPE_MISMATCH = 0x0104,
    ISSUER_UNKNOWN = 0x0105,
    TOKEN_MALFORMED = 0x0106,
    UNSUPPORTED_TOKEN_TYPE = 0x0107,
    INVALID_CHALLENGE = 0x0108,

    // HTTP errors
    INVALID_HEADER = 0x0200,
    MISSING_PARAMETER = 0x0201,
    INVALID_BASE64 = 0x0202,
};

// Error with context
struct Error {
    ErrorCode code;
    std::string message;

    Error(ErrorCode c) : code(c) {}
    Error(ErrorCode c, std::string msg) : code(c), message(std::move(msg)) {}

    [[nodiscard]] bool is_ok() const noexcept { return code == ErrorCode::OK; }
    [[nodiscard]] explicit operator bool() const noexcept { return !is_ok(); }
};

// Result type for operations that can fail
template <typename T>
using Result = std::expected<T, Error>;

// Byte buffer types - zero-copy where possible
using Bytes = std::vector<uint8_t>;
using ByteView = std::span<const uint8_t>;
using MutableByteView = std::span<uint8_t>;

// Fixed-size byte arrays for common sizes
using Nonce = std::array<uint8_t, 32>;
using ChallengeDigest = std::array<uint8_t, 32>;
using TokenKeyId = std::array<uint8_t, 32>;
using Hash256 = std::array<uint8_t, 32>;
using Hash384 = std::array<uint8_t, 48>;

// Token type size constants
struct TokenTypeInfo {
    TokenType type;
    size_t authenticator_size;  // Nk
    size_t key_id_size;         // Nid
    size_t blinded_element_size;
    bool publicly_verifiable;

    static constexpr TokenTypeInfo for_type(TokenType t) noexcept {
        switch (t) {
            case TokenType::VOPRF_P384_SHA384:
                return {t, 48, 32, 49, false};
            case TokenType::BLIND_RSA:
                return {t, 256, 32, 256, true};
            case TokenType::VOPRF_RISTRETTO255_SHA512:
                return {t, 64, 32, 32, false};
            case TokenType::PARTIALLY_BLIND_RSA:
                return {t, 256, 32, 256, true};
            case TokenType::ARC_P256:
                return {t, 65, 32, 65, false};  // TBD values
            default:
                return {t, 0, 0, 0, false};
        }
    }
};

// Secure byte buffer that zeros memory on destruction
class SecureBytes {
public:
    SecureBytes() = default;
    explicit SecureBytes(size_t size) : data_(size) {}
    SecureBytes(ByteView data) : data_(data.begin(), data.end()) {}
    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;
    SecureBytes(SecureBytes&& other) noexcept : data_(std::move(other.data_)) {}
    SecureBytes& operator=(SecureBytes&& other) noexcept {
        if (this != &other) {
            clear();
            data_ = std::move(other.data_);
        }
        return *this;
    }

    ~SecureBytes() { clear(); }

    void clear() noexcept {
        if (!data_.empty()) {
            // Use OPENSSL_cleanse for guaranteed secure memory clearing
            OPENSSL_cleanse(data_.data(), data_.size());
            data_.clear();
        }
    }

    void resize(size_t size) { data_.resize(size); }

    [[nodiscard]] uint8_t* data() noexcept { return data_.data(); }
    [[nodiscard]] const uint8_t* data() const noexcept { return data_.data(); }
    [[nodiscard]] size_t size() const noexcept { return data_.size(); }
    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }

    [[nodiscard]] ByteView view() const noexcept { return {data_.data(), data_.size()}; }
    [[nodiscard]] MutableByteView mutable_view() noexcept { return {data_.data(), data_.size()}; }

    [[nodiscard]] uint8_t& operator[](size_t i) noexcept { return data_[i]; }
    [[nodiscard]] const uint8_t& operator[](size_t i) const noexcept { return data_[i]; }

private:
    std::vector<uint8_t> data_;
};

// Key types
struct PublicKey {
    TokenType type;
    Bytes data;
    TokenKeyId key_id;

    [[nodiscard]] ByteView view() const noexcept { return {data.data(), data.size()}; }
    [[nodiscard]] uint8_t truncated_key_id() const noexcept { return key_id[31]; }
};

struct PrivateKey {
    TokenType type;
    SecureBytes data;

    [[nodiscard]] ByteView view() const noexcept { return data.view(); }
};

struct KeyPair {
    PublicKey public_key;
    PrivateKey private_key;
};

// String conversion utilities
[[nodiscard]] constexpr std::string_view token_type_name(TokenType type) noexcept {
    switch (type) {
        case TokenType::VOPRF_P384_SHA384:
            return "VOPRF-P384-SHA384";
        case TokenType::BLIND_RSA:
            return "Blind-RSA";
        case TokenType::VOPRF_RISTRETTO255_SHA512:
            return "VOPRF-ristretto255-SHA512";
        case TokenType::PARTIALLY_BLIND_RSA:
            return "Partially-Blind-RSA";
        case TokenType::ARC_P256:
            return "ARC-P256";
        default:
            return "Unknown";
    }
}

[[nodiscard]] constexpr std::string_view error_code_name(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::OK:
            return "OK";
        case ErrorCode::BUFFER_TOO_SMALL:
            return "BUFFER_TOO_SMALL";
        case ErrorCode::INVALID_LENGTH:
            return "INVALID_LENGTH";
        case ErrorCode::MALFORMED_DATA:
            return "MALFORMED_DATA";
        case ErrorCode::UNEXPECTED_END:
            return "UNEXPECTED_END";
        case ErrorCode::CRYPTO_ERROR:
            return "CRYPTO_ERROR";
        case ErrorCode::INVALID_KEY:
            return "INVALID_KEY";
        case ErrorCode::INVALID_SIGNATURE:
            return "INVALID_SIGNATURE";
        case ErrorCode::BLINDING_FAILED:
            return "BLINDING_FAILED";
        case ErrorCode::UNBLINDING_FAILED:
            return "UNBLINDING_FAILED";
        case ErrorCode::VERIFICATION_FAILED:
            return "VERIFICATION_FAILED";
        case ErrorCode::RANDOM_GENERATION_FAILED:
            return "RANDOM_GENERATION_FAILED";
        case ErrorCode::TOKEN_MISSING:
            return "TOKEN_MISSING";
        case ErrorCode::TOKEN_INVALID:
            return "TOKEN_INVALID";
        case ErrorCode::TOKEN_EXPIRED:
            return "TOKEN_EXPIRED";
        case ErrorCode::TOKEN_REPLAYED:
            return "TOKEN_REPLAYED";
        case ErrorCode::SCOPE_MISMATCH:
            return "SCOPE_MISMATCH";
        case ErrorCode::ISSUER_UNKNOWN:
            return "ISSUER_UNKNOWN";
        case ErrorCode::TOKEN_MALFORMED:
            return "TOKEN_MALFORMED";
        case ErrorCode::UNSUPPORTED_TOKEN_TYPE:
            return "UNSUPPORTED_TOKEN_TYPE";
        case ErrorCode::INVALID_CHALLENGE:
            return "INVALID_CHALLENGE";
        case ErrorCode::INVALID_HEADER:
            return "INVALID_HEADER";
        case ErrorCode::MISSING_PARAMETER:
            return "MISSING_PARAMETER";
        case ErrorCode::INVALID_BASE64:
            return "INVALID_BASE64";
        default:
            return "UNKNOWN";
    }
}

}  // namespace privacy_pass
