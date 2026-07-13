// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/crypto/random.hpp>

#include <openssl/rand.h>

namespace privacy_pass::crypto {

constexpr size_t MAX_RANDOM_SIZE = static_cast<size_t>(INT_MAX);

Result<Bytes> random_bytes(size_t count) {
    if (count > MAX_RANDOM_SIZE) {
        return std::unexpected(Error{ErrorCode::RANDOM_GENERATION_FAILED,
            "Requested random size too large"});
    }
    Bytes result(count);
    if (RAND_bytes(result.data(), static_cast<int>(count)) != 1) {
        return std::unexpected(Error{ErrorCode::RANDOM_GENERATION_FAILED,
            "Failed to generate random bytes"});
    }
    return result;
}

Result<void> random_fill(MutableByteView buffer) {
    if (buffer.size() > MAX_RANDOM_SIZE) {
        return std::unexpected(Error{ErrorCode::RANDOM_GENERATION_FAILED,
            "Buffer size too large"});
    }
    if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1) {
        return std::unexpected(Error{ErrorCode::RANDOM_GENERATION_FAILED,
            "Failed to fill buffer with random bytes"});
    }
    return {};
}

Result<Nonce> random_nonce() {
    Nonce result;
    if (RAND_bytes(result.data(), static_cast<int>(result.size())) != 1) {
        return std::unexpected(Error{ErrorCode::RANDOM_GENERATION_FAILED,
            "Failed to generate random nonce"});
    }
    return result;
}

Result<uint64_t> random_u64() {
    uint64_t result;
    if (RAND_bytes(reinterpret_cast<uint8_t*>(&result), sizeof(result)) != 1) {
        return std::unexpected(Error{ErrorCode::RANDOM_GENERATION_FAILED,
            "Failed to generate random uint64"});
    }
    return result;
}

}  // namespace privacy_pass::crypto
