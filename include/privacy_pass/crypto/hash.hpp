// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/types.hpp>

namespace privacy_pass::crypto {

// SHA-256 hash
[[nodiscard]] Result<Hash256> sha256(ByteView data);

// SHA-384 hash
[[nodiscard]] Result<Hash384> sha384(ByteView data);

// Incremental SHA-256 hasher
class Sha256Hasher {
public:
    Sha256Hasher();
    ~Sha256Hasher();

    Sha256Hasher(const Sha256Hasher&) = delete;
    Sha256Hasher& operator=(const Sha256Hasher&) = delete;
    Sha256Hasher(Sha256Hasher&&) noexcept;
    Sha256Hasher& operator=(Sha256Hasher&&) noexcept;

    void update(ByteView data);
    [[nodiscard]] Result<Hash256> finalize();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Incremental SHA-384 hasher
class Sha384Hasher {
public:
    Sha384Hasher();
    ~Sha384Hasher();

    Sha384Hasher(const Sha384Hasher&) = delete;
    Sha384Hasher& operator=(const Sha384Hasher&) = delete;
    Sha384Hasher(Sha384Hasher&&) noexcept;
    Sha384Hasher& operator=(Sha384Hasher&&) noexcept;

    void update(ByteView data);
    [[nodiscard]] Result<Hash384> finalize();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// HMAC-SHA256
[[nodiscard]] Result<Hash256> hmac_sha256(ByteView key, ByteView data);

// HKDF-Extract and Expand (RFC 5869)
[[nodiscard]] Result<Bytes> hkdf_extract_sha256(ByteView salt, ByteView ikm);
[[nodiscard]] Result<Bytes> hkdf_expand_sha256(ByteView prk, ByteView info, size_t length);

}  // namespace privacy_pass::crypto
