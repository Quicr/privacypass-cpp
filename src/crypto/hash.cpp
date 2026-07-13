// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/crypto/hash.hpp>

#include "compat.hpp"

#include <openssl/hmac.h>

namespace privacy_pass::crypto {

using namespace detail;

constexpr size_t MAX_INPUT_SIZE = static_cast<size_t>(INT_MAX);

Result<Hash256> sha256(ByteView data) {
    Hash256 result;
    auto ctx = make_evp_md_ctx();
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create hash context"});
    }
    unsigned int len = 0;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), result.data(), &len) != 1 || len != 32) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "SHA-256 computation failed"});
    }
    return result;
}

Result<Hash384> sha384(ByteView data) {
    Hash384 result;
    auto ctx = make_evp_md_ctx();
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create hash context"});
    }
    unsigned int len = 0;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha384(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), result.data(), &len) != 1 || len != 48) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "SHA-384 computation failed"});
    }
    return result;
}

struct Sha256Hasher::Impl {
    UniqueEVP_MD_CTX ctx;
    Impl() : ctx(make_evp_md_ctx()) {
        if (ctx) EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr);
    }
};

Sha256Hasher::Sha256Hasher() : impl_(std::make_unique<Impl>()) {}
Sha256Hasher::~Sha256Hasher() = default;
Sha256Hasher::Sha256Hasher(Sha256Hasher&&) noexcept = default;
Sha256Hasher& Sha256Hasher::operator=(Sha256Hasher&&) noexcept = default;

void Sha256Hasher::update(ByteView data) {
    if (impl_ && impl_->ctx) EVP_DigestUpdate(impl_->ctx.get(), data.data(), data.size());
}

Result<Hash256> Sha256Hasher::finalize() {
    if (!impl_ || !impl_->ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Invalid hasher state"});
    }
    Hash256 result;
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(impl_->ctx.get(), result.data(), &len) != 1 || len != 32) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Finalize failed"});
    }
    return result;
}

struct Sha384Hasher::Impl {
    UniqueEVP_MD_CTX ctx;
    Impl() : ctx(make_evp_md_ctx()) {
        if (ctx) EVP_DigestInit_ex(ctx.get(), EVP_sha384(), nullptr);
    }
};

Sha384Hasher::Sha384Hasher() : impl_(std::make_unique<Impl>()) {}
Sha384Hasher::~Sha384Hasher() = default;
Sha384Hasher::Sha384Hasher(Sha384Hasher&&) noexcept = default;
Sha384Hasher& Sha384Hasher::operator=(Sha384Hasher&&) noexcept = default;

void Sha384Hasher::update(ByteView data) {
    if (impl_ && impl_->ctx) EVP_DigestUpdate(impl_->ctx.get(), data.data(), data.size());
}

Result<Hash384> Sha384Hasher::finalize() {
    if (!impl_ || !impl_->ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Invalid hasher state"});
    }
    Hash384 result;
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(impl_->ctx.get(), result.data(), &len) != 1 || len != 48) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Finalize failed"});
    }
    return result;
}

Result<Hash256> hmac_sha256(ByteView key, ByteView data) {
    if (key.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "HMAC key too large"});
    }
    Hash256 result;
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
              data.data(), data.size(), result.data(), &len) || len != 32) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "HMAC-SHA256 failed"});
    }
    return result;
}

Result<Bytes> hkdf_extract_sha256(ByteView salt, ByteView ikm) {
    if (salt.size() > MAX_INPUT_SIZE || ikm.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "HKDF input too large"});
    }
    return compat::hkdf_extract(EVP_sha256(), salt, ikm);
}

Result<Bytes> hkdf_expand_sha256(ByteView prk, ByteView info, size_t length) {
    if (prk.size() > MAX_INPUT_SIZE || info.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "HKDF input too large"});
    }
    return compat::hkdf_expand(EVP_sha256(), prk, info, length);
}

}  // namespace privacy_pass::crypto
