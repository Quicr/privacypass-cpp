// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/crypto/hash.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

#include <spdlog/spdlog.h>

namespace privacy_pass::crypto {

// Maximum input size for OpenSSL APIs (prevent integer truncation)
constexpr size_t MAX_INPUT_SIZE = static_cast<size_t>(INT_MAX);

Result<Hash256> sha256(ByteView data) {
    Hash256 result;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create hash context"});
    }

    bool success = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                   EVP_DigestUpdate(ctx, data.data(), data.size()) == 1;

    unsigned int len = 0;
    success = success && EVP_DigestFinal_ex(ctx, result.data(), &len) == 1;

    EVP_MD_CTX_free(ctx);

    if (!success || len != 32) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "SHA-256 computation failed"});
    }

    return result;
}

Result<Hash384> sha384(ByteView data) {
    Hash384 result;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create hash context"});
    }

    bool success = EVP_DigestInit_ex(ctx, EVP_sha384(), nullptr) == 1 &&
                   EVP_DigestUpdate(ctx, data.data(), data.size()) == 1;

    unsigned int len = 0;
    success = success && EVP_DigestFinal_ex(ctx, result.data(), &len) == 1;

    EVP_MD_CTX_free(ctx);

    if (!success || len != 48) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "SHA-384 computation failed"});
    }

    return result;
}

struct Sha256Hasher::Impl {
    EVP_MD_CTX* ctx = nullptr;

    Impl() {
        ctx = EVP_MD_CTX_new();
        if (ctx) {
            EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        }
    }

    ~Impl() {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    }
};

Sha256Hasher::Sha256Hasher() : impl_(std::make_unique<Impl>()) {}
Sha256Hasher::~Sha256Hasher() = default;
Sha256Hasher::Sha256Hasher(Sha256Hasher&&) noexcept = default;
Sha256Hasher& Sha256Hasher::operator=(Sha256Hasher&&) noexcept = default;

void Sha256Hasher::update(ByteView data) {
    if (impl_ && impl_->ctx) {
        EVP_DigestUpdate(impl_->ctx, data.data(), data.size());
    }
}

Result<Hash256> Sha256Hasher::finalize() {
    if (!impl_ || !impl_->ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Invalid hasher state"});
    }

    Hash256 result;
    unsigned int len = 0;

    if (EVP_DigestFinal_ex(impl_->ctx, result.data(), &len) != 1 || len != 32) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Finalize failed"});
    }

    return result;
}

struct Sha384Hasher::Impl {
    EVP_MD_CTX* ctx = nullptr;

    Impl() {
        ctx = EVP_MD_CTX_new();
        if (ctx) {
            EVP_DigestInit_ex(ctx, EVP_sha384(), nullptr);
        }
    }

    ~Impl() {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    }
};

Sha384Hasher::Sha384Hasher() : impl_(std::make_unique<Impl>()) {}
Sha384Hasher::~Sha384Hasher() = default;
Sha384Hasher::Sha384Hasher(Sha384Hasher&&) noexcept = default;
Sha384Hasher& Sha384Hasher::operator=(Sha384Hasher&&) noexcept = default;

void Sha384Hasher::update(ByteView data) {
    if (impl_ && impl_->ctx) {
        EVP_DigestUpdate(impl_->ctx, data.data(), data.size());
    }
}

Result<Hash384> Sha384Hasher::finalize() {
    if (!impl_ || !impl_->ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Invalid hasher state"});
    }

    Hash384 result;
    unsigned int len = 0;

    if (EVP_DigestFinal_ex(impl_->ctx, result.data(), &len) != 1 || len != 48) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Finalize failed"});
    }

    return result;
}

Result<Hash256> hmac_sha256(ByteView key, ByteView data) {
    // Validate key size to prevent integer truncation
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
    // Validate input sizes to prevent integer truncation
    if (salt.size() > MAX_INPUT_SIZE || ikm.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "HKDF input too large"});
    }

    Bytes prk(32);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create HKDF context"});
    }

    size_t prk_len = prk.size();
    bool success =
        EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), static_cast<int>(salt.size())) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm.data(), static_cast<int>(ikm.size())) == 1 &&
        EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) == 1 &&
        EVP_PKEY_derive(ctx, prk.data(), &prk_len) == 1;

    EVP_PKEY_CTX_free(ctx);

    if (!success) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "HKDF-Extract failed"});
    }

    prk.resize(prk_len);
    return prk;
}

Result<Bytes> hkdf_expand_sha256(ByteView prk, ByteView info, size_t length) {
    // Validate input sizes to prevent integer truncation
    if (prk.size() > MAX_INPUT_SIZE || info.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "HKDF input too large"});
    }

    Bytes okm(length);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create HKDF context"});
    }

    size_t okm_len = okm.size();
    bool success =
        EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_key(ctx, prk.data(), static_cast<int>(prk.size())) == 1 &&
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info.data(), static_cast<int>(info.size())) == 1 &&
        EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) == 1 &&
        EVP_PKEY_derive(ctx, okm.data(), &okm_len) == 1;

    EVP_PKEY_CTX_free(ctx);

    if (!success) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "HKDF-Expand failed"});
    }

    okm.resize(okm_len);
    return okm;
}

}  // namespace privacy_pass::crypto
