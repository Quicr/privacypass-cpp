// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

// Shared RAII wrappers for OpenSSL/BoringSSL C types.
// Both libraries use the same C type names, so these wrappers work with either.

#pragma once

#include <memory>

// Suppress deprecation warnings for OpenSSL 3.0 low-level APIs (RSA, EC)
// that we must use for Blind RSA arithmetic. These are not deprecated in BoringSSL.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4996)
#endif

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

namespace privacy_pass::crypto::detail {

// Generic deleter adapter: wraps a C free function as a std::unique_ptr deleter.
template <typename T, void (*Free)(T*)>
struct CDeleter {
    void operator()(T* ptr) const noexcept {
        if (ptr) Free(ptr);
    }
};

// Secure-clear deleter for sensitive BIGNUMs
struct BNClearDeleter {
    void operator()(BIGNUM* ptr) const noexcept {
        if (ptr) BN_clear_free(ptr);
    }
};

// EVP types
using UniqueEVP_MD_CTX = std::unique_ptr<EVP_MD_CTX, CDeleter<EVP_MD_CTX, EVP_MD_CTX_free>>;
using UniqueEVP_PKEY = std::unique_ptr<EVP_PKEY, CDeleter<EVP_PKEY, EVP_PKEY_free>>;
using UniqueEVP_PKEY_CTX = std::unique_ptr<EVP_PKEY_CTX, CDeleter<EVP_PKEY_CTX, EVP_PKEY_CTX_free>>;

// BIGNUM types
using UniqueBIGNUM = std::unique_ptr<BIGNUM, CDeleter<BIGNUM, BN_free>>;
using UniqueSecureBIGNUM = std::unique_ptr<BIGNUM, BNClearDeleter>;
using UniqueBN_CTX = std::unique_ptr<BN_CTX, CDeleter<BN_CTX, BN_CTX_free>>;
using UniqueBN_MONT_CTX = std::unique_ptr<BN_MONT_CTX, CDeleter<BN_MONT_CTX, BN_MONT_CTX_free>>;

// EC types
using UniqueEC_POINT = std::unique_ptr<EC_POINT, CDeleter<EC_POINT, EC_POINT_free>>;
using UniqueEC_GROUP = std::unique_ptr<EC_GROUP, CDeleter<EC_GROUP, EC_GROUP_free>>;

// RSA type
using UniqueRSA = std::unique_ptr<RSA, CDeleter<RSA, RSA_free>>;

// Convenience factory functions
inline UniqueEVP_MD_CTX make_evp_md_ctx() {
    return UniqueEVP_MD_CTX(EVP_MD_CTX_new());
}

inline UniqueEVP_PKEY_CTX make_evp_pkey_ctx(int id) {
    return UniqueEVP_PKEY_CTX(EVP_PKEY_CTX_new_id(id, nullptr));
}

inline UniqueBIGNUM make_bignum() {
    return UniqueBIGNUM(BN_new());
}

inline UniqueSecureBIGNUM make_secure_bignum() {
    return UniqueSecureBIGNUM(BN_new());
}

inline UniqueBN_CTX make_bn_ctx() {
    return UniqueBN_CTX(BN_CTX_new());
}

inline UniqueBN_MONT_CTX make_bn_mont_ctx() {
    return UniqueBN_MONT_CTX(BN_MONT_CTX_new());
}

inline UniqueEC_POINT make_ec_point(const EC_GROUP* group) {
    return UniqueEC_POINT(EC_POINT_new(group));
}

inline UniqueBIGNUM bin2bn(const uint8_t* data, int len) {
    return UniqueBIGNUM(BN_bin2bn(data, len, nullptr));
}

inline UniqueSecureBIGNUM bin2bn_secure(const uint8_t* data, int len) {
    return UniqueSecureBIGNUM(BN_bin2bn(data, len, nullptr));
}

}  // namespace privacy_pass::crypto::detail

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif
