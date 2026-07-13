// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

// Thin compatibility layer bridging OpenSSL 3.x and BoringSSL API differences.
// Each function provides a unified interface; the implementation is selected
// at compile time via PRIVACY_PASS_WITH_BORINGSSL / PRIVACY_PASS_WITH_OPENSSL.

#pragma once

// Suppress OpenSSL 3.0 deprecation warnings for low-level RSA APIs
// that we must use for Blind RSA arithmetic (not deprecated in BoringSSL).
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4996)  // deprecated declarations
#endif

#include "common.hpp"
#include <privacy_pass/core/types.hpp>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#ifdef PRIVACY_PASS_WITH_BORINGSSL
#include <openssl/bytestring.h>
#include <openssl/hkdf.h>
#else
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define PRIVACY_PASS_OPENSSL3
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif
#include <openssl/kdf.h>
#endif

#include <spdlog/spdlog.h>

namespace privacy_pass::crypto::compat {

using namespace detail;

// ── Helpers ──────────────────────────────────────────────────────────────────

inline std::string get_openssl_error() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return buf;
}

inline std::string get_sanitized_error() {
    spdlog::debug("Crypto error: {}", get_openssl_error());
    return "Cryptographic operation failed";
}

// ── EC curve query ───────────────────────────────────────────────────────────
// BoringSSL only has EC_GROUP_get_curve_GFp; OpenSSL 3.x has the generic name.

inline int ec_group_get_curve(const EC_GROUP* group, BIGNUM* p,
                              BIGNUM* a, BIGNUM* b, BN_CTX* ctx) {
#ifdef PRIVACY_PASS_WITH_BORINGSSL
    return EC_GROUP_get_curve_GFp(group, p, a, b, ctx);
#else
    return EC_GROUP_get_curve(group, p, a, b, ctx);
#endif
}

// ── HKDF ─────────────────────────────────────────────────────────────────────
// OpenSSL 3.x: EVP_PKEY_CTX + EVP_PKEY_HKDF
// BoringSSL:   HKDF_extract / HKDF_expand

inline Result<Bytes> hkdf_extract(const EVP_MD* md, ByteView salt, ByteView ikm) {
    size_t hash_len = static_cast<size_t>(EVP_MD_size(md));
    Bytes prk(hash_len);
    size_t prk_len = prk.size();

#ifdef PRIVACY_PASS_WITH_BORINGSSL
    if (HKDF_extract(prk.data(), &prk_len, md,
                     ikm.data(), ikm.size(),
                     salt.data(), salt.size()) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "HKDF-Extract failed"});
    }
#else
    auto ctx = make_evp_pkey_ctx(EVP_PKEY_HKDF);
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create HKDF context"});
    }
    if (EVP_PKEY_derive_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), md) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(), static_cast<int>(salt.size())) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), ikm.data(), static_cast<int>(ikm.size())) != 1 ||
        EVP_PKEY_CTX_hkdf_mode(ctx.get(), EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1 ||
        EVP_PKEY_derive(ctx.get(), prk.data(), &prk_len) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "HKDF-Extract failed"});
    }
#endif
    prk.resize(prk_len);
    return prk;
}

inline Result<Bytes> hkdf_expand(const EVP_MD* md, ByteView prk, ByteView info, size_t length) {
    Bytes okm(length);

#ifdef PRIVACY_PASS_WITH_BORINGSSL
    if (HKDF_expand(okm.data(), length, md,
                    prk.data(), prk.size(),
                    info.data(), info.size()) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "HKDF-Expand failed"});
    }
#else
    auto ctx = make_evp_pkey_ctx(EVP_PKEY_HKDF);
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create HKDF context"});
    }
    size_t okm_len = length;
    if (EVP_PKEY_derive_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), md) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), prk.data(), static_cast<int>(prk.size())) != 1 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(), static_cast<int>(info.size())) != 1 ||
        EVP_PKEY_CTX_hkdf_mode(ctx.get(), EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1 ||
        EVP_PKEY_derive(ctx.get(), okm.data(), &okm_len) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "HKDF-Expand failed"});
    }
#endif
    return okm;
}

// ── RSA key validation ───────────────────────────────────────────────────────
// OpenSSL 3.x: queries EVP_PKEY params via OSSL_PKEY_PARAM_*
// BoringSSL:   queries RSA struct directly via RSA_get0_key

inline Result<void> validate_rsa_params(const EVP_PKEY* pkey,
                                        int expected_bits, unsigned long expected_e) {
#ifdef PRIVACY_PASS_WITH_BORINGSSL
    if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Not an RSA key"});
    }
    const RSA* rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Failed to get RSA key"});
    }
    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    RSA_get0_key(rsa, &n, &e, nullptr);
    if (!n || !e || BN_num_bits(n) != static_cast<unsigned>(expected_bits) ||
        !BN_is_word(e, expected_e)) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY,
            "RSA key must be RSA-2048 with exponent 65537"});
    }
#elif defined(PRIVACY_PASS_OPENSSL3)
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA_PSS) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Not an RSASSA-PSS key"});
    }
    BIGNUM* n_raw = nullptr;
    BIGNUM* e_raw = nullptr;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n_raw) != 1 ||
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e_raw) != 1) {
        BN_free(n_raw);
        BN_free(e_raw);
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Missing RSA key parameters"});
    }
    UniqueBIGNUM n(n_raw);
    UniqueBIGNUM e(e_raw);
    if (BN_num_bits(n.get()) != expected_bits || !BN_is_word(e.get(), expected_e)) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY,
            "RSA key must be RSA-2048 with exponent 65537"});
    }

    int salt_len = 0;
    if (EVP_PKEY_get_int_param(pkey, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, &salt_len) != 1 ||
        salt_len != 48) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY,
            "RSASSA-PSS key must use 48-byte salt"});
    }
    auto digest_ok = [](const char* param, const EVP_PKEY* k) {
        char buf[80]{};
        size_t len = 0;
        if (EVP_PKEY_get_utf8_string_param(k, param, buf, sizeof(buf), &len) != 1)
            return false;
        std::string_view sv(buf, len);
        return sv == "SHA384" || sv == "SHA-384" || sv == "SHA2-384";
    };
    if (!digest_ok(OSSL_PKEY_PARAM_RSA_DIGEST, pkey) ||
        !digest_ok(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, pkey)) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY,
            "RSASSA-PSS key must use SHA-384 and MGF1-SHA-384"});
    }
#else
    // OpenSSL 1.1: use low-level RSA API
    int pkey_type = EVP_PKEY_base_id(pkey);
    if (pkey_type != EVP_PKEY_RSA && pkey_type != EVP_PKEY_RSA_PSS) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Not an RSA key"});
    }
    const RSA* rsa = EVP_PKEY_get0_RSA(const_cast<EVP_PKEY*>(pkey));
    if (!rsa) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Failed to get RSA key"});
    }
    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    RSA_get0_key(rsa, &n, &e, nullptr);
    if (!n || !e || BN_num_bits(n) != expected_bits ||
        !BN_is_word(e, expected_e)) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY,
            "RSA key must be RSA-2048 with exponent 65537"});
    }
#endif
    return {};
}

// ── RSA EMSA-PSS encode ─────────────────────────────────────────────────────

inline Result<Bytes> emsa_pss_encode(EVP_PKEY* pkey, ByteView msg_hash,
                                     int salt_len) {
#ifdef PRIVACY_PASS_WITH_BORINGSSL
    const RSA* rsa = EVP_PKEY_get0_RSA(pkey);
#else
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    UniqueRSA rsa_guard(rsa);
#endif
    if (!rsa) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Failed to get RSA key"});
    }

    Bytes encoded(static_cast<size_t>(RSA_size(rsa)));
    if (RSA_padding_add_PKCS1_PSS_mgf1(rsa, encoded.data(), msg_hash.data(),
                                         EVP_sha384(), EVP_sha384(), salt_len) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, get_sanitized_error()});
    }
    return encoded;
}

// ── RSA key parsing ──────────────────────────────────────────────────────────

inline UniqueEVP_PKEY parse_public_key_spki(ByteView spki) {
#ifdef PRIVACY_PASS_WITH_BORINGSSL
    // Try BoringSSL parser, fall back to d2i_PUBKEY for RSA-PSS SPKI
    CBS cbs;
    CBS_init(&cbs, spki.data(), spki.size());
    UniqueEVP_PKEY pkey(EVP_parse_public_key(&cbs));
    if (!pkey || CBS_len(&cbs) != 0) {
        const uint8_t* p = spki.data();
        pkey.reset(d2i_PUBKEY(nullptr, &p, static_cast<long>(spki.size())));
    }
    return pkey;
#else
    const uint8_t* p = spki.data();
    return UniqueEVP_PKEY(d2i_PUBKEY(nullptr, &p, static_cast<long>(spki.size())));
#endif
}

inline UniqueEVP_PKEY parse_private_key_der(ByteView der) {
#ifdef PRIVACY_PASS_WITH_BORINGSSL
    CBS cbs;
    CBS_init(&cbs, der.data(), der.size());
    UniqueEVP_PKEY pkey(EVP_parse_private_key(&cbs));
    if (pkey && CBS_len(&cbs) != 0) pkey.reset();
    return pkey;
#else
    const uint8_t* p = der.data();
    return UniqueEVP_PKEY(d2i_AutoPrivateKey(nullptr, &p, static_cast<long>(der.size())));
#endif
}

// ── RSA key serialization ────────────────────────────────────────────────────

inline Result<Bytes> marshal_public_key(const EVP_PKEY* pkey) {
#ifdef PRIVACY_PASS_WITH_BORINGSSL
    CBB cbb;
    if (!CBB_init(&cbb, 0) || !EVP_marshal_public_key(&cbb, pkey)) {
        CBB_cleanup(&cbb);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to encode SPKI"});
    }
    uint8_t* data = nullptr;
    size_t len = 0;
    if (!CBB_finish(&cbb, &data, &len)) {
        CBB_cleanup(&cbb);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to finish SPKI"});
    }
    Bytes result(data, data + len);
    OPENSSL_free(data);
    return result;
#else
    // OpenSSL 1.1 i2d_PUBKEY doesn't accept const EVP_PKEY*
    auto* mutable_pkey = const_cast<EVP_PKEY*>(pkey);
    int len = i2d_PUBKEY(mutable_pkey, nullptr);
    if (len <= 0) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to compute SPKI size"});
    }
    Bytes result(static_cast<size_t>(len));
    uint8_t* p = result.data();
    if (i2d_PUBKEY(mutable_pkey, &p) != len) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to encode SPKI"});
    }
    return result;
#endif
}

inline Result<SecureBytes> marshal_private_key(const EVP_PKEY* pkey) {
#ifdef PRIVACY_PASS_WITH_BORINGSSL
    CBB cbb;
    if (!CBB_init(&cbb, 0) || !EVP_marshal_private_key(&cbb, pkey)) {
        CBB_cleanup(&cbb);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to encode PKCS#8"});
    }
    uint8_t* data = nullptr;
    size_t len = 0;
    if (!CBB_finish(&cbb, &data, &len)) {
        CBB_cleanup(&cbb);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to finish PKCS#8"});
    }
    SecureBytes result(ByteView(data, len));
    OPENSSL_free(data);
    return result;
#else
    // OpenSSL 1.1 i2d_PrivateKey doesn't accept const EVP_PKEY*
    auto* mutable_pkey = const_cast<EVP_PKEY*>(pkey);
    int len = i2d_PrivateKey(mutable_pkey, nullptr);
    if (len <= 0) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to compute PKCS#8 size"});
    }
    SecureBytes result(static_cast<size_t>(len));
    uint8_t* p = result.data();
    if (i2d_PrivateKey(mutable_pkey, &p) != len) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to encode PKCS#8"});
    }
    return result;
#endif
}

// ── RSA key construction from components ─────────────────────────────────────

inline UniqueEVP_PKEY rsa_public_key_from_components(const BIGNUM* n, const BIGNUM* e) {
#if defined(PRIVACY_PASS_WITH_BORINGSSL) || !defined(PRIVACY_PASS_OPENSSL3)
    // BoringSSL and OpenSSL 1.1: use low-level RSA API
    RSA* rsa = RSA_new();
    if (!rsa) return nullptr;
    BIGNUM* n_dup = BN_dup(n);
    BIGNUM* e_dup = BN_dup(e);
    if (!n_dup || !e_dup || RSA_set0_key(rsa, n_dup, e_dup, nullptr) != 1) {
        if (n_dup) BN_free(n_dup);
        if (e_dup) BN_free(e_dup);
        RSA_free(rsa);
        return nullptr;
    }
    auto pkey = UniqueEVP_PKEY(EVP_PKEY_new());
    if (!pkey || EVP_PKEY_assign_RSA(pkey.get(), rsa) != 1) {
        RSA_free(rsa);
        return nullptr;
    }
    return pkey;  // rsa ownership transferred to pkey
#else
    // OpenSSL 3.x: use EVP_PKEY_fromdata with OSSL_PARAM
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) return nullptr;

    bool ok =
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) == 1 &&
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) == 1 &&
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_RSA_DIGEST,
            const_cast<char*>("SHA384"), 0) == 1 &&
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_RSA_MASKGENFUNC,
            const_cast<char*>("MGF1"), 0) == 1 &&
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST,
            const_cast<char*>("SHA384"), 0) == 1 &&
        OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, 48) == 1;
    if (!ok) {
        OSSL_PARAM_BLD_free(bld);
        return nullptr;
    }

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) return nullptr;

    auto ctx = UniqueEVP_PKEY_CTX(EVP_PKEY_CTX_new_from_name(nullptr, "RSA-PSS", nullptr));
    if (!ctx) { OSSL_PARAM_free(params); return nullptr; }

    EVP_PKEY* pkey = nullptr;
    ok = EVP_PKEY_fromdata_init(ctx.get()) == 1 &&
         EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_PUBLIC_KEY, params) == 1;
    OSSL_PARAM_free(params);

    if (!ok || !pkey) return nullptr;
    return UniqueEVP_PKEY(pkey);
#endif
}

// ── RSA key generation ───────────────────────────────────────────────────────

inline UniqueEVP_PKEY generate_rsa_pss_keypair(int bits, [[maybe_unused]] int salt_len) {
#ifdef PRIVACY_PASS_WITH_BORINGSSL
    auto bn_e = make_bignum();
    if (!bn_e || !BN_set_word(bn_e.get(), RSA_F4)) return nullptr;

    RSA* rsa = RSA_new();
    if (!rsa) return nullptr;
    if (RSA_generate_key_ex(rsa, bits, bn_e.get(), nullptr) != 1) {
        RSA_free(rsa);
        return nullptr;
    }
    auto pkey = UniqueEVP_PKEY(EVP_PKEY_new());
    if (!pkey || EVP_PKEY_assign_RSA(pkey.get(), rsa) != 1) {
        RSA_free(rsa);
        return nullptr;
    }
    return pkey;
#else
    auto ctx = UniqueEVP_PKEY_CTX(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, nullptr));
    if (!ctx) return nullptr;
    if (EVP_PKEY_keygen_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) != 1 ||
        EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx.get(), EVP_sha384()) != 1 ||
        EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx.get(), EVP_sha384()) != 1 ||
        EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx.get(), salt_len) != 1) {
        return nullptr;
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey) != 1) return nullptr;
    return UniqueEVP_PKEY(pkey);
#endif
}

// ── RSA get key parameters ───────────────────────────────────────────────────

inline bool rsa_get_bn_param(const EVP_PKEY* pkey, const char* name, UniqueBIGNUM& out) {
#if defined(PRIVACY_PASS_WITH_BORINGSSL) || !defined(PRIVACY_PASS_OPENSSL3)
    // BoringSSL and OpenSSL 1.1: use low-level RSA API
    const RSA* rsa = EVP_PKEY_get0_RSA(const_cast<EVP_PKEY*>(pkey));
    if (!rsa) return false;
    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    const BIGNUM* d = nullptr;
    RSA_get0_key(rsa, &n, &e, &d);
    const BIGNUM* src = nullptr;
    if (std::string_view(name) == "n") src = n;
    else if (std::string_view(name) == "e") src = e;
    if (!src) return false;
    out.reset(BN_dup(src));
    return out != nullptr;
#else
    BIGNUM* raw = nullptr;
    if (EVP_PKEY_get_bn_param(pkey, name, &raw) != 1) return false;
    out.reset(raw);
    return true;
#endif
}

inline bool rsa_get_secure_bn_param(const EVP_PKEY* pkey, const char* name,
                                     UniqueSecureBIGNUM& out) {
#if defined(PRIVACY_PASS_WITH_BORINGSSL) || !defined(PRIVACY_PASS_OPENSSL3)
    // BoringSSL and OpenSSL 1.1: use low-level RSA API
    const RSA* rsa = EVP_PKEY_get0_RSA(const_cast<EVP_PKEY*>(pkey));
    if (!rsa) return false;
    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    const BIGNUM* d = nullptr;
    RSA_get0_key(rsa, &n, &e, &d);
    const BIGNUM* src = nullptr;
    if (std::string_view(name) == "d") src = d;
    if (!src) return false;
    out.reset(BN_dup(src));
    return out != nullptr;
#else
    BIGNUM* raw = nullptr;
    if (EVP_PKEY_get_bn_param(pkey, name, &raw) != 1) return false;
    out.reset(raw);
    return true;
#endif
}

// Portable param name constants
#if defined(PRIVACY_PASS_WITH_BORINGSSL) || !defined(PRIVACY_PASS_OPENSSL3)
constexpr const char* PARAM_RSA_N = "n";
constexpr const char* PARAM_RSA_E = "e";
constexpr const char* PARAM_RSA_D = "d";
#else
constexpr const char* PARAM_RSA_N = OSSL_PKEY_PARAM_RSA_N;
constexpr const char* PARAM_RSA_E = OSSL_PKEY_PARAM_RSA_E;
constexpr const char* PARAM_RSA_D = OSSL_PKEY_PARAM_RSA_D;
#endif

// ── BN consttime flag ────────────────────────────────────────────────────────
// BoringSSL: always constant-time, no flag needed

inline void bn_set_consttime(BIGNUM* bn) {
#ifdef PRIVACY_PASS_WITH_BORINGSSL
    (void)bn;  // BoringSSL is always constant-time
#else
    BN_set_flags(bn, BN_FLG_CONSTTIME);
#endif
}

// ── Init / shutdown ──────────────────────────────────────────────────────────

inline void backend_init() {
#ifdef PRIVACY_PASS_WITH_BORINGSSL
    // BoringSSL auto-initializes
#else
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
#endif
}

inline void backend_shutdown() {
#ifdef PRIVACY_PASS_WITH_BORINGSSL
    // nothing to do
#else
    EVP_cleanup();
    ERR_free_strings();
#endif
}

}  // namespace privacy_pass::crypto::compat

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif
