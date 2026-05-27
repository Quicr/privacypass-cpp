// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/crypto/blind_rsa.hpp>
#include <privacy_pass/crypto/hash.hpp>
#include <privacy_pass/crypto/random.hpp>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <spdlog/spdlog.h>

namespace privacy_pass::crypto {

namespace {

// RSASSA-PSS parameters for Privacy Pass
constexpr int RSA_BITS = 2048;
constexpr int SALT_LENGTH = 48;  // SHA-384 output size

// Maximum input size for OpenSSL APIs (prevent integer truncation)
constexpr size_t MAX_INPUT_SIZE = static_cast<size_t>(INT_MAX);

// Get OpenSSL error string (sanitized for external exposure)
std::string get_openssl_error() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return buf;
}

// Get sanitized error string for external callers
std::string get_sanitized_error() {
    // Log the detailed error internally
    spdlog::debug("OpenSSL error: {}", get_openssl_error());
    // Return generic message to callers
    return "Cryptographic operation failed";
}

bool is_rsa_pss_key(const EVP_PKEY* key) {
    return EVP_PKEY_base_id(key) == EVP_PKEY_RSA_PSS;
}

bool digest_name_is_sha384(std::string_view name) {
    return name == "SHA384" || name == "SHA-384" || name == "SHA2-384";
}

Result<void> validate_rsa_pss_params(const EVP_PKEY* key) {
    if (!is_rsa_pss_key(key)) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Not an RSASSA-PSS key"});
    }

    BIGNUM* n = nullptr;
    BIGNUM* e = nullptr;
    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n) != 1 ||
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e) != 1) {
        BN_free(n);
        BN_free(e);
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Missing RSA key parameters"});
    }

    const bool key_params_ok = BN_num_bits(n) == RSA_BITS && BN_is_word(e, RSA_PUBLIC_EXPONENT) == 1;
    BN_free(n);
    BN_free(e);
    if (!key_params_ok) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY,
            "RSASSA-PSS key must use RSA-2048 and exponent 65537"});
    }

    int salt_len = 0;
    if (EVP_PKEY_get_int_param(key, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, &salt_len) != 1 ||
        salt_len != SALT_LENGTH) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY,
            "RSASSA-PSS key must use 48-byte salt"});
    }

    char digest[80]{};
    char mgf1_digest[80]{};
    size_t digest_len = 0;
    size_t mgf1_digest_len = 0;
    if (EVP_PKEY_get_utf8_string_param(
            key, OSSL_PKEY_PARAM_RSA_DIGEST, digest, sizeof(digest), &digest_len) != 1 ||
        EVP_PKEY_get_utf8_string_param(
            key, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, mgf1_digest, sizeof(mgf1_digest),
            &mgf1_digest_len) != 1 ||
        !digest_name_is_sha384(std::string_view(digest, digest_len)) ||
        !digest_name_is_sha384(std::string_view(mgf1_digest, mgf1_digest_len))) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY,
            "RSASSA-PSS key must use SHA-384 and MGF1-SHA-384"});
    }

    return {};
}

// EMSA-PSS encoding for blind RSA (RFC 9474)
Result<Bytes> emsa_pss_encode(EVP_PKEY* pkey, ByteView msg) {
    auto mHash = sha384(msg);
    if (!mHash) {
        return std::unexpected(mHash.error());
    }

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Failed to get RSA key"});
    }

    Bytes encoded(static_cast<size_t>(RSA_size(rsa)));
    const int ok = RSA_padding_add_PKCS1_PSS_mgf1(
        rsa,
        encoded.data(),
        mHash->data(),
        EVP_sha384(),
        EVP_sha384(),
        SALT_LENGTH);
    RSA_free(rsa);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

    if (ok != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, get_sanitized_error()});
    }

    return encoded;
}

}  // namespace

// BlindRsaPublicKey implementation
struct BlindRsaPublicKey::Impl {
    EVP_PKEY* pkey = nullptr;
    Bytes original_spki;
    TokenKeyId cached_key_id{};
    bool key_id_computed = false;

    ~Impl() {
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
    }
};

BlindRsaPublicKey::BlindRsaPublicKey() : impl_(std::make_unique<Impl>()) {}
BlindRsaPublicKey::~BlindRsaPublicKey() = default;
BlindRsaPublicKey::BlindRsaPublicKey(BlindRsaPublicKey&&) noexcept = default;
BlindRsaPublicKey& BlindRsaPublicKey::operator=(BlindRsaPublicKey&&) noexcept = default;

Result<BlindRsaPublicKey> BlindRsaPublicKey::from_spki(ByteView spki) {
    // Validate input size to prevent integer truncation
    if (spki.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "SPKI data too large"});
    }

    BlindRsaPublicKey key;

    const uint8_t* p = spki.data();
    key.impl_->pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(spki.size()));

    if (!key.impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, get_sanitized_error()});
    }

    auto params = validate_rsa_pss_params(key.impl_->pkey);
    if (!params) {
        return std::unexpected(params.error());
    }

    key.impl_->original_spki.assign(spki.begin(), spki.end());

    return key;
}

Result<BlindRsaPublicKey> BlindRsaPublicKey::from_components(ByteView modulus, ByteView exponent) {
    // Validate input sizes to prevent integer truncation
    if (modulus.size() > MAX_INPUT_SIZE || exponent.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key component too large"});
    }

    BlindRsaPublicKey key;

    BIGNUM* n = BN_bin2bn(modulus.data(), static_cast<int>(modulus.size()), nullptr);
    BIGNUM* e = BN_bin2bn(exponent.data(), static_cast<int>(exponent.size()), nullptr);

    if (!n || !e) {
        BN_free(n);
        BN_free(e);
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Failed to create bignums"});
    }

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        BN_free(n);
        BN_free(e);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create parameter builder"});
    }

    const bool params_pushed =
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) == 1 &&
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) == 1 &&
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_RSA_DIGEST,
            const_cast<char*>("SHA384"), 0) == 1 &&
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_RSA_MASKGENFUNC,
            const_cast<char*>("MGF1"), 0) == 1 &&
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST,
            const_cast<char*>("SHA384"), 0) == 1 &&
        OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, SALT_LENGTH) == 1;
    if (!params_pushed) {
        OSSL_PARAM_BLD_free(bld);
        BN_free(n);
        BN_free(e);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to build RSA parameters"});
    }

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) {
        OSSL_PARAM_BLD_free(bld);
        BN_free(n);
        BN_free(e);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create RSA parameters"});
    }

    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* from_data_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA-PSS", nullptr);
    if (!from_data_ctx) {
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        BN_free(n);
        BN_free(e);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create RSA-PSS context"});
    }

    bool success = EVP_PKEY_fromdata_init(from_data_ctx) == 1 &&
                   EVP_PKEY_fromdata(from_data_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) == 1;

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(from_data_ctx);
    BN_free(n);
    BN_free(e);

    if (!success || !pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Failed to create RSASSA-PSS key"});
    }

    auto validated = validate_rsa_pss_params(pkey);
    if (!validated) {
        EVP_PKEY_free(pkey);
        return std::unexpected(validated.error());
    }

    key.impl_->pkey = pkey;
    return key;
}

Result<Bytes> BlindRsaPublicKey::to_spki() const {
    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }

    int len = i2d_PUBKEY(impl_->pkey, nullptr);
    if (len <= 0) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to compute SPKI size"});
    }

    Bytes result(static_cast<size_t>(len));
    uint8_t* p = result.data();
    if (i2d_PUBKEY(impl_->pkey, &p) != len) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to encode SPKI"});
    }

    return result;
}

Result<TokenKeyId> BlindRsaPublicKey::key_id() const {
    if (impl_->key_id_computed) {
        return impl_->cached_key_id;
    }

    Bytes spki;
    if (!impl_->original_spki.empty()) {
        spki = impl_->original_spki;
    } else {
        auto encoded = to_spki();
        if (!encoded) {
            return std::unexpected(encoded.error());
        }
        spki = std::move(*encoded);
    }

    auto hash = sha256(ByteView(spki.data(), spki.size()));
    if (!hash) {
        return std::unexpected(hash.error());
    }

    impl_->cached_key_id = *hash;
    impl_->key_id_computed = true;
    return impl_->cached_key_id;
}

Result<BlindingData> BlindRsaPublicKey::blind(ByteView msg) const {
    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }

    // Get modulus size
    BIGNUM* n_bn = nullptr;
    EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_N, &n_bn);
    if (!n_bn) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get modulus"});
    }

    int mod_size = BN_num_bytes(n_bn);

    // EMSA-PSS encode the message
    auto encoded = emsa_pss_encode(impl_->pkey, msg);
    if (!encoded) {
        BN_free(n_bn);
        return std::unexpected(encoded.error());
    }

    // Convert encoded message to BIGNUM
    BIGNUM* m = BN_bin2bn(encoded->data(), static_cast<int>(encoded->size()), nullptr);
    if (!m) {
        BN_free(n_bn);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to convert message"});
    }

    // Get public exponent
    BIGNUM* e_bn = nullptr;
    EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_E, &e_bn);
    if (!e_bn) {
        BN_free(n_bn);
        BN_free(m);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get exponent"});
    }

    BN_CTX* bn_ctx = BN_CTX_new();
    if (!bn_ctx) {
        BN_free(n_bn);
        BN_free(m);
        BN_free(e_bn);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create BN context"});
    }

    // Generate random blinding factor r
    BIGNUM* r = BN_new();
    BIGNUM* r_inv = BN_new();
    BIGNUM* x = BN_new();
    BIGNUM* x_mont = BN_new();
    BIGNUM* blinded = BN_new();
    BN_MONT_CTX* mont = BN_MONT_CTX_new();

    if (!r || !r_inv || !x || !x_mont || !blinded || !mont) {
        BN_free(n_bn);
        BN_free(m);
        BN_free(e_bn);
        BN_clear_free(r);
        BN_clear_free(r_inv);
        BN_free(x);
        BN_free(x_mont);
        BN_free(blinded);
        BN_MONT_CTX_free(mont);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to allocate bignums"});
    }

    if (BN_MONT_CTX_set(mont, n_bn, bn_ctx) != 1) {
        BN_free(n_bn);
        BN_free(m);
        BN_free(e_bn);
        BN_clear_free(r);
        BN_clear_free(r_inv);
        BN_free(x);
        BN_free(x_mont);
        BN_free(blinded);
        BN_MONT_CTX_free(mont);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create Montgomery context"});
    }

    // Generate r coprime to n
    do {
        if (!BN_rand_range(r, n_bn)) {
            BN_free(n_bn);
            BN_free(m);
            BN_free(e_bn);
            BN_clear_free(r);
            BN_clear_free(r_inv);
            BN_free(x);
            BN_free(x_mont);
            BN_free(blinded);
            BN_MONT_CTX_free(mont);
            BN_CTX_free(bn_ctx);
            return std::unexpected(Error{ErrorCode::BLINDING_FAILED, "Failed to generate r"});
        }
    } while (BN_is_zero(r) || !BN_mod_inverse(r_inv, r, n_bn, bn_ctx));

    // x = r^e mod n
    if (BN_mod_exp_mont(x, r, e_bn, n_bn, bn_ctx, mont) != 1 ||
        BN_to_montgomery(x_mont, x, mont, bn_ctx) != 1) {
        BN_free(n_bn);
        BN_free(m);
        BN_free(e_bn);
        BN_clear_free(r);
        BN_clear_free(r_inv);
        BN_free(x);
        BN_free(x_mont);
        BN_free(blinded);
        BN_MONT_CTX_free(mont);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::BLINDING_FAILED, "Failed to compute x"});
    }

    // blinded = m * x mod n
    if (BN_mod_mul_montgomery(blinded, m, x_mont, mont, bn_ctx) != 1) {
        BN_free(n_bn);
        BN_free(m);
        BN_free(e_bn);
        BN_clear_free(r);
        BN_clear_free(r_inv);
        BN_free(x);
        BN_free(x_mont);
        BN_free(blinded);
        BN_MONT_CTX_free(mont);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::BLINDING_FAILED, "Failed to blind message"});
    }

    BlindingData result;

    // Store inverse in standard form for portable serialization.
    result.inverse.resize(static_cast<size_t>(mod_size));
    BN_bn2binpad(r_inv, result.inverse.data(), mod_size);

    // Store blinded message
    result.blinded_msg.resize(static_cast<size_t>(mod_size));
    int blinded_len = BN_bn2binpad(blinded, result.blinded_msg.data(), mod_size);
    if (blinded_len != mod_size) {
        result.blinded_msg.resize(static_cast<size_t>(blinded_len));
    }

    BN_free(n_bn);
    BN_free(m);
    BN_free(e_bn);
    BN_clear_free(r);
    BN_clear_free(r_inv);
    BN_free(x);
    BN_free(x_mont);
    BN_free(blinded);
    BN_MONT_CTX_free(mont);
    BN_CTX_free(bn_ctx);

    return result;
}

Result<Bytes> BlindRsaPublicKey::finalize(
    ByteView blind_sig,
    BlindingData& blinding_data,
    ByteView msg) const {

    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }

    // Validate input sizes
    if (blind_sig.size() > MAX_INPUT_SIZE || blinding_data.inverse.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Input too large"});
    }

    // Get modulus
    BIGNUM* n_bn = nullptr;
    EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_N, &n_bn);
    if (!n_bn) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get modulus"});
    }

    int mod_size = BN_num_bytes(n_bn);

    BN_CTX* bn_ctx = BN_CTX_new();
    if (!bn_ctx) {
        BN_free(n_bn);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create BN context"});
    }

    BIGNUM* z = BN_bin2bn(blind_sig.data(), static_cast<int>(blind_sig.size()), nullptr);
    BIGNUM* r_inv = BN_bin2bn(blinding_data.inverse.data(),
        static_cast<int>(blinding_data.inverse.size()), nullptr);
    BIGNUM* r_inv_mont = BN_new();
    BIGNUM* sig = BN_new();
    BN_MONT_CTX* mont = BN_MONT_CTX_new();

    if (!z || !r_inv || !r_inv_mont || !sig || !mont) {
        BN_free(n_bn);
        BN_free(z);
        BN_clear_free(r_inv);
        BN_clear_free(r_inv_mont);
        BN_free(sig);
        BN_MONT_CTX_free(mont);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to allocate bignums"});
    }

    if (BN_MONT_CTX_set(mont, n_bn, bn_ctx) != 1) {
        BN_free(n_bn);
        BN_free(z);
        BN_clear_free(r_inv);
        BN_clear_free(r_inv_mont);
        BN_free(sig);
        BN_MONT_CTX_free(mont);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create Montgomery context"});
    }

    // Convert standard-form inverse to Montgomery form for constant-shape multiply
    if (BN_to_montgomery(r_inv_mont, r_inv, mont, bn_ctx) != 1) {
        BN_free(n_bn);
        BN_free(z);
        BN_clear_free(r_inv);
        BN_clear_free(r_inv_mont);
        BN_free(sig);
        BN_MONT_CTX_free(mont);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::UNBLINDING_FAILED, "Failed to convert inverse to Montgomery form"});
    }

    // sig = z * r_inv mod n
    if (BN_mod_mul_montgomery(sig, z, r_inv_mont, mont, bn_ctx) != 1) {
        BN_free(n_bn);
        BN_free(z);
        BN_clear_free(r_inv);
        BN_clear_free(r_inv_mont);
        BN_free(sig);
        BN_MONT_CTX_free(mont);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::UNBLINDING_FAILED, "Failed to unblind"});
    }

    Bytes result(static_cast<size_t>(mod_size));
    BN_bn2binpad(sig, result.data(), mod_size);

    BN_free(n_bn);
    BN_free(z);
    BN_clear_free(r_inv);
    BN_clear_free(r_inv_mont);
    BN_free(sig);
    BN_MONT_CTX_free(mont);
    BN_CTX_free(bn_ctx);

    // Clear the blinding data after successful use to prevent reuse
    blinding_data.inverse.clear();

    // Verify the unblinded signature if message was provided
    if (!msg.empty()) {
        auto verify_result = verify(msg, ByteView(result.data(), result.size()));
        if (!verify_result || !*verify_result) {
            return std::unexpected(Error{ErrorCode::VERIFICATION_FAILED,
                "Unblinded signature verification failed"});
        }
    }

    return result;
}

Result<bool> BlindRsaPublicKey::verify(ByteView msg, ByteView signature) const {
    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    EVP_PKEY_CTX* pkey_ctx = nullptr;

    bool success = EVP_DigestVerifyInit(md_ctx, &pkey_ctx, EVP_sha384(), nullptr, impl_->pkey) == 1;

    if (success) {
        success = EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) == 1 &&
                  EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, SALT_LENGTH) == 1 &&
                  EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha384()) == 1;
    }

    int result = 0;
    if (success) {
        result = EVP_DigestVerify(md_ctx,
            signature.data(), signature.size(),
            msg.data(), msg.size());
    }

    EVP_MD_CTX_free(md_ctx);

    if (!success) {
        return std::unexpected(Error{ErrorCode::VERIFICATION_FAILED, "Verification setup failed"});
    }

    return result == 1;
}

bool BlindRsaPublicKey::is_valid() const noexcept {
    return impl_ && impl_->pkey;
}

// BlindRsaPrivateKey implementation
struct BlindRsaPrivateKey::Impl {
    EVP_PKEY* pkey = nullptr;

    ~Impl() {
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
    }
};

BlindRsaPrivateKey::BlindRsaPrivateKey() : impl_(std::make_unique<Impl>()) {}
BlindRsaPrivateKey::~BlindRsaPrivateKey() = default;
BlindRsaPrivateKey::BlindRsaPrivateKey(BlindRsaPrivateKey&&) noexcept = default;
BlindRsaPrivateKey& BlindRsaPrivateKey::operator=(BlindRsaPrivateKey&&) noexcept = default;

Result<std::pair<BlindRsaPrivateKey, BlindRsaPublicKey>> BlindRsaPrivateKey::generate() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, nullptr);
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    bool success = EVP_PKEY_keygen_init(ctx) == 1 &&
                   EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_BITS) == 1 &&
                   EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, EVP_sha384()) == 1 &&
                   EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx, EVP_sha384()) == 1 &&
                   EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, SALT_LENGTH) == 1;

    EVP_PKEY* pkey = nullptr;
    success = success && EVP_PKEY_keygen(ctx, &pkey) == 1;

    EVP_PKEY_CTX_free(ctx);

    if (!success || !pkey) {
        spdlog::debug("Key generation failed: {}", get_openssl_error());
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR,
            "Key generation failed"});
    }

    BlindRsaPrivateKey private_key;
    private_key.impl_->pkey = pkey;

    auto public_key_result = private_key.public_key();
    if (!public_key_result) {
        return std::unexpected(public_key_result.error());
    }

    return std::make_pair(std::move(private_key), std::move(*public_key_result));
}

Result<BlindRsaPrivateKey> BlindRsaPrivateKey::from_pkcs8(ByteView pkcs8) {
    // Validate input size to prevent integer truncation
    if (pkcs8.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "PKCS#8 data too large"});
    }

    BlindRsaPrivateKey key;

    const uint8_t* p = pkcs8.data();
    key.impl_->pkey = d2i_AutoPrivateKey(nullptr, &p, static_cast<long>(pkcs8.size()));

    if (!key.impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, get_sanitized_error()});
    }

    auto params = validate_rsa_pss_params(key.impl_->pkey);
    if (!params) {
        return std::unexpected(params.error());
    }

    return key;
}

Result<SecureBytes> BlindRsaPrivateKey::to_pkcs8() const {
    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }

    int len = i2d_PrivateKey(impl_->pkey, nullptr);
    if (len <= 0) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to compute PKCS#8 size"});
    }

    SecureBytes result(static_cast<size_t>(len));
    uint8_t* p = result.data();
    if (i2d_PrivateKey(impl_->pkey, &p) != len) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to encode PKCS#8"});
    }

    return result;
}

Result<BlindRsaPublicKey> BlindRsaPrivateKey::public_key() const {
    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }

    // Export SPKI and reimport as public key
    int len = i2d_PUBKEY(impl_->pkey, nullptr);
    if (len <= 0) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to extract public key"});
    }

    Bytes spki(static_cast<size_t>(len));
    uint8_t* p = spki.data();
    i2d_PUBKEY(impl_->pkey, &p);

    return BlindRsaPublicKey::from_spki(ByteView(spki.data(), spki.size()));
}

Result<Bytes> BlindRsaPrivateKey::blind_sign(ByteView blinded_msg) const {
    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }

    // Validate input size to prevent integer truncation
    if (blinded_msg.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Blinded message too large"});
    }

    // Get modulus
    BIGNUM* n_bn = nullptr;
    BIGNUM* d_bn = nullptr;
    EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_N, &n_bn);
    EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_D, &d_bn);

    if (!n_bn || !d_bn) {
        BN_free(n_bn);
        BN_clear_free(d_bn);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get key parameters"});
    }

    int mod_size = BN_num_bytes(n_bn);
    if (blinded_msg.size() != static_cast<size_t>(mod_size)) {
        BN_free(n_bn);
        BN_clear_free(d_bn);
        return std::unexpected(Error{ErrorCode::INVALID_LENGTH,
            "Blinded message must match RSA modulus size"});
    }

    BN_CTX* bn_ctx = BN_CTX_new();
    BN_MONT_CTX* mont = BN_MONT_CTX_new();
    BIGNUM* m = BN_bin2bn(blinded_msg.data(), static_cast<int>(blinded_msg.size()), nullptr);
    BIGNUM* sig = BN_new();

    if (!bn_ctx || !mont || !m || !sig) {
        BN_free(n_bn);
        BN_clear_free(d_bn);
        BN_free(m);
        BN_free(sig);
        BN_MONT_CTX_free(mont);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to allocate bignums"});
    }

    if (BN_is_zero(m) || BN_cmp(m, n_bn) >= 0) {
        BN_free(n_bn);
        BN_clear_free(d_bn);
        BN_free(m);
        BN_free(sig);
        BN_MONT_CTX_free(mont);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::INVALID_LENGTH,
            "Blinded message representative out of range"});
    }

    if (BN_MONT_CTX_set(mont, n_bn, bn_ctx) != 1) {
        BN_free(n_bn);
        BN_clear_free(d_bn);
        BN_free(m);
        BN_free(sig);
        BN_MONT_CTX_free(mont);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create Montgomery context"});
    }

    // sig = m^d mod n
    BN_set_flags(d_bn, BN_FLG_CONSTTIME);
    if (BN_mod_exp_mont_consttime(sig, m, d_bn, n_bn, bn_ctx, mont) != 1) {
        BN_free(n_bn);
        BN_clear_free(d_bn);
        BN_free(m);
        BN_free(sig);
        BN_MONT_CTX_free(mont);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Blind sign failed"});
    }

    Bytes result(static_cast<size_t>(mod_size));
    BN_bn2binpad(sig, result.data(), mod_size);

    BN_free(n_bn);
    BN_clear_free(d_bn);
    BN_free(m);
    BN_free(sig);
    BN_MONT_CTX_free(mont);
    BN_CTX_free(bn_ctx);

    return result;
}

Result<Bytes> BlindRsaPrivateKey::sign(ByteView msg) const {
    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    EVP_PKEY_CTX* pkey_ctx = nullptr;

    bool success = EVP_DigestSignInit(md_ctx, &pkey_ctx, EVP_sha384(), nullptr, impl_->pkey) == 1;

    if (success) {
        success = EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) == 1 &&
                  EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, SALT_LENGTH) == 1 &&
                  EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha384()) == 1;
    }

    size_t sig_len = 0;
    if (success) {
        success = EVP_DigestSign(md_ctx, nullptr, &sig_len, msg.data(), msg.size()) == 1;
    }

    Bytes signature;
    if (success) {
        signature.resize(sig_len);
        success = EVP_DigestSign(md_ctx, signature.data(), &sig_len, msg.data(), msg.size()) == 1;
        signature.resize(sig_len);
    }

    EVP_MD_CTX_free(md_ctx);

    if (!success) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Sign failed"});
    }

    return signature;
}

bool BlindRsaPrivateKey::is_valid() const noexcept {
    return impl_ && impl_->pkey;
}

}  // namespace privacy_pass::crypto
