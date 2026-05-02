// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/crypto/blind_rsa.hpp>
#include <privacy_pass/crypto/hash.hpp>
#include <privacy_pass/crypto/random.hpp>

#include <openssl/bn.h>
#include <openssl/core_names.h>
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

// Get OpenSSL error string
std::string get_openssl_error() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return buf;
}

// EMSA-PSS encoding for blind RSA (RFC 9474)
Result<Bytes> emsa_pss_encode(ByteView msg, size_t emLen) {
    // Hash the message with SHA-384
    auto mHash = sha384(msg);
    if (!mHash) {
        return std::unexpected(mHash.error());
    }

    // Generate random salt
    auto salt_result = random_bytes(SALT_LENGTH);
    if (!salt_result) {
        return std::unexpected(salt_result.error());
    }
    const auto& salt = *salt_result;

    // Build M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    Bytes m_prime(8 + 48 + SALT_LENGTH);
    std::fill(m_prime.begin(), m_prime.begin() + 8, 0);
    std::copy(mHash->begin(), mHash->end(), m_prime.begin() + 8);
    std::copy(salt.begin(), salt.end(), m_prime.begin() + 8 + 48);

    // H = Hash(M')
    auto H = sha384(ByteView(m_prime.data(), m_prime.size()));
    if (!H) {
        return std::unexpected(H.error());
    }

    // Generate MGF1 mask
    size_t dbLen = emLen - 48 - 1;
    Bytes DB(dbLen);

    // PS = zeros, DB = PS || 0x01 || salt
    std::fill(DB.begin(), DB.end() - SALT_LENGTH - 1, 0);
    DB[dbLen - SALT_LENGTH - 1] = 0x01;
    std::copy(salt.begin(), salt.end(), DB.end() - SALT_LENGTH);

    // MGF1 with SHA-384
    Bytes dbMask(dbLen);
    size_t counter = 0;
    size_t offset = 0;
    while (offset < dbLen) {
        Bytes c_input(48 + 4);
        std::copy(H->begin(), H->end(), c_input.begin());
        c_input[48] = static_cast<uint8_t>(counter >> 24);
        c_input[49] = static_cast<uint8_t>(counter >> 16);
        c_input[50] = static_cast<uint8_t>(counter >> 8);
        c_input[51] = static_cast<uint8_t>(counter);

        auto c_hash = sha384(ByteView(c_input.data(), c_input.size()));
        if (!c_hash) {
            return std::unexpected(c_hash.error());
        }

        size_t to_copy = std::min(static_cast<size_t>(48), dbLen - offset);
        std::copy(c_hash->begin(), c_hash->begin() + to_copy, dbMask.begin() + offset);
        offset += to_copy;
        counter++;
    }

    // maskedDB = DB XOR dbMask
    Bytes maskedDB(dbLen);
    for (size_t i = 0; i < dbLen; i++) {
        maskedDB[i] = DB[i] ^ dbMask[i];
    }

    // Clear top bits
    maskedDB[0] &= 0x7F;

    // EM = maskedDB || H || 0xbc
    Bytes EM(emLen);
    std::copy(maskedDB.begin(), maskedDB.end(), EM.begin());
    std::copy(H->begin(), H->end(), EM.begin() + dbLen);
    EM[emLen - 1] = 0xBC;

    return EM;
}

}  // namespace

// BlindRsaPublicKey implementation
struct BlindRsaPublicKey::Impl {
    EVP_PKEY* pkey = nullptr;
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
    BlindRsaPublicKey key;

    const uint8_t* p = spki.data();
    key.impl_->pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(spki.size()));

    if (!key.impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY,
            "Failed to parse SPKI: " + get_openssl_error()});
    }

    if (EVP_PKEY_base_id(key.impl_->pkey) != EVP_PKEY_RSA) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Not an RSA key"});
    }

    return key;
}

Result<BlindRsaPublicKey> BlindRsaPublicKey::from_components(ByteView modulus, ByteView exponent) {
    BlindRsaPublicKey key;

    BIGNUM* n = BN_bin2bn(modulus.data(), static_cast<int>(modulus.size()), nullptr);
    BIGNUM* e = BN_bin2bn(exponent.data(), static_cast<int>(exponent.size()), nullptr);

    if (!n || !e) {
        BN_free(n);
        BN_free(e);
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Failed to create bignums"});
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        BN_free(n);
        BN_free(e);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e);
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);

    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* from_data_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);

    bool success = EVP_PKEY_fromdata_init(from_data_ctx) == 1 &&
                   EVP_PKEY_fromdata(from_data_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) == 1;

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(from_data_ctx);
    EVP_PKEY_CTX_free(ctx);
    BN_free(n);
    BN_free(e);

    if (!success || !pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Failed to create RSA key"});
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

    auto spki = to_spki();
    if (!spki) {
        return std::unexpected(spki.error());
    }

    auto hash = sha256(ByteView(spki->data(), spki->size()));
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
    auto encoded = emsa_pss_encode(msg, static_cast<size_t>(mod_size));
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
    BIGNUM* blinded = BN_new();

    if (!r || !r_inv || !x || !blinded) {
        BN_free(n_bn);
        BN_free(m);
        BN_free(e_bn);
        BN_free(r);
        BN_free(r_inv);
        BN_free(x);
        BN_free(blinded);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to allocate bignums"});
    }

    // Generate r coprime to n
    do {
        if (!BN_rand_range(r, n_bn)) {
            BN_free(n_bn);
            BN_free(m);
            BN_free(e_bn);
            BN_free(r);
            BN_free(r_inv);
            BN_free(x);
            BN_free(blinded);
            BN_CTX_free(bn_ctx);
            return std::unexpected(Error{ErrorCode::BLINDING_FAILED, "Failed to generate r"});
        }
    } while (BN_is_zero(r) || !BN_mod_inverse(r_inv, r, n_bn, bn_ctx));

    // x = r^e mod n
    if (!BN_mod_exp(x, r, e_bn, n_bn, bn_ctx)) {
        BN_free(n_bn);
        BN_free(m);
        BN_free(e_bn);
        BN_free(r);
        BN_free(r_inv);
        BN_free(x);
        BN_free(blinded);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::BLINDING_FAILED, "Failed to compute x"});
    }

    // blinded = m * x mod n
    if (!BN_mod_mul(blinded, m, x, n_bn, bn_ctx)) {
        BN_free(n_bn);
        BN_free(m);
        BN_free(e_bn);
        BN_free(r);
        BN_free(r_inv);
        BN_free(x);
        BN_free(blinded);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::BLINDING_FAILED, "Failed to blind message"});
    }

    BlindingData result;

    // Store inverse
    result.inverse.resize(BN_num_bytes(r_inv));
    BN_bn2bin(r_inv, result.inverse.data());

    // Store blinded message
    result.blinded_msg.resize(static_cast<size_t>(mod_size));
    int blinded_len = BN_bn2binpad(blinded, result.blinded_msg.data(), mod_size);
    if (blinded_len != mod_size) {
        result.blinded_msg.resize(static_cast<size_t>(blinded_len));
    }

    BN_free(n_bn);
    BN_free(m);
    BN_free(e_bn);
    BN_free(r);
    BN_free(r_inv);
    BN_free(x);
    BN_free(blinded);
    BN_CTX_free(bn_ctx);

    return result;
}

Result<Bytes> BlindRsaPublicKey::finalize(
    ByteView blind_sig,
    const BlindingData& blinding_data,
    [[maybe_unused]] ByteView msg) const {

    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
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
    BIGNUM* sig = BN_new();

    if (!z || !r_inv || !sig) {
        BN_free(n_bn);
        BN_free(z);
        BN_free(r_inv);
        BN_free(sig);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to allocate bignums"});
    }

    // sig = z * r_inv mod n
    if (!BN_mod_mul(sig, z, r_inv, n_bn, bn_ctx)) {
        BN_free(n_bn);
        BN_free(z);
        BN_free(r_inv);
        BN_free(sig);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::UNBLINDING_FAILED, "Failed to unblind"});
    }

    Bytes result(static_cast<size_t>(mod_size));
    BN_bn2binpad(sig, result.data(), mod_size);

    BN_free(n_bn);
    BN_free(z);
    BN_free(r_inv);
    BN_free(sig);
    BN_CTX_free(bn_ctx);

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
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    bool success = EVP_PKEY_keygen_init(ctx) == 1 &&
                   EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_BITS) == 1;

    EVP_PKEY* pkey = nullptr;
    success = success && EVP_PKEY_keygen(ctx, &pkey) == 1;

    EVP_PKEY_CTX_free(ctx);

    if (!success || !pkey) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR,
            "Key generation failed: " + get_openssl_error()});
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
    BlindRsaPrivateKey key;

    const uint8_t* p = pkcs8.data();
    key.impl_->pkey = d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &p, static_cast<long>(pkcs8.size()));

    if (!key.impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY,
            "Failed to parse PKCS#8: " + get_openssl_error()});
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

    // Get modulus
    BIGNUM* n_bn = nullptr;
    BIGNUM* d_bn = nullptr;
    EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_N, &n_bn);
    EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_D, &d_bn);

    if (!n_bn || !d_bn) {
        BN_free(n_bn);
        BN_free(d_bn);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get key parameters"});
    }

    int mod_size = BN_num_bytes(n_bn);

    BN_CTX* bn_ctx = BN_CTX_new();
    BIGNUM* m = BN_bin2bn(blinded_msg.data(), static_cast<int>(blinded_msg.size()), nullptr);
    BIGNUM* sig = BN_new();

    if (!bn_ctx || !m || !sig) {
        BN_free(n_bn);
        BN_free(d_bn);
        BN_free(m);
        BN_free(sig);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to allocate bignums"});
    }

    // sig = m^d mod n
    if (!BN_mod_exp(sig, m, d_bn, n_bn, bn_ctx)) {
        BN_free(n_bn);
        BN_free(d_bn);
        BN_free(m);
        BN_free(sig);
        BN_CTX_free(bn_ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Blind sign failed"});
    }

    Bytes result(static_cast<size_t>(mod_size));
    BN_bn2binpad(sig, result.data(), mod_size);

    BN_free(n_bn);
    BN_free(d_bn);
    BN_free(m);
    BN_free(sig);
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
