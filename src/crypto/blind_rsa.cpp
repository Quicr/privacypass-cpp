// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/crypto/blind_rsa.hpp>
#include <privacy_pass/crypto/hash.hpp>
#include <privacy_pass/crypto/random.hpp>

#include "compat.hpp"

#include <spdlog/spdlog.h>

namespace privacy_pass::crypto {

using namespace detail;
using namespace compat;

namespace {

constexpr int RSA_BITS = 2048;
constexpr int SALT_LENGTH = 48;
constexpr size_t MAX_INPUT_SIZE = static_cast<size_t>(INT_MAX);

Result<Bytes> do_emsa_pss_encode(EVP_PKEY* pkey, ByteView msg) {
    auto mHash = sha384(msg);
    if (!mHash) return std::unexpected(mHash.error());
    return emsa_pss_encode(pkey, ByteView(mHash->data(), mHash->size()), SALT_LENGTH);
}

}  // namespace

// BlindRsaPublicKey implementation
struct BlindRsaPublicKey::Impl {
    UniqueEVP_PKEY pkey;
    Bytes original_spki;
    TokenKeyId cached_key_id{};
    bool key_id_computed = false;
};

BlindRsaPublicKey::BlindRsaPublicKey() : impl_(std::make_unique<Impl>()) {}
BlindRsaPublicKey::~BlindRsaPublicKey() = default;
BlindRsaPublicKey::BlindRsaPublicKey(BlindRsaPublicKey&&) noexcept = default;
BlindRsaPublicKey& BlindRsaPublicKey::operator=(BlindRsaPublicKey&&) noexcept = default;

Result<BlindRsaPublicKey> BlindRsaPublicKey::from_spki(ByteView spki) {
    if (spki.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "SPKI data too large"});
    }

    BlindRsaPublicKey key;
    key.impl_->pkey = parse_public_key_spki(spki);
    if (!key.impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, get_sanitized_error()});
    }

    auto params = validate_rsa_params(key.impl_->pkey.get(), RSA_BITS, RSA_PUBLIC_EXPONENT);
    if (!params) return std::unexpected(params.error());

    key.impl_->original_spki.assign(spki.begin(), spki.end());
    return key;
}

Result<BlindRsaPublicKey> BlindRsaPublicKey::from_components(ByteView modulus, ByteView exponent) {
    if (modulus.size() > MAX_INPUT_SIZE || exponent.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key component too large"});
    }

    auto n = bin2bn(modulus.data(), static_cast<int>(modulus.size()));
    auto e = bin2bn(exponent.data(), static_cast<int>(exponent.size()));
    if (!n || !e) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Failed to create bignums"});
    }

    BlindRsaPublicKey key;
    key.impl_->pkey = rsa_public_key_from_components(n.get(), e.get());
    if (!key.impl_->pkey) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create RSA key"});
    }

    auto validated = validate_rsa_params(key.impl_->pkey.get(), RSA_BITS, RSA_PUBLIC_EXPONENT);
    if (!validated) return std::unexpected(validated.error());

    return key;
}

Result<Bytes> BlindRsaPublicKey::to_spki() const {
    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }
    return marshal_public_key(impl_->pkey.get());
}

Result<TokenKeyId> BlindRsaPublicKey::key_id() const {
    if (impl_->key_id_computed) return impl_->cached_key_id;

    Bytes spki;
    if (!impl_->original_spki.empty()) {
        spki = impl_->original_spki;
    } else {
        auto encoded = to_spki();
        if (!encoded) return std::unexpected(encoded.error());
        spki = std::move(*encoded);
    }

    auto hash = sha256(ByteView(spki.data(), spki.size()));
    if (!hash) return std::unexpected(hash.error());

    impl_->cached_key_id = *hash;
    impl_->key_id_computed = true;
    return impl_->cached_key_id;
}

Result<BlindingData> BlindRsaPublicKey::blind(ByteView msg) const {
    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }

    UniqueBIGNUM n_bn, e_bn;
    if (!rsa_get_bn_param(impl_->pkey.get(), PARAM_RSA_N, n_bn) ||
        !rsa_get_bn_param(impl_->pkey.get(), PARAM_RSA_E, e_bn)) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get key params"});
    }

    int mod_size = BN_num_bytes(n_bn.get());

    auto encoded = do_emsa_pss_encode(impl_->pkey.get(), msg);
    if (!encoded) return std::unexpected(encoded.error());

    auto m = bin2bn(encoded->data(), static_cast<int>(encoded->size()));
    if (!m) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to convert message"});
    }

    auto bn_ctx = make_bn_ctx();
    auto r = make_secure_bignum();
    auto r_inv = make_secure_bignum();
    auto x = make_bignum();
    auto x_mont = make_bignum();
    auto blinded = make_bignum();
    auto mont = make_bn_mont_ctx();

    if (!bn_ctx || !r || !r_inv || !x || !x_mont || !blinded || !mont) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to allocate bignums"});
    }

    if (BN_MONT_CTX_set(mont.get(), n_bn.get(), bn_ctx.get()) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create Montgomery context"});
    }

    do {
        if (!BN_rand_range(r.get(), n_bn.get())) {
            return std::unexpected(Error{ErrorCode::BLINDING_FAILED, "Failed to generate r"});
        }
    } while (BN_is_zero(r.get()) || !BN_mod_inverse(r_inv.get(), r.get(), n_bn.get(), bn_ctx.get()));

    if (BN_mod_exp_mont(x.get(), r.get(), e_bn.get(), n_bn.get(), bn_ctx.get(), mont.get()) != 1 ||
        BN_to_montgomery(x_mont.get(), x.get(), mont.get(), bn_ctx.get()) != 1 ||
        BN_mod_mul_montgomery(blinded.get(), m.get(), x_mont.get(), mont.get(), bn_ctx.get()) != 1) {
        return std::unexpected(Error{ErrorCode::BLINDING_FAILED, "Failed to blind message"});
    }

    BlindingData result;
    result.inverse.resize(static_cast<size_t>(mod_size));
    result.blinded_msg.resize(static_cast<size_t>(mod_size));
    if (BN_bn2binpad(r_inv.get(), result.inverse.data(), mod_size) != mod_size ||
        BN_bn2binpad(blinded.get(), result.blinded_msg.data(), mod_size) != mod_size) {
        return std::unexpected(Error{ErrorCode::BLINDING_FAILED, "Failed to serialize"});
    }

    return result;
}

Result<Bytes> BlindRsaPublicKey::finalize(
    ByteView blind_sig, BlindingData& blinding_data, ByteView msg) const {

    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }
    if (blind_sig.size() > MAX_INPUT_SIZE || blinding_data.inverse.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Input too large"});
    }

    UniqueBIGNUM n_bn;
    if (!rsa_get_bn_param(impl_->pkey.get(), PARAM_RSA_N, n_bn)) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get modulus"});
    }

    int mod_size = BN_num_bytes(n_bn.get());
    auto expected_size = static_cast<size_t>(mod_size);
    if (blind_sig.size() != expected_size || blinding_data.inverse.size() != expected_size) {
        return std::unexpected(Error{ErrorCode::INVALID_LENGTH,
            "Blind signature and inverse must match modulus length"});
    }

    auto bn_ctx = make_bn_ctx();
    auto z = bin2bn(blind_sig.data(), static_cast<int>(blind_sig.size()));
    auto r_inv = bin2bn_secure(blinding_data.inverse.data(),
        static_cast<int>(blinding_data.inverse.size()));
    auto r_inv_mont = make_secure_bignum();
    auto sig = make_bignum();
    auto mont = make_bn_mont_ctx();

    if (!bn_ctx || !z || !r_inv || !r_inv_mont || !sig || !mont) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to allocate bignums"});
    }

    if (BN_cmp(z.get(), n_bn.get()) >= 0) {
        return std::unexpected(Error{ErrorCode::UNBLINDING_FAILED, "Blind signature out of range"});
    }

    if (BN_MONT_CTX_set(mont.get(), n_bn.get(), bn_ctx.get()) != 1 ||
        BN_to_montgomery(r_inv_mont.get(), r_inv.get(), mont.get(), bn_ctx.get()) != 1 ||
        BN_mod_mul_montgomery(sig.get(), z.get(), r_inv_mont.get(), mont.get(), bn_ctx.get()) != 1) {
        return std::unexpected(Error{ErrorCode::UNBLINDING_FAILED, "Failed to unblind"});
    }

    Bytes result(static_cast<size_t>(mod_size));
    BN_bn2binpad(sig.get(), result.data(), mod_size);
    blinding_data.inverse.clear();

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

    auto md_ctx = make_evp_md_ctx();
    if (!md_ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    EVP_PKEY_CTX* pkey_ctx = nullptr;
    bool success = EVP_DigestVerifyInit(md_ctx.get(), &pkey_ctx, EVP_sha384(), nullptr, impl_->pkey.get()) == 1;
    if (success) {
        success = EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) == 1 &&
                  EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, SALT_LENGTH) == 1 &&
                  EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha384()) == 1;
    }

    int result = 0;
    if (success) {
        result = EVP_DigestVerify(md_ctx.get(),
            signature.data(), signature.size(), msg.data(), msg.size());
    }

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
    UniqueEVP_PKEY pkey;
};

BlindRsaPrivateKey::BlindRsaPrivateKey() : impl_(std::make_unique<Impl>()) {}
BlindRsaPrivateKey::~BlindRsaPrivateKey() = default;
BlindRsaPrivateKey::BlindRsaPrivateKey(BlindRsaPrivateKey&&) noexcept = default;
BlindRsaPrivateKey& BlindRsaPrivateKey::operator=(BlindRsaPrivateKey&&) noexcept = default;

Result<std::pair<BlindRsaPrivateKey, BlindRsaPublicKey>> BlindRsaPrivateKey::generate() {
    auto pkey = generate_rsa_pss_keypair(RSA_BITS, SALT_LENGTH);
    if (!pkey) {
        spdlog::debug("Key generation failed: {}", get_openssl_error());
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Key generation failed"});
    }

    BlindRsaPrivateKey private_key;
    private_key.impl_->pkey = std::move(pkey);

    auto public_key_result = private_key.public_key();
    if (!public_key_result) return std::unexpected(public_key_result.error());
    return std::make_pair(std::move(private_key), std::move(*public_key_result));
}

Result<BlindRsaPrivateKey> BlindRsaPrivateKey::from_pkcs8(ByteView pkcs8) {
    if (pkcs8.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "PKCS#8 data too large"});
    }

    BlindRsaPrivateKey key;
    key.impl_->pkey = parse_private_key_der(pkcs8);
    if (!key.impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, get_sanitized_error()});
    }

    auto params = validate_rsa_params(key.impl_->pkey.get(), RSA_BITS, RSA_PUBLIC_EXPONENT);
    if (!params) return std::unexpected(params.error());
    return key;
}

Result<SecureBytes> BlindRsaPrivateKey::to_pkcs8() const {
    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }
    return marshal_private_key(impl_->pkey.get());
}

Result<BlindRsaPublicKey> BlindRsaPrivateKey::public_key() const {
    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }
    auto spki = marshal_public_key(impl_->pkey.get());
    if (!spki) return std::unexpected(spki.error());
    return BlindRsaPublicKey::from_spki(ByteView(spki->data(), spki->size()));
}

Result<Bytes> BlindRsaPrivateKey::blind_sign(ByteView blinded_msg) const {
    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }
    if (blinded_msg.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Blinded message too large"});
    }

    UniqueBIGNUM n_bn;
    UniqueSecureBIGNUM d_bn;
    if (!rsa_get_bn_param(impl_->pkey.get(), PARAM_RSA_N, n_bn) ||
        !rsa_get_secure_bn_param(impl_->pkey.get(), PARAM_RSA_D, d_bn)) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get key parameters"});
    }

    int mod_size = BN_num_bytes(n_bn.get());
    if (blinded_msg.size() != static_cast<size_t>(mod_size)) {
        return std::unexpected(Error{ErrorCode::INVALID_LENGTH,
            "Blinded message must match RSA modulus size"});
    }

    auto bn_ctx = make_bn_ctx();
    auto mont = make_bn_mont_ctx();
    auto m = bin2bn(blinded_msg.data(), static_cast<int>(blinded_msg.size()));
    auto sig = make_bignum();

    if (!bn_ctx || !mont || !m || !sig) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to allocate bignums"});
    }

    if (BN_is_zero(m.get()) || BN_cmp(m.get(), n_bn.get()) >= 0) {
        return std::unexpected(Error{ErrorCode::INVALID_LENGTH,
            "Blinded message representative out of range"});
    }

    if (BN_MONT_CTX_set(mont.get(), n_bn.get(), bn_ctx.get()) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create Montgomery context"});
    }

    bn_set_consttime(d_bn.get());
    if (BN_mod_exp_mont_consttime(sig.get(), m.get(), d_bn.get(), n_bn.get(), bn_ctx.get(), mont.get()) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Blind sign failed"});
    }

    Bytes result(static_cast<size_t>(mod_size));
    BN_bn2binpad(sig.get(), result.data(), mod_size);
    return result;
}

Result<Bytes> BlindRsaPrivateKey::sign(ByteView msg) const {
    if (!impl_->pkey) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }

    auto md_ctx = make_evp_md_ctx();
    if (!md_ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    EVP_PKEY_CTX* pkey_ctx = nullptr;
    bool success = EVP_DigestSignInit(md_ctx.get(), &pkey_ctx, EVP_sha384(), nullptr, impl_->pkey.get()) == 1;
    if (success) {
        success = EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) == 1 &&
                  EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, SALT_LENGTH) == 1 &&
                  EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha384()) == 1;
    }

    size_t sig_len = 0;
    if (success) success = EVP_DigestSign(md_ctx.get(), nullptr, &sig_len, msg.data(), msg.size()) == 1;

    Bytes signature;
    if (success) {
        signature.resize(sig_len);
        success = EVP_DigestSign(md_ctx.get(), signature.data(), &sig_len, msg.data(), msg.size()) == 1;
        signature.resize(sig_len);
    }

    if (!success) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Sign failed"});
    }
    return signature;
}

bool BlindRsaPrivateKey::is_valid() const noexcept {
    return impl_ && impl_->pkey;
}

}  // namespace privacy_pass::crypto
