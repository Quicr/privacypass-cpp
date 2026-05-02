// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/crypto/voprf.hpp>
#include <privacy_pass/crypto/hash.hpp>
#include <privacy_pass/crypto/random.hpp>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <spdlog/spdlog.h>

namespace privacy_pass::crypto {

namespace {

// Domain separation tags for hash-to-curve and DLEQ (for future use)
[[maybe_unused]] constexpr uint8_t DST_H2C[] = "VOPRF10-P384-SHA384-SSWU-RO";
[[maybe_unused]] constexpr uint8_t DST_DLEQ[] = "VOPRF10-P384-SHA384-SSWU-RO-DLEQ";

// Get P-384 curve group
EC_GROUP* get_p384_group() {
    static EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    return group;
}

// Serialize EC point to uncompressed form (per RFC 9497)
Result<Bytes> point_to_bytes(const EC_POINT* point, const EC_GROUP* group) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create BN context"});
    }

    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
        nullptr, 0, ctx);

    if (len == 0) {
        BN_CTX_free(ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get point size"});
    }

    Bytes result(len);
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
            result.data(), len, ctx) != len) {
        BN_CTX_free(ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to serialize point"});
    }

    BN_CTX_free(ctx);
    return result;
}

// Deserialize EC point (accepts both compressed and uncompressed forms)
EC_POINT* bytes_to_point(ByteView data, const EC_GROUP* group) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        return nullptr;
    }

    EC_POINT* point = EC_POINT_new(group);
    if (!point) {
        BN_CTX_free(ctx);
        return nullptr;
    }

    if (EC_POINT_oct2point(group, point, data.data(), data.size(), ctx) != 1) {
        EC_POINT_free(point);
        BN_CTX_free(ctx);
        return nullptr;
    }

    BN_CTX_free(ctx);
    return point;
}

// Hash to curve (simplified - real implementation would use RFC 9380)
Result<EC_POINT*> hash_to_curve(ByteView input, const EC_GROUP* group) {
    // This is a simplified hash-to-curve for demonstration
    // A production implementation should use the full RFC 9380 algorithm

    auto hash_result = sha384(input);
    if (!hash_result) {
        return std::unexpected(hash_result.error());
    }

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    BIGNUM* x = BN_bin2bn(hash_result->data(), 48, nullptr);
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, ctx);

    // Reduce modulo order
    BN_mod(x, x, order, ctx);

    // Multiply generator by hash value to get a point
    EC_POINT* point = EC_POINT_new(group);
    if (!point || EC_POINT_mul(group, point, x, nullptr, nullptr, ctx) != 1) {
        EC_POINT_free(point);
        BN_free(x);
        BN_free(order);
        BN_CTX_free(ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Hash to curve failed"});
    }

    BN_free(x);
    BN_free(order);
    BN_CTX_free(ctx);

    return point;
}

}  // namespace

// VoprfPublicKey implementation
struct VoprfPublicKey::Impl {
    EC_POINT* point = nullptr;
    EC_GROUP* group = nullptr;
    TokenKeyId cached_key_id{};
    bool key_id_computed = false;

    Impl() : group(get_p384_group()) {}

    ~Impl() {
        if (point) {
            EC_POINT_free(point);
        }
    }
};

VoprfPublicKey::VoprfPublicKey() : impl_(std::make_unique<Impl>()) {}
VoprfPublicKey::~VoprfPublicKey() = default;
VoprfPublicKey::VoprfPublicKey(VoprfPublicKey&&) noexcept = default;
VoprfPublicKey& VoprfPublicKey::operator=(VoprfPublicKey&&) noexcept = default;

Result<VoprfPublicKey> VoprfPublicKey::from_bytes(ByteView data) {
    VoprfPublicKey key;

    key.impl_->point = bytes_to_point(data, key.impl_->group);
    if (!key.impl_->point) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Failed to parse public key"});
    }

    return key;
}

Result<Bytes> VoprfPublicKey::to_bytes() const {
    if (!impl_->point) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }

    return point_to_bytes(impl_->point, impl_->group);
}

Result<TokenKeyId> VoprfPublicKey::key_id() const {
    if (impl_->key_id_computed) {
        return impl_->cached_key_id;
    }

    auto bytes = to_bytes();
    if (!bytes) {
        return std::unexpected(bytes.error());
    }

    auto hash = sha256(ByteView(bytes->data(), bytes->size()));
    if (!hash) {
        return std::unexpected(hash.error());
    }

    impl_->cached_key_id = *hash;
    impl_->key_id_computed = true;
    return impl_->cached_key_id;
}

bool VoprfPublicKey::is_valid() const noexcept {
    return impl_ && impl_->point;
}

// VoprfPrivateKey implementation
struct VoprfPrivateKey::Impl {
    BIGNUM* scalar = nullptr;
    EC_GROUP* group = nullptr;

    Impl() : group(get_p384_group()) {}

    ~Impl() {
        if (scalar) {
            BN_clear_free(scalar);
        }
    }
};

VoprfPrivateKey::VoprfPrivateKey() : impl_(std::make_unique<Impl>()) {}
VoprfPrivateKey::~VoprfPrivateKey() = default;
VoprfPrivateKey::VoprfPrivateKey(VoprfPrivateKey&&) noexcept = default;
VoprfPrivateKey& VoprfPrivateKey::operator=(VoprfPrivateKey&&) noexcept = default;

Result<std::pair<VoprfPrivateKey, VoprfPublicKey>> VoprfPrivateKey::generate() {
    VoprfPrivateKey private_key;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    BIGNUM* order = BN_new();
    EC_GROUP_get_order(private_key.impl_->group, order, ctx);

    private_key.impl_->scalar = BN_new();
    if (!BN_rand_range(private_key.impl_->scalar, order) ||
        BN_is_zero(private_key.impl_->scalar)) {
        BN_free(order);
        BN_CTX_free(ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Key generation failed"});
    }

    // Compute public key: Y = k * G
    EC_POINT* pub_point = EC_POINT_new(private_key.impl_->group);
    if (!pub_point ||
        EC_POINT_mul(private_key.impl_->group, pub_point, private_key.impl_->scalar,
            nullptr, nullptr, ctx) != 1) {
        EC_POINT_free(pub_point);
        BN_free(order);
        BN_CTX_free(ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Public key computation failed"});
    }

    VoprfPublicKey public_key;
    public_key.impl_->point = pub_point;

    BN_free(order);
    BN_CTX_free(ctx);

    return std::make_pair(std::move(private_key), std::move(public_key));
}

Result<VoprfPrivateKey> VoprfPrivateKey::from_bytes(ByteView data) {
    if (data.empty()) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Empty private key data"});
    }

    VoprfPrivateKey key;

    key.impl_->scalar = BN_bin2bn(data.data(), static_cast<int>(data.size()), nullptr);
    if (!key.impl_->scalar) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Failed to parse private key"});
    }

    return key;
}

Result<SecureBytes> VoprfPrivateKey::to_bytes() const {
    if (!impl_->scalar) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }

    SecureBytes result(P384_SCALAR_SIZE);
    int len = BN_bn2binpad(impl_->scalar, result.data(), P384_SCALAR_SIZE);
    if (len != P384_SCALAR_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to serialize private key"});
    }

    return result;
}

Result<VoprfPublicKey> VoprfPrivateKey::public_key() const {
    if (!impl_->scalar) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    EC_POINT* pub_point = EC_POINT_new(impl_->group);
    if (!pub_point ||
        EC_POINT_mul(impl_->group, pub_point, impl_->scalar, nullptr, nullptr, ctx) != 1) {
        EC_POINT_free(pub_point);
        BN_CTX_free(ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Public key computation failed"});
    }

    BN_CTX_free(ctx);

    VoprfPublicKey public_key;
    public_key.impl_->point = pub_point;

    return public_key;
}

bool VoprfPrivateKey::is_valid() const noexcept {
    return impl_ && impl_->scalar;
}

// VoprfClient implementation
struct VoprfClient::Impl {
    VoprfPublicKey public_key;
};

VoprfClient::VoprfClient(VoprfPublicKey public_key)
    : impl_(std::make_unique<Impl>()) {
    impl_->public_key = std::move(public_key);
}

VoprfClient::~VoprfClient() = default;
VoprfClient::VoprfClient(VoprfClient&&) noexcept = default;
VoprfClient& VoprfClient::operator=(VoprfClient&&) noexcept = default;

Result<VoprfFinalizationData> VoprfClient::blind(ByteView input) const {
    EC_GROUP* group = get_p384_group();

    // Hash input to curve point
    auto h_result = hash_to_curve(input, group);
    if (!h_result) {
        return std::unexpected(h_result.error());
    }
    EC_POINT* P = *h_result;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        EC_POINT_free(P);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    // Generate random blinding scalar r
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, ctx);

    BIGNUM* r = BN_new();
    if (!BN_rand_range(r, order) || BN_is_zero(r)) {
        BN_free(r);
        BN_free(order);
        BN_CTX_free(ctx);
        EC_POINT_free(P);
        return std::unexpected(Error{ErrorCode::BLINDING_FAILED, "Failed to generate blinding scalar"});
    }

    // Compute blinded element: R = r * P
    EC_POINT* R = EC_POINT_new(group);
    if (!R || EC_POINT_mul(group, R, nullptr, P, r, ctx) != 1) {
        EC_POINT_free(R);
        BN_free(r);
        BN_free(order);
        BN_CTX_free(ctx);
        EC_POINT_free(P);
        return std::unexpected(Error{ErrorCode::BLINDING_FAILED, "Failed to compute blinded element"});
    }

    // Serialize results
    VoprfFinalizationData result;

    // Store blinding scalar
    result.blind_scalar.resize(P384_SCALAR_SIZE);
    BN_bn2binpad(r, result.blind_scalar.data(), P384_SCALAR_SIZE);

    // Store blinded element
    auto blinded_bytes = point_to_bytes(R, group);
    if (!blinded_bytes) {
        EC_POINT_free(R);
        BN_free(r);
        BN_free(order);
        BN_CTX_free(ctx);
        EC_POINT_free(P);
        return std::unexpected(blinded_bytes.error());
    }
    result.blinded_element = std::move(*blinded_bytes);

    // Store input for finalization
    result.input.assign(input.begin(), input.end());

    EC_POINT_free(R);
    EC_POINT_free(P);
    BN_free(r);
    BN_free(order);
    BN_CTX_free(ctx);

    return result;
}

Result<Bytes> VoprfClient::finalize(
    const VoprfFinalizationData& finalization_data,
    const VoprfEvaluation& evaluation) const {

    EC_GROUP* group = get_p384_group();

    // Deserialize evaluated element
    EC_POINT* Z = bytes_to_point(
        ByteView(evaluation.evaluated_element.data(), evaluation.evaluated_element.size()),
        group);
    if (!Z) {
        return std::unexpected(Error{ErrorCode::UNBLINDING_FAILED, "Invalid evaluated element"});
    }

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        EC_POINT_free(Z);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    // Recover blinding scalar
    BIGNUM* r = BN_bin2bn(finalization_data.blind_scalar.data(),
        static_cast<int>(finalization_data.blind_scalar.size()), nullptr);

    // Compute r^-1
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, ctx);

    BIGNUM* r_inv = BN_mod_inverse(nullptr, r, order, ctx);
    if (!r_inv) {
        BN_free(r);
        BN_free(order);
        BN_CTX_free(ctx);
        EC_POINT_free(Z);
        return std::unexpected(Error{ErrorCode::UNBLINDING_FAILED, "Failed to compute inverse"});
    }

    // Compute unblinded result: N = r^-1 * Z
    EC_POINT* N = EC_POINT_new(group);
    if (!N || EC_POINT_mul(group, N, nullptr, Z, r_inv, ctx) != 1) {
        EC_POINT_free(N);
        BN_free(r_inv);
        BN_free(r);
        BN_free(order);
        BN_CTX_free(ctx);
        EC_POINT_free(Z);
        return std::unexpected(Error{ErrorCode::UNBLINDING_FAILED, "Failed to unblind"});
    }

    // Serialize output point
    auto output_point = point_to_bytes(N, group);

    EC_POINT_free(N);
    EC_POINT_free(Z);
    BN_free(r_inv);
    BN_free(r);
    BN_free(order);
    BN_CTX_free(ctx);

    if (!output_point) {
        return std::unexpected(output_point.error());
    }

    // Hash point to final output
    auto final_output = sha384(ByteView(output_point->data(), output_point->size()));
    if (!final_output) {
        return std::unexpected(final_output.error());
    }

    return Bytes(final_output->begin(), final_output->end());
}

// VoprfServer implementation
struct VoprfServer::Impl {
    VoprfPrivateKey private_key;
};

VoprfServer::VoprfServer(VoprfPrivateKey private_key)
    : impl_(std::make_unique<Impl>()) {
    impl_->private_key = std::move(private_key);
}

VoprfServer::~VoprfServer() = default;
VoprfServer::VoprfServer(VoprfServer&&) noexcept = default;
VoprfServer& VoprfServer::operator=(VoprfServer&&) noexcept = default;

Result<VoprfEvaluation> VoprfServer::blind_evaluate(ByteView blinded_element) const {
    EC_GROUP* group = get_p384_group();

    // Deserialize blinded element
    EC_POINT* R = bytes_to_point(blinded_element, group);
    if (!R) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Invalid blinded element"});
    }

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        EC_POINT_free(R);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    // Get private scalar
    auto scalar_bytes = impl_->private_key.to_bytes();
    if (!scalar_bytes) {
        BN_CTX_free(ctx);
        EC_POINT_free(R);
        return std::unexpected(scalar_bytes.error());
    }

    BIGNUM* k = BN_bin2bn(scalar_bytes->data(),
        static_cast<int>(scalar_bytes->size()), nullptr);

    // Compute Z = k * R
    EC_POINT* Z = EC_POINT_new(group);
    if (!Z || EC_POINT_mul(group, Z, nullptr, R, k, ctx) != 1) {
        EC_POINT_free(Z);
        BN_clear_free(k);
        BN_CTX_free(ctx);
        EC_POINT_free(R);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Evaluation failed"});
    }

    // Serialize evaluated element
    auto z_bytes = point_to_bytes(Z, group);
    if (!z_bytes) {
        EC_POINT_free(Z);
        BN_clear_free(k);
        BN_CTX_free(ctx);
        EC_POINT_free(R);
        return std::unexpected(z_bytes.error());
    }

    // Generate DLEQ proof (simplified)
    // A full implementation would compute the proper DLEQ proof per RFC 9497

    VoprfEvaluation result;
    result.evaluated_element = std::move(*z_bytes);

    // Placeholder proof (real implementation needed)
    result.proof.resize(P384_PROOF_SIZE, 0);

    EC_POINT_free(Z);
    EC_POINT_free(R);
    BN_clear_free(k);
    BN_CTX_free(ctx);

    return result;
}

Result<bool> VoprfServer::verify_finalize(ByteView input, ByteView output) const {
    EC_GROUP* group = get_p384_group();

    // Hash input to curve
    auto h_result = hash_to_curve(input, group);
    if (!h_result) {
        return std::unexpected(h_result.error());
    }
    EC_POINT* P = *h_result;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        EC_POINT_free(P);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    // Get private scalar
    auto scalar_bytes = impl_->private_key.to_bytes();
    if (!scalar_bytes) {
        BN_CTX_free(ctx);
        EC_POINT_free(P);
        return std::unexpected(scalar_bytes.error());
    }

    BIGNUM* k = BN_bin2bn(scalar_bytes->data(),
        static_cast<int>(scalar_bytes->size()), nullptr);

    // Compute expected output: k * P
    EC_POINT* expected = EC_POINT_new(group);
    if (!expected || EC_POINT_mul(group, expected, nullptr, P, k, ctx) != 1) {
        EC_POINT_free(expected);
        BN_clear_free(k);
        BN_CTX_free(ctx);
        EC_POINT_free(P);
        return std::unexpected(Error{ErrorCode::VERIFICATION_FAILED, "Failed to compute expected output"});
    }

    // Hash expected point
    auto expected_bytes = point_to_bytes(expected, group);
    if (!expected_bytes) {
        EC_POINT_free(expected);
        BN_clear_free(k);
        BN_CTX_free(ctx);
        EC_POINT_free(P);
        return std::unexpected(expected_bytes.error());
    }

    auto expected_hash = sha384(ByteView(expected_bytes->data(), expected_bytes->size()));

    EC_POINT_free(expected);
    EC_POINT_free(P);
    BN_clear_free(k);
    BN_CTX_free(ctx);

    if (!expected_hash) {
        return std::unexpected(expected_hash.error());
    }

    // Compare with provided output
    if (output.size() != expected_hash->size()) {
        return false;
    }

    return std::equal(output.begin(), output.end(), expected_hash->begin());
}

Result<VoprfPublicKey> VoprfServer::public_key() const {
    return impl_->private_key.public_key();
}

}  // namespace privacy_pass::crypto
