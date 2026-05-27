// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/crypto/voprf.hpp>
#include <privacy_pass/crypto/hash.hpp>
#include <privacy_pass/crypto/random.hpp>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <spdlog/spdlog.h>
#include <mutex>

namespace privacy_pass::crypto {

namespace {

// Domain separation tags for hash-to-curve and DLEQ per RFC 9497
constexpr const char* DST_H2C = "VOPRF10-P384-SHA384-SSWU-RO";
constexpr const char* DST_CHALLENGE = "Challenge";

// Maximum input size for OpenSSL APIs (prevent integer truncation)
constexpr size_t MAX_INPUT_SIZE = static_cast<size_t>(INT_MAX);

// Thread-safe P-384 curve group singleton
class P384Group {
public:
    static EC_GROUP* get() {
        static P384Group instance;
        return instance.group_;
    }

    ~P384Group() {
        if (group_) {
            EC_GROUP_free(group_);
        }
    }

private:
    P384Group() {
        group_ = EC_GROUP_new_by_curve_name(NID_secp384r1);
        if (!group_) {
            spdlog::error("Failed to create P-384 group");
        }
    }

    P384Group(const P384Group&) = delete;
    P384Group& operator=(const P384Group&) = delete;

    EC_GROUP* group_ = nullptr;
};

// Get P-384 curve group (thread-safe)
EC_GROUP* get_p384_group() {
    return P384Group::get();
}

// Constant-time comparison for cryptographic values
bool constant_time_compare(ByteView a, ByteView b) {
    if (a.size() != b.size()) {
        return false;
    }
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

// Serialize EC point to compressed form (per RFC 9497 SerializeElement)
Result<Bytes> point_to_bytes(const EC_POINT* point, const EC_GROUP* group) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create BN context"});
    }

    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED,
        nullptr, 0, ctx);

    if (len == 0) {
        BN_CTX_free(ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get point size"});
    }

    Bytes result(len);
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED,
            result.data(), len, ctx) != len) {
        BN_CTX_free(ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to serialize point"});
    }

    BN_CTX_free(ctx);
    return result;
}

// Deserialize EC point with validation (accepts both compressed and uncompressed forms)
EC_POINT* bytes_to_point(ByteView data, const EC_GROUP* group) {
    if (data.size() > MAX_INPUT_SIZE) {
        return nullptr;
    }

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

    // Validate point is on the curve
    if (EC_POINT_is_on_curve(group, point, ctx) != 1) {
        EC_POINT_free(point);
        BN_CTX_free(ctx);
        return nullptr;
    }

    BN_CTX_free(ctx);
    return point;
}

// Expand message using XMD (hash to arbitrary length) per RFC 9380 Section 5.3.1
Result<Bytes> expand_message_xmd(ByteView msg, ByteView dst, size_t len_in_bytes) {
    const size_t b_in_bytes = 48;  // SHA-384 output size
    const size_t s_in_bytes = 128; // SHA-384 block size

    if (len_in_bytes > 255 * b_in_bytes || dst.size() > 255) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Invalid expand_message_xmd parameters"});
    }

    size_t ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;

    // DST_prime = DST || I2OSP(len(DST), 1)
    Bytes dst_prime(dst.begin(), dst.end());
    dst_prime.push_back(static_cast<uint8_t>(dst.size()));

    // Z_pad = I2OSP(0, s_in_bytes)
    Bytes z_pad(s_in_bytes, 0);

    // l_i_b_str = I2OSP(len_in_bytes, 2)
    Bytes l_i_b_str = {static_cast<uint8_t>(len_in_bytes >> 8), static_cast<uint8_t>(len_in_bytes)};

    // msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
    Bytes msg_prime;
    msg_prime.reserve(z_pad.size() + msg.size() + l_i_b_str.size() + 1 + dst_prime.size());
    msg_prime.insert(msg_prime.end(), z_pad.begin(), z_pad.end());
    msg_prime.insert(msg_prime.end(), msg.begin(), msg.end());
    msg_prime.insert(msg_prime.end(), l_i_b_str.begin(), l_i_b_str.end());
    msg_prime.push_back(0);
    msg_prime.insert(msg_prime.end(), dst_prime.begin(), dst_prime.end());

    // b_0 = H(msg_prime)
    auto b_0 = sha384(ByteView(msg_prime.data(), msg_prime.size()));
    if (!b_0) {
        return std::unexpected(b_0.error());
    }

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    Bytes b_1_input;
    b_1_input.reserve(b_0->size() + 1 + dst_prime.size());
    b_1_input.insert(b_1_input.end(), b_0->begin(), b_0->end());
    b_1_input.push_back(1);
    b_1_input.insert(b_1_input.end(), dst_prime.begin(), dst_prime.end());

    auto b_1 = sha384(ByteView(b_1_input.data(), b_1_input.size()));
    if (!b_1) {
        return std::unexpected(b_1.error());
    }

    Bytes uniform_bytes;
    uniform_bytes.reserve(len_in_bytes);
    uniform_bytes.insert(uniform_bytes.end(), b_1->begin(), b_1->end());

    Hash384 b_prev = *b_1;
    for (size_t i = 2; i <= ell; ++i) {
        // strxor(b_0, b_(i-1))
        Hash384 xored;
        for (size_t j = 0; j < b_in_bytes; ++j) {
            xored[j] = (*b_0)[j] ^ b_prev[j];
        }

        // b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
        Bytes b_i_input;
        b_i_input.reserve(xored.size() + 1 + dst_prime.size());
        b_i_input.insert(b_i_input.end(), xored.begin(), xored.end());
        b_i_input.push_back(static_cast<uint8_t>(i));
        b_i_input.insert(b_i_input.end(), dst_prime.begin(), dst_prime.end());

        auto b_i = sha384(ByteView(b_i_input.data(), b_i_input.size()));
        if (!b_i) {
            return std::unexpected(b_i.error());
        }

        uniform_bytes.insert(uniform_bytes.end(), b_i->begin(), b_i->end());
        b_prev = *b_i;
    }

    uniform_bytes.resize(len_in_bytes);
    return uniform_bytes;
}

// SSWU map for P-384 per RFC 9380 Appendix F.2
Result<EC_POINT*> map_to_curve_sswu(const BIGNUM* u, const EC_GROUP* group, BN_CTX* ctx) {
    // P-384 constants
    // A = -3 (mod p)
    // B = b4050a85 0c04b3ab f5413256 5044b0b7 d7bfd8ba 270b3943 2355ffb4
    //     a9c7a8a9 acb4b9da 4db97dc6 e2b8a62a cb8dfe7b
    // Z = -12 (mod p)
    // c1 = (p - 3) / 4
    // c2 = sqrt(-Z)

    BIGNUM* p = BN_new();
    BIGNUM* A = BN_new();
    BIGNUM* B = BN_new();
    BIGNUM* Z = BN_new();
    BIGNUM* tv1 = BN_new();
    BIGNUM* tv2 = BN_new();
    BIGNUM* tv3 = BN_new();
    BIGNUM* tv4 = BN_new();
    BIGNUM* tv5 = BN_new();
    BIGNUM* tv6 = BN_new();
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    BIGNUM* gx = BN_new();
    BIGNUM* one = BN_new();
    BIGNUM* neg_one = BN_new();

    if (!p || !A || !B || !Z || !tv1 || !tv2 || !tv3 || !tv4 || !tv5 || !tv6 ||
        !x || !y || !gx || !one || !neg_one) {
        BN_free(p); BN_free(A); BN_free(B); BN_free(Z);
        BN_free(tv1); BN_free(tv2); BN_free(tv3); BN_free(tv4); BN_free(tv5); BN_free(tv6);
        BN_free(x); BN_free(y); BN_free(gx); BN_free(one); BN_free(neg_one);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to allocate bignums"});
    }

    // Get curve parameters
    EC_GROUP_get_curve(group, p, A, B, ctx);
    BN_set_word(one, 1);
    BN_sub(neg_one, p, one);
    BN_set_word(Z, 12);
    BN_sub(Z, p, Z);  // Z = -12 mod p

    // tv1 = u^2
    BN_mod_sqr(tv1, u, p, ctx);
    // tv3 = Z * tv1
    BN_mod_mul(tv3, Z, tv1, p, ctx);
    // tv5 = tv3^2
    BN_mod_sqr(tv5, tv3, p, ctx);
    // tv5 = tv5 + tv3
    BN_mod_add(tv5, tv5, tv3, p, ctx);
    // tv4 = tv5 + 1
    BN_mod_add(tv4, tv5, one, p, ctx);
    // tv4 = tv4 * B
    BN_mod_mul(tv4, tv4, B, p, ctx);
    // tv2 = tv3 * B
    BN_mod_mul(tv2, tv3, B, p, ctx);

    // Check if tv5 is zero (special case)
    BIGNUM* temp = BN_new();
    BN_copy(temp, tv5);

    // tv6 = -A (need to compute denominator)
    BN_sub(tv6, p, A);

    if (BN_is_zero(temp)) {
        // tv6 = Z * A
        BN_mod_mul(tv6, Z, A, p, ctx);
    } else {
        // tv6 = tv5 * (-A)
        BIGNUM* neg_A = BN_new();
        BN_sub(neg_A, p, A);
        BN_mod_mul(tv6, tv5, neg_A, p, ctx);
        BN_free(neg_A);
    }
    BN_free(temp);

    // x = tv4 / tv6 (using modular inverse)
    BIGNUM* tv6_inv = BN_mod_inverse(nullptr, tv6, p, ctx);
    if (!tv6_inv) {
        BN_free(p); BN_free(A); BN_free(B); BN_free(Z);
        BN_free(tv1); BN_free(tv2); BN_free(tv3); BN_free(tv4); BN_free(tv5); BN_free(tv6);
        BN_free(x); BN_free(y); BN_free(gx); BN_free(one); BN_free(neg_one);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to compute inverse"});
    }
    BN_mod_mul(x, tv4, tv6_inv, p, ctx);
    BN_free(tv6_inv);

    // gx = x^2
    BN_mod_sqr(gx, x, p, ctx);
    // gx = gx + A
    BN_mod_add(gx, gx, A, p, ctx);
    // gx = gx * x
    BN_mod_mul(gx, gx, x, p, ctx);
    // gx = gx + B
    BN_mod_add(gx, gx, B, p, ctx);

    // y = sqrt(gx) using Tonelli-Shanks (for p = 3 mod 4, use y = gx^((p+1)/4))
    BIGNUM* exp = BN_new();
    BN_add(exp, p, one);
    BN_rshift(exp, exp, 2);  // exp = (p+1)/4
    BN_mod_exp(y, gx, exp, p, ctx);
    BN_free(exp);

    // Check if y^2 = gx using constant-time comparison
    BIGNUM* y_sq = BN_new();
    BN_mod_sqr(y_sq, y, p, ctx);

    // Serialize both for constant-time comparison
    int p_bytes = BN_num_bytes(p);
    Bytes y_sq_bytes(static_cast<size_t>(p_bytes));
    Bytes gx_bytes(static_cast<size_t>(p_bytes));
    BN_bn2binpad(y_sq, y_sq_bytes.data(), p_bytes);
    BN_bn2binpad(gx, gx_bytes.data(), p_bytes);

    bool is_square = constant_time_compare(
        ByteView(y_sq_bytes.data(), y_sq_bytes.size()),
        ByteView(gx_bytes.data(), gx_bytes.size()));
    BN_free(y_sq);

    if (!is_square) {
        // Use other branch: x = tv3 * x, y = sqrt(Z * u^3 * gx)
        BN_mod_mul(x, tv3, x, p, ctx);

        // Recompute gx for new x
        BN_mod_sqr(gx, x, p, ctx);
        BN_mod_add(gx, gx, A, p, ctx);
        BN_mod_mul(gx, gx, x, p, ctx);
        BN_mod_add(gx, gx, B, p, ctx);

        exp = BN_new();
        BN_add(exp, p, one);
        BN_rshift(exp, exp, 2);
        BN_mod_exp(y, gx, exp, p, ctx);
        BN_free(exp);
    }

    // Ensure y has correct sign (CMOV based on sgn0)
    // sgn0(u) = u mod 2
    // sgn0(y) = y mod 2
    int sgn0_u = BN_is_odd(u);
    int sgn0_y = BN_is_odd(y);
    if (sgn0_u != sgn0_y) {
        BN_sub(y, p, y);  // y = -y
    }

    // Create point
    EC_POINT* point = EC_POINT_new(group);
    if (!point || EC_POINT_set_affine_coordinates(group, point, x, y, ctx) != 1) {
        EC_POINT_free(point);
        BN_free(p); BN_free(A); BN_free(B); BN_free(Z);
        BN_free(tv1); BN_free(tv2); BN_free(tv3); BN_free(tv4); BN_free(tv5); BN_free(tv6);
        BN_free(x); BN_free(y); BN_free(gx); BN_free(one); BN_free(neg_one);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create point"});
    }

    BN_free(p); BN_free(A); BN_free(B); BN_free(Z);
    BN_free(tv1); BN_free(tv2); BN_free(tv3); BN_free(tv4); BN_free(tv5); BN_free(tv6);
    BN_free(x); BN_free(y); BN_free(gx); BN_free(one); BN_free(neg_one);

    return point;
}

// Hash to curve using RFC 9380 compliant SSWU method
Result<EC_POINT*> hash_to_curve(ByteView input, const EC_GROUP* group) {
    if (input.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Input too large"});
    }

    // Per RFC 9380 Section 5.2: hash_to_curve for P-384
    // 1. u = hash_to_field(msg, 2)
    // 2. Q0 = map_to_curve(u[0])
    // 3. Q1 = map_to_curve(u[1])
    // 4. R = Q0 + Q1
    // 5. P = clear_cofactor(R)  -- cofactor is 1 for P-384

    // Expand message to get 2 field elements (each 72 bytes for security margin)
    size_t L = 72;  // ceil((ceil(log2(p)) + k) / 8) where k=128
    auto expanded = expand_message_xmd(input, ByteView(reinterpret_cast<const uint8_t*>(DST_H2C),
        strlen(DST_H2C)), 2 * L);
    if (!expanded) {
        return std::unexpected(expanded.error());
    }

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    BIGNUM* p = BN_new();
    EC_GROUP_get_curve(group, p, nullptr, nullptr, ctx);

    // u[0] = OS2IP(expand[0:L]) mod p
    BIGNUM* u0 = BN_bin2bn(expanded->data(), static_cast<int>(L), nullptr);
    BN_mod(u0, u0, p, ctx);

    // u[1] = OS2IP(expand[L:2L]) mod p
    BIGNUM* u1 = BN_bin2bn(expanded->data() + L, static_cast<int>(L), nullptr);
    BN_mod(u1, u1, p, ctx);

    // Map to curve points
    auto Q0_result = map_to_curve_sswu(u0, group, ctx);
    if (!Q0_result) {
        BN_free(u0);
        BN_free(u1);
        BN_free(p);
        BN_CTX_free(ctx);
        return std::unexpected(Q0_result.error());
    }
    EC_POINT* Q0 = *Q0_result;

    auto Q1_result = map_to_curve_sswu(u1, group, ctx);
    if (!Q1_result) {
        EC_POINT_free(Q0);
        BN_free(u0);
        BN_free(u1);
        BN_free(p);
        BN_CTX_free(ctx);
        return std::unexpected(Q1_result.error());
    }
    EC_POINT* Q1 = *Q1_result;

    // R = Q0 + Q1
    EC_POINT* R = EC_POINT_new(group);
    if (!R || EC_POINT_add(group, R, Q0, Q1, ctx) != 1) {
        EC_POINT_free(Q0);
        EC_POINT_free(Q1);
        EC_POINT_free(R);
        BN_free(u0);
        BN_free(u1);
        BN_free(p);
        BN_CTX_free(ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Point addition failed"});
    }

    EC_POINT_free(Q0);
    EC_POINT_free(Q1);
    BN_free(u0);
    BN_free(u1);
    BN_free(p);
    BN_CTX_free(ctx);

    // P-384 has cofactor 1, so no cofactor clearing needed
    return R;
}

// Compute DLEQ challenge per RFC 9497 Section 3.3.2
Result<BIGNUM*> compute_dleq_challenge(
    const EC_GROUP* group,
    const EC_POINT* A,
    const EC_POINT* B,
    const EC_POINT* C,
    const EC_POINT* D,
    BN_CTX* ctx) {

    // c = H(G, Y, A, B, C, D) where G is generator, Y is public key
    // For VOPRF: A=blinded, B=evaluated, C=G, D=Y

    const EC_POINT* G = EC_GROUP_get0_generator(group);

    Bytes input;

    // Serialize all points
    auto G_bytes = point_to_bytes(G, group);
    auto A_bytes = point_to_bytes(A, group);
    auto B_bytes = point_to_bytes(B, group);
    auto C_bytes = point_to_bytes(C, group);
    auto D_bytes = point_to_bytes(D, group);

    if (!G_bytes || !A_bytes || !B_bytes || !C_bytes || !D_bytes) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to serialize points"});
    }

    // Concatenate: DST || G || Y || A || B || C || D
    input.insert(input.end(), reinterpret_cast<const uint8_t*>(DST_CHALLENGE),
        reinterpret_cast<const uint8_t*>(DST_CHALLENGE) + strlen(DST_CHALLENGE));
    input.insert(input.end(), G_bytes->begin(), G_bytes->end());
    input.insert(input.end(), C_bytes->begin(), C_bytes->end());  // C is public key Y
    input.insert(input.end(), A_bytes->begin(), A_bytes->end());
    input.insert(input.end(), B_bytes->begin(), B_bytes->end());
    input.insert(input.end(), D_bytes->begin(), D_bytes->end());

    auto hash = sha384(ByteView(input.data(), input.size()));
    if (!hash) {
        return std::unexpected(hash.error());
    }

    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, ctx);

    BIGNUM* c = BN_bin2bn(hash->data(), static_cast<int>(hash->size()), nullptr);
    BN_mod(c, c, order, ctx);
    BN_free(order);

    return c;
}

// Generate DLEQ proof per RFC 9497
Result<Bytes> generate_dleq_proof(
    const EC_GROUP* group,
    const BIGNUM* k,           // private key
    const EC_POINT* Y,         // public key
    const EC_POINT* R,         // blinded element
    const EC_POINT* Z,         // evaluated element
    BN_CTX* ctx) {

    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, ctx);

    // Generate random scalar t
    BIGNUM* t = BN_new();
    if (!BN_rand_range(t, order) || BN_is_zero(t)) {
        BN_free(order);
        BN_free(t);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to generate random scalar"});
    }

    // A = t * G (G is the generator, implicit when first scalar is non-null)
    EC_POINT* A = EC_POINT_new(group);
    if (!A || EC_POINT_mul(group, A, t, nullptr, nullptr, ctx) != 1) {
        EC_POINT_free(A);
        BN_free(order);
        BN_free(t);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to compute A"});
    }

    // B = t * R
    EC_POINT* B = EC_POINT_new(group);
    if (!B || EC_POINT_mul(group, B, nullptr, R, t, ctx) != 1) {
        EC_POINT_free(A);
        EC_POINT_free(B);
        BN_free(order);
        BN_free(t);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to compute B"});
    }

    // c = H(G, Y, R, Z, A, B)
    auto c_result = compute_dleq_challenge(group, R, Z, Y, A, ctx);
    if (!c_result) {
        EC_POINT_free(A);
        EC_POINT_free(B);
        BN_free(order);
        BN_free(t);
        return std::unexpected(c_result.error());
    }
    BIGNUM* c = *c_result;

    // s = t - c * k mod order
    BIGNUM* s = BN_new();
    BIGNUM* ck = BN_new();
    BN_mod_mul(ck, c, k, order, ctx);
    BN_mod_sub(s, t, ck, order, ctx);

    // Proof = (c, s)
    Bytes proof(P384_PROOF_SIZE);
    int c_len = BN_bn2binpad(c, proof.data(), P384_SCALAR_SIZE);
    int s_len = BN_bn2binpad(s, proof.data() + P384_SCALAR_SIZE, P384_SCALAR_SIZE);

    EC_POINT_free(A);
    EC_POINT_free(B);
    BN_free(order);
    BN_free(t);
    BN_free(c);
    BN_free(s);
    BN_free(ck);

    if (c_len != P384_SCALAR_SIZE || s_len != P384_SCALAR_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to serialize proof"});
    }

    return proof;
}

// Verify DLEQ proof per RFC 9497
Result<bool> verify_dleq_proof(
    const EC_GROUP* group,
    const EC_POINT* Y,        // public key
    const EC_POINT* R,        // blinded element
    const EC_POINT* Z,        // evaluated element
    ByteView proof,
    BN_CTX* ctx) {

    if (proof.size() != P384_PROOF_SIZE) {
        return std::unexpected(Error{ErrorCode::VERIFICATION_FAILED, "Invalid proof size"});
    }

    // Parse proof (c, s)
    BIGNUM* c = BN_bin2bn(proof.data(), P384_SCALAR_SIZE, nullptr);
    BIGNUM* s = BN_bin2bn(proof.data() + P384_SCALAR_SIZE, P384_SCALAR_SIZE, nullptr);

    if (!c || !s) {
        BN_free(c);
        BN_free(s);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to parse proof"});
    }

    // A' = s * G + c * Y (G is the generator, implicit in EC_POINT_mul with non-null first scalar)
    EC_POINT* A_prime = EC_POINT_new(group);
    if (!A_prime || EC_POINT_mul(group, A_prime, s, Y, c, ctx) != 1) {
        EC_POINT_free(A_prime);
        BN_free(c);
        BN_free(s);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to compute A'"});
    }

    // B' = s * R + c * Z
    EC_POINT* sR = EC_POINT_new(group);
    EC_POINT* cZ = EC_POINT_new(group);
    EC_POINT* B_prime = EC_POINT_new(group);

    if (!sR || !cZ || !B_prime ||
        EC_POINT_mul(group, sR, nullptr, R, s, ctx) != 1 ||
        EC_POINT_mul(group, cZ, nullptr, Z, c, ctx) != 1 ||
        EC_POINT_add(group, B_prime, sR, cZ, ctx) != 1) {
        EC_POINT_free(A_prime);
        EC_POINT_free(sR);
        EC_POINT_free(cZ);
        EC_POINT_free(B_prime);
        BN_free(c);
        BN_free(s);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to compute B'"});
    }

    // c' = H(G, Y, R, Z, A', B')
    auto c_prime_result = compute_dleq_challenge(group, R, Z, Y, A_prime, ctx);
    if (!c_prime_result) {
        EC_POINT_free(A_prime);
        EC_POINT_free(sR);
        EC_POINT_free(cZ);
        EC_POINT_free(B_prime);
        BN_free(c);
        BN_free(s);
        return std::unexpected(c_prime_result.error());
    }
    BIGNUM* c_prime = *c_prime_result;

    // Verify c == c' using constant-time comparison
    // Serialize both to fixed-size byte arrays for constant-time comparison
    Bytes c_bytes(P384_SCALAR_SIZE);
    Bytes c_prime_bytes(P384_SCALAR_SIZE);
    BN_bn2binpad(c, c_bytes.data(), P384_SCALAR_SIZE);
    BN_bn2binpad(c_prime, c_prime_bytes.data(), P384_SCALAR_SIZE);

    bool valid = constant_time_compare(
        ByteView(c_bytes.data(), c_bytes.size()),
        ByteView(c_prime_bytes.data(), c_prime_bytes.size()));

    EC_POINT_free(A_prime);
    EC_POINT_free(sR);
    EC_POINT_free(cZ);
    EC_POINT_free(B_prime);
    BN_free(c);
    BN_free(s);
    BN_free(c_prime);

    return valid;
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

    // Validate input size to prevent integer truncation
    if (data.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Private key data too large"});
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
    if (!group) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get curve group"});
    }

    // Validate input sizes
    if (evaluation.evaluated_element.size() > MAX_INPUT_SIZE ||
        evaluation.proof.size() != P384_PROOF_SIZE ||
        finalization_data.blind_scalar.size() > MAX_INPUT_SIZE ||
        finalization_data.blinded_element.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Invalid input sizes"});
    }

    // Deserialize evaluated element
    EC_POINT* Z = bytes_to_point(
        ByteView(evaluation.evaluated_element.data(), evaluation.evaluated_element.size()),
        group);
    if (!Z) {
        return std::unexpected(Error{ErrorCode::UNBLINDING_FAILED, "Invalid evaluated element"});
    }

    // Deserialize blinded element (R) for DLEQ verification
    EC_POINT* R = bytes_to_point(
        ByteView(finalization_data.blinded_element.data(), finalization_data.blinded_element.size()),
        group);
    if (!R) {
        EC_POINT_free(Z);
        return std::unexpected(Error{ErrorCode::UNBLINDING_FAILED, "Invalid blinded element"});
    }

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        EC_POINT_free(Z);
        EC_POINT_free(R);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    // Get public key for DLEQ verification
    auto pub_bytes = impl_->public_key.to_bytes();
    if (!pub_bytes) {
        BN_CTX_free(ctx);
        EC_POINT_free(Z);
        EC_POINT_free(R);
        return std::unexpected(pub_bytes.error());
    }

    EC_POINT* Y = bytes_to_point(ByteView(pub_bytes->data(), pub_bytes->size()), group);
    if (!Y) {
        BN_CTX_free(ctx);
        EC_POINT_free(Z);
        EC_POINT_free(R);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to parse public key"});
    }

    // Verify DLEQ proof before accepting the evaluation
    auto verify_result = verify_dleq_proof(
        group, Y, R, Z,
        ByteView(evaluation.proof.data(), evaluation.proof.size()),
        ctx);

    if (!verify_result) {
        EC_POINT_free(Y);
        EC_POINT_free(R);
        EC_POINT_free(Z);
        BN_CTX_free(ctx);
        return std::unexpected(verify_result.error());
    }

    if (!*verify_result) {
        EC_POINT_free(Y);
        EC_POINT_free(R);
        EC_POINT_free(Z);
        BN_CTX_free(ctx);
        return std::unexpected(Error{ErrorCode::VERIFICATION_FAILED,
            "DLEQ proof verification failed - evaluation may be malicious"});
    }

    EC_POINT_free(Y);
    EC_POINT_free(R);

    // Recover blinding scalar
    BIGNUM* r = BN_bin2bn(finalization_data.blind_scalar.data(),
        static_cast<int>(finalization_data.blind_scalar.size()), nullptr);

    // Compute r^-1
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, ctx);

    BIGNUM* r_inv = BN_mod_inverse(nullptr, r, order, ctx);
    if (!r_inv) {
        BN_clear_free(r);
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
        BN_clear_free(r);
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
    BN_clear_free(r);
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
    if (!group) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get curve group"});
    }

    // Validate input size
    if (blinded_element.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Blinded element too large"});
    }

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

    if (scalar_bytes->size() > MAX_INPUT_SIZE) {
        BN_CTX_free(ctx);
        EC_POINT_free(R);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Scalar too large"});
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

    // Get public key for DLEQ proof
    auto pub_key_result = impl_->private_key.public_key();
    if (!pub_key_result) {
        EC_POINT_free(Z);
        EC_POINT_free(R);
        BN_clear_free(k);
        BN_CTX_free(ctx);
        return std::unexpected(pub_key_result.error());
    }

    auto pub_bytes = pub_key_result->to_bytes();
    if (!pub_bytes) {
        EC_POINT_free(Z);
        EC_POINT_free(R);
        BN_clear_free(k);
        BN_CTX_free(ctx);
        return std::unexpected(pub_bytes.error());
    }

    EC_POINT* Y = bytes_to_point(ByteView(pub_bytes->data(), pub_bytes->size()), group);
    if (!Y) {
        EC_POINT_free(Z);
        EC_POINT_free(R);
        BN_clear_free(k);
        BN_CTX_free(ctx);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get public key point"});
    }

    // Generate DLEQ proof per RFC 9497
    auto proof_result = generate_dleq_proof(group, k, Y, R, Z, ctx);
    if (!proof_result) {
        EC_POINT_free(Y);
        EC_POINT_free(Z);
        EC_POINT_free(R);
        BN_clear_free(k);
        BN_CTX_free(ctx);
        return std::unexpected(proof_result.error());
    }

    // Serialize evaluated element
    auto z_bytes = point_to_bytes(Z, group);
    if (!z_bytes) {
        EC_POINT_free(Y);
        EC_POINT_free(Z);
        BN_clear_free(k);
        BN_CTX_free(ctx);
        EC_POINT_free(R);
        return std::unexpected(z_bytes.error());
    }

    VoprfEvaluation result;
    result.evaluated_element = std::move(*z_bytes);
    result.proof = std::move(*proof_result);

    // Clear sensitive data
    scalar_bytes->clear();

    EC_POINT_free(Y);
    EC_POINT_free(Z);
    EC_POINT_free(R);
    BN_clear_free(k);
    BN_CTX_free(ctx);

    return result;
}

Result<bool> VoprfServer::verify_finalize(ByteView input, ByteView output) const {
    EC_GROUP* group = get_p384_group();
    if (!group) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get curve group"});
    }

    // Validate input sizes
    if (input.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Input too large"});
    }

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

    if (scalar_bytes->size() > MAX_INPUT_SIZE) {
        BN_CTX_free(ctx);
        EC_POINT_free(P);
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Scalar too large"});
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

    // Clear sensitive data
    scalar_bytes->clear();

    EC_POINT_free(expected);
    EC_POINT_free(P);
    BN_clear_free(k);
    BN_CTX_free(ctx);

    if (!expected_hash) {
        return std::unexpected(expected_hash.error());
    }

    // Use constant-time comparison to prevent timing attacks
    return constant_time_compare(output, ByteView(expected_hash->data(), expected_hash->size()));
}

Result<VoprfPublicKey> VoprfServer::public_key() const {
    return impl_->private_key.public_key();
}

}  // namespace privacy_pass::crypto
