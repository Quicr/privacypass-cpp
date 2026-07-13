// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/crypto/voprf.hpp>
#include <privacy_pass/crypto/hash.hpp>
#include <privacy_pass/crypto/random.hpp>

#include "compat.hpp"

#include <openssl/obj_mac.h>

namespace privacy_pass::crypto {

using namespace detail;

namespace {

constexpr std::string_view CONTEXT_STRING = "OPRFV1-\x01-P384-SHA384";
constexpr std::string_view DST_H2C = "HashToGroup-OPRFV1-\x01-P384-SHA384";
constexpr std::string_view DST_H2S = "HashToScalar-OPRFV1-\x01-P384-SHA384";
constexpr std::string_view DST_CHALLENGE = "Challenge";
constexpr std::string_view DST_COMPOSITE = "Composite";
constexpr std::string_view DST_SEED_PREFIX = "Seed-";
constexpr std::string_view DST_FINALIZE = "Finalize";

constexpr size_t MAX_INPUT_SIZE = static_cast<size_t>(INT_MAX);

// Thread-safe P-384 curve group singleton
class P384Group {
public:
    static EC_GROUP* get() {
        static P384Group instance;
        return instance.group_;
    }
private:
    P384Group() {
        group_ = EC_GROUP_new_by_curve_name(NID_secp384r1);
    }
    ~P384Group() {
        if (group_) EC_GROUP_free(group_);
    }
    P384Group(const P384Group&) = delete;
    P384Group& operator=(const P384Group&) = delete;
    EC_GROUP* group_ = nullptr;
};

EC_GROUP* get_p384_group() {
    return P384Group::get();
}

bool constant_time_compare(ByteView a, ByteView b) {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

void append_u16(Bytes& out, size_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

void append_u16_len_prefixed(Bytes& out, ByteView data) {
    append_u16(out, data.size());
    out.insert(out.end(), data.begin(), data.end());
}

void append_string(Bytes& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

Result<Bytes> finalize_output(ByteView input, ByteView issued_element) {
    constexpr size_t MAX_U16 = 0xFFFF;
    if (input.size() > MAX_U16 || issued_element.size() > MAX_U16) {
        return std::unexpected(Error{ErrorCode::INVALID_LENGTH, "VOPRF finalize input too large"});
    }

    Bytes hash_input;
    hash_input.reserve(2 + input.size() + 2 + issued_element.size() + DST_FINALIZE.size());
    append_u16_len_prefixed(hash_input, input);
    append_u16_len_prefixed(hash_input, issued_element);
    hash_input.insert(hash_input.end(), DST_FINALIZE.begin(), DST_FINALIZE.end());

    auto output = sha384(ByteView(hash_input.data(), hash_input.size()));
    if (!output) return std::unexpected(output.error());
    return Bytes(output->begin(), output->end());
}

Result<Bytes> point_to_bytes(const EC_POINT* point, const EC_GROUP* group) {
    auto ctx = make_bn_ctx();
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create BN context"});
    }
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, nullptr, 0, ctx.get());
    if (len == 0) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get point size"});
    }
    Bytes result(len);
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, result.data(), len, ctx.get()) != len) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to serialize point"});
    }
    return result;
}

UniqueEC_POINT bytes_to_point(ByteView data, const EC_GROUP* group) {
    if (data.size() != P384_ELEMENT_SIZE || (data[0] != 0x02 && data[0] != 0x03)) {
        return nullptr;
    }
    auto ctx = make_bn_ctx();
    if (!ctx) return nullptr;

    auto point = make_ec_point(group);
    if (!point) return nullptr;

    if (EC_POINT_oct2point(group, point.get(), data.data(), data.size(), ctx.get()) != 1) {
        return nullptr;
    }
    if (EC_POINT_is_on_curve(group, point.get(), ctx.get()) != 1 ||
        EC_POINT_is_at_infinity(group, point.get()) == 1) {
        return nullptr;
    }
    return point;
}

Result<Bytes> expand_message_xmd(ByteView msg, ByteView dst, size_t len_in_bytes) {
    const size_t b_in_bytes = 48;
    const size_t s_in_bytes = 128;

    if (len_in_bytes > 255 * b_in_bytes || dst.size() > 255) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Invalid expand_message_xmd parameters"});
    }

    size_t ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;

    Bytes dst_prime(dst.begin(), dst.end());
    dst_prime.push_back(static_cast<uint8_t>(dst.size()));

    Bytes z_pad(s_in_bytes, 0);
    Bytes l_i_b_str = {static_cast<uint8_t>(len_in_bytes >> 8), static_cast<uint8_t>(len_in_bytes)};

    Bytes msg_prime;
    msg_prime.reserve(z_pad.size() + msg.size() + l_i_b_str.size() + 1 + dst_prime.size());
    msg_prime.insert(msg_prime.end(), z_pad.begin(), z_pad.end());
    msg_prime.insert(msg_prime.end(), msg.begin(), msg.end());
    msg_prime.insert(msg_prime.end(), l_i_b_str.begin(), l_i_b_str.end());
    msg_prime.push_back(0);
    msg_prime.insert(msg_prime.end(), dst_prime.begin(), dst_prime.end());

    auto b_0 = sha384(ByteView(msg_prime.data(), msg_prime.size()));
    if (!b_0) return std::unexpected(b_0.error());

    Bytes b_1_input;
    b_1_input.reserve(b_0->size() + 1 + dst_prime.size());
    b_1_input.insert(b_1_input.end(), b_0->begin(), b_0->end());
    b_1_input.push_back(1);
    b_1_input.insert(b_1_input.end(), dst_prime.begin(), dst_prime.end());

    auto b_1 = sha384(ByteView(b_1_input.data(), b_1_input.size()));
    if (!b_1) return std::unexpected(b_1.error());

    Bytes uniform_bytes;
    uniform_bytes.reserve(len_in_bytes);
    uniform_bytes.insert(uniform_bytes.end(), b_1->begin(), b_1->end());

    Hash384 b_prev = *b_1;
    for (size_t i = 2; i <= ell; ++i) {
        Hash384 xored;
        for (size_t j = 0; j < b_in_bytes; ++j) {
            xored[j] = (*b_0)[j] ^ b_prev[j];
        }

        Bytes b_i_input;
        b_i_input.reserve(xored.size() + 1 + dst_prime.size());
        b_i_input.insert(b_i_input.end(), xored.begin(), xored.end());
        b_i_input.push_back(static_cast<uint8_t>(i));
        b_i_input.insert(b_i_input.end(), dst_prime.begin(), dst_prime.end());

        auto b_i = sha384(ByteView(b_i_input.data(), b_i_input.size()));
        if (!b_i) return std::unexpected(b_i.error());

        uniform_bytes.insert(uniform_bytes.end(), b_i->begin(), b_i->end());
        b_prev = *b_i;
    }

    uniform_bytes.resize(len_in_bytes);
    return uniform_bytes;
}

Result<UniqueEC_POINT> map_to_curve_sswu(const BIGNUM* u, const EC_GROUP* group, BN_CTX* ctx) {
    auto p = make_bignum();
    auto A = make_bignum();
    auto B = make_bignum();
    auto Z = make_bignum();
    auto tv1 = make_bignum();
    auto tv2 = make_bignum();
    auto tv3 = make_bignum();
    auto tv4 = make_bignum();
    auto tv5 = make_bignum();
    auto tv6 = make_bignum();
    auto x = make_bignum();
    auto y = make_bignum();
    auto gx = make_bignum();
    auto one = make_bignum();
    auto neg_one = make_bignum();

    if (!p || !A || !B || !Z || !tv1 || !tv2 || !tv3 || !tv4 || !tv5 || !tv6 ||
        !x || !y || !gx || !one || !neg_one) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to allocate bignums"});
    }

    compat::ec_group_get_curve(group, p.get(), A.get(), B.get(), ctx);
    BN_set_word(one.get(), 1);
    BN_sub(neg_one.get(), p.get(), one.get());
    BN_set_word(Z.get(), 12);
    BN_sub(Z.get(), p.get(), Z.get());

    BN_mod_sqr(tv1.get(), u, p.get(), ctx);
    BN_mod_mul(tv3.get(), Z.get(), tv1.get(), p.get(), ctx);
    BN_mod_sqr(tv5.get(), tv3.get(), p.get(), ctx);
    BN_mod_add(tv5.get(), tv5.get(), tv3.get(), p.get(), ctx);
    BN_mod_add(tv4.get(), tv5.get(), one.get(), p.get(), ctx);
    BN_mod_mul(tv4.get(), tv4.get(), B.get(), p.get(), ctx);
    BN_mod_mul(tv2.get(), tv3.get(), B.get(), p.get(), ctx);

    auto temp = make_bignum();
    BN_copy(temp.get(), tv5.get());

    BN_sub(tv6.get(), p.get(), A.get());

    if (BN_is_zero(temp.get())) {
        BN_mod_mul(tv6.get(), Z.get(), A.get(), p.get(), ctx);
    } else {
        auto neg_A = make_bignum();
        BN_sub(neg_A.get(), p.get(), A.get());
        BN_mod_mul(tv6.get(), tv5.get(), neg_A.get(), p.get(), ctx);
    }

    auto tv6_inv = UniqueBIGNUM(BN_mod_inverse(nullptr, tv6.get(), p.get(), ctx));
    if (!tv6_inv) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to compute inverse"});
    }
    BN_mod_mul(x.get(), tv4.get(), tv6_inv.get(), p.get(), ctx);

    BN_mod_sqr(gx.get(), x.get(), p.get(), ctx);
    BN_mod_add(gx.get(), gx.get(), A.get(), p.get(), ctx);
    BN_mod_mul(gx.get(), gx.get(), x.get(), p.get(), ctx);
    BN_mod_add(gx.get(), gx.get(), B.get(), p.get(), ctx);

    auto exp = make_bignum();
    BN_add(exp.get(), p.get(), one.get());
    BN_rshift(exp.get(), exp.get(), 2);
    BN_mod_exp(y.get(), gx.get(), exp.get(), p.get(), ctx);

    auto y_sq = make_bignum();
    BN_mod_sqr(y_sq.get(), y.get(), p.get(), ctx);

    int p_bytes = BN_num_bytes(p.get());
    Bytes y_sq_bytes(static_cast<size_t>(p_bytes));
    Bytes gx_bytes(static_cast<size_t>(p_bytes));
    BN_bn2binpad(y_sq.get(), y_sq_bytes.data(), p_bytes);
    BN_bn2binpad(gx.get(), gx_bytes.data(), p_bytes);

    bool is_square = constant_time_compare(
        ByteView(y_sq_bytes.data(), y_sq_bytes.size()),
        ByteView(gx_bytes.data(), gx_bytes.size()));

    if (!is_square) {
        BN_mod_mul(x.get(), tv3.get(), x.get(), p.get(), ctx);

        BN_mod_sqr(gx.get(), x.get(), p.get(), ctx);
        BN_mod_add(gx.get(), gx.get(), A.get(), p.get(), ctx);
        BN_mod_mul(gx.get(), gx.get(), x.get(), p.get(), ctx);
        BN_mod_add(gx.get(), gx.get(), B.get(), p.get(), ctx);

        exp = make_bignum();
        BN_add(exp.get(), p.get(), one.get());
        BN_rshift(exp.get(), exp.get(), 2);
        BN_mod_exp(y.get(), gx.get(), exp.get(), p.get(), ctx);
    }

    int sgn0_u = BN_is_odd(u);
    int sgn0_y = BN_is_odd(y.get());
    if (sgn0_u != sgn0_y) {
        BN_sub(y.get(), p.get(), y.get());
    }

    auto point = make_ec_point(group);
    if (!point || EC_POINT_set_affine_coordinates(group, point.get(), x.get(), y.get(), ctx) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create point"});
    }
    return point;
}

Result<UniqueEC_POINT> hash_to_curve(ByteView input, const EC_GROUP* group) {
    if (input.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Input too large"});
    }

    size_t L = 72;
    auto expanded = expand_message_xmd(input, ByteView(
        reinterpret_cast<const uint8_t*>(DST_H2C.data()), DST_H2C.size()), 2 * L);
    if (!expanded) return std::unexpected(expanded.error());

    auto ctx = make_bn_ctx();
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    auto p = make_bignum();
    compat::ec_group_get_curve(group, p.get(), nullptr, nullptr, ctx.get());

    auto u0 = bin2bn(expanded->data(), static_cast<int>(L));
    BN_mod(u0.get(), u0.get(), p.get(), ctx.get());

    auto u1 = bin2bn(expanded->data() + L, static_cast<int>(L));
    BN_mod(u1.get(), u1.get(), p.get(), ctx.get());

    auto Q0_result = map_to_curve_sswu(u0.get(), group, ctx.get());
    if (!Q0_result) return std::unexpected(Q0_result.error());

    auto Q1_result = map_to_curve_sswu(u1.get(), group, ctx.get());
    if (!Q1_result) return std::unexpected(Q1_result.error());

    auto R = make_ec_point(group);
    if (!R || EC_POINT_add(group, R.get(), Q0_result->get(), Q1_result->get(), ctx.get()) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Point addition failed"});
    }
    return R;
}

Result<UniqueBIGNUM> hash_to_scalar(ByteView input, const EC_GROUP* group, BN_CTX* ctx) {
    constexpr size_t L = 72;
    auto uniform = expand_message_xmd(input,
        ByteView(reinterpret_cast<const uint8_t*>(DST_H2S.data()), DST_H2S.size()), L);
    if (!uniform) return std::unexpected(uniform.error());

    auto order = make_bignum();
    auto scalar = bin2bn(uniform->data(), static_cast<int>(uniform->size()));
    if (!order || !scalar || EC_GROUP_get_order(group, order.get(), ctx) != 1 ||
        BN_mod(scalar.get(), scalar.get(), order.get(), ctx) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to hash to scalar"});
    }
    return scalar;
}

Result<UniqueBIGNUM> compute_composite_scalar(
    const EC_GROUP* group, const EC_POINT* B,
    const EC_POINT* C, const EC_POINT* D, BN_CTX* ctx) {

    auto Bm = point_to_bytes(B, group);
    auto Ci = point_to_bytes(C, group);
    auto Di = point_to_bytes(D, group);
    if (!Bm || !Ci || !Di) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to serialize composite inputs"});
    }

    Bytes seed_dst;
    append_string(seed_dst, DST_SEED_PREFIX);
    append_string(seed_dst, CONTEXT_STRING);

    Bytes seed_transcript;
    append_u16_len_prefixed(seed_transcript, ByteView(Bm->data(), Bm->size()));
    append_u16_len_prefixed(seed_transcript, ByteView(seed_dst.data(), seed_dst.size()));

    auto seed = sha384(ByteView(seed_transcript.data(), seed_transcript.size()));
    if (!seed) return std::unexpected(seed.error());

    Bytes composite_transcript;
    append_u16_len_prefixed(composite_transcript, ByteView(seed->data(), seed->size()));
    append_u16(composite_transcript, 0);
    append_u16_len_prefixed(composite_transcript, ByteView(Ci->data(), Ci->size()));
    append_u16_len_prefixed(composite_transcript, ByteView(Di->data(), Di->size()));
    append_string(composite_transcript, DST_COMPOSITE);

    return hash_to_scalar(ByteView(composite_transcript.data(), composite_transcript.size()), group, ctx);
}

Result<std::pair<UniqueEC_POINT, UniqueEC_POINT>> compute_composites(
    const EC_GROUP* group, const EC_POINT* B,
    const EC_POINT* C, const EC_POINT* D, BN_CTX* ctx) {

    auto di_result = compute_composite_scalar(group, B, C, D, ctx);
    if (!di_result) return std::unexpected(di_result.error());

    auto M = make_ec_point(group);
    auto Z = make_ec_point(group);
    if (!M || !Z ||
        EC_POINT_mul(group, M.get(), nullptr, C, di_result->get(), ctx) != 1 ||
        EC_POINT_mul(group, Z.get(), nullptr, D, di_result->get(), ctx) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to compute composites"});
    }
    return std::make_pair(std::move(M), std::move(Z));
}

Result<UniqueBIGNUM> compute_dleq_challenge(
    const EC_GROUP* group, const EC_POINT* B,
    const EC_POINT* M, const EC_POINT* Z,
    const EC_POINT* t2, const EC_POINT* t3, BN_CTX* ctx) {

    auto Bm = point_to_bytes(B, group);
    auto a0 = point_to_bytes(M, group);
    auto a1 = point_to_bytes(Z, group);
    auto a2 = point_to_bytes(t2, group);
    auto a3 = point_to_bytes(t3, group);
    if (!Bm || !a0 || !a1 || !a2 || !a3) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to serialize challenge inputs"});
    }

    Bytes transcript;
    append_u16_len_prefixed(transcript, ByteView(Bm->data(), Bm->size()));
    append_u16_len_prefixed(transcript, ByteView(a0->data(), a0->size()));
    append_u16_len_prefixed(transcript, ByteView(a1->data(), a1->size()));
    append_u16_len_prefixed(transcript, ByteView(a2->data(), a2->size()));
    append_u16_len_prefixed(transcript, ByteView(a3->data(), a3->size()));
    append_string(transcript, DST_CHALLENGE);

    return hash_to_scalar(ByteView(transcript.data(), transcript.size()), group, ctx);
}

Result<Bytes> generate_dleq_proof(
    const EC_GROUP* group, const BIGNUM* k, const EC_POINT* Y,
    const EC_POINT* R, const EC_POINT* Z, BN_CTX* ctx) {

    auto order = make_bignum();
    if (!order || EC_GROUP_get_order(group, order.get(), ctx) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get group order"});
    }

    auto composites = compute_composites(group, Y, R, Z, ctx);
    if (!composites) return std::unexpected(composites.error());
    auto& [M, composite_Z] = *composites;

    auto t = make_bignum();
    if (!BN_rand_range(t.get(), order.get()) || BN_is_zero(t.get())) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to generate random scalar"});
    }

    auto A = make_ec_point(group);
    if (!A || EC_POINT_mul(group, A.get(), t.get(), nullptr, nullptr, ctx) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to compute A"});
    }

    auto B_pt = make_ec_point(group);
    if (!B_pt || EC_POINT_mul(group, B_pt.get(), nullptr, M.get(), t.get(), ctx) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to compute B"});
    }

    auto c_result = compute_dleq_challenge(group, Y, M.get(), composite_Z.get(), A.get(), B_pt.get(), ctx);
    if (!c_result) return std::unexpected(c_result.error());

    auto s = make_bignum();
    auto ck = make_bignum();
    BN_mod_mul(ck.get(), c_result->get(), k, order.get(), ctx);
    BN_mod_sub(s.get(), t.get(), ck.get(), order.get(), ctx);

    Bytes proof(P384_PROOF_SIZE);
    int c_len = BN_bn2binpad(c_result->get(), proof.data(), P384_SCALAR_SIZE);
    int s_len = BN_bn2binpad(s.get(), proof.data() + P384_SCALAR_SIZE, P384_SCALAR_SIZE);

    if (c_len != P384_SCALAR_SIZE || s_len != P384_SCALAR_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to serialize proof"});
    }
    return proof;
}

Result<bool> verify_dleq_proof(
    const EC_GROUP* group, const EC_POINT* Y,
    const EC_POINT* R, const EC_POINT* Z,
    ByteView proof, BN_CTX* ctx) {

    if (proof.size() != P384_PROOF_SIZE) {
        return std::unexpected(Error{ErrorCode::VERIFICATION_FAILED, "Invalid proof size"});
    }

    auto c = bin2bn(proof.data(), P384_SCALAR_SIZE);
    auto s = bin2bn(proof.data() + P384_SCALAR_SIZE, P384_SCALAR_SIZE);
    if (!c || !s) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to parse proof"});
    }

    auto order = make_bignum();
    if (!order || EC_GROUP_get_order(group, order.get(), ctx) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get group order"});
    }

    if (BN_cmp(c.get(), order.get()) >= 0 || BN_cmp(s.get(), order.get()) >= 0) {
        return std::unexpected(Error{ErrorCode::VERIFICATION_FAILED, "Proof scalars out of range"});
    }

    auto composites = compute_composites(group, Y, R, Z, ctx);
    if (!composites) return std::unexpected(composites.error());
    auto& [M, composite_Z] = *composites;

    auto A_prime = make_ec_point(group);
    if (!A_prime || EC_POINT_mul(group, A_prime.get(), s.get(), Y, c.get(), ctx) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to compute A'"});
    }

    auto sM = make_ec_point(group);
    auto cZ = make_ec_point(group);
    auto B_prime = make_ec_point(group);

    if (!sM || !cZ || !B_prime ||
        EC_POINT_mul(group, sM.get(), nullptr, M.get(), s.get(), ctx) != 1 ||
        EC_POINT_mul(group, cZ.get(), nullptr, composite_Z.get(), c.get(), ctx) != 1 ||
        EC_POINT_add(group, B_prime.get(), sM.get(), cZ.get(), ctx) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to compute B'"});
    }

    auto c_prime = compute_dleq_challenge(group, Y, M.get(), composite_Z.get(), A_prime.get(), B_prime.get(), ctx);
    if (!c_prime) return std::unexpected(c_prime.error());

    Bytes c_bytes(P384_SCALAR_SIZE);
    Bytes c_prime_bytes(P384_SCALAR_SIZE);
    BN_bn2binpad(c.get(), c_bytes.data(), P384_SCALAR_SIZE);
    BN_bn2binpad(c_prime->get(), c_prime_bytes.data(), P384_SCALAR_SIZE);

    return constant_time_compare(
        ByteView(c_bytes.data(), c_bytes.size()),
        ByteView(c_prime_bytes.data(), c_prime_bytes.size()));
}

}  // namespace

// VoprfPublicKey implementation
struct VoprfPublicKey::Impl {
    UniqueEC_POINT point;
    EC_GROUP* group = nullptr;
    TokenKeyId cached_key_id{};
    bool key_id_computed = false;

    Impl() : group(get_p384_group()) {}
};

VoprfPublicKey::VoprfPublicKey() : impl_(std::make_unique<Impl>()) {}
VoprfPublicKey::~VoprfPublicKey() = default;
VoprfPublicKey::VoprfPublicKey(VoprfPublicKey&&) noexcept = default;
VoprfPublicKey& VoprfPublicKey::operator=(VoprfPublicKey&&) noexcept = default;

Result<VoprfPublicKey> VoprfPublicKey::from_bytes(ByteView data) {
    VoprfPublicKey key;
    if (!key.impl_->group) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get curve group"});
    }
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
    if (!impl_->group) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get curve group"});
    }
    return point_to_bytes(impl_->point.get(), impl_->group);
}

Result<TokenKeyId> VoprfPublicKey::key_id() const {
    if (impl_->key_id_computed) return impl_->cached_key_id;

    auto bytes = to_bytes();
    if (!bytes) return std::unexpected(bytes.error());

    auto hash = sha256(ByteView(bytes->data(), bytes->size()));
    if (!hash) return std::unexpected(hash.error());

    impl_->cached_key_id = *hash;
    impl_->key_id_computed = true;
    return impl_->cached_key_id;
}

bool VoprfPublicKey::is_valid() const noexcept {
    return impl_ && impl_->point;
}

// VoprfPrivateKey implementation
struct VoprfPrivateKey::Impl {
    UniqueSecureBIGNUM scalar;
    EC_GROUP* group = nullptr;

    Impl() : group(get_p384_group()) {}
};

VoprfPrivateKey::VoprfPrivateKey() : impl_(std::make_unique<Impl>()) {}
VoprfPrivateKey::~VoprfPrivateKey() = default;
VoprfPrivateKey::VoprfPrivateKey(VoprfPrivateKey&&) noexcept = default;
VoprfPrivateKey& VoprfPrivateKey::operator=(VoprfPrivateKey&&) noexcept = default;

Result<std::pair<VoprfPrivateKey, VoprfPublicKey>> VoprfPrivateKey::generate() {
    VoprfPrivateKey private_key;
    if (!private_key.impl_->group) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get curve group"});
    }

    auto ctx = make_bn_ctx();
    auto order = make_bignum();
    if (!ctx || !order || EC_GROUP_get_order(private_key.impl_->group, order.get(), ctx.get()) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get group order"});
    }

    private_key.impl_->scalar = make_secure_bignum();
    if (!BN_rand_range(private_key.impl_->scalar.get(), order.get()) ||
        BN_is_zero(private_key.impl_->scalar.get())) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Key generation failed"});
    }

    auto pub_point = make_ec_point(private_key.impl_->group);
    if (!pub_point ||
        EC_POINT_mul(private_key.impl_->group, pub_point.get(), private_key.impl_->scalar.get(),
            nullptr, nullptr, ctx.get()) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Public key computation failed"});
    }

    VoprfPublicKey public_key;
    if (!public_key.impl_->group) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get curve group"});
    }
    public_key.impl_->point = std::move(pub_point);

    return std::make_pair(std::move(private_key), std::move(public_key));
}

Result<VoprfPrivateKey> VoprfPrivateKey::from_bytes(ByteView data) {
    if (data.size() != P384_SCALAR_SIZE) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Invalid private key length"});
    }

    VoprfPrivateKey key;
    if (!key.impl_->group) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get curve group"});
    }

    key.impl_->scalar = bin2bn_secure(data.data(), static_cast<int>(data.size()));
    if (!key.impl_->scalar) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Failed to parse private key"});
    }

    auto ctx = make_bn_ctx();
    auto order = make_bignum();
    if (!ctx || !order || EC_GROUP_get_order(key.impl_->group, order.get(), ctx.get()) != 1 ||
        BN_is_zero(key.impl_->scalar.get()) || BN_cmp(key.impl_->scalar.get(), order.get()) >= 0) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Invalid private key scalar"});
    }

    return key;
}

Result<SecureBytes> VoprfPrivateKey::to_bytes() const {
    if (!impl_->scalar) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }
    SecureBytes result(P384_SCALAR_SIZE);
    if (BN_bn2binpad(impl_->scalar.get(), result.data(), P384_SCALAR_SIZE) != P384_SCALAR_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to serialize private key"});
    }
    return result;
}

Result<VoprfPublicKey> VoprfPrivateKey::public_key() const {
    if (!impl_->scalar) {
        return std::unexpected(Error{ErrorCode::INVALID_KEY, "Key not initialized"});
    }
    if (!impl_->group) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get curve group"});
    }

    auto ctx = make_bn_ctx();
    auto pub_point = make_ec_point(impl_->group);
    if (!ctx || !pub_point ||
        EC_POINT_mul(impl_->group, pub_point.get(), impl_->scalar.get(), nullptr, nullptr, ctx.get()) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Public key computation failed"});
    }

    VoprfPublicKey public_key;
    if (!public_key.impl_->group) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get curve group"});
    }
    public_key.impl_->point = std::move(pub_point);
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
    if (!group) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get curve group"});
    }

    auto h_result = hash_to_curve(input, group);
    if (!h_result) return std::unexpected(h_result.error());

    auto ctx = make_bn_ctx();
    auto order = make_bignum();
    if (!ctx || !order || EC_GROUP_get_order(group, order.get(), ctx.get()) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get group order"});
    }

    auto r = make_secure_bignum();
    if (!BN_rand_range(r.get(), order.get()) || BN_is_zero(r.get())) {
        return std::unexpected(Error{ErrorCode::BLINDING_FAILED, "Failed to generate blinding scalar"});
    }

    auto R = make_ec_point(group);
    if (!R || EC_POINT_mul(group, R.get(), nullptr, h_result->get(), r.get(), ctx.get()) != 1) {
        return std::unexpected(Error{ErrorCode::BLINDING_FAILED, "Failed to compute blinded element"});
    }

    VoprfFinalizationData result;
    result.blind_scalar.resize(P384_SCALAR_SIZE);
    BN_bn2binpad(r.get(), result.blind_scalar.data(), P384_SCALAR_SIZE);

    auto blinded_bytes = point_to_bytes(R.get(), group);
    if (!blinded_bytes) return std::unexpected(blinded_bytes.error());
    result.blinded_element = std::move(*blinded_bytes);
    result.input.assign(input.begin(), input.end());

    return result;
}

Result<Bytes> VoprfClient::finalize(
    const VoprfFinalizationData& finalization_data,
    const VoprfEvaluation& evaluation) const {

    EC_GROUP* group = get_p384_group();
    if (!group) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get curve group"});
    }

    if (evaluation.evaluated_element.size() > MAX_INPUT_SIZE ||
        evaluation.proof.size() != P384_PROOF_SIZE ||
        finalization_data.blind_scalar.size() > MAX_INPUT_SIZE ||
        finalization_data.blinded_element.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Invalid input sizes"});
    }

    auto Z = bytes_to_point(
        ByteView(evaluation.evaluated_element.data(), evaluation.evaluated_element.size()), group);
    if (!Z) {
        return std::unexpected(Error{ErrorCode::UNBLINDING_FAILED, "Invalid evaluated element"});
    }

    auto R = bytes_to_point(
        ByteView(finalization_data.blinded_element.data(), finalization_data.blinded_element.size()), group);
    if (!R) {
        return std::unexpected(Error{ErrorCode::UNBLINDING_FAILED, "Invalid blinded element"});
    }

    auto ctx = make_bn_ctx();
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    auto pub_bytes = impl_->public_key.to_bytes();
    if (!pub_bytes) return std::unexpected(pub_bytes.error());

    auto Y = bytes_to_point(ByteView(pub_bytes->data(), pub_bytes->size()), group);
    if (!Y) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to parse public key"});
    }

    auto verify_result = verify_dleq_proof(
        group, Y.get(), R.get(), Z.get(),
        ByteView(evaluation.proof.data(), evaluation.proof.size()), ctx.get());
    if (!verify_result) return std::unexpected(verify_result.error());
    if (!*verify_result) {
        return std::unexpected(Error{ErrorCode::VERIFICATION_FAILED,
            "DLEQ proof verification failed - evaluation may be malicious"});
    }

    auto r = bin2bn_secure(finalization_data.blind_scalar.data(),
        static_cast<int>(finalization_data.blind_scalar.size()));

    auto order = make_bignum();
    if (!order || EC_GROUP_get_order(group, order.get(), ctx.get()) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get group order"});
    }

    auto r_inv = UniqueBIGNUM(BN_mod_inverse(nullptr, r.get(), order.get(), ctx.get()));
    if (!r_inv) {
        return std::unexpected(Error{ErrorCode::UNBLINDING_FAILED, "Failed to compute inverse"});
    }

    auto N = make_ec_point(group);
    if (!N || EC_POINT_mul(group, N.get(), nullptr, Z.get(), r_inv.get(), ctx.get()) != 1) {
        return std::unexpected(Error{ErrorCode::UNBLINDING_FAILED, "Failed to unblind"});
    }

    auto output_point = point_to_bytes(N.get(), group);
    if (!output_point) return std::unexpected(output_point.error());

    return finalize_output(
        ByteView(finalization_data.input.data(), finalization_data.input.size()),
        ByteView(output_point->data(), output_point->size()));
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
    if (blinded_element.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Blinded element too large"});
    }

    auto R = bytes_to_point(blinded_element, group);
    if (!R) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Invalid blinded element"});
    }

    auto ctx = make_bn_ctx();
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    auto scalar_bytes = impl_->private_key.to_bytes();
    if (!scalar_bytes) return std::unexpected(scalar_bytes.error());

    auto k = bin2bn_secure(scalar_bytes->data(), static_cast<int>(scalar_bytes->size()));

    auto Z = make_ec_point(group);
    if (!Z || EC_POINT_mul(group, Z.get(), nullptr, R.get(), k.get(), ctx.get()) != 1) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Evaluation failed"});
    }

    auto pub_key_result = impl_->private_key.public_key();
    if (!pub_key_result) return std::unexpected(pub_key_result.error());

    auto pub_bytes = pub_key_result->to_bytes();
    if (!pub_bytes) return std::unexpected(pub_bytes.error());

    auto Y = bytes_to_point(ByteView(pub_bytes->data(), pub_bytes->size()), group);
    if (!Y) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get public key point"});
    }

    auto proof_result = generate_dleq_proof(group, k.get(), Y.get(), R.get(), Z.get(), ctx.get());
    if (!proof_result) return std::unexpected(proof_result.error());

    auto z_bytes = point_to_bytes(Z.get(), group);
    if (!z_bytes) return std::unexpected(z_bytes.error());

    VoprfEvaluation result;
    result.evaluated_element = std::move(*z_bytes);
    result.proof = std::move(*proof_result);

    scalar_bytes->clear();
    return result;
}

Result<bool> VoprfServer::verify_finalize(ByteView input, ByteView output) const {
    EC_GROUP* group = get_p384_group();
    if (!group) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to get curve group"});
    }
    if (input.size() > MAX_INPUT_SIZE) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Input too large"});
    }

    auto h_result = hash_to_curve(input, group);
    if (!h_result) return std::unexpected(h_result.error());

    auto ctx = make_bn_ctx();
    if (!ctx) {
        return std::unexpected(Error{ErrorCode::CRYPTO_ERROR, "Failed to create context"});
    }

    auto scalar_bytes = impl_->private_key.to_bytes();
    if (!scalar_bytes) return std::unexpected(scalar_bytes.error());

    auto k = bin2bn_secure(scalar_bytes->data(), static_cast<int>(scalar_bytes->size()));

    auto expected = make_ec_point(group);
    if (!expected || EC_POINT_mul(group, expected.get(), nullptr, h_result->get(), k.get(), ctx.get()) != 1) {
        return std::unexpected(Error{ErrorCode::VERIFICATION_FAILED, "Failed to compute expected output"});
    }

    auto expected_bytes = point_to_bytes(expected.get(), group);
    if (!expected_bytes) return std::unexpected(expected_bytes.error());

    auto expected_hash = finalize_output(input, ByteView(expected_bytes->data(), expected_bytes->size()));

    scalar_bytes->clear();

    if (!expected_hash) return std::unexpected(expected_hash.error());

    return constant_time_compare(output, ByteView(expected_hash->data(), expected_hash->size()));
}

Result<VoprfPublicKey> VoprfServer::public_key() const {
    return impl_->private_key.public_key();
}

}  // namespace privacy_pass::crypto
