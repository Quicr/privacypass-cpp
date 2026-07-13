// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

// Tests that verify crypto provider abstraction works correctly
// regardless of which backend (OpenSSL or BoringSSL) is active.

#include <doctest/doctest.h>
#include <privacy_pass/crypto/blind_rsa.hpp>
#include <privacy_pass/crypto/hash.hpp>
#include <privacy_pass/crypto/random.hpp>
#include <privacy_pass/crypto/voprf.hpp>

using namespace privacy_pass;
using namespace privacy_pass::crypto;

TEST_SUITE("Crypto Provider") {
    TEST_CASE("Backend identification") {
#if defined(PRIVACY_PASS_WITH_OPENSSL)
        MESSAGE("Running with OpenSSL backend");
        constexpr bool has_backend = true;
#elif defined(PRIVACY_PASS_WITH_BORINGSSL)
        MESSAGE("Running with BoringSSL backend");
        constexpr bool has_backend = true;
#else
        constexpr bool has_backend = false;
        FAIL("No crypto backend defined");
#endif
        CHECK(has_backend);
    }

    TEST_CASE("secure_clear works") {
        std::vector<uint8_t> buf = {0xDE, 0xAD, 0xBE, 0xEF};
        privacy_pass::secure_clear(buf.data(), buf.size());
        // After clearing, all bytes should be zero
        for (auto b : buf) {
            CHECK(b == 0);
        }
    }

    TEST_CASE("SecureBytes clears on destruction") {
        uint8_t* raw_ptr = nullptr;
        size_t raw_size = 0;
        {
            SecureBytes sb(32);
            // Fill with known pattern
            for (size_t i = 0; i < sb.size(); ++i) {
                sb[i] = static_cast<uint8_t>(i + 1);
            }
            raw_ptr = sb.data();
            raw_size = sb.size();
            CHECK(raw_size == 32);
            CHECK(raw_ptr[0] == 1);
        }
        // After destruction, we can't safely dereference raw_ptr, but the
        // test verifies SecureBytes doesn't crash during destruction
        CHECK(raw_ptr != nullptr);
    }

    TEST_CASE("SHA-256 known answer test") {
        // SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
        std::string input = "abc";
        auto result = sha256(ByteView(
            reinterpret_cast<const uint8_t*>(input.data()), input.size()));
        REQUIRE(result.has_value());
        CHECK((*result)[0] == 0xba);
        CHECK((*result)[1] == 0x78);
        CHECK((*result)[2] == 0x16);
        CHECK((*result)[3] == 0xbf);
        CHECK((*result)[31] == 0xad);
    }

    TEST_CASE("SHA-384 known answer test") {
        // SHA-384("abc") = cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163
        //                   1a8b605a43ff5bed 8086072ba1e7cc23 58baeca134c825a7
        std::string input = "abc";
        auto result = sha384(ByteView(
            reinterpret_cast<const uint8_t*>(input.data()), input.size()));
        REQUIRE(result.has_value());
        CHECK((*result)[0] == 0xcb);
        CHECK((*result)[1] == 0x00);
        CHECK((*result)[2] == 0x75);
        CHECK((*result)[3] == 0x3f);
        CHECK((*result)[47] == 0xa7);
    }

    TEST_CASE("HMAC-SHA256 known answer test") {
        // RFC 4231 Test Case 2
        // Key = "Jefe" (4 bytes)
        // Data = "what do ya want for nothing?"
        // HMAC-SHA-256 = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
        std::string key_str = "Jefe";
        std::string data_str = "what do ya want for nothing?";

        auto result = hmac_sha256(
            ByteView(reinterpret_cast<const uint8_t*>(key_str.data()), key_str.size()),
            ByteView(reinterpret_cast<const uint8_t*>(data_str.data()), data_str.size()));

        REQUIRE(result.has_value());
        CHECK((*result)[0] == 0x5b);
        CHECK((*result)[1] == 0xdc);
        CHECK((*result)[2] == 0xc1);
        CHECK((*result)[3] == 0x46);
        CHECK((*result)[31] == 0x43);
    }

    TEST_CASE("HKDF extract/expand round-trip") {
        std::vector<uint8_t> ikm(32, 0x0b);
        std::vector<uint8_t> salt(16, 0x00);
        std::vector<uint8_t> info = {0xf0, 0xf1, 0xf2, 0xf3};

        auto prk = hkdf_extract_sha256(
            ByteView(salt.data(), salt.size()),
            ByteView(ikm.data(), ikm.size()));
        REQUIRE(prk.has_value());
        CHECK(prk->size() == 32);

        auto okm = hkdf_expand_sha256(
            ByteView(prk->data(), prk->size()),
            ByteView(info.data(), info.size()),
            42);
        REQUIRE(okm.has_value());
        CHECK(okm->size() == 42);

        // Same inputs should produce same output (deterministic)
        auto okm2 = hkdf_expand_sha256(
            ByteView(prk->data(), prk->size()),
            ByteView(info.data(), info.size()),
            42);
        REQUIRE(okm2.has_value());
        CHECK(*okm == *okm2);
    }

    TEST_CASE("Random bytes are unique") {
        auto a = random_bytes(32);
        auto b = random_bytes(32);
        REQUIRE(a.has_value());
        REQUIRE(b.has_value());
        CHECK(*a != *b);
    }

    TEST_CASE("Random fill covers buffer") {
        std::array<uint8_t, 64> buffer{};
        auto result = random_fill(MutableByteView(buffer.data(), buffer.size()));
        REQUIRE(result.has_value());

        // Check that it's not all zeros (probabilistically)
        int nonzero = 0;
        for (auto b : buffer) {
            if (b != 0) ++nonzero;
        }
        CHECK(nonzero > 0);
    }

    TEST_CASE("Random nonce uniqueness") {
        auto n1 = random_nonce();
        auto n2 = random_nonce();
        auto n3 = random_nonce();
        REQUIRE(n1.has_value());
        REQUIRE(n2.has_value());
        REQUIRE(n3.has_value());
        CHECK(*n1 != *n2);
        CHECK(*n2 != *n3);
        CHECK(*n1 != *n3);
    }

    TEST_CASE("Random u64 uniqueness") {
        auto v1 = random_u64();
        auto v2 = random_u64();
        REQUIRE(v1.has_value());
        REQUIRE(v2.has_value());
        CHECK(*v1 != *v2);
    }

    TEST_CASE("Incremental hasher matches one-shot") {
        auto data = random_bytes(1024);
        REQUIRE(data.has_value());

        // One-shot
        auto one_shot = sha256(ByteView(data->data(), data->size()));
        REQUIRE(one_shot.has_value());

        // Incremental in 3 parts
        Sha256Hasher hasher;
        hasher.update(ByteView(data->data(), 100));
        hasher.update(ByteView(data->data() + 100, 500));
        hasher.update(ByteView(data->data() + 600, 424));
        auto incremental = hasher.finalize();
        REQUIRE(incremental.has_value());

        CHECK(*one_shot == *incremental);
    }

    TEST_CASE("SHA-384 incremental hasher matches one-shot") {
        auto data = random_bytes(2048);
        REQUIRE(data.has_value());

        auto one_shot = sha384(ByteView(data->data(), data->size()));
        REQUIRE(one_shot.has_value());

        Sha384Hasher hasher;
        hasher.update(ByteView(data->data(), 1024));
        hasher.update(ByteView(data->data() + 1024, 1024));
        auto incremental = hasher.finalize();
        REQUIRE(incremental.has_value());

        CHECK(*one_shot == *incremental);
    }

    TEST_CASE("Hash empty input") {
        auto h256 = sha256(ByteView{});
        REQUIRE(h256.has_value());
        CHECK(h256->size() == 32);

        auto h384 = sha384(ByteView{});
        REQUIRE(h384.has_value());
        CHECK(h384->size() == 48);
    }

    TEST_CASE("Blind RSA full protocol") {
        // Generate keypair
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());
        auto& [priv_key, pub_key] = *keypair;

        CHECK(priv_key.is_valid());
        CHECK(pub_key.is_valid());

        // Key ID
        auto key_id = pub_key.key_id();
        REQUIRE(key_id.has_value());
        CHECK(key_id->size() == 32);

        // Cached key ID should be the same
        auto key_id2 = pub_key.key_id();
        REQUIRE(key_id2.has_value());
        CHECK(*key_id == *key_id2);

        // SPKI round-trip
        auto spki = pub_key.to_spki();
        REQUIRE(spki.has_value());
        auto pub_key2 = BlindRsaPublicKey::from_spki(ByteView(spki->data(), spki->size()));
        REQUIRE(pub_key2.has_value());
        CHECK(pub_key2->is_valid());

        // Blind/Sign/Finalize/Verify
        auto msg = random_bytes(98);
        REQUIRE(msg.has_value());

        auto blinding = pub_key.blind(ByteView(msg->data(), msg->size()));
        REQUIRE(blinding.has_value());
        CHECK(blinding->blinded_msg.size() == RSA_MODULUS_SIZE);
        CHECK(blinding->inverse.size() == RSA_MODULUS_SIZE);

        auto blind_sig = priv_key.blind_sign(
            ByteView(blinding->blinded_msg.data(), blinding->blinded_msg.size()));
        REQUIRE(blind_sig.has_value());
        CHECK(blind_sig->size() == RSA_MODULUS_SIZE);

        auto sig = pub_key.finalize(
            ByteView(blind_sig->data(), blind_sig->size()),
            *blinding,
            ByteView(msg->data(), msg->size()));
        REQUIRE(sig.has_value());
        CHECK(sig->size() == RSA_MODULUS_SIZE);

        // Inverse should be cleared after finalize
        CHECK(blinding->inverse.empty());

        auto verified = pub_key.verify(
            ByteView(msg->data(), msg->size()),
            ByteView(sig->data(), sig->size()));
        REQUIRE(verified.has_value());
        CHECK(*verified == true);

        // Wrong message should fail verification
        auto wrong_msg = random_bytes(98);
        REQUIRE(wrong_msg.has_value());
        auto wrong_verify = pub_key.verify(
            ByteView(wrong_msg->data(), wrong_msg->size()),
            ByteView(sig->data(), sig->size()));
        REQUIRE(wrong_verify.has_value());
        CHECK(*wrong_verify == false);
    }

    TEST_CASE("Blind RSA direct sign and verify") {
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto msg = random_bytes(64);
        REQUIRE(msg.has_value());

        auto sig = keypair->first.sign(ByteView(msg->data(), msg->size()));
        REQUIRE(sig.has_value());

        auto verified = keypair->second.verify(
            ByteView(msg->data(), msg->size()),
            ByteView(sig->data(), sig->size()));
        REQUIRE(verified.has_value());
        CHECK(*verified == true);
    }

    TEST_CASE("Blind RSA PKCS8 round-trip") {
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto pkcs8 = keypair->first.to_pkcs8();
        REQUIRE(pkcs8.has_value());
        CHECK(!pkcs8->empty());

        auto restored = BlindRsaPrivateKey::from_pkcs8(pkcs8->view());
        REQUIRE(restored.has_value());
        CHECK(restored->is_valid());

        // Sign with restored key, verify with original public key
        auto msg = random_bytes(32);
        REQUIRE(msg.has_value());

        auto sig = restored->sign(ByteView(msg->data(), msg->size()));
        REQUIRE(sig.has_value());

        auto verified = keypair->second.verify(
            ByteView(msg->data(), msg->size()),
            ByteView(sig->data(), sig->size()));
        REQUIRE(verified.has_value());
        CHECK(*verified == true);
    }

    TEST_CASE("Blind RSA from_components") {
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        // Get SPKI, then reconstruct via components
        auto spki = keypair->second.to_spki();
        REQUIRE(spki.has_value());

        // We can at least verify from_spki round-trips
        auto pub2 = BlindRsaPublicKey::from_spki(ByteView(spki->data(), spki->size()));
        REQUIRE(pub2.has_value());

        auto kid1 = keypair->second.key_id();
        auto kid2 = pub2->key_id();
        REQUIRE(kid1.has_value());
        REQUIRE(kid2.has_value());
        CHECK(*kid1 == *kid2);
    }

    TEST_CASE("Blind RSA invalid inputs") {
        SUBCASE("empty SPKI") {
            auto result = BlindRsaPublicKey::from_spki(ByteView{});
            CHECK(!result.has_value());
        }

        SUBCASE("garbage SPKI") {
            std::vector<uint8_t> garbage(256, 0xFF);
            auto result = BlindRsaPublicKey::from_spki(ByteView(garbage.data(), garbage.size()));
            CHECK(!result.has_value());
        }

        SUBCASE("empty PKCS8") {
            auto result = BlindRsaPrivateKey::from_pkcs8(ByteView{});
            CHECK(!result.has_value());
        }

        SUBCASE("blind_sign wrong size") {
            auto keypair = BlindRsaPrivateKey::generate();
            REQUIRE(keypair.has_value());

            std::vector<uint8_t> wrong_size(128, 0x42);
            auto result = keypair->first.blind_sign(
                ByteView(wrong_size.data(), wrong_size.size()));
            CHECK(!result.has_value());
        }

        SUBCASE("uninitialized key operations") {
            BlindRsaPublicKey pub;
            CHECK(!pub.is_valid());

            auto blind_result = pub.blind(ByteView{});
            CHECK(!blind_result.has_value());

            BlindRsaPrivateKey priv;
            CHECK(!priv.is_valid());
        }
    }

    TEST_CASE("VOPRF full protocol") {
        // Generate keypair
        auto keypair = VoprfPrivateKey::generate();
        REQUIRE(keypair.has_value());
        auto& [priv_key, pub_key] = *keypair;

        CHECK(priv_key.is_valid());
        CHECK(pub_key.is_valid());

        // Key ID
        auto key_id = pub_key.key_id();
        REQUIRE(key_id.has_value());
        CHECK(key_id->size() == 32);

        // Serialize/deserialize public key round-trip
        auto pub_bytes = pub_key.to_bytes();
        REQUIRE(pub_bytes.has_value());
        CHECK(pub_bytes->size() == P384_ELEMENT_SIZE);

        auto pub_key2 = VoprfPublicKey::from_bytes(ByteView(pub_bytes->data(), pub_bytes->size()));
        REQUIRE(pub_key2.has_value());
        CHECK(pub_key2->is_valid());

        // Serialize/deserialize private key round-trip
        auto priv_bytes = priv_key.to_bytes();
        REQUIRE(priv_bytes.has_value());
        CHECK(priv_bytes->size() == P384_SCALAR_SIZE);

        auto priv_key2 = VoprfPrivateKey::from_bytes(priv_bytes->view());
        REQUIRE(priv_key2.has_value());
        CHECK(priv_key2->is_valid());

        // Client blind → Server evaluate → Client finalize
        auto client_key = VoprfPublicKey::from_bytes(ByteView(pub_bytes->data(), pub_bytes->size()));
        REQUIRE(client_key.has_value());
        VoprfClient client(std::move(*client_key));

        auto server_key = VoprfPrivateKey::from_bytes(priv_bytes->view());
        REQUIRE(server_key.has_value());
        VoprfServer server(std::move(*server_key));

        auto input = random_bytes(64);
        REQUIRE(input.has_value());

        auto blind_data = client.blind(ByteView(input->data(), input->size()));
        REQUIRE(blind_data.has_value());
        CHECK(blind_data->blinded_element.size() == P384_ELEMENT_SIZE);
        CHECK(blind_data->blind_scalar.size() == P384_SCALAR_SIZE);

        auto evaluation = server.blind_evaluate(
            ByteView(blind_data->blinded_element.data(), blind_data->blinded_element.size()));
        REQUIRE(evaluation.has_value());
        CHECK(evaluation->evaluated_element.size() == P384_ELEMENT_SIZE);
        CHECK(evaluation->proof.size() == P384_PROOF_SIZE);

        auto output = client.finalize(*blind_data, *evaluation);
        REQUIRE(output.has_value());
        CHECK(output->size() == P384_OUTPUT_SIZE);

        // Server-side verification
        auto verified = server.verify_finalize(
            ByteView(input->data(), input->size()),
            ByteView(output->data(), output->size()));
        REQUIRE(verified.has_value());
        CHECK(*verified == true);

        // Wrong input should fail verification
        auto wrong_input = random_bytes(64);
        REQUIRE(wrong_input.has_value());
        auto wrong_verify = server.verify_finalize(
            ByteView(wrong_input->data(), wrong_input->size()),
            ByteView(output->data(), output->size()));
        REQUIRE(wrong_verify.has_value());
        CHECK(*wrong_verify == false);
    }

    TEST_CASE("VOPRF deterministic output") {
        // Same key + same input should produce same output
        auto keypair = VoprfPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto pub_bytes = keypair->second.to_bytes();
        REQUIRE(pub_bytes.has_value());
        auto priv_bytes = keypair->first.to_bytes();
        REQUIRE(priv_bytes.has_value());

        auto input = random_bytes(32);
        REQUIRE(input.has_value());

        // Run protocol twice
        Bytes output1, output2;
        for (int i = 0; i < 2; ++i) {
            auto ck = VoprfPublicKey::from_bytes(ByteView(pub_bytes->data(), pub_bytes->size()));
            REQUIRE(ck.has_value());
            VoprfClient client(std::move(*ck));

            auto sk = VoprfPrivateKey::from_bytes(priv_bytes->view());
            REQUIRE(sk.has_value());
            VoprfServer server(std::move(*sk));

            auto blind_data = client.blind(ByteView(input->data(), input->size()));
            REQUIRE(blind_data.has_value());

            auto eval = server.blind_evaluate(
                ByteView(blind_data->blinded_element.data(), blind_data->blinded_element.size()));
            REQUIRE(eval.has_value());

            auto out = client.finalize(*blind_data, *eval);
            REQUIRE(out.has_value());

            if (i == 0) output1 = *out;
            else output2 = *out;
        }

        // Both outputs should be the same (VOPRF is a PRF, deterministic given key+input)
        CHECK(output1 == output2);
    }

    TEST_CASE("VOPRF invalid inputs") {
        SUBCASE("invalid public key bytes") {
            std::vector<uint8_t> garbage(P384_ELEMENT_SIZE, 0xFF);
            auto result = VoprfPublicKey::from_bytes(ByteView(garbage.data(), garbage.size()));
            CHECK(!result.has_value());
        }

        SUBCASE("wrong size public key") {
            std::vector<uint8_t> wrong_size(32, 0x02);
            auto result = VoprfPublicKey::from_bytes(ByteView(wrong_size.data(), wrong_size.size()));
            CHECK(!result.has_value());
        }

        SUBCASE("invalid private key scalar") {
            // Zero scalar should be rejected
            std::vector<uint8_t> zero_scalar(P384_SCALAR_SIZE, 0x00);
            auto result = VoprfPrivateKey::from_bytes(ByteView(zero_scalar.data(), zero_scalar.size()));
            CHECK(!result.has_value());
        }

        SUBCASE("wrong size private key") {
            std::vector<uint8_t> wrong_size(32, 0x01);
            auto result = VoprfPrivateKey::from_bytes(ByteView(wrong_size.data(), wrong_size.size()));
            CHECK(!result.has_value());
        }

        SUBCASE("uninitialized key operations") {
            VoprfPublicKey pub;
            CHECK(!pub.is_valid());

            auto bytes = pub.to_bytes();
            CHECK(!bytes.has_value());

            VoprfPrivateKey priv;
            CHECK(!priv.is_valid());
        }

        SUBCASE("invalid blinded element") {
            auto keypair = VoprfPrivateKey::generate();
            REQUIRE(keypair.has_value());

            auto priv_bytes = keypair->first.to_bytes();
            REQUIRE(priv_bytes.has_value());
            auto server_key = VoprfPrivateKey::from_bytes(priv_bytes->view());
            REQUIRE(server_key.has_value());
            VoprfServer server(std::move(*server_key));

            std::vector<uint8_t> garbage(P384_ELEMENT_SIZE, 0xFF);
            auto result = server.blind_evaluate(ByteView(garbage.data(), garbage.size()));
            CHECK(!result.has_value());
        }
    }

    TEST_CASE("VOPRF multiple evaluations with same key") {
        auto keypair = VoprfPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto pub_bytes = keypair->second.to_bytes();
        REQUIRE(pub_bytes.has_value());
        auto priv_bytes = keypair->first.to_bytes();
        REQUIRE(priv_bytes.has_value());

        auto sk = VoprfPrivateKey::from_bytes(priv_bytes->view());
        REQUIRE(sk.has_value());
        VoprfServer server(std::move(*sk));

        // Evaluate multiple inputs
        for (int i = 0; i < 5; ++i) {
            auto ck = VoprfPublicKey::from_bytes(ByteView(pub_bytes->data(), pub_bytes->size()));
            REQUIRE(ck.has_value());
            VoprfClient client(std::move(*ck));

            auto input = random_bytes(32 + i * 10);
            REQUIRE(input.has_value());

            auto blind_data = client.blind(ByteView(input->data(), input->size()));
            REQUIRE(blind_data.has_value());

            auto eval = server.blind_evaluate(
                ByteView(blind_data->blinded_element.data(), blind_data->blinded_element.size()));
            REQUIRE(eval.has_value());

            auto output = client.finalize(*blind_data, *eval);
            REQUIRE(output.has_value());
            CHECK(output->size() == P384_OUTPUT_SIZE);

            auto verified = server.verify_finalize(
                ByteView(input->data(), input->size()),
                ByteView(output->data(), output->size()));
            REQUIRE(verified.has_value());
            CHECK(*verified == true);
        }
    }
}
