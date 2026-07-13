// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/crypto/blind_rsa.hpp>
#include <privacy_pass/core/token.hpp>

#include "test_vector_utils.hpp"

using namespace privacy_pass;
using namespace privacy_pass::crypto;

TEST_SUITE("Blind RSA") {
    TEST_CASE("Key generation") {
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto& [private_key, public_key] = *keypair;
        CHECK(private_key.is_valid());
        CHECK(public_key.is_valid());
    }

    TEST_CASE("Key serialization") {
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto& [private_key, public_key] = *keypair;

        SUBCASE("Public key SPKI roundtrip") {
            auto spki = public_key.to_spki();
            REQUIRE(spki.has_value());
            CHECK(!spki->empty());

            auto restored = BlindRsaPublicKey::from_spki(
                ByteView(spki->data(), spki->size()));
            REQUIRE(restored.has_value());
            CHECK(restored->is_valid());
        }

        SUBCASE("Private key PKCS#8 roundtrip") {
            auto pkcs8 = private_key.to_pkcs8();
            REQUIRE(pkcs8.has_value());
            CHECK(!pkcs8->empty());

            auto restored = BlindRsaPrivateKey::from_pkcs8(pkcs8->view());
            REQUIRE(restored.has_value());
            CHECK(restored->is_valid());
        }
    }

    TEST_CASE("Key ID computation") {
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto key_id = keypair->second.key_id();
        REQUIRE(key_id.has_value());
        CHECK(key_id->size() == 32);

        // Same key should produce same ID
        auto key_id2 = keypair->second.key_id();
        REQUIRE(key_id2.has_value());
        CHECK(*key_id == *key_id2);
    }

    TEST_CASE("Direct signing and verification") {
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto& [private_key, public_key] = *keypair;

        std::string message = "Hello, Privacy Pass!";
        ByteView msg(reinterpret_cast<const uint8_t*>(message.data()), message.size());

        auto signature = private_key.sign(msg);
        REQUIRE(signature.has_value());
        CHECK(signature->size() == 256);

        auto valid = public_key.verify(msg, ByteView(signature->data(), signature->size()));
        REQUIRE(valid.has_value());
        CHECK(*valid == true);
    }

    TEST_CASE("Blind signature protocol") {
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto& [private_key, public_key] = *keypair;

        std::string message = "This is the message to be signed blindly";
        ByteView msg(reinterpret_cast<const uint8_t*>(message.data()), message.size());

        SUBCASE("Blind, sign, unblind, verify") {
            // Client: blind the message
            auto blinding = public_key.blind(msg);
            REQUIRE(blinding.has_value());
            CHECK(blinding->blinded_msg.size() == 256);
            CHECK(!blinding->inverse.empty());

            // Server: sign the blinded message
            auto blind_sig = private_key.blind_sign(
                ByteView(blinding->blinded_msg.data(), blinding->blinded_msg.size()));
            REQUIRE(blind_sig.has_value());
            CHECK(blind_sig->size() == 256);

            // Client: unblind the signature
            auto signature = public_key.finalize(
                ByteView(blind_sig->data(), blind_sig->size()),
                *blinding,
                msg);
            REQUIRE(signature.has_value());
            CHECK(signature->size() == 256);

            // Verify the unblinded signature
            auto valid = public_key.verify(msg, ByteView(signature->data(), signature->size()));
            REQUIRE(valid.has_value());
            CHECK(*valid == true);
        }

        SUBCASE("Reject overlong blind signature") {
            auto blinding = public_key.blind(msg);
            REQUIRE(blinding.has_value());

            auto blind_sig = private_key.blind_sign(
                ByteView(blinding->blinded_msg.data(), blinding->blinded_msg.size()));
            REQUIRE(blind_sig.has_value());

            Bytes overlong_blind_sig;
            overlong_blind_sig.reserve(blind_sig->size() + 1);
            overlong_blind_sig.push_back(0);
            overlong_blind_sig.insert(overlong_blind_sig.end(), blind_sig->begin(), blind_sig->end());

            auto signature = public_key.finalize(
                ByteView(overlong_blind_sig.data(), overlong_blind_sig.size()),
                *blinding,
                msg);
            CHECK(!signature.has_value());
        }

        SUBCASE("Reject wrong-length blinding inverse") {
            auto blinding = public_key.blind(msg);
            REQUIRE(blinding.has_value());

            auto blind_sig = private_key.blind_sign(
                ByteView(blinding->blinded_msg.data(), blinding->blinded_msg.size()));
            REQUIRE(blind_sig.has_value());

            BlindingData bad_blinding;
            bad_blinding.inverse = SecureBytes(blinding->inverse.view());
            bad_blinding.inverse.resize(blinding->inverse.size() - 1);
            bad_blinding.blinded_msg = blinding->blinded_msg;

            auto signature = public_key.finalize(
                ByteView(blind_sig->data(), blind_sig->size()),
                bad_blinding,
                msg);
            CHECK(!signature.has_value());
        }
    }

    TEST_CASE("Verification fails for wrong message") {
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto& [private_key, public_key] = *keypair;

        std::string message1 = "Original message";
        std::string message2 = "Different message";

        ByteView msg1(reinterpret_cast<const uint8_t*>(message1.data()), message1.size());
        ByteView msg2(reinterpret_cast<const uint8_t*>(message2.data()), message2.size());

        auto signature = private_key.sign(msg1);
        REQUIRE(signature.has_value());

        auto valid = public_key.verify(msg2, ByteView(signature->data(), signature->size()));
        REQUIRE(valid.has_value());
        CHECK(*valid == false);
    }

    TEST_CASE("Invalid key parsing") {
        SUBCASE("Empty SPKI") {
            auto result = BlindRsaPublicKey::from_spki(ByteView{});
            CHECK(!result.has_value());
        }

        SUBCASE("Garbage SPKI") {
            std::vector<uint8_t> garbage = {0x00, 0x01, 0x02, 0x03};
            auto result = BlindRsaPublicKey::from_spki(ByteView(garbage.data(), garbage.size()));
            CHECK(!result.has_value());
        }

        SUBCASE("Empty PKCS#8") {
            auto result = BlindRsaPrivateKey::from_pkcs8(ByteView{});
            CHECK(!result.has_value());
        }
    }

    // BoringSSL cannot parse RSA-PSS OID (1.2.840.113549.1.1.10) SPKI that
    // OpenSSL generates. These test vectors use that format, so skip on BoringSSL.
    TEST_CASE("RFC 9578 public-verifiable token vectors verify") {
#ifdef PRIVACY_PASS_WITH_BORINGSSL
        MESSAGE("Skipped: BoringSSL does not support RSA-PSS OID in SPKI");
        return;
#endif
        const std::array files{
            "pub_verif_rfc9578.go.json",
            "pub_verif_rfc9578.rust.json",
        };

        for (const auto* file : files) {
            const auto vectors = test_vectors::load_json(file);
            for (const auto& vector : vectors) {
                CAPTURE(file);
                CAPTURE(vector.dump());

                auto public_key = BlindRsaPublicKey::from_spki(
                    test_vectors::view(test_vectors::hex_field(vector, "pkS")));
                REQUIRE(public_key.has_value());

                const auto token_bytes = test_vectors::hex_field(vector, "token");
                auto token = Token::deserialize(test_vectors::view(token_bytes));
                REQUIRE(token.has_value());

                auto key_id = public_key->key_id();
                REQUIRE(key_id.has_value());
                CHECK(*key_id == token->token_key_id);

                auto input = token->authenticator_input().serialize();
                REQUIRE(input.has_value());
                auto valid = public_key->verify(
                    test_vectors::view(*input),
                    test_vectors::view(token->authenticator));
                REQUIRE(valid.has_value());
                CHECK(*valid);
            }
        }
    }

    TEST_CASE("RFC 9474 4096-bit vectors are outside Privacy Pass profile") {
        const auto vectors = test_vectors::load_json("blindrsa_rfc9474_sha384_pss.json");

        for (const auto& vector : vectors) {
            CAPTURE(vector.at("name").get<std::string>());

            const auto modulus = test_vectors::hex_field(vector, "n");
            CHECK(modulus.size() == 512);

            auto public_key = BlindRsaPublicKey::from_components(
                test_vectors::view(modulus),
                test_vectors::view(test_vectors::hex_field(vector, "e")));
            CHECK(!public_key.has_value());
        }
    }
}
