// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/crypto/voprf.hpp>
#include <privacy_pass/core/token.hpp>

#include "test_vector_utils.hpp"

using namespace privacy_pass;
using namespace privacy_pass::crypto;

TEST_SUITE("VOPRF") {
    TEST_CASE("Key generation") {
        auto keypair = VoprfPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto& [private_key, public_key] = *keypair;
        CHECK(private_key.is_valid());
        CHECK(public_key.is_valid());
    }

    TEST_CASE("Key serialization") {
        auto keypair = VoprfPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto& [private_key, public_key] = *keypair;

        SUBCASE("Public key roundtrip") {
            auto bytes = public_key.to_bytes();
            REQUIRE(bytes.has_value());
            CHECK(bytes->size() == P384_ELEMENT_SIZE);

            auto restored = VoprfPublicKey::from_bytes(
                ByteView(bytes->data(), bytes->size()));
            REQUIRE(restored.has_value());
            CHECK(restored->is_valid());
        }

        SUBCASE("Private key roundtrip") {
            auto bytes = private_key.to_bytes();
            REQUIRE(bytes.has_value());
            CHECK(bytes->size() == P384_SCALAR_SIZE);  // 48 bytes

            auto restored = VoprfPrivateKey::from_bytes(bytes->view());
            REQUIRE(restored.has_value());
            CHECK(restored->is_valid());
        }
    }

    TEST_CASE("Key ID computation") {
        auto keypair = VoprfPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto key_id = keypair->second.key_id();
        REQUIRE(key_id.has_value());
        CHECK(key_id->size() == 32);

        // Same key should produce same ID (cached)
        auto key_id2 = keypair->second.key_id();
        REQUIRE(key_id2.has_value());
        CHECK(*key_id == *key_id2);
    }

    TEST_CASE("VOPRF evaluation protocol") {
        auto keypair = VoprfPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto& [server_private_key, server_public_key] = *keypair;

        // Copy keys for client (in real use, client would receive public key)
        auto pub_bytes = server_public_key.to_bytes();
        REQUIRE(pub_bytes.has_value());
        auto client_public_key = VoprfPublicKey::from_bytes(
            ByteView(pub_bytes->data(), pub_bytes->size()));
        REQUIRE(client_public_key.has_value());

        auto priv_bytes = server_private_key.to_bytes();
        REQUIRE(priv_bytes.has_value());
        auto server_key_copy = VoprfPrivateKey::from_bytes(priv_bytes->view());
        REQUIRE(server_key_copy.has_value());

        VoprfClient client(std::move(*client_public_key));
        VoprfServer server(std::move(*server_key_copy));

        std::string input_str = "Hello, VOPRF!";
        ByteView input(reinterpret_cast<const uint8_t*>(input_str.data()), input_str.size());

        SUBCASE("Blind, evaluate, finalize") {
            // Client: blind the input
            auto finalization_data = client.blind(input);
            REQUIRE(finalization_data.has_value());
            CHECK(finalization_data->blinded_element.size() == P384_ELEMENT_SIZE);

            // Server: evaluate
            auto evaluation = server.blind_evaluate(
                ByteView(finalization_data->blinded_element.data(),
                         finalization_data->blinded_element.size()));
            REQUIRE(evaluation.has_value());
            CHECK(evaluation->evaluated_element.size() == P384_ELEMENT_SIZE);

            // Client: finalize
            auto output = client.finalize(*finalization_data, *evaluation);
            REQUIRE(output.has_value());
            CHECK(output->size() == P384_OUTPUT_SIZE);  // 48 bytes
        }
    }

    TEST_CASE("Server verification") {
        auto keypair = VoprfPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto& [private_key, public_key] = *keypair;

        auto pub_bytes = public_key.to_bytes();
        REQUIRE(pub_bytes.has_value());
        auto client_pub_key = VoprfPublicKey::from_bytes(
            ByteView(pub_bytes->data(), pub_bytes->size()));
        REQUIRE(client_pub_key.has_value());

        auto priv_bytes = private_key.to_bytes();
        REQUIRE(priv_bytes.has_value());
        auto server_priv_key = VoprfPrivateKey::from_bytes(priv_bytes->view());
        REQUIRE(server_priv_key.has_value());

        VoprfClient client(std::move(*client_pub_key));
        VoprfServer server(std::move(*server_priv_key));

        std::string input_str = "Verification test";
        ByteView input(reinterpret_cast<const uint8_t*>(input_str.data()), input_str.size());

        // Complete protocol
        auto finalization_data = client.blind(input);
        REQUIRE(finalization_data.has_value());

        auto evaluation = server.blind_evaluate(
            ByteView(finalization_data->blinded_element.data(),
                     finalization_data->blinded_element.size()));
        REQUIRE(evaluation.has_value());

        auto output = client.finalize(*finalization_data, *evaluation);
        REQUIRE(output.has_value());

        // Server verifies
        auto valid = server.verify_finalize(input,
            ByteView(output->data(), output->size()));
        REQUIRE(valid.has_value());
        CHECK(*valid == true);
    }

    TEST_CASE("Different inputs produce different outputs") {
        auto keypair = VoprfPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto pub_bytes = keypair->second.to_bytes();
        REQUIRE(pub_bytes.has_value());

        auto priv_bytes = keypair->first.to_bytes();
        REQUIRE(priv_bytes.has_value());

        std::string input1_str = "Input 1";
        std::string input2_str = "Input 2";

        // Evaluate both inputs
        auto evaluate_input = [&](const std::string& input_str) -> Result<Bytes> {
            auto client_key = VoprfPublicKey::from_bytes(
                ByteView(pub_bytes->data(), pub_bytes->size()));
            if (!client_key) return std::unexpected(client_key.error());

            auto server_key = VoprfPrivateKey::from_bytes(priv_bytes->view());
            if (!server_key) return std::unexpected(server_key.error());

            VoprfClient client(std::move(*client_key));
            VoprfServer server(std::move(*server_key));

            ByteView input(reinterpret_cast<const uint8_t*>(input_str.data()), input_str.size());

            auto blind = client.blind(input);
            if (!blind) return std::unexpected(blind.error());

            auto eval = server.blind_evaluate(
                ByteView(blind->blinded_element.data(), blind->blinded_element.size()));
            if (!eval) return std::unexpected(eval.error());

            return client.finalize(*blind, *eval);
        };

        auto output1 = evaluate_input(input1_str);
        auto output2 = evaluate_input(input2_str);

        REQUIRE(output1.has_value());
        REQUIRE(output2.has_value());
        CHECK(*output1 != *output2);
    }

    TEST_CASE("Invalid key parsing") {
        SUBCASE("Empty public key") {
            auto result = VoprfPublicKey::from_bytes(ByteView{});
            CHECK(!result.has_value());
        }

        SUBCASE("Too short public key") {
            std::vector<uint8_t> short_data(32, 0);
            auto result = VoprfPublicKey::from_bytes(
                ByteView(short_data.data(), short_data.size()));
            CHECK(!result.has_value());
        }

        SUBCASE("Empty private key") {
            auto result = VoprfPrivateKey::from_bytes(ByteView{});
            CHECK(!result.has_value());
        }

        SUBCASE("Private key scalar equal to group order") {
            const Bytes order{
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
                0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a,
                0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
            };

            auto result = VoprfPrivateKey::from_bytes(ByteView(order.data(), order.size()));
            CHECK(!result.has_value());
        }
    }

    TEST_CASE("RFC 9578 private-verifiable token vectors verify") {
        const std::array files{
            "priv_verif_rfc9578.go.json",
            "priv_verif_rfc9578.rust.json",
        };

        for (const auto* file : files) {
            const auto vectors = test_vectors::load_json(file);
            for (const auto& vector : vectors) {
                CAPTURE(file);
                CAPTURE(vector.dump());

                auto private_key = VoprfPrivateKey::from_bytes(
                    test_vectors::view(test_vectors::hex_field(vector, "skS")));
                REQUIRE(private_key.has_value());

                auto public_key = private_key->public_key();
                REQUIRE(public_key.has_value());
                auto public_key_bytes = public_key->to_bytes();
                REQUIRE(public_key_bytes.has_value());
                CHECK(*public_key_bytes == test_vectors::hex_field(vector, "pkS"));

                const auto token_bytes = test_vectors::hex_field(vector, "token");
                auto token = Token::deserialize(test_vectors::view(token_bytes));
                REQUIRE(token.has_value());

                VoprfServer server(std::move(*private_key));
                auto input = token->authenticator_input().serialize();
                REQUIRE(input.has_value());
                auto valid = server.verify_finalize(
                    test_vectors::view(*input),
                    test_vectors::view(token->authenticator));
                REQUIRE(valid.has_value());
                CHECK(*valid);
            }
        }
    }

    TEST_CASE("RFC 9497 P-384 VOPRF vectors finalize") {
        const auto vector_set = test_vectors::load_json("voprf_p384_v20.json");

        auto private_key = VoprfPrivateKey::from_bytes(
            test_vectors::view(test_vectors::hex_field(vector_set, "skSm")));
        REQUIRE(private_key.has_value());

        auto public_key = private_key->public_key();
        REQUIRE(public_key.has_value());
        auto public_key_bytes = public_key->to_bytes();
        REQUIRE(public_key_bytes.has_value());
        CHECK(*public_key_bytes == test_vectors::hex_field(vector_set, "pkSm"));

        for (const auto& vector : vector_set.at("vectors")) {
            CAPTURE(vector.dump());

            auto client_key = VoprfPublicKey::from_bytes(
                test_vectors::view(test_vectors::hex_field(vector_set, "pkSm")));
            REQUIRE(client_key.has_value());

            VoprfClient client(std::move(*client_key));
            VoprfFinalizationData finalization;
            finalization.blind_scalar = SecureBytes(test_vectors::view(test_vectors::hex_field(vector, "Blind")));
            finalization.blinded_element = test_vectors::hex_field(vector, "BlindedElement");
            finalization.input = test_vectors::hex_field(vector, "Input");

            VoprfEvaluation evaluation{
                .evaluated_element = test_vectors::hex_field(vector, "EvaluationElement"),
                .proof = test_vectors::hex_field(vector, "Proof"),
            };

            auto output = client.finalize(finalization, evaluation);
            REQUIRE(output.has_value());
            CHECK(*output == test_vectors::hex_field(vector, "Output"));
        }
    }
}
