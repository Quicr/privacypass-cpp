// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/crypto/voprf.hpp>

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
            CHECK(bytes->size() == P384_ELEMENT_SIZE);  // 97 bytes compressed

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
    }
}
