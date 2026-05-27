// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/core/client.hpp>

using namespace privacy_pass;
using namespace privacy_pass::crypto;

TEST_SUITE("PublicClient") {
    TEST_CASE("Create token request") {
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto& [private_key, public_key] = *keypair;

        auto challenge = TokenChallenge::create(
            TokenType::BLIND_RSA,
            "issuer.example.com",
            std::nullopt,
            {"origin.example.com"});

        PublicClient client;
        auto result = client.create_token_request(challenge, public_key);

        REQUIRE(result.has_value());
        CHECK(result->request.token_type == TokenType::BLIND_RSA);
        CHECK(result->request.blinded_msg.size() == 256);
        CHECK(result->finalization_data.token_type == TokenType::BLIND_RSA);
    }
}

TEST_SUITE("PrivateClient") {
    TEST_CASE("Create token request") {
        auto keypair = VoprfPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto& [private_key, public_key] = *keypair;

        auto challenge = TokenChallenge::create(
            TokenType::VOPRF_P384_SHA384,
            "issuer.example.com",
            std::nullopt,
            {"origin.example.com"});

        PrivateClient client;
        auto result = client.create_token_request(challenge, public_key);

        REQUIRE(result.has_value());
        CHECK(result->request.token_type == TokenType::VOPRF_P384_SHA384);
        CHECK(result->request.blinded_msg.size() == 49);  // P-384 element
    }
}

TEST_SUITE("Unified Client") {
    TEST_CASE("Blind RSA flow") {
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto& [private_key, public_key] = *keypair;

        // Get public key info
        auto spki = public_key.to_spki();
        REQUIRE(spki.has_value());

        auto key_id = public_key.key_id();
        REQUIRE(key_id.has_value());

        PublicKey pub{
            .type = TokenType::BLIND_RSA,
            .data = std::move(*spki),
            .key_id = *key_id,
        };

        auto challenge = TokenChallenge::create(
            TokenType::BLIND_RSA,
            "issuer.example.com",
            std::nullopt,
            {"origin.example.com"});

        Client client;
        auto result = client.create_token_request(challenge, pub);

        REQUIRE(result.has_value());
        CHECK(result->request.token_type == TokenType::BLIND_RSA);
    }

    TEST_CASE("Type mismatch error") {
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto spki = keypair->second.to_spki();
        auto key_id = keypair->second.key_id();
        REQUIRE(spki.has_value());
        REQUIRE(key_id.has_value());

        PublicKey pub{
            .type = TokenType::BLIND_RSA,
            .data = std::move(*spki),
            .key_id = *key_id,
        };

        // Challenge with different type
        auto challenge = TokenChallenge::create(
            TokenType::VOPRF_P384_SHA384,  // Mismatch!
            "issuer.example.com",
            std::nullopt,
            {"origin.example.com"});

        Client client;
        auto result = client.create_token_request(challenge, pub);

        CHECK(!result.has_value());
        CHECK(result.error().code == ErrorCode::UNSUPPORTED_TOKEN_TYPE);
    }
}
