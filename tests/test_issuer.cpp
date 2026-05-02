// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/core/issuer.hpp>
#include <privacy_pass/crypto/voprf.hpp>

using namespace privacy_pass;
using namespace privacy_pass::crypto;

TEST_SUITE("PublicIssuer") {
    TEST_CASE("Generate issuer") {
        auto issuer = PublicIssuer::generate();
        REQUIRE(issuer.has_value());

        auto pub_key = issuer->public_key();
        REQUIRE(pub_key.has_value());
        CHECK(pub_key->is_valid());
    }

    TEST_CASE("Issue token") {
        auto issuer = PublicIssuer::generate();
        REQUIRE(issuer.has_value());

        Bytes blinded(256, 0x42);
        auto request = TokenRequest::create(
            TokenType::BLIND_RSA,
            issuer->truncated_key_id(),
            std::move(blinded));

        auto response = issuer->issue(request);
        REQUIRE(response.has_value());

        CHECK(response->token_type == TokenType::BLIND_RSA);
        auto* rsa_resp = response->as_blind_rsa();
        REQUIRE(rsa_resp != nullptr);
        CHECK(rsa_resp->blind_sig.size() == 256);
    }

    TEST_CASE("Reject wrong key ID") {
        auto issuer = PublicIssuer::generate();
        REQUIRE(issuer.has_value());

        Bytes blinded(256, 0x42);
        auto request = TokenRequest::create(
            TokenType::BLIND_RSA,
            static_cast<uint8_t>(issuer->truncated_key_id() + 1),  // Wrong ID
            std::move(blinded));

        auto response = issuer->issue(request);
        CHECK(!response.has_value());
        CHECK(response.error().code == ErrorCode::ISSUER_UNKNOWN);
    }

    TEST_CASE("Reject wrong token type") {
        auto issuer = PublicIssuer::generate();
        REQUIRE(issuer.has_value());

        Bytes blinded(97, 0x42);
        auto request = TokenRequest::create(
            TokenType::VOPRF_P384_SHA384,  // Wrong type
            issuer->truncated_key_id(),
            std::move(blinded));

        auto response = issuer->issue(request);
        CHECK(!response.has_value());
        CHECK(response.error().code == ErrorCode::UNSUPPORTED_TOKEN_TYPE);
    }

    TEST_CASE("Batch issuance") {
        auto issuer = PublicIssuer::generate();
        REQUIRE(issuer.has_value());

        BatchedTokenRequest batch;
        for (int i = 0; i < 5; ++i) {
            Bytes blinded(256, static_cast<uint8_t>(i));
            batch.requests.push_back(TokenRequest::create(
                TokenType::BLIND_RSA,
                issuer->truncated_key_id(),
                std::move(blinded)));
        }

        auto response = issuer->issue_batch(batch);
        REQUIRE(response.has_value());
        CHECK(response->responses.size() == 5);

        for (const auto& resp : response->responses) {
            CHECK(resp.present);
            REQUIRE(resp.response.has_value());
        }
    }
}

TEST_SUITE("PrivateIssuer") {
    TEST_CASE("Generate issuer") {
        auto issuer = PrivateIssuer::generate();
        REQUIRE(issuer.has_value());

        auto pub_key = issuer->public_key();
        REQUIRE(pub_key.has_value());
        CHECK(pub_key->is_valid());
    }

    TEST_CASE("Issue VOPRF token") {
        auto issuer = PrivateIssuer::generate();
        REQUIRE(issuer.has_value());

        // Get public key for client
        auto pub_key = issuer->public_key();
        REQUIRE(pub_key.has_value());

        auto pub_bytes = pub_key->to_bytes();
        REQUIRE(pub_bytes.has_value());

        auto client_pub_key = VoprfPublicKey::from_bytes(
            ByteView(pub_bytes->data(), pub_bytes->size()));
        REQUIRE(client_pub_key.has_value());

        // Create client and blind input
        VoprfClient client(std::move(*client_pub_key));
        std::string input_str = "test input";
        auto blind_result = client.blind(
            ByteView(reinterpret_cast<const uint8_t*>(input_str.data()), input_str.size()));
        REQUIRE(blind_result.has_value());

        auto request = TokenRequest::create(
            TokenType::VOPRF_P384_SHA384,
            issuer->truncated_key_id(),
            Bytes(blind_result->blinded_element.begin(), blind_result->blinded_element.end()));

        auto response = issuer->issue(request);
        REQUIRE(response.has_value());

        CHECK(response->token_type == TokenType::VOPRF_P384_SHA384);
        auto* voprf_resp = response->as_voprf();
        REQUIRE(voprf_resp != nullptr);
        CHECK(voprf_resp->evaluate_msg.size() == 97);
    }
}

TEST_SUITE("MultiKeyIssuer") {
    TEST_CASE("Add and use multiple keys") {
        MultiKeyIssuer issuer;

        // Add RSA key
        auto rsa_keypair = BlindRsaPrivateKey::generate();
        REQUIRE(rsa_keypair.has_value());
        auto rsa_key_id = rsa_keypair->second.key_id();
        REQUIRE(rsa_key_id.has_value());
        uint8_t rsa_truncated = (*rsa_key_id)[31];

        auto result = issuer.add_blind_rsa_key(std::move(rsa_keypair->first));
        REQUIRE(result.has_value());

        // Add VOPRF key - get public key bytes BEFORE moving private key
        auto voprf_keypair = VoprfPrivateKey::generate();
        REQUIRE(voprf_keypair.has_value());
        auto voprf_key_id = voprf_keypair->second.key_id();
        REQUIRE(voprf_key_id.has_value());
        uint8_t voprf_truncated = (*voprf_key_id)[31];

        // Get public key bytes before moving private key
        auto voprf_pub_bytes = voprf_keypair->second.to_bytes();
        REQUIRE(voprf_pub_bytes.has_value());

        result = issuer.add_voprf_key(std::move(voprf_keypair->first));
        REQUIRE(result.has_value());

        // Issue RSA token
        Bytes rsa_blinded(256, 0x11);
        auto rsa_request = TokenRequest::create(
            TokenType::BLIND_RSA, rsa_truncated, std::move(rsa_blinded));

        auto rsa_response = issuer.issue(rsa_request);
        REQUIRE(rsa_response.has_value());
        CHECK(rsa_response->token_type == TokenType::BLIND_RSA);

        // Issue VOPRF token - use the public key bytes we saved earlier
        auto client_voprf_key = VoprfPublicKey::from_bytes(
            ByteView(voprf_pub_bytes->data(), voprf_pub_bytes->size()));
        REQUIRE(client_voprf_key.has_value());

        VoprfClient voprf_client(std::move(*client_voprf_key));
        std::string voprf_input = "voprf input";
        auto voprf_blind = voprf_client.blind(
            ByteView(reinterpret_cast<const uint8_t*>(voprf_input.data()), voprf_input.size()));
        REQUIRE(voprf_blind.has_value());

        auto voprf_request = TokenRequest::create(
            TokenType::VOPRF_P384_SHA384, voprf_truncated,
            Bytes(voprf_blind->blinded_element.begin(), voprf_blind->blinded_element.end()));

        auto voprf_response = issuer.issue(voprf_request);
        REQUIRE(voprf_response.has_value());
        CHECK(voprf_response->token_type == TokenType::VOPRF_P384_SHA384);

        // Get public keys
        auto keys = issuer.public_keys();
        CHECK(keys.size() == 2);
    }

    TEST_CASE("Remove key") {
        MultiKeyIssuer issuer;

        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());
        auto key_id = keypair->second.key_id();
        REQUIRE(key_id.has_value());
        uint8_t truncated = (*key_id)[31];

        issuer.add_blind_rsa_key(std::move(keypair->first));

        // Remove the key
        issuer.remove_key(truncated);

        // Issue should fail
        Bytes blinded(256, 0x42);
        auto request = TokenRequest::create(
            TokenType::BLIND_RSA, truncated, std::move(blinded));

        auto response = issuer.issue(request);
        CHECK(!response.has_value());
    }

    TEST_CASE("Get issuer config") {
        MultiKeyIssuer issuer;

        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());
        issuer.add_blind_rsa_key(std::move(keypair->first));

        auto config = issuer.config("https://issuer.example.com/token-request");

        CHECK(config.issuer_request_uri == "https://issuer.example.com/token-request");
        CHECK(config.token_keys.size() == 1);
        CHECK(config.token_keys[0].type == TokenType::BLIND_RSA);
    }
}
