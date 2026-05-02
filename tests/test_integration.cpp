// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/privacy_pass.hpp>

using namespace privacy_pass;
using namespace privacy_pass::crypto;

TEST_SUITE("Integration Tests") {
    TEST_CASE("Complete Blind RSA flow") {
        // Setup: Generate issuer keys
        auto issuer = PublicIssuer::generate();
        REQUIRE(issuer.has_value());

        auto issuer_pub = issuer->public_key();
        REQUIRE(issuer_pub.has_value());

        auto issuer_spki = issuer_pub->to_spki();
        auto issuer_key_id = issuer_pub->key_id();
        REQUIRE(issuer_spki.has_value());
        REQUIRE(issuer_key_id.has_value());

        // Setup: Create origin
        OriginConfig origin_config{
            .issuer_name = "issuer.example.com",
            .origin_names = {"origin.example.com"},
            .require_redemption_context = true,
        };

        // Copy public key for origin
        auto origin_key = BlindRsaPublicKey::from_spki(
            ByteView(issuer_spki->data(), issuer_spki->size()));
        REQUIRE(origin_key.has_value());

        std::vector<BlindRsaPublicKey> origin_keys;
        origin_keys.push_back(std::move(*origin_key));

        PublicOrigin origin(origin_config, std::move(origin_keys));

        // Step 1: Origin creates challenge
        auto challenge = origin.create_challenge();
        REQUIRE(challenge.has_value());

        // Step 2: Client creates token request
        PublicClient client;

        auto client_key = BlindRsaPublicKey::from_spki(
            ByteView(issuer_spki->data(), issuer_spki->size()));
        REQUIRE(client_key.has_value());

        auto request_result = client.create_token_request(*challenge, *client_key);
        REQUIRE(request_result.has_value());

        // Step 3: Issuer processes request
        auto response = issuer->issue(request_result->request);
        REQUIRE(response.has_value());

        // Step 4: Client finalizes token
        auto finalize_key = BlindRsaPublicKey::from_spki(
            ByteView(issuer_spki->data(), issuer_spki->size()));
        REQUIRE(finalize_key.has_value());

        auto token = client.finalize(*response, std::move(request_result->finalization_data), *finalize_key);
        REQUIRE(token.has_value());

        // Step 5: Origin verifies token
        auto valid = origin.verify(*token, *challenge);
        REQUIRE(valid.has_value());
        CHECK(*valid == true);

        // Step 6: Origin redeems token (with replay protection)
        auto redeem = origin.verify_and_redeem(*token, *challenge);
        REQUIRE(redeem.has_value());
        CHECK(*redeem == true);

        // Step 7: Replay attempt fails
        // Need fresh origin for this test since token was already redeemed
        auto origin_key2 = BlindRsaPublicKey::from_spki(
            ByteView(issuer_spki->data(), issuer_spki->size()));
        REQUIRE(origin_key2.has_value());

        std::vector<BlindRsaPublicKey> origin_keys2;
        origin_keys2.push_back(std::move(*origin_key2));

        PublicOrigin fresh_origin(origin_config, std::move(origin_keys2));

        // First redemption succeeds
        auto first_redeem = fresh_origin.verify_and_redeem(*token, *challenge);
        REQUIRE(first_redeem.has_value());

        // Second redemption fails (replay)
        auto replay_attempt = fresh_origin.verify_and_redeem(*token, *challenge);
        CHECK(!replay_attempt.has_value());
        CHECK(replay_attempt.error().code == ErrorCode::TOKEN_REPLAYED);
    }

    TEST_CASE("Unified Client integration") {
        // Generate issuer
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        auto& [private_key, public_key] = *keypair;

        auto spki = public_key.to_spki();
        auto key_id = public_key.key_id();
        REQUIRE(spki.has_value());
        REQUIRE(key_id.has_value());

        PublicKey pub{
            .type = TokenType::BLIND_RSA,
            .data = *spki,
            .key_id = *key_id,
        };

        // Create challenge
        auto challenge = TokenChallenge::create(
            TokenType::BLIND_RSA,
            "issuer.example.com",
            std::nullopt,
            {"origin.example.com"});

        // Use unified client
        Client client;
        auto request_result = client.create_token_request(challenge, pub);
        REQUIRE(request_result.has_value());

        // Create issuer from private key
        PublicIssuer issuer(std::move(private_key));

        // Issue
        auto response = issuer.issue(request_result->request);
        REQUIRE(response.has_value());

        // Finalize
        auto token = client.finalize(*response, std::move(request_result->finalization_data), pub);
        REQUIRE(token.has_value());

        CHECK(token->token_type == TokenType::BLIND_RSA);
        CHECK(token->authenticator.size() == 256);
    }

    TEST_CASE("HTTP header integration") {
        // Generate issuer
        auto issuer = PublicIssuer::generate();
        REQUIRE(issuer.has_value());

        auto pub_key = issuer->public_key();
        REQUIRE(pub_key.has_value());

        auto spki = pub_key->to_spki();
        REQUIRE(spki.has_value());

        // Create challenge
        auto challenge = TokenChallenge::create(
            TokenType::BLIND_RSA,
            "issuer.example.com",
            std::nullopt,
            {"origin.example.com"});

        // Build WWW-Authenticate header
        auto www_auth = http::build_www_authenticate(
            challenge,
            ByteView(spki->data(), spki->size()),
            600);
        REQUIRE(www_auth.has_value());

        CHECK(www_auth->starts_with("PrivateToken "));

        // Parse it back
        auto parsed_challenge = http::ChallengeHeader::parse(*www_auth);
        REQUIRE(parsed_challenge.has_value());

        auto decoded_challenge = parsed_challenge->decode_challenge();
        REQUIRE(decoded_challenge.has_value());

        CHECK(decoded_challenge->token_type == TokenType::BLIND_RSA);
        CHECK(decoded_challenge->issuer_name == "issuer.example.com");

        // Create and issue token (simplified - reusing same flow)
        PublicClient client;

        auto client_key = BlindRsaPublicKey::from_spki(
            ByteView(spki->data(), spki->size()));
        REQUIRE(client_key.has_value());

        auto request_result = client.create_token_request(*decoded_challenge, *client_key);
        REQUIRE(request_result.has_value());

        auto response = issuer->issue(request_result->request);
        REQUIRE(response.has_value());

        auto finalize_key = BlindRsaPublicKey::from_spki(ByteView(spki->data(), spki->size()));
        REQUIRE(finalize_key.has_value());

        auto token = client.finalize(*response, std::move(request_result->finalization_data), *finalize_key);
        REQUIRE(token.has_value());

        // Build Authorization header
        auto auth_header = http::build_authorization(*token);
        REQUIRE(auth_header.has_value());

        CHECK(auth_header->starts_with("PrivateToken "));

        // Parse it back
        auto parsed_token = http::parse_authorization(*auth_header);
        REQUIRE(parsed_token.has_value());

        CHECK(parsed_token->token_type == token->token_type);
        CHECK(parsed_token->nonce == token->nonce);
    }

    TEST_CASE("Wrong issuer key fails verification") {
        // Generate two different issuers
        auto issuer1 = PublicIssuer::generate();
        auto issuer2 = PublicIssuer::generate();
        REQUIRE(issuer1.has_value());
        REQUIRE(issuer2.has_value());

        auto pub1 = issuer1->public_key();
        auto pub2 = issuer2->public_key();
        REQUIRE(pub1.has_value());
        REQUIRE(pub2.has_value());

        auto spki1 = pub1->to_spki();
        auto spki2 = pub2->to_spki();
        REQUIRE(spki1.has_value());
        REQUIRE(spki2.has_value());

        // Create challenge and token with issuer1
        auto challenge = TokenChallenge::create(
            TokenType::BLIND_RSA,
            "issuer1.example.com",
            std::nullopt,
            {"origin.example.com"});

        PublicClient client;
        auto client_key = BlindRsaPublicKey::from_spki(ByteView(spki1->data(), spki1->size()));
        REQUIRE(client_key.has_value());

        auto request_result = client.create_token_request(challenge, *client_key);
        REQUIRE(request_result.has_value());

        auto response = issuer1->issue(request_result->request);
        REQUIRE(response.has_value());

        auto finalize_key = BlindRsaPublicKey::from_spki(ByteView(spki1->data(), spki1->size()));
        REQUIRE(finalize_key.has_value());

        auto token = client.finalize(*response, std::move(request_result->finalization_data), *finalize_key);
        REQUIRE(token.has_value());

        // Setup origin with issuer2's key (wrong key!)
        OriginConfig origin_config{
            .issuer_name = "issuer1.example.com",
            .origin_names = {"origin.example.com"},
        };

        auto wrong_key = BlindRsaPublicKey::from_spki(ByteView(spki2->data(), spki2->size()));
        REQUIRE(wrong_key.has_value());

        std::vector<BlindRsaPublicKey> wrong_keys;
        wrong_keys.push_back(std::move(*wrong_key));

        PublicOrigin origin(origin_config, std::move(wrong_keys));

        // Verification should fail
        auto valid = origin.verify(*token, challenge);

        // Either key mismatch or signature verification failure
        CHECK(!valid.has_value());
    }
}
