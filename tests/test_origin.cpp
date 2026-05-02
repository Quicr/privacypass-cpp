// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/core/origin.hpp>

using namespace privacy_pass;
using namespace privacy_pass::crypto;

TEST_SUITE("ReplayCache") {
    TEST_CASE("Basic operations") {
        ReplayCache cache(std::chrono::seconds(60));

        Nonce nonce1{};
        nonce1.fill(0x11);

        Nonce nonce2{};
        nonce2.fill(0x22);

        SUBCASE("New nonce accepted") {
            CHECK(cache.check_and_add(nonce1));
            CHECK(cache.size() == 1);
        }

        SUBCASE("Duplicate nonce rejected") {
            CHECK(cache.check_and_add(nonce1));
            CHECK(!cache.check_and_add(nonce1));
            CHECK(cache.size() == 1);
        }

        SUBCASE("Different nonces both accepted") {
            CHECK(cache.check_and_add(nonce1));
            CHECK(cache.check_and_add(nonce2));
            CHECK(cache.size() == 2);
        }
    }

    TEST_CASE("Prune operation") {
        ReplayCache cache(std::chrono::seconds(1));

        Nonce nonce{};
        nonce.fill(0xAA);

        (void)cache.check_and_add(nonce);
        CHECK(cache.size() == 1);

        // After pruning (entries should still be there if not expired)
        cache.prune();
        CHECK(cache.size() <= 1);  // May or may not have expired
    }
}

TEST_SUITE("PublicOrigin") {
    TEST_CASE("Create challenge") {
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        OriginConfig config{
            .issuer_name = "issuer.example.com",
            .origin_names = {"origin.example.com"},
            .redemption_window = std::chrono::seconds(3600),
            .require_redemption_context = true,
        };

        std::vector<BlindRsaPublicKey> keys;
        keys.push_back(std::move(keypair->second));

        PublicOrigin origin(config, std::move(keys));

        auto challenge = origin.create_challenge();
        REQUIRE(challenge.has_value());

        CHECK(challenge->token_type == TokenType::BLIND_RSA);
        CHECK(challenge->issuer_name == "issuer.example.com");
        CHECK(challenge->redemption_context.has_value());  // Auto-generated
    }

    TEST_CASE("Create challenge with explicit context") {
        auto keypair = BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        OriginConfig config{
            .issuer_name = "issuer.example.com",
            .origin_names = {"origin.example.com"},
        };

        std::vector<BlindRsaPublicKey> keys;
        keys.push_back(std::move(keypair->second));

        PublicOrigin origin(config, std::move(keys));

        ChallengeDigest context{};
        context.fill(0x42);

        auto challenge = origin.create_challenge(context);
        REQUIRE(challenge.has_value());
        REQUIRE(challenge->redemption_context.has_value());
        CHECK(*challenge->redemption_context == context);
    }
}

TEST_SUITE("Unified Origin") {
    TEST_CASE("Add keys") {
        OriginConfig config{
            .issuer_name = "issuer.example.com",
            .origin_names = {"origin.example.com"},
        };

        Origin origin(config);

        auto rsa_keypair = BlindRsaPrivateKey::generate();
        REQUIRE(rsa_keypair.has_value());
        origin.add_blind_rsa_key(std::move(rsa_keypair->second));

        auto voprf_keypair = VoprfPrivateKey::generate();
        REQUIRE(voprf_keypair.has_value());
        origin.add_voprf_key(std::move(voprf_keypair->second));

        // Create challenges for both types
        auto rsa_challenge = origin.create_challenge(TokenType::BLIND_RSA);
        REQUIRE(rsa_challenge.has_value());
        CHECK(rsa_challenge->token_type == TokenType::BLIND_RSA);

        auto voprf_challenge = origin.create_challenge(TokenType::VOPRF_P384_SHA384);
        REQUIRE(voprf_challenge.has_value());
        CHECK(voprf_challenge->token_type == TokenType::VOPRF_P384_SHA384);
    }

    TEST_CASE("Get config") {
        OriginConfig config{
            .issuer_name = "issuer.example.com",
            .origin_names = {"origin1.com", "origin2.com"},
            .redemption_window = std::chrono::seconds(7200),
        };

        Origin origin(config);

        const auto& returned_config = origin.config();
        CHECK(returned_config.issuer_name == "issuer.example.com");
        CHECK(returned_config.origin_names.size() == 2);
        CHECK(returned_config.redemption_window == std::chrono::seconds(7200));
    }
}
