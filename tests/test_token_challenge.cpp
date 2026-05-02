// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/core/token_challenge.hpp>

using namespace privacy_pass;

TEST_SUITE("TokenChallenge") {
    TEST_CASE("Creation") {
        auto challenge = TokenChallenge::create(
            TokenType::BLIND_RSA,
            "issuer.example.com",
            std::nullopt,
            {"origin1.example.com", "origin2.example.com"});

        CHECK(challenge.token_type == TokenType::BLIND_RSA);
        CHECK(challenge.issuer_name == "issuer.example.com");
        CHECK(!challenge.redemption_context.has_value());
        CHECK(challenge.origin_info.size() == 2);
        CHECK(challenge.origin_info[0] == "origin1.example.com");
    }

    TEST_CASE("With redemption context") {
        ChallengeDigest context{};
        for (size_t i = 0; i < 32; ++i) {
            context[i] = static_cast<uint8_t>(i);
        }

        auto challenge = TokenChallenge::create(
            TokenType::VOPRF_P384_SHA384,
            "issuer.example.com",
            context,
            {"origin.example.com"});

        REQUIRE(challenge.redemption_context.has_value());
        CHECK(*challenge.redemption_context == context);
    }

    TEST_CASE("origin_info_string") {
        SUBCASE("Empty") {
            auto challenge = TokenChallenge::create(
                TokenType::BLIND_RSA, "issuer", std::nullopt, {});
            CHECK(challenge.origin_info_string().empty());
        }

        SUBCASE("Single origin") {
            auto challenge = TokenChallenge::create(
                TokenType::BLIND_RSA, "issuer", std::nullopt, {"origin.com"});
            CHECK(challenge.origin_info_string() == "origin.com");
        }

        SUBCASE("Multiple origins") {
            auto challenge = TokenChallenge::create(
                TokenType::BLIND_RSA, "issuer", std::nullopt,
                {"a.com", "b.com", "c.com"});
            CHECK(challenge.origin_info_string() == "a.com,b.com,c.com");
        }
    }

    TEST_CASE("Serialization roundtrip") {
        SUBCASE("Without context") {
            auto original = TokenChallenge::create(
                TokenType::BLIND_RSA,
                "test.issuer.com",
                std::nullopt,
                {"origin.com"});

            auto serialized = original.serialize();
            REQUIRE(serialized.has_value());

            auto restored = TokenChallenge::deserialize(
                ByteView(serialized->data(), serialized->size()));
            REQUIRE(restored.has_value());

            CHECK(restored->token_type == original.token_type);
            CHECK(restored->issuer_name == original.issuer_name);
        }

        SUBCASE("With context and multiple origins") {
            ChallengeDigest context{};
            context.fill(0xAB);

            auto original = TokenChallenge::create(
                TokenType::VOPRF_P384_SHA384,
                "voprf.issuer.com",
                context,
                {"origin1.com", "origin2.com"});

            auto serialized = original.serialize();
            REQUIRE(serialized.has_value());

            auto restored = TokenChallenge::deserialize(
                ByteView(serialized->data(), serialized->size()));
            REQUIRE(restored.has_value());

            CHECK(restored->token_type == TokenType::VOPRF_P384_SHA384);
            CHECK(restored->issuer_name == "voprf.issuer.com");
        }
    }

    TEST_CASE("Digest computation") {
        auto challenge = TokenChallenge::create(
            TokenType::BLIND_RSA,
            "issuer.example.com",
            std::nullopt,
            {"origin.example.com"});

        auto digest1 = challenge.digest();
        REQUIRE(digest1.has_value());
        CHECK(digest1->size() == 32);

        // Same challenge should produce same digest
        auto digest2 = challenge.digest();
        REQUIRE(digest2.has_value());
        CHECK(*digest1 == *digest2);

        // Different challenge should produce different digest
        auto different = TokenChallenge::create(
            TokenType::BLIND_RSA,
            "different.issuer.com",
            std::nullopt,
            {"origin.example.com"});

        auto digest3 = different.digest();
        REQUIRE(digest3.has_value());
        CHECK(*digest1 != *digest3);
    }

    TEST_CASE("Serialized size") {
        auto challenge = TokenChallenge::create(
            TokenType::BLIND_RSA,
            "test",
            std::nullopt,
            {"origin"});

        auto serialized = challenge.serialize();
        REQUIRE(serialized.has_value());
        CHECK(serialized->size() == challenge.serialized_size());
    }

    TEST_CASE("Deserialization errors") {
        SUBCASE("Empty data") {
            auto result = TokenChallenge::deserialize(ByteView{});
            CHECK(!result.has_value());
        }

        SUBCASE("Truncated data") {
            std::vector<uint8_t> truncated = {0x00, 0x02};  // Just token_type
            auto result = TokenChallenge::deserialize(
                ByteView(truncated.data(), truncated.size()));
            CHECK(!result.has_value());
        }
    }
}
