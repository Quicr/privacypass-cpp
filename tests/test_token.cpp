// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/core/token.hpp>

using namespace privacy_pass;

TEST_SUITE("Token") {
    TEST_CASE("Creation") {
        Nonce nonce{};
        nonce.fill(0x11);

        ChallengeDigest digest{};
        digest.fill(0x22);

        TokenKeyId key_id{};
        key_id.fill(0x33);

        Bytes auth(256, 0x44);

        auto token = Token::create(
            TokenType::BLIND_RSA,
            nonce,
            digest,
            key_id,
            std::move(auth));

        CHECK(token.token_type == TokenType::BLIND_RSA);
        CHECK(token.nonce == nonce);
        CHECK(token.challenge_digest == digest);
        CHECK(token.token_key_id == key_id);
        CHECK(token.authenticator.size() == 256);
    }

    TEST_CASE("Serialization roundtrip - Blind RSA") {
        Nonce nonce{};
        ChallengeDigest digest{};
        TokenKeyId key_id{};

        for (size_t i = 0; i < 32; ++i) {
            nonce[i] = static_cast<uint8_t>(i);
            digest[i] = static_cast<uint8_t>(i + 32);
            key_id[i] = static_cast<uint8_t>(i + 64);
        }

        Bytes auth(256);
        for (size_t i = 0; i < 256; ++i) {
            auth[i] = static_cast<uint8_t>(i);
        }

        auto original = Token::create(
            TokenType::BLIND_RSA,
            nonce,
            digest,
            key_id,
            std::move(auth));

        auto serialized = original.serialize();
        REQUIRE(serialized.has_value());

        auto restored = Token::deserialize(
            ByteView(serialized->data(), serialized->size()));
        REQUIRE(restored.has_value());

        CHECK(restored->token_type == TokenType::BLIND_RSA);
        CHECK(restored->nonce == nonce);
        CHECK(restored->challenge_digest == digest);
        CHECK(restored->token_key_id == key_id);
        CHECK(restored->authenticator.size() == 256);
        CHECK(restored->authenticator[0] == 0);
        CHECK(restored->authenticator[255] == 255);
    }

    TEST_CASE("Serialization roundtrip - VOPRF") {
        Nonce nonce{};
        ChallengeDigest digest{};
        TokenKeyId key_id{};

        nonce.fill(0xAA);
        digest.fill(0xBB);
        key_id.fill(0xCC);

        Bytes auth(48, 0xDD);  // VOPRF P-384 output size

        auto original = Token::create(
            TokenType::VOPRF_P384_SHA384,
            nonce,
            digest,
            key_id,
            std::move(auth));

        auto serialized = original.serialize();
        REQUIRE(serialized.has_value());

        auto restored = Token::deserialize(
            ByteView(serialized->data(), serialized->size()));
        REQUIRE(restored.has_value());

        CHECK(restored->token_type == TokenType::VOPRF_P384_SHA384);
        CHECK(restored->authenticator.size() == 48);
    }

    TEST_CASE("authenticator_input") {
        Nonce nonce{};
        ChallengeDigest digest{};
        TokenKeyId key_id{};

        nonce.fill(0x11);
        digest.fill(0x22);
        key_id.fill(0x33);

        Bytes auth(256, 0x44);

        auto token = Token::create(
            TokenType::BLIND_RSA,
            nonce,
            digest,
            key_id,
            std::move(auth));

        auto input = token.authenticator_input();

        CHECK(input.token_type == token.token_type);
        CHECK(input.nonce == token.nonce);
        CHECK(input.challenge_digest == token.challenge_digest);
        CHECK(input.token_key_id == token.token_key_id);
    }

    TEST_CASE("Serialized size") {
        Nonce nonce{};
        ChallengeDigest digest{};
        TokenKeyId key_id{};
        Bytes auth(256);

        auto token = Token::create(TokenType::BLIND_RSA, nonce, digest, key_id, std::move(auth));

        // type(2) + nonce(32) + digest(32) + key_id(32) + auth(256) = 354
        CHECK(token.serialized_size() == 354);

        auto serialized = token.serialize();
        REQUIRE(serialized.has_value());
        CHECK(serialized->size() == 354);
    }

    TEST_CASE("Validation") {
        SUBCASE("Valid Blind RSA token") {
            Nonce nonce{};
            ChallengeDigest digest{};
            TokenKeyId key_id{};
            Bytes auth(256);

            auto token = Token::create(TokenType::BLIND_RSA, nonce, digest, key_id, std::move(auth));
            auto result = token.validate();
            CHECK(result.has_value());
        }

        SUBCASE("Invalid authenticator size") {
            Nonce nonce{};
            ChallengeDigest digest{};
            TokenKeyId key_id{};
            Bytes auth(128);  // Wrong size for Blind RSA

            auto token = Token::create(TokenType::BLIND_RSA, nonce, digest, key_id, std::move(auth));
            auto result = token.validate();
            CHECK(!result.has_value());
            CHECK(result.error().code == ErrorCode::TOKEN_MALFORMED);
        }
    }

    TEST_CASE("Deserialization errors") {
        SUBCASE("Empty") {
            auto result = Token::deserialize(ByteView{});
            CHECK(!result.has_value());
        }

        SUBCASE("Truncated") {
            std::vector<uint8_t> data(50, 0);  // Not enough for full token
            data[0] = 0x00;
            data[1] = 0x02;  // BLIND_RSA type

            auto result = Token::deserialize(ByteView(data.data(), data.size()));
            CHECK(!result.has_value());
        }
    }
}

TEST_SUITE("AuthenticatorInput") {
    TEST_CASE("Serialization roundtrip") {
        AuthenticatorInput input{
            .token_type = TokenType::BLIND_RSA,
            .nonce = {},
            .challenge_digest = {},
            .token_key_id = {},
        };

        input.nonce.fill(0x11);
        input.challenge_digest.fill(0x22);
        input.token_key_id.fill(0x33);

        auto serialized = input.serialize();
        REQUIRE(serialized.has_value());

        auto restored = AuthenticatorInput::deserialize(
            ByteView(serialized->data(), serialized->size()));
        REQUIRE(restored.has_value());

        CHECK(restored->token_type == input.token_type);
        CHECK(restored->nonce == input.nonce);
        CHECK(restored->challenge_digest == input.challenge_digest);
        CHECK(restored->token_key_id == input.token_key_id);
    }

    TEST_CASE("Serialized size") {
        AuthenticatorInput input{};
        CHECK(input.serialized_size() == 2 + 32 + 32 + 32);
    }
}
