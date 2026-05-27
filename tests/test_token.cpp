// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/core/token.hpp>
#include <privacy_pass/core/token_challenge.hpp>

#include "test_vector_utils.hpp"

#include <optional>

using namespace privacy_pass;

namespace {

std::vector<std::string> split_origins(const std::string& origin_info) {
    std::vector<std::string> origins;
    size_t offset = 0;
    while (offset < origin_info.size()) {
        const auto comma = origin_info.find(',', offset);
        if (comma == std::string::npos) {
            origins.push_back(origin_info.substr(offset));
            break;
        }
        origins.push_back(origin_info.substr(offset, comma - offset));
        offset = comma + 1;
    }
    return origins;
}

}  // namespace

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

    TEST_CASE("RFC 9578 token vectors deserialize and serialize") {
        const std::array files{
            "pub_verif_rfc9578.go.json",
            "pub_verif_rfc9578.rust.json",
            "priv_verif_rfc9578.go.json",
            "priv_verif_rfc9578.rust.json",
        };

        for (const auto* file : files) {
            const auto vectors = test_vectors::load_json(file);
            for (const auto& vector : vectors) {
                CAPTURE(file);
                CAPTURE(vector.dump());

                const auto token_bytes = test_vectors::hex_field(vector, "token");
                auto token = Token::deserialize(test_vectors::view(token_bytes));
                REQUIRE(token.has_value());

                auto serialized = token->serialize();
                REQUIRE(serialized.has_value());
                CHECK(*serialized == token_bytes);

                const auto challenge_bytes = test_vectors::hex_field(vector, "token_challenge");
                auto challenge = TokenChallenge::deserialize(test_vectors::view(challenge_bytes));
                REQUIRE(challenge.has_value());
                auto digest = challenge->digest();
                REQUIRE(digest.has_value());
                CHECK(token->challenge_digest == *digest);
            }
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

    TEST_CASE("RFC 9577 token authenticator input vectors") {
        const auto vectors = test_vectors::load_json("auth_scheme_token_rfc9577.json");

        for (const auto& vector : vectors) {
            CAPTURE(vector.dump());

            const auto type = test_vectors::token_type_from_bytes(
                test_vectors::hex_field(vector, "token_type"));
            const auto issuer = test_vectors::bytes_to_string(
                test_vectors::hex_field(vector, "issuer_name"));
            const auto redemption_context = test_vectors::hex_field(vector, "redemption_context");
            const auto origin_info = test_vectors::bytes_to_string(
                test_vectors::hex_field(vector, "origin_info"));

            std::optional<ChallengeDigest> context;
            if (!redemption_context.empty()) {
                context = test_vectors::fixed_bytes<32>(redemption_context);
            }

            const auto challenge = TokenChallenge::create(
                type,
                issuer,
                context,
                split_origins(origin_info));
            auto challenge_digest = challenge.digest();
            REQUIRE(challenge_digest.has_value());

            const AuthenticatorInput input{
                .token_type = type,
                .nonce = test_vectors::fixed_bytes<32>(test_vectors::hex_field(vector, "nonce")),
                .challenge_digest = *challenge_digest,
                .token_key_id = test_vectors::fixed_bytes<32>(test_vectors::hex_field(vector, "token_key_id")),
            };

            auto serialized = input.serialize();
            REQUIRE(serialized.has_value());
            CHECK(*serialized == test_vectors::hex_field(vector, "token_authenticator_input"));
        }
    }
}
