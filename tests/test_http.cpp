// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <ostream>
#include <privacy_pass/http/auth_scheme.hpp>

#include "test_vector_utils.hpp"

using namespace privacy_pass;
using namespace privacy_pass::http;

TEST_SUITE("HTTP Auth Scheme") {
    TEST_CASE("ChallengeHeader formatting") {
        ChallengeHeader header;
        header.challenge = "Y2hhbGxlbmdlX2RhdGE";
        header.token_key = "a2V5X2RhdGE";
        header.max_age = 600;

        auto formatted = header.format();

        CHECK(formatted.find("PrivateToken") != std::string::npos);
        CHECK(formatted.find("challenge=\"Y2hhbGxlbmdlX2RhdGE\"") != std::string::npos);
        CHECK(formatted.find("token-key=\"a2V5X2RhdGE\"") != std::string::npos);
        CHECK(formatted.find("max-age=600") != std::string::npos);
    }

    TEST_CASE("ChallengeHeader parsing") {
        std::string header =
            "PrivateToken challenge=\"Y2hhbGxlbmdl\", token-key=\"a2V5\", max-age=300";

        auto result = ChallengeHeader::parse(header);
        REQUIRE(result.has_value());

        CHECK(result->challenge == "Y2hhbGxlbmdl");
        REQUIRE(result->token_key.has_value());
        CHECK(*result->token_key == "a2V5");
        REQUIRE(result->max_age.has_value());
        CHECK(*result->max_age == 300);
    }

    TEST_CASE("ChallengeHeader parsing without max-age") {
        std::string header = "PrivateToken challenge=\"Y2hhbGxlbmdl\", token-key=\"a2V5\"";

        auto result = ChallengeHeader::parse(header);
        REQUIRE(result.has_value());

        CHECK(result->challenge == "Y2hhbGxlbmdl");
        REQUIRE(result->token_key.has_value());
        CHECK(*result->token_key == "a2V5");
        CHECK(!result->max_age.has_value());
    }

    TEST_CASE("ChallengeHeader parsing errors") {
        SUBCASE("Wrong scheme") {
            auto result = ChallengeHeader::parse("Basic challenge=\"abc\"");
            CHECK(!result.has_value());
        }

        SUBCASE("Missing challenge") {
            auto result = ChallengeHeader::parse("PrivateToken token-key=\"abc\"");
            CHECK(!result.has_value());
        }

        SUBCASE("Missing token-key allowed") {
            auto result = ChallengeHeader::parse("PrivateToken challenge=\"abc\"");
            REQUIRE(result.has_value());
            CHECK(!result->token_key.has_value());
            CHECK(!result->decode_token_key().has_value());
        }
    }

    TEST_CASE("AuthorizationHeader formatting") {
        AuthorizationHeader header;
        header.token = "dG9rZW5fZGF0YQ";

        auto formatted = header.format();

        CHECK(formatted == "PrivateToken token=\"dG9rZW5fZGF0YQ\"");
    }

    TEST_CASE("AuthorizationHeader parsing") {
        std::string header = "PrivateToken token=\"dG9rZW5fZGF0YQ\"";

        auto result = AuthorizationHeader::parse(header);
        REQUIRE(result.has_value());

        CHECK(result->token == "dG9rZW5fZGF0YQ");
    }

    TEST_CASE("AuthorizationHeader parsing errors") {
        SUBCASE("Wrong scheme") {
            auto result = AuthorizationHeader::parse("Bearer token123");
            CHECK(!result.has_value());
        }

        SUBCASE("Missing token") {
            auto result = AuthorizationHeader::parse("PrivateToken other=\"value\"");
            CHECK(!result.has_value());
        }
    }

    TEST_CASE("build_www_authenticate") {
        auto challenge = TokenChallenge::create(
            TokenType::BLIND_RSA,
            "issuer.example.com",
            std::nullopt,
            {"origin.example.com"});

        std::vector<uint8_t> key_data(256, 0x42);

        auto result = build_www_authenticate(
            challenge,
            ByteView(key_data.data(), key_data.size()),
            600);

        REQUIRE(result.has_value());
        CHECK(result->starts_with("PrivateToken "));
        CHECK(result->find("challenge=") != std::string::npos);
        CHECK(result->find("token-key=") != std::string::npos);
        CHECK(result->find("max-age=600") != std::string::npos);
    }

    TEST_CASE("build_authorization") {
        Nonce nonce{};
        ChallengeDigest digest{};
        TokenKeyId key_id{};
        Bytes auth(256, 0x42);

        auto token = Token::create(
            TokenType::BLIND_RSA,
            nonce,
            digest,
            key_id,
            std::move(auth));

        auto result = build_authorization(token);

        REQUIRE(result.has_value());
        CHECK(result->starts_with("PrivateToken "));
        CHECK(result->find("token=") != std::string::npos);
    }

    TEST_CASE("parse_authorization") {
        // Create a token
        Nonce nonce{};
        nonce.fill(0x11);

        ChallengeDigest digest{};
        digest.fill(0x22);

        TokenKeyId key_id{};
        key_id.fill(0x33);

        Bytes auth(256, 0x44);

        auto original_token = Token::create(
            TokenType::BLIND_RSA,
            nonce,
            digest,
            key_id,
            std::move(auth));

        // Build header
        auto header = build_authorization(original_token);
        REQUIRE(header.has_value());

        // Parse back
        auto parsed = parse_authorization(*header);
        REQUIRE(parsed.has_value());

        CHECK(parsed->token_type == original_token.token_type);
        CHECK(parsed->nonce == original_token.nonce);
        CHECK(parsed->challenge_digest == original_token.challenge_digest);
        CHECK(parsed->token_key_id == original_token.token_key_id);
        CHECK(parsed->authenticator.size() == original_token.authenticator.size());
    }

    TEST_CASE("Media type constants") {
        CHECK(MEDIA_TYPE_ISSUER_DIRECTORY == "application/private-token-issuer-directory");
        CHECK(MEDIA_TYPE_TOKEN_REQUEST == "application/private-token-request");
        CHECK(MEDIA_TYPE_TOKEN_RESPONSE == "application/private-token-response");
    }

    TEST_CASE("RFC 9577 WWW-Authenticate vectors") {
        const std::array files{
            "auth_scheme_header_rfc9577.json",
            "auth_scheme_header_complicated.json",
        };

        for (const auto* file : files) {
            const auto vectors = test_vectors::load_json(file);
            for (const auto& vector : vectors) {
                CAPTURE(file);
                CAPTURE(vector.dump());

                auto parsed = ChallengeHeader::parse_all(vector.at("WWW-Authenticate").get<std::string>());
                REQUIRE(parsed.has_value());

                for (size_t i = 0; i < parsed->size(); ++i) {
                    const auto suffix = std::to_string(i);
                    CAPTURE(i);

                    auto challenge = (*parsed)[i].decode_challenge();
                    REQUIRE(challenge.has_value());
                    auto challenge_bytes = challenge->serialize();
                    REQUIRE(challenge_bytes.has_value());
                    CHECK(*challenge_bytes == test_vectors::hex_field(vector, "token-challenge-" + suffix));

                    auto token_key = (*parsed)[i].decode_token_key();
                    REQUIRE(token_key.has_value());
                    CHECK(*token_key == test_vectors::hex_field(vector, "token-key-" + suffix));

                    REQUIRE((*parsed)[i].max_age.has_value());
                    CHECK(*(*parsed)[i].max_age == vector.at("max-age-" + suffix).get<uint32_t>());
                }
            }
        }
    }
}
