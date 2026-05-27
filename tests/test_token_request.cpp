// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/core/token_request.hpp>

#include "test_vector_utils.hpp"

using namespace privacy_pass;

TEST_SUITE("TokenRequest") {
    TEST_CASE("Creation") {
        Bytes blinded(256, 0x42);

        auto request = TokenRequest::create(
            TokenType::BLIND_RSA,
            0xAB,
            std::move(blinded));

        CHECK(request.token_type == TokenType::BLIND_RSA);
        CHECK(request.truncated_token_key_id == 0xAB);
        CHECK(request.blinded_msg.size() == 256);
    }

    TEST_CASE("Serialization roundtrip - Blind RSA") {
        Bytes blinded(256);
        for (size_t i = 0; i < 256; ++i) {
            blinded[i] = static_cast<uint8_t>(i);
        }

        auto original = TokenRequest::create(
            TokenType::BLIND_RSA,
            0x42,
            std::move(blinded));

        auto serialized = original.serialize();
        REQUIRE(serialized.has_value());

        auto restored = TokenRequest::deserialize(
            ByteView(serialized->data(), serialized->size()));
        REQUIRE(restored.has_value());

        CHECK(restored->token_type == TokenType::BLIND_RSA);
        CHECK(restored->truncated_token_key_id == 0x42);
        CHECK(restored->blinded_msg.size() == 256);
        CHECK(restored->blinded_msg[0] == 0);
        CHECK(restored->blinded_msg[255] == 255);
    }

    TEST_CASE("Serialization roundtrip - VOPRF") {
        Bytes blinded(49, 0x33);  // P-384 element size

        auto original = TokenRequest::create(
            TokenType::VOPRF_P384_SHA384,
            0x99,
            std::move(blinded));

        auto serialized = original.serialize();
        REQUIRE(serialized.has_value());

        auto restored = TokenRequest::deserialize(
            ByteView(serialized->data(), serialized->size()));
        REQUIRE(restored.has_value());

        CHECK(restored->token_type == TokenType::VOPRF_P384_SHA384);
        CHECK(restored->truncated_token_key_id == 0x99);
        CHECK(restored->blinded_msg.size() == 49);
    }

    TEST_CASE("Serialized size") {
        Bytes blinded(256);
        auto request = TokenRequest::create(TokenType::BLIND_RSA, 0x00, std::move(blinded));

        CHECK(request.serialized_size() == 2 + 1 + 256);  // type + key_id + blinded

        auto serialized = request.serialize();
        REQUIRE(serialized.has_value());
        CHECK(serialized->size() == request.serialized_size());
    }

    TEST_CASE("Deserialization errors") {
        SUBCASE("Empty") {
            auto result = TokenRequest::deserialize(ByteView{});
            CHECK(!result.has_value());
        }

        SUBCASE("Only type") {
            std::vector<uint8_t> data = {0x00, 0x02};
            auto result = TokenRequest::deserialize(ByteView(data.data(), data.size()));
            CHECK(!result.has_value());
        }
    }

    TEST_CASE("RFC 9578 token request vectors deserialize and serialize") {
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

                const auto request_bytes = test_vectors::hex_field(vector, "token_request");
                auto request = TokenRequest::deserialize(test_vectors::view(request_bytes));
                REQUIRE(request.has_value());

                auto serialized = request->serialize();
                REQUIRE(serialized.has_value());
                CHECK(*serialized == request_bytes);
            }
        }
    }
}

TEST_SUITE("BatchedTokenRequest") {
    TEST_CASE("Empty batch") {
        BatchedTokenRequest batch;
        batch.requests = {};

        auto serialized = batch.serialize();
        REQUIRE(serialized.has_value());

        auto restored = BatchedTokenRequest::deserialize(
            ByteView(serialized->data(), serialized->size()));
        REQUIRE(restored.has_value());
        CHECK(restored->requests.empty());
    }

    TEST_CASE("Multiple requests") {
        BatchedTokenRequest batch;

        for (int i = 0; i < 3; ++i) {
            Bytes blinded(256, static_cast<uint8_t>(i));
            batch.requests.push_back(TokenRequest::create(
                TokenType::BLIND_RSA,
                static_cast<uint8_t>(i),
                std::move(blinded)));
        }

        auto serialized = batch.serialize();
        REQUIRE(serialized.has_value());

        auto restored = BatchedTokenRequest::deserialize(
            ByteView(serialized->data(), serialized->size()));
        REQUIRE(restored.has_value());
        CHECK(restored->requests.size() == 3);

        for (int i = 0; i < 3; ++i) {
            CHECK(restored->requests[i].truncated_token_key_id == static_cast<uint8_t>(i));
        }
    }

    TEST_CASE("Serialized size") {
        BatchedTokenRequest batch;
        Bytes blinded1(256, 0x11);
        Bytes blinded2(256, 0x22);

        batch.requests.push_back(TokenRequest::create(TokenType::BLIND_RSA, 0x01, std::move(blinded1)));
        batch.requests.push_back(TokenRequest::create(TokenType::BLIND_RSA, 0x02, std::move(blinded2)));

        auto serialized = batch.serialize();
        REQUIRE(serialized.has_value());
        CHECK(serialized->size() == batch.serialized_size());
    }

    TEST_CASE("generic batched token vectors deserialize and serialize") {
        const std::array files{
            "generic_batched_tokens_v6_go.json",
            "generic_batched_tokens_v6_rs.json",
        };

        for (const auto* file : files) {
            const auto vectors = test_vectors::load_json(file);
            for (const auto& vector : vectors) {
                CAPTURE(file);
                CAPTURE(vector.dump());

                const auto request_bytes = test_vectors::hex_field(vector, "token_request");
                auto request = BatchedTokenRequest::deserialize(test_vectors::view(request_bytes));
                REQUIRE(request.has_value());
                CHECK(request->requests.size() == vector.at("issuance").size());

                auto serialized = request->serialize();
                REQUIRE(serialized.has_value());
                CHECK(*serialized == request_bytes);
            }
        }
    }
}
