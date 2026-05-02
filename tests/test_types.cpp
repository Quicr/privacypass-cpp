// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/core/types.hpp>

using namespace privacy_pass;

TEST_SUITE("Types") {
    TEST_CASE("TokenType constants") {
        CHECK(static_cast<uint16_t>(TokenType::VOPRF_P384_SHA384) == 0x0001);
        CHECK(static_cast<uint16_t>(TokenType::BLIND_RSA) == 0x0002);
        CHECK(static_cast<uint16_t>(TokenType::PARTIALLY_BLIND_RSA) == 0xDA7A);
    }

    TEST_CASE("TokenTypeInfo") {
        SUBCASE("Blind RSA") {
            auto info = TokenTypeInfo::for_type(TokenType::BLIND_RSA);
            CHECK(info.authenticator_size == 256);
            CHECK(info.key_id_size == 32);
            CHECK(info.blinded_element_size == 256);
            CHECK(info.publicly_verifiable == true);
        }

        SUBCASE("VOPRF P-384") {
            auto info = TokenTypeInfo::for_type(TokenType::VOPRF_P384_SHA384);
            CHECK(info.authenticator_size == 48);
            CHECK(info.key_id_size == 32);
            CHECK(info.blinded_element_size == 97);
            CHECK(info.publicly_verifiable == false);
        }
    }

    TEST_CASE("SecureBytes") {
        SUBCASE("Construction and access") {
            SecureBytes bytes(32);
            CHECK(bytes.size() == 32);
            CHECK(!bytes.empty());
        }

        SUBCASE("From ByteView") {
            std::vector<uint8_t> data = {1, 2, 3, 4, 5};
            SecureBytes bytes(ByteView(data.data(), data.size()));
            CHECK(bytes.size() == 5);
            CHECK(bytes[0] == 1);
            CHECK(bytes[4] == 5);
        }

        SUBCASE("Move semantics") {
            SecureBytes a(16);
            a[0] = 0x42;

            SecureBytes b = std::move(a);
            CHECK(b.size() == 16);
            CHECK(b[0] == 0x42);
            CHECK(a.empty());
        }

        SUBCASE("Clear zeros memory") {
            SecureBytes bytes(8);
            for (size_t i = 0; i < 8; ++i) {
                bytes[i] = static_cast<uint8_t>(i + 1);
            }

            bytes.clear();
            CHECK(bytes.empty());
        }
    }

    TEST_CASE("Error") {
        SUBCASE("Simple error") {
            Error err(ErrorCode::CRYPTO_ERROR);
            CHECK(err.code == ErrorCode::CRYPTO_ERROR);
            CHECK(err.message.empty());
            CHECK(!err.is_ok());
            CHECK(static_cast<bool>(err));
        }

        SUBCASE("Error with message") {
            Error err(ErrorCode::INVALID_KEY, "Bad key format");
            CHECK(err.code == ErrorCode::INVALID_KEY);
            CHECK(err.message == "Bad key format");
        }

        SUBCASE("OK error") {
            Error err(ErrorCode::OK);
            CHECK(err.is_ok());
            CHECK(!static_cast<bool>(err));
        }
    }

    TEST_CASE("token_type_name") {
        CHECK(token_type_name(TokenType::BLIND_RSA) == "Blind-RSA");
        CHECK(token_type_name(TokenType::VOPRF_P384_SHA384) == "VOPRF-P384-SHA384");
    }

    TEST_CASE("error_code_name") {
        CHECK(error_code_name(ErrorCode::OK) == "OK");
        CHECK(error_code_name(ErrorCode::TOKEN_REPLAYED) == "TOKEN_REPLAYED");
    }
}
