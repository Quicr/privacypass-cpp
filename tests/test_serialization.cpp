// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/core/serialization.hpp>
#include <privacy_pass/core/token_response.hpp>

#include "test_vector_utils.hpp"

using namespace privacy_pass;

TEST_SUITE("Serialization") {
    TEST_CASE("ByteReader") {
        std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        ByteReader reader(ByteView(data.data(), data.size()));

        SUBCASE("read_u8") {
            auto val = reader.read_u8();
            REQUIRE(val.has_value());
            CHECK(*val == 0x00);
            CHECK(reader.position() == 1);
        }

        SUBCASE("read_u16 big-endian") {
            auto val = reader.read_u16();
            REQUIRE(val.has_value());
            CHECK(*val == 0x0001);
            CHECK(reader.position() == 2);
        }

        SUBCASE("read_u32 big-endian") {
            auto val = reader.read_u32();
            REQUIRE(val.has_value());
            CHECK(*val == 0x00010203);
            CHECK(reader.position() == 4);
        }

        SUBCASE("read_bytes") {
            auto bytes = reader.read_bytes(4);
            REQUIRE(bytes.has_value());
            CHECK(bytes->size() == 4);
            CHECK((*bytes)[0] == 0x00);
            CHECK((*bytes)[3] == 0x03);
        }

        SUBCASE("read_array") {
            auto arr = reader.read_array<4>();
            REQUIRE(arr.has_value());
            CHECK((*arr)[0] == 0x00);
            CHECK((*arr)[3] == 0x03);
        }

        SUBCASE("insufficient data") {
            reader.skip(6);
            auto val = reader.read_u32();
            CHECK(!val.has_value());
        }

        SUBCASE("remaining") {
            (void)reader.read_u16();
            CHECK(reader.remaining() == 6);
        }
    }

    TEST_CASE("ByteReader varint") {
        SUBCASE("1-byte varint") {
            std::vector<uint8_t> data = {0x25};  // 37
            ByteReader reader(ByteView(data.data(), data.size()));
            auto val = reader.read_varint();
            REQUIRE(val.has_value());
            CHECK(*val == 37);
        }

        SUBCASE("2-byte varint") {
            std::vector<uint8_t> data = {0x41, 0x23};  // 0x4123 with prefix 01
            ByteReader reader(ByteView(data.data(), data.size()));
            auto val = reader.read_varint();
            REQUIRE(val.has_value());
            CHECK(*val == 0x0123);
        }

        SUBCASE("4-byte varint") {
            std::vector<uint8_t> data = {0x80, 0x12, 0x34, 0x56};
            ByteReader reader(ByteView(data.data(), data.size()));
            auto val = reader.read_varint();
            REQUIRE(val.has_value());
            CHECK(*val == 0x00123456);
        }
    }

    TEST_CASE("ByteWriter") {
        ByteWriter writer;

        SUBCASE("write_u8") {
            writer.write_u8(0x42);
            auto result = writer.view();
            CHECK(result.size() == 1);
            CHECK(result[0] == 0x42);
        }

        SUBCASE("write_u16 big-endian") {
            writer.write_u16(0x1234);
            auto result = writer.view();
            CHECK(result.size() == 2);
            CHECK(result[0] == 0x12);
            CHECK(result[1] == 0x34);
        }

        SUBCASE("write_u32 big-endian") {
            writer.write_u32(0x12345678);
            auto result = writer.view();
            CHECK(result.size() == 4);
            CHECK(result[0] == 0x12);
            CHECK(result[1] == 0x34);
            CHECK(result[2] == 0x56);
            CHECK(result[3] == 0x78);
        }

        SUBCASE("write_bytes") {
            std::vector<uint8_t> data = {1, 2, 3, 4};
            writer.write_bytes(ByteView(data.data(), data.size()));
            auto result = writer.view();
            CHECK(result.size() == 4);
        }

        SUBCASE("write_bytes_u8 length-prefixed") {
            std::vector<uint8_t> data = {0xAB, 0xCD, 0xEF};
            writer.write_bytes_u8(ByteView(data.data(), data.size()));
            auto result = writer.view();
            CHECK(result.size() == 4);
            CHECK(result[0] == 3);  // Length
            CHECK(result[1] == 0xAB);
        }

        SUBCASE("write_bytes_u16 length-prefixed") {
            std::vector<uint8_t> data = {0xAB, 0xCD};
            writer.write_bytes_u16(ByteView(data.data(), data.size()));
            auto result = writer.view();
            CHECK(result.size() == 4);
            CHECK(result[0] == 0x00);  // Length high byte
            CHECK(result[1] == 0x02);  // Length low byte
        }

        SUBCASE("write_varint") {
            writer.write_varint(37);  // 1-byte
            CHECK(writer.view().size() == 1);
            CHECK(writer.view()[0] == 37);

            writer.clear();
            writer.write_varint(0x123);  // 2-byte
            CHECK(writer.view().size() == 2);

            writer.clear();
            writer.write_varint(0x12345);  // 4-byte
            CHECK(writer.view().size() == 4);
        }

        SUBCASE("take ownership") {
            writer.write_u32(0x11223344);
            auto data = writer.take();
            CHECK(data.size() == 4);
            CHECK(data[0] == 0x11);
        }
    }

    TEST_CASE("ByteWriter external buffer") {
        std::array<uint8_t, 16> buffer{};
        ByteWriter writer(MutableByteView(buffer.data(), buffer.size()));

        writer.write_u32(0xDEADBEEF);
        CHECK(writer.size() == 4);
        CHECK(buffer[0] == 0xDE);
        CHECK(buffer[1] == 0xAD);
        CHECK(buffer[2] == 0xBE);
        CHECK(buffer[3] == 0xEF);
    }

    TEST_CASE("base64url") {
        SUBCASE("encode empty") {
            auto result = base64url::encode(ByteView{});
            CHECK(result.empty());
        }

        SUBCASE("encode basic") {
            std::vector<uint8_t> data = {0x00, 0x01, 0x02};
            auto result = base64url::encode(ByteView(data.data(), data.size()));
            CHECK(!result.empty());
        }

        SUBCASE("decode empty") {
            auto result = base64url::decode("");
            REQUIRE(result.has_value());
            CHECK(result->empty());
        }

        SUBCASE("roundtrip") {
            std::vector<uint8_t> original = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
            auto encoded = base64url::encode(ByteView(original.data(), original.size()));
            auto decoded = base64url::decode(encoded);
            REQUIRE(decoded.has_value());
            CHECK(*decoded == original);
        }

        SUBCASE("invalid character") {
            auto result = base64url::decode("!!!invalid!!!");
            CHECK(!result.has_value());
        }
    }

    TEST_CASE("varint_size") {
        CHECK(varint_size(0) == 1);
        CHECK(varint_size(63) == 1);       // 0x3F
        CHECK(varint_size(64) == 2);       // 0x40
        CHECK(varint_size(16383) == 2);    // 0x3FFF
        CHECK(varint_size(16384) == 4);    // 0x4000
        CHECK(varint_size(0x3FFFFFFF) == 4);
        CHECK(varint_size(0x40000000) == 8);
    }
}

TEST_SUITE("TokenResponse") {
    TEST_CASE("RFC 9578 token response vectors deserialize and serialize") {
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

                const auto challenge_bytes = test_vectors::hex_field(vector, "token_challenge");
                const Bytes type_bytes{challenge_bytes[0], challenge_bytes[1]};
                const auto type = test_vectors::token_type_from_bytes(type_bytes);
                const auto response_bytes = test_vectors::hex_field(vector, "token_response");

                auto response = TokenResponse::deserialize(type, test_vectors::view(response_bytes));
                REQUIRE(response.has_value());

                if (type == TokenType::BLIND_RSA) {
                    const auto* blind_rsa = response->as_blind_rsa();
                    REQUIRE(blind_rsa != nullptr);
                    CHECK(blind_rsa->blind_sig == response_bytes);
                } else if (type == TokenType::VOPRF_P384_SHA384) {
                    const auto* voprf = response->as_voprf();
                    REQUIRE(voprf != nullptr);
                    CHECK(voprf->evaluate_msg == Bytes(response_bytes.begin(), response_bytes.begin() + 49));
                    CHECK(voprf->evaluate_proof == Bytes(response_bytes.begin() + 49, response_bytes.end()));
                }

                auto serialized = response->serialize();
                REQUIRE(serialized.has_value());
                CHECK(*serialized == response_bytes);
            }
        }
    }
}
