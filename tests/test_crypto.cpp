// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/crypto/hash.hpp>
#include <privacy_pass/crypto/random.hpp>

using namespace privacy_pass;
using namespace privacy_pass::crypto;

TEST_SUITE("Crypto Utilities") {
    TEST_CASE("SHA-256") {
        SUBCASE("empty input") {
            auto result = sha256(ByteView{});
            REQUIRE(result.has_value());
            CHECK(result->size() == 32);
        }

        SUBCASE("known vector") {
            // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            auto result = sha256(ByteView{});
            REQUIRE(result.has_value());
            CHECK((*result)[0] == 0xe3);
            CHECK((*result)[1] == 0xb0);
            CHECK((*result)[31] == 0x55);
        }

        SUBCASE("hello world") {
            std::string input = "hello world";
            auto result = sha256(ByteView(
                reinterpret_cast<const uint8_t*>(input.data()), input.size()));
            REQUIRE(result.has_value());
            CHECK(result->size() == 32);
        }
    }

    TEST_CASE("SHA-384") {
        SUBCASE("empty input") {
            auto result = sha384(ByteView{});
            REQUIRE(result.has_value());
            CHECK(result->size() == 48);
        }

        SUBCASE("produces 48 bytes") {
            std::string input = "test";
            auto result = sha384(ByteView(
                reinterpret_cast<const uint8_t*>(input.data()), input.size()));
            REQUIRE(result.has_value());
            CHECK(result->size() == 48);
        }
    }

    TEST_CASE("Incremental hashing") {
        SUBCASE("Sha256Hasher") {
            Sha256Hasher hasher;
            std::string part1 = "hello ";
            std::string part2 = "world";

            hasher.update(ByteView(
                reinterpret_cast<const uint8_t*>(part1.data()), part1.size()));
            hasher.update(ByteView(
                reinterpret_cast<const uint8_t*>(part2.data()), part2.size()));

            auto result = hasher.finalize();
            REQUIRE(result.has_value());

            // Should equal sha256("hello world")
            std::string full = "hello world";
            auto direct = sha256(ByteView(
                reinterpret_cast<const uint8_t*>(full.data()), full.size()));
            REQUIRE(direct.has_value());

            CHECK(*result == *direct);
        }

        SUBCASE("Sha384Hasher") {
            Sha384Hasher hasher;
            std::string data = "test data";

            hasher.update(ByteView(
                reinterpret_cast<const uint8_t*>(data.data()), data.size()));

            auto result = hasher.finalize();
            REQUIRE(result.has_value());
            CHECK(result->size() == 48);
        }
    }

    TEST_CASE("HMAC-SHA256") {
        std::vector<uint8_t> key = {0x0b, 0x0b, 0x0b, 0x0b};
        std::string data = "Hi There";

        auto result = hmac_sha256(
            ByteView(key.data(), key.size()),
            ByteView(reinterpret_cast<const uint8_t*>(data.data()), data.size()));

        REQUIRE(result.has_value());
        CHECK(result->size() == 32);
    }

    TEST_CASE("Random generation") {
        SUBCASE("random_bytes") {
            auto result = random_bytes(32);
            REQUIRE(result.has_value());
            CHECK(result->size() == 32);

            // Should be different on subsequent calls
            auto result2 = random_bytes(32);
            REQUIRE(result2.has_value());
            CHECK(*result != *result2);
        }

        SUBCASE("random_fill") {
            std::array<uint8_t, 16> buffer{};
            auto result = random_fill(MutableByteView(buffer.data(), buffer.size()));
            REQUIRE(result.has_value());

            // Check that at least some bytes were filled
            bool has_nonzero = false;
            for (auto b : buffer) {
                if (b != 0) {
                    has_nonzero = true;
                    break;
                }
            }
            CHECK(has_nonzero);
        }

        SUBCASE("random_nonce") {
            auto nonce1 = random_nonce();
            auto nonce2 = random_nonce();

            REQUIRE(nonce1.has_value());
            REQUIRE(nonce2.has_value());
            CHECK(nonce1->size() == 32);
            CHECK(*nonce1 != *nonce2);
        }

        SUBCASE("random_u64") {
            auto val1 = random_u64();
            auto val2 = random_u64();

            REQUIRE(val1.has_value());
            REQUIRE(val2.has_value());
            CHECK(*val1 != *val2);  // Probabilistically true
        }
    }

    TEST_CASE("HKDF") {
        std::vector<uint8_t> salt = {0x00, 0x01, 0x02, 0x03};
        std::vector<uint8_t> ikm = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        std::vector<uint8_t> info = {0x10, 0x11};

        SUBCASE("extract") {
            auto prk = hkdf_extract_sha256(
                ByteView(salt.data(), salt.size()),
                ByteView(ikm.data(), ikm.size()));

            REQUIRE(prk.has_value());
            CHECK(prk->size() == 32);
        }

        SUBCASE("expand") {
            auto prk = hkdf_extract_sha256(
                ByteView(salt.data(), salt.size()),
                ByteView(ikm.data(), ikm.size()));
            REQUIRE(prk.has_value());

            auto okm = hkdf_expand_sha256(
                ByteView(prk->data(), prk->size()),
                ByteView(info.data(), info.size()),
                64);

            REQUIRE(okm.has_value());
            CHECK(okm->size() == 64);
        }
    }
}
