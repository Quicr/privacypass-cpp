// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <benchmark/benchmark.h>
#include <privacy_pass/core/serialization.hpp>
#include <privacy_pass/core/token.hpp>
#include <privacy_pass/core/token_challenge.hpp>
#include <privacy_pass/crypto/random.hpp>

using namespace privacy_pass;

// Base64url benchmarks
static void BM_Base64url_Encode_256bytes(benchmark::State& state) {
    auto data = crypto::random_bytes(256).value();
    for (auto _ : state) {
        auto result = base64url::encode(ByteView(data.data(), data.size()));
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Base64url_Encode_256bytes);

static void BM_Base64url_Decode_256bytes(benchmark::State& state) {
    auto data = crypto::random_bytes(256).value();
    auto encoded = base64url::encode(ByteView(data.data(), data.size()));

    for (auto _ : state) {
        auto result = base64url::decode(encoded);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Base64url_Decode_256bytes);

// ByteReader benchmarks
static void BM_ByteReader_ReadU16_1000(benchmark::State& state) {
    Bytes data(2000);
    for (size_t i = 0; i < 2000; ++i) {
        data[i] = static_cast<uint8_t>(i);
    }

    for (auto _ : state) {
        ByteReader reader(ByteView(data.data(), data.size()));
        for (int i = 0; i < 1000; ++i) {
            auto val = reader.read_u16();
            benchmark::DoNotOptimize(val);
        }
    }
}
BENCHMARK(BM_ByteReader_ReadU16_1000);

static void BM_ByteReader_ReadVarint_1000(benchmark::State& state) {
    // Create data with varints of various sizes
    ByteWriter writer;
    for (int i = 0; i < 1000; ++i) {
        writer.write_varint(static_cast<uint64_t>(i * 100));
    }
    auto data = writer.take();

    for (auto _ : state) {
        ByteReader reader(ByteView(data.data(), data.size()));
        for (int i = 0; i < 1000; ++i) {
            auto val = reader.read_varint();
            benchmark::DoNotOptimize(val);
        }
    }
}
BENCHMARK(BM_ByteReader_ReadVarint_1000);

// ByteWriter benchmarks
static void BM_ByteWriter_WriteU16_1000(benchmark::State& state) {
    for (auto _ : state) {
        ByteWriter writer(2000);
        for (int i = 0; i < 1000; ++i) {
            writer.write_u16(static_cast<uint16_t>(i));
        }
        auto result = writer.take();
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_ByteWriter_WriteU16_1000);

static void BM_ByteWriter_WriteBytes_1000x256(benchmark::State& state) {
    Bytes chunk(256, 0x42);

    for (auto _ : state) {
        ByteWriter writer;
        writer.reserve(256 * 1000);
        for (int i = 0; i < 1000; ++i) {
            writer.write_bytes(ByteView(chunk.data(), chunk.size()));
        }
        auto result = writer.take();
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_ByteWriter_WriteBytes_1000x256);

// TokenChallenge serialization benchmarks
static void BM_TokenChallenge_Serialize(benchmark::State& state) {
    auto challenge = TokenChallenge::create(
        TokenType::BLIND_RSA,
        "issuer.example.com",
        std::nullopt,
        {"origin1.example.com", "origin2.example.com"});

    for (auto _ : state) {
        auto result = challenge.serialize();
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_TokenChallenge_Serialize);

static void BM_TokenChallenge_Deserialize(benchmark::State& state) {
    auto challenge = TokenChallenge::create(
        TokenType::BLIND_RSA,
        "issuer.example.com",
        std::nullopt,
        {"origin1.example.com", "origin2.example.com"});

    auto serialized = challenge.serialize().value();

    for (auto _ : state) {
        auto result = TokenChallenge::deserialize(
            ByteView(serialized.data(), serialized.size()));
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_TokenChallenge_Deserialize);

static void BM_TokenChallenge_Digest(benchmark::State& state) {
    auto challenge = TokenChallenge::create(
        TokenType::BLIND_RSA,
        "issuer.example.com",
        std::nullopt,
        {"origin.example.com"});

    for (auto _ : state) {
        auto result = challenge.digest();
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_TokenChallenge_Digest);

// Token serialization benchmarks
static void BM_Token_Serialize_BlindRSA(benchmark::State& state) {
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

    for (auto _ : state) {
        auto result = token.serialize();
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Token_Serialize_BlindRSA);

static void BM_Token_Deserialize_BlindRSA(benchmark::State& state) {
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

    auto serialized = token.serialize().value();

    for (auto _ : state) {
        auto result = Token::deserialize(ByteView(serialized.data(), serialized.size()));
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Token_Deserialize_BlindRSA);

// AuthenticatorInput benchmarks
static void BM_AuthenticatorInput_Serialize(benchmark::State& state) {
    AuthenticatorInput input{
        .token_type = TokenType::BLIND_RSA,
        .nonce = {},
        .challenge_digest = {},
        .token_key_id = {},
    };

    for (auto _ : state) {
        auto result = input.serialize();
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_AuthenticatorInput_Serialize);
