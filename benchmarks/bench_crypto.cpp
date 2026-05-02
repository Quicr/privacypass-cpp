// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <benchmark/benchmark.h>
#include <privacy_pass/crypto/blind_rsa.hpp>
#include <privacy_pass/crypto/hash.hpp>
#include <privacy_pass/crypto/random.hpp>
#include <privacy_pass/crypto/voprf.hpp>

using namespace privacy_pass;
using namespace privacy_pass::crypto;

// SHA-256 benchmarks
static void BM_SHA256_32bytes(benchmark::State& state) {
    auto data = random_bytes(32).value();
    for (auto _ : state) {
        auto result = sha256(ByteView(data.data(), data.size()));
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_SHA256_32bytes);

static void BM_SHA256_1KB(benchmark::State& state) {
    auto data = random_bytes(1024).value();
    for (auto _ : state) {
        auto result = sha256(ByteView(data.data(), data.size()));
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_SHA256_1KB);

static void BM_SHA256_1MB(benchmark::State& state) {
    auto data = random_bytes(1024 * 1024).value();
    for (auto _ : state) {
        auto result = sha256(ByteView(data.data(), data.size()));
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_SHA256_1MB);

// SHA-384 benchmarks
static void BM_SHA384_32bytes(benchmark::State& state) {
    auto data = random_bytes(32).value();
    for (auto _ : state) {
        auto result = sha384(ByteView(data.data(), data.size()));
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_SHA384_32bytes);

// Random generation benchmarks
static void BM_RandomBytes_32(benchmark::State& state) {
    for (auto _ : state) {
        auto result = random_bytes(32);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_RandomBytes_32);

static void BM_RandomNonce(benchmark::State& state) {
    for (auto _ : state) {
        auto result = random_nonce();
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_RandomNonce);

// Blind RSA benchmarks
static void BM_BlindRSA_KeyGen(benchmark::State& state) {
    for (auto _ : state) {
        auto keypair = BlindRsaPrivateKey::generate();
        benchmark::DoNotOptimize(keypair);
    }
}
BENCHMARK(BM_BlindRSA_KeyGen);

static void BM_BlindRSA_Blind(benchmark::State& state) {
    auto keypair = BlindRsaPrivateKey::generate().value();
    auto msg = random_bytes(98).value();  // AuthenticatorInput size

    for (auto _ : state) {
        auto result = keypair.second.blind(ByteView(msg.data(), msg.size()));
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_BlindRSA_Blind);

static void BM_BlindRSA_BlindSign(benchmark::State& state) {
    auto keypair = BlindRsaPrivateKey::generate().value();
    auto msg = random_bytes(98).value();
    auto blinding = keypair.second.blind(ByteView(msg.data(), msg.size())).value();

    for (auto _ : state) {
        auto result = keypair.first.blind_sign(
            ByteView(blinding.blinded_msg.data(), blinding.blinded_msg.size()));
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_BlindRSA_BlindSign);

static void BM_BlindRSA_Finalize(benchmark::State& state) {
    auto keypair = BlindRsaPrivateKey::generate().value();
    auto msg = random_bytes(98).value();
    auto blinding = keypair.second.blind(ByteView(msg.data(), msg.size())).value();
    auto blind_sig = keypair.first.blind_sign(
        ByteView(blinding.blinded_msg.data(), blinding.blinded_msg.size())).value();

    for (auto _ : state) {
        auto result = keypair.second.finalize(
            ByteView(blind_sig.data(), blind_sig.size()),
            blinding,
            ByteView(msg.data(), msg.size()));
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_BlindRSA_Finalize);

static void BM_BlindRSA_Verify(benchmark::State& state) {
    auto keypair = BlindRsaPrivateKey::generate().value();
    auto msg = random_bytes(98).value();
    auto sig = keypair.first.sign(ByteView(msg.data(), msg.size())).value();

    for (auto _ : state) {
        auto result = keypair.second.verify(
            ByteView(msg.data(), msg.size()),
            ByteView(sig.data(), sig.size()));
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_BlindRSA_Verify);

// Full Blind RSA protocol
static void BM_BlindRSA_FullProtocol(benchmark::State& state) {
    auto keypair = BlindRsaPrivateKey::generate().value();
    auto msg = random_bytes(98).value();

    for (auto _ : state) {
        // Client: blind
        auto blinding = keypair.second.blind(ByteView(msg.data(), msg.size())).value();

        // Server: sign
        auto blind_sig = keypair.first.blind_sign(
            ByteView(blinding.blinded_msg.data(), blinding.blinded_msg.size())).value();

        // Client: finalize
        auto sig = keypair.second.finalize(
            ByteView(blind_sig.data(), blind_sig.size()),
            blinding,
            ByteView(msg.data(), msg.size())).value();

        // Verify
        auto valid = keypair.second.verify(
            ByteView(msg.data(), msg.size()),
            ByteView(sig.data(), sig.size()));

        benchmark::DoNotOptimize(valid);
    }
}
BENCHMARK(BM_BlindRSA_FullProtocol);

// VOPRF benchmarks
static void BM_VOPRF_KeyGen(benchmark::State& state) {
    for (auto _ : state) {
        auto keypair = VoprfPrivateKey::generate();
        benchmark::DoNotOptimize(keypair);
    }
}
BENCHMARK(BM_VOPRF_KeyGen);

static void BM_VOPRF_Blind(benchmark::State& state) {
    auto keypair = VoprfPrivateKey::generate().value();
    auto pub_bytes = keypair.second.to_bytes().value();
    auto client_key = VoprfPublicKey::from_bytes(
        ByteView(pub_bytes.data(), pub_bytes.size())).value();

    VoprfClient client(std::move(client_key));
    auto input = random_bytes(64).value();

    for (auto _ : state) {
        auto result = client.blind(ByteView(input.data(), input.size()));
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_VOPRF_Blind);

static void BM_VOPRF_Evaluate(benchmark::State& state) {
    auto keypair = VoprfPrivateKey::generate().value();

    auto pub_bytes = keypair.second.to_bytes().value();
    auto client_key = VoprfPublicKey::from_bytes(
        ByteView(pub_bytes.data(), pub_bytes.size())).value();

    auto priv_bytes = keypair.first.to_bytes().value();
    auto server_key = VoprfPrivateKey::from_bytes(priv_bytes.view()).value();

    VoprfClient client(std::move(client_key));
    VoprfServer server(std::move(server_key));

    auto input = random_bytes(64).value();
    auto blind_data = client.blind(ByteView(input.data(), input.size())).value();

    for (auto _ : state) {
        auto result = server.blind_evaluate(
            ByteView(blind_data.blinded_element.data(), blind_data.blinded_element.size()));
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_VOPRF_Evaluate);

static void BM_VOPRF_Finalize(benchmark::State& state) {
    auto keypair = VoprfPrivateKey::generate().value();

    auto pub_bytes = keypair.second.to_bytes().value();
    auto client_key = VoprfPublicKey::from_bytes(
        ByteView(pub_bytes.data(), pub_bytes.size())).value();

    auto priv_bytes = keypair.first.to_bytes().value();
    auto server_key = VoprfPrivateKey::from_bytes(priv_bytes.view()).value();

    VoprfClient client(std::move(client_key));
    VoprfServer server(std::move(server_key));

    auto input = random_bytes(64).value();
    auto blind_data = client.blind(ByteView(input.data(), input.size())).value();
    auto evaluation = server.blind_evaluate(
        ByteView(blind_data.blinded_element.data(), blind_data.blinded_element.size())).value();

    for (auto _ : state) {
        auto result = client.finalize(blind_data, evaluation);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_VOPRF_Finalize);
