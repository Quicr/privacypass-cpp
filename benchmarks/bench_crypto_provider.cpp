// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

// Benchmarks labeled by crypto backend for easy comparison between
// OpenSSL and BoringSSL builds.

#include <benchmark/benchmark.h>
#include <privacy_pass/crypto/blind_rsa.hpp>
#include <privacy_pass/crypto/hash.hpp>
#include <privacy_pass/crypto/random.hpp>
#include <privacy_pass/crypto/voprf.hpp>

#include <string>

using namespace privacy_pass;
using namespace privacy_pass::crypto;

// Backend label for benchmark names
#if defined(PRIVACY_PASS_WITH_BORINGSSL)
static const std::string BACKEND = "BoringSSL";
#else
static const std::string BACKEND = "OpenSSL";
#endif

// --- Hash benchmarks ---

static void BM_Provider_SHA256(benchmark::State& state) {
    auto data = random_bytes(static_cast<size_t>(state.range(0))).value();
    for (auto _ : state) {
        auto result = sha256(ByteView(data.data(), data.size()));
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(state.iterations() * state.range(0));
    state.SetLabel(BACKEND);
}
BENCHMARK(BM_Provider_SHA256)->Arg(32)->Arg(256)->Arg(1024)->Arg(4096);

static void BM_Provider_SHA384(benchmark::State& state) {
    auto data = random_bytes(static_cast<size_t>(state.range(0))).value();
    for (auto _ : state) {
        auto result = sha384(ByteView(data.data(), data.size()));
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(state.iterations() * state.range(0));
    state.SetLabel(BACKEND);
}
BENCHMARK(BM_Provider_SHA384)->Arg(32)->Arg(256)->Arg(1024)->Arg(4096);

static void BM_Provider_HMAC_SHA256(benchmark::State& state) {
    auto key = random_bytes(32).value();
    auto data = random_bytes(static_cast<size_t>(state.range(0))).value();
    for (auto _ : state) {
        auto result = hmac_sha256(
            ByteView(key.data(), key.size()),
            ByteView(data.data(), data.size()));
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(state.iterations() * state.range(0));
    state.SetLabel(BACKEND);
}
BENCHMARK(BM_Provider_HMAC_SHA256)->Arg(32)->Arg(256)->Arg(1024);

static void BM_Provider_HKDF_Extract(benchmark::State& state) {
    auto salt = random_bytes(32).value();
    auto ikm = random_bytes(32).value();
    for (auto _ : state) {
        auto result = hkdf_extract_sha256(
            ByteView(salt.data(), salt.size()),
            ByteView(ikm.data(), ikm.size()));
        benchmark::DoNotOptimize(result);
    }
    state.SetLabel(BACKEND);
}
BENCHMARK(BM_Provider_HKDF_Extract);

static void BM_Provider_HKDF_Expand(benchmark::State& state) {
    auto salt = random_bytes(32).value();
    auto ikm = random_bytes(32).value();
    auto prk = hkdf_extract_sha256(
        ByteView(salt.data(), salt.size()),
        ByteView(ikm.data(), ikm.size())).value();
    auto info = random_bytes(16).value();

    for (auto _ : state) {
        auto result = hkdf_expand_sha256(
            ByteView(prk.data(), prk.size()),
            ByteView(info.data(), info.size()),
            64);
        benchmark::DoNotOptimize(result);
    }
    state.SetLabel(BACKEND);
}
BENCHMARK(BM_Provider_HKDF_Expand);

// --- Random benchmarks ---

static void BM_Provider_RandomBytes(benchmark::State& state) {
    for (auto _ : state) {
        auto result = random_bytes(static_cast<size_t>(state.range(0)));
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(state.iterations() * state.range(0));
    state.SetLabel(BACKEND);
}
BENCHMARK(BM_Provider_RandomBytes)->Arg(32)->Arg(256)->Arg(1024);

// --- Blind RSA benchmarks ---

static void BM_Provider_BlindRSA_KeyGen(benchmark::State& state) {
    for (auto _ : state) {
        auto keypair = BlindRsaPrivateKey::generate();
        benchmark::DoNotOptimize(keypair);
    }
    state.SetLabel(BACKEND);
}
BENCHMARK(BM_Provider_BlindRSA_KeyGen);

static void BM_Provider_BlindRSA_Blind(benchmark::State& state) {
    auto keypair = BlindRsaPrivateKey::generate().value();
    auto msg = random_bytes(98).value();
    for (auto _ : state) {
        auto result = keypair.second.blind(ByteView(msg.data(), msg.size()));
        benchmark::DoNotOptimize(result);
    }
    state.SetLabel(BACKEND);
}
BENCHMARK(BM_Provider_BlindRSA_Blind);

static void BM_Provider_BlindRSA_BlindSign(benchmark::State& state) {
    auto keypair = BlindRsaPrivateKey::generate().value();
    auto msg = random_bytes(98).value();
    auto blinding = keypair.second.blind(ByteView(msg.data(), msg.size())).value();
    for (auto _ : state) {
        auto result = keypair.first.blind_sign(
            ByteView(blinding.blinded_msg.data(), blinding.blinded_msg.size()));
        benchmark::DoNotOptimize(result);
    }
    state.SetLabel(BACKEND);
}
BENCHMARK(BM_Provider_BlindRSA_BlindSign);

static void BM_Provider_BlindRSA_Verify(benchmark::State& state) {
    auto keypair = BlindRsaPrivateKey::generate().value();
    auto msg = random_bytes(98).value();
    auto sig = keypair.first.sign(ByteView(msg.data(), msg.size())).value();
    for (auto _ : state) {
        auto result = keypair.second.verify(
            ByteView(msg.data(), msg.size()),
            ByteView(sig.data(), sig.size()));
        benchmark::DoNotOptimize(result);
    }
    state.SetLabel(BACKEND);
}
BENCHMARK(BM_Provider_BlindRSA_Verify);

static void BM_Provider_BlindRSA_FullProtocol(benchmark::State& state) {
    auto keypair = BlindRsaPrivateKey::generate().value();
    auto msg = random_bytes(98).value();
    for (auto _ : state) {
        auto blinding = keypair.second.blind(ByteView(msg.data(), msg.size())).value();
        auto blind_sig = keypair.first.blind_sign(
            ByteView(blinding.blinded_msg.data(), blinding.blinded_msg.size())).value();
        auto sig = keypair.second.finalize(
            ByteView(blind_sig.data(), blind_sig.size()),
            blinding,
            ByteView(msg.data(), msg.size())).value();
        auto valid = keypair.second.verify(
            ByteView(msg.data(), msg.size()),
            ByteView(sig.data(), sig.size()));
        benchmark::DoNotOptimize(valid);
    }
    state.SetLabel(BACKEND);
}
BENCHMARK(BM_Provider_BlindRSA_FullProtocol);

// --- VOPRF benchmarks ---

static void BM_Provider_VOPRF_KeyGen(benchmark::State& state) {
    for (auto _ : state) {
        auto keypair = VoprfPrivateKey::generate();
        benchmark::DoNotOptimize(keypair);
    }
    state.SetLabel(BACKEND);
}
BENCHMARK(BM_Provider_VOPRF_KeyGen);

static void BM_Provider_VOPRF_Blind(benchmark::State& state) {
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
    state.SetLabel(BACKEND);
}
BENCHMARK(BM_Provider_VOPRF_Blind);

static void BM_Provider_VOPRF_Evaluate(benchmark::State& state) {
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
    state.SetLabel(BACKEND);
}
BENCHMARK(BM_Provider_VOPRF_Evaluate);

static void BM_Provider_VOPRF_FullProtocol(benchmark::State& state) {
    auto keypair = VoprfPrivateKey::generate().value();
    auto pub_bytes = keypair.second.to_bytes().value();
    auto priv_bytes = keypair.first.to_bytes().value();

    auto input = random_bytes(64).value();

    for (auto _ : state) {
        auto ck = VoprfPublicKey::from_bytes(ByteView(pub_bytes.data(), pub_bytes.size())).value();
        VoprfClient client(std::move(ck));
        auto sk = VoprfPrivateKey::from_bytes(priv_bytes.view()).value();
        VoprfServer server(std::move(sk));

        auto blind_data = client.blind(ByteView(input.data(), input.size())).value();
        auto eval = server.blind_evaluate(
            ByteView(blind_data.blinded_element.data(), blind_data.blinded_element.size())).value();
        auto output = client.finalize(blind_data, eval).value();
        auto valid = server.verify_finalize(
            ByteView(input.data(), input.size()),
            ByteView(output.data(), output.size()));
        benchmark::DoNotOptimize(valid);
    }
    state.SetLabel(BACKEND);
}
BENCHMARK(BM_Provider_VOPRF_FullProtocol);
