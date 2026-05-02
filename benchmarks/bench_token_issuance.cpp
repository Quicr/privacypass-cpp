// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <benchmark/benchmark.h>
#include <privacy_pass/core/client.hpp>
#include <privacy_pass/core/issuer.hpp>
#include <privacy_pass/core/origin.hpp>

using namespace privacy_pass;

// Token request creation benchmarks
static void BM_CreateTokenRequest_BlindRSA(benchmark::State& state) {
    auto keypair = crypto::BlindRsaPrivateKey::generate().value();
    auto challenge = TokenChallenge::create(
        TokenType::BLIND_RSA,
        "issuer.example.com",
        std::nullopt,
        {"origin.example.com"});

    PublicClient client;

    for (auto _ : state) {
        auto result = client.create_token_request(challenge, keypair.second);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_CreateTokenRequest_BlindRSA);

// Token issuance benchmarks
static void BM_IssueToken_BlindRSA(benchmark::State& state) {
    auto issuer = PublicIssuer::generate().value();

    Bytes blinded(256, 0x42);
    auto request = TokenRequest::create(
        TokenType::BLIND_RSA,
        issuer.truncated_key_id(),
        std::move(blinded));

    for (auto _ : state) {
        auto response = issuer.issue(request);
        benchmark::DoNotOptimize(response);
    }
}
BENCHMARK(BM_IssueToken_BlindRSA);

// Token finalization benchmarks
static void BM_FinalizeToken_BlindRSA(benchmark::State& state) {
    auto keypair = crypto::BlindRsaPrivateKey::generate().value();
    auto challenge = TokenChallenge::create(
        TokenType::BLIND_RSA,
        "issuer.example.com",
        std::nullopt,
        {"origin.example.com"});

    PublicClient client;
    auto request_result = client.create_token_request(challenge, keypair.second).value();

    PublicIssuer issuer(std::move(keypair.first));
    auto response = issuer.issue(request_result.request).value();

    auto pub_key = issuer.public_key().value();

    for (auto _ : state) {
        // Need to recreate finalization data each iteration
        auto new_request = client.create_token_request(challenge, pub_key).value();
        auto new_response = issuer.issue(new_request.request).value();
        auto token = client.finalize(new_response, std::move(new_request.finalization_data), pub_key);
        benchmark::DoNotOptimize(token);
    }
}
BENCHMARK(BM_FinalizeToken_BlindRSA);

// Token verification benchmarks
static void BM_VerifyToken_BlindRSA(benchmark::State& state) {
    // Setup
    auto keypair = crypto::BlindRsaPrivateKey::generate().value();
    auto spki = keypair.second.to_spki().value();

    OriginConfig origin_config{
        .issuer_name = "issuer.example.com",
        .origin_names = {"origin.example.com"},
        .require_redemption_context = true,
    };

    auto origin_key = crypto::BlindRsaPublicKey::from_spki(
        ByteView(spki.data(), spki.size())).value();

    std::vector<crypto::BlindRsaPublicKey> origin_keys;
    origin_keys.push_back(std::move(origin_key));

    PublicOrigin origin(origin_config, std::move(origin_keys));

    auto challenge = origin.create_challenge().value();

    PublicClient client;
    auto client_key = crypto::BlindRsaPublicKey::from_spki(
        ByteView(spki.data(), spki.size())).value();
    auto request_result = client.create_token_request(challenge, client_key).value();

    PublicIssuer issuer(std::move(keypair.first));
    auto response = issuer.issue(request_result.request).value();

    auto finalize_key = crypto::BlindRsaPublicKey::from_spki(
        ByteView(spki.data(), spki.size())).value();
    auto token = client.finalize(response, std::move(request_result.finalization_data), finalize_key).value();

    for (auto _ : state) {
        auto valid = origin.verify(token, challenge);
        benchmark::DoNotOptimize(valid);
    }
}
BENCHMARK(BM_VerifyToken_BlindRSA);

// Full protocol benchmarks
static void BM_FullProtocol_BlindRSA(benchmark::State& state) {
    // Pre-setup
    auto keypair = crypto::BlindRsaPrivateKey::generate().value();
    auto spki = keypair.second.to_spki().value();

    OriginConfig origin_config{
        .issuer_name = "issuer.example.com",
        .origin_names = {"origin.example.com"},
    };

    for (auto _ : state) {
        // Create origin
        auto origin_key = crypto::BlindRsaPublicKey::from_spki(
            ByteView(spki.data(), spki.size())).value();
        std::vector<crypto::BlindRsaPublicKey> origin_keys;
        origin_keys.push_back(std::move(origin_key));
        PublicOrigin origin(origin_config, std::move(origin_keys));

        // Step 1: Origin creates challenge
        auto challenge = origin.create_challenge().value();

        // Step 2: Client creates request
        PublicClient client;
        auto client_key = crypto::BlindRsaPublicKey::from_spki(
            ByteView(spki.data(), spki.size())).value();
        auto request_result = client.create_token_request(challenge, client_key).value();

        // Step 3: Issuer signs
        auto priv_copy = crypto::BlindRsaPrivateKey::from_pkcs8(
            keypair.first.to_pkcs8().value().view()).value();
        PublicIssuer issuer(std::move(priv_copy));
        auto response = issuer.issue(request_result.request).value();

        // Step 4: Client finalizes
        auto finalize_key = crypto::BlindRsaPublicKey::from_spki(
            ByteView(spki.data(), spki.size())).value();
        auto token = client.finalize(response, std::move(request_result.finalization_data), finalize_key).value();

        // Step 5: Origin verifies
        auto valid = origin.verify(token, challenge);

        benchmark::DoNotOptimize(valid);
    }
}
BENCHMARK(BM_FullProtocol_BlindRSA);

// Batch issuance benchmarks
static void BM_BatchIssuance_5Tokens(benchmark::State& state) {
    auto issuer = PublicIssuer::generate().value();

    BatchedTokenRequest batch;
    for (int i = 0; i < 5; ++i) {
        Bytes blinded(256, static_cast<uint8_t>(i));
        batch.requests.push_back(TokenRequest::create(
            TokenType::BLIND_RSA,
            issuer.truncated_key_id(),
            std::move(blinded)));
    }

    for (auto _ : state) {
        auto response = issuer.issue_batch(batch);
        benchmark::DoNotOptimize(response);
    }
}
BENCHMARK(BM_BatchIssuance_5Tokens);

static void BM_BatchIssuance_20Tokens(benchmark::State& state) {
    auto issuer = PublicIssuer::generate().value();

    BatchedTokenRequest batch;
    for (int i = 0; i < 20; ++i) {
        Bytes blinded(256, static_cast<uint8_t>(i));
        batch.requests.push_back(TokenRequest::create(
            TokenType::BLIND_RSA,
            issuer.truncated_key_id(),
            std::move(blinded)));
    }

    for (auto _ : state) {
        auto response = issuer.issue_batch(batch);
        benchmark::DoNotOptimize(response);
    }
}
BENCHMARK(BM_BatchIssuance_20Tokens);
