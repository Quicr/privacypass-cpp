// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/core/token_provider.hpp>
#include <privacy_pass/crypto/blind_rsa.hpp>
#include <privacy_pass/crypto/voprf.hpp>

#include <spdlog/spdlog.h>
#include <mutex>
#include <unordered_map>

namespace privacy_pass {

namespace {

struct DigestHash {
    size_t operator()(const ChallengeDigest& digest) const {
        size_t hash = 0;
        for (size_t i = 0; i < digest.size(); i += sizeof(size_t)) {
            size_t chunk = 0;
            std::memcpy(&chunk, digest.data() + i, std::min(sizeof(size_t), digest.size() - i));
            hash ^= chunk + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        }
        return hash;
    }
};

}  // namespace

struct TokenProvider::Impl {
    TokenProviderConfig config;
    std::unordered_map<std::string, std::vector<PublicKey>> issuer_keys;
    std::unordered_map<ChallengeDigest, std::vector<Token>, DigestHash> token_cache;
    mutable std::mutex mutex;

    explicit Impl(TokenProviderConfig cfg) : config(std::move(cfg)) {}

    std::optional<PublicKey> find_key(std::string_view issuer, TokenType type) const {
        auto it = issuer_keys.find(std::string(issuer));
        if (it == issuer_keys.end()) {
            return std::nullopt;
        }
        for (const auto& key : it->second) {
            if (key.type == type) {
                return key;
            }
        }
        return std::nullopt;
    }
};

TokenProvider::TokenProvider(TokenProviderConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

TokenProvider::~TokenProvider() = default;
TokenProvider::TokenProvider(TokenProvider&&) noexcept = default;
TokenProvider& TokenProvider::operator=(TokenProvider&&) noexcept = default;

void TokenProvider::add_issuer_key(std::string_view issuer_name, PublicKey key) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->issuer_keys[std::string(issuer_name)].push_back(std::move(key));
}

void TokenProvider::remove_issuer(std::string_view issuer_name) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->issuer_keys.erase(std::string(issuer_name));
}

bool TokenProvider::has_issuer(std::string_view issuer_name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->issuer_keys.count(std::string(issuer_name)) > 0;
}

std::optional<PublicKey> TokenProvider::get_issuer_key(
    std::string_view issuer_name,
    TokenType type) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->find_key(issuer_name, type);
}

Result<TokenRequestContext> TokenProvider::prepare_request(
    const TokenChallenge& challenge) const {

    std::lock_guard<std::mutex> lock(impl_->mutex);

    auto key = impl_->find_key(challenge.issuer_name, challenge.token_type);
    if (!key) {
        return std::unexpected(Error{ErrorCode::ISSUER_UNKNOWN,
            "No key found for issuer: " + challenge.issuer_name});
    }

    auto challenge_digest = challenge.digest();
    if (!challenge_digest) {
        return std::unexpected(challenge_digest.error());
    }

    if (challenge.token_type == TokenType::BLIND_RSA ||
        challenge.token_type == TokenType::PARTIALLY_BLIND_RSA) {
        auto rsa_key = crypto::BlindRsaPublicKey::from_spki(
            ByteView(key->data.data(), key->data.size()));
        if (!rsa_key) {
            return std::unexpected(rsa_key.error());
        }

        PublicClient client;
        auto result = client.create_token_request(challenge, *rsa_key);
        if (!result) {
            return std::unexpected(result.error());
        }

        return TokenRequestContext{
            .request = std::move(result->request),
            .finalization_data = std::move(result->finalization_data),
            .challenge_digest = *challenge_digest,
        };
    } else if (challenge.token_type == TokenType::VOPRF_P384_SHA384) {
        auto voprf_key = crypto::VoprfPublicKey::from_bytes(
            ByteView(key->data.data(), key->data.size()));
        if (!voprf_key) {
            return std::unexpected(voprf_key.error());
        }

        PrivateClient client;
        auto result = client.create_token_request(challenge, *voprf_key);
        if (!result) {
            return std::unexpected(result.error());
        }

        return TokenRequestContext{
            .request = std::move(result->request),
            .finalization_data = std::move(result->finalization_data),
            .challenge_digest = *challenge_digest,
        };
    }

    return std::unexpected(Error{ErrorCode::UNSUPPORTED_TOKEN_TYPE,
        "Unsupported token type"});
}

Result<std::vector<TokenRequestContext>> TokenProvider::prepare_batch_request(
    const TokenChallenge& challenge,
    size_t count) const {

    std::vector<TokenRequestContext> contexts;
    contexts.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        auto ctx = prepare_request(challenge);
        if (!ctx) {
            return std::unexpected(ctx.error());
        }
        contexts.push_back(std::move(*ctx));
    }

    return contexts;
}

Result<Token> TokenProvider::finalize(
    const TokenResponse& response,
    TokenRequestContext context) const {

    std::lock_guard<std::mutex> lock(impl_->mutex);

    if (response.token_type == TokenType::BLIND_RSA ||
        response.token_type == TokenType::PARTIALLY_BLIND_RSA) {

        // Find the key used for this request
        for (const auto& [issuer, keys] : impl_->issuer_keys) {
            for (const auto& key : keys) {
                if (key.type == response.token_type) {
                    auto rsa_key = crypto::BlindRsaPublicKey::from_spki(
                        ByteView(key.data.data(), key.data.size()));
                    if (!rsa_key) {
                        continue;
                    }

                    PublicClient client;
                    return client.finalize(response, std::move(context.finalization_data), *rsa_key);
                }
            }
        }
    } else if (response.token_type == TokenType::VOPRF_P384_SHA384) {
        for (const auto& [issuer, keys] : impl_->issuer_keys) {
            for (const auto& key : keys) {
                if (key.type == response.token_type) {
                    auto voprf_key = crypto::VoprfPublicKey::from_bytes(
                        ByteView(key.data.data(), key.data.size()));
                    if (!voprf_key) {
                        continue;
                    }

                    PrivateClient client;
                    return client.finalize(response, std::move(context.finalization_data), *voprf_key);
                }
            }
        }
    }

    return std::unexpected(Error{ErrorCode::ISSUER_UNKNOWN,
        "No matching key found for finalization"});
}

Result<std::vector<Token>> TokenProvider::finalize_batch(
    const std::vector<TokenResponse>& responses,
    std::vector<TokenRequestContext> contexts) const {

    if (responses.size() != contexts.size()) {
        return std::unexpected(Error{ErrorCode::MALFORMED_DATA,
            "Response and context count mismatch"});
    }

    std::vector<Token> tokens;
    tokens.reserve(responses.size());

    for (size_t i = 0; i < responses.size(); ++i) {
        auto token = finalize(responses[i], std::move(contexts[i]));
        if (!token) {
            return std::unexpected(token.error());
        }
        tokens.push_back(std::move(*token));
    }

    return tokens;
}

void TokenProvider::store_tokens(
    const ChallengeDigest& challenge_digest,
    std::vector<Token> tokens) {

    std::lock_guard<std::mutex> lock(impl_->mutex);

    auto& cache = impl_->token_cache[challenge_digest];
    for (auto& token : tokens) {
        if (cache.size() < impl_->config.max_cached_tokens) {
            cache.push_back(std::move(token));
        }
    }
}

std::optional<Token> TokenProvider::get_cached_token(
    const ChallengeDigest& challenge_digest) {

    std::lock_guard<std::mutex> lock(impl_->mutex);

    auto it = impl_->token_cache.find(challenge_digest);
    if (it == impl_->token_cache.end() || it->second.empty()) {
        return std::nullopt;
    }

    Token token = std::move(it->second.back());
    it->second.pop_back();

    if (it->second.empty()) {
        impl_->token_cache.erase(it);
    }

    return token;
}

size_t TokenProvider::cached_token_count(
    const ChallengeDigest& challenge_digest) const {

    std::lock_guard<std::mutex> lock(impl_->mutex);

    auto it = impl_->token_cache.find(challenge_digest);
    if (it == impl_->token_cache.end()) {
        return 0;
    }
    return it->second.size();
}

void TokenProvider::clear_cache() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->token_cache.clear();
}

const TokenProviderConfig& TokenProvider::config() const {
    return impl_->config;
}

}  // namespace privacy_pass
