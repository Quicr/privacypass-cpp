// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/core/token_authenticator.hpp>

#include <spdlog/spdlog.h>
#include <deque>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace privacy_pass {

// Default maximum replay cache size to prevent memory exhaustion
constexpr size_t DEFAULT_MAX_AUTHENTICATOR_CACHE_SIZE = 100000;

ValidationResult ValidationResult::success(ChallengeDigest digest) {
    return ValidationResult{
        .valid = true,
        .error_code = std::nullopt,
        .error_message = std::nullopt,
        .challenge_digest = std::move(digest),
    };
}

ValidationResult ValidationResult::failure(ErrorCode code, std::string message) {
    return ValidationResult{
        .valid = false,
        .error_code = code,
        .error_message = message.empty() ? std::nullopt : std::optional(std::move(message)),
        .challenge_digest = std::nullopt,
    };
}

namespace {

struct NonceHash {
    size_t operator()(const Nonce& nonce) const {
        // Fast hash: reinterpret first sizeof(size_t) bytes of the 32-byte nonce
        size_t hash = 0;
        std::memcpy(&hash, nonce.data(), sizeof(size_t));
        return hash;
    }
};

// Transparent hash/equal for heterogeneous string_view lookup
struct StringHash {
    using is_transparent = void;
    size_t operator()(std::string_view sv) const { return std::hash<std::string_view>{}(sv); }
    size_t operator()(const std::string& s) const { return std::hash<std::string_view>{}(s); }
};
struct StringEqual {
    using is_transparent = void;
    bool operator()(std::string_view a, std::string_view b) const { return a == b; }
};

}  // namespace

struct TokenAuthenticator::Impl {
    TokenAuthenticatorConfig config;
    Origin origin;
    std::unordered_map<std::string, std::vector<crypto::BlindRsaPublicKey>, StringHash, StringEqual> rsa_keys;
    std::unordered_map<std::string, std::vector<crypto::VoprfPublicKey>, StringHash, StringEqual> voprf_keys;

    struct NonceEntry {
        Nonce nonce;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::unordered_set<Nonce, NonceHash> redeemed_nonces;
    std::deque<NonceEntry> nonce_entries;
    mutable std::mutex mutex;

    explicit Impl(TokenAuthenticatorConfig cfg)
        : config(std::move(cfg))
        , origin(OriginConfig{
            .issuer_name = config.issuer_name,
            .origin_names = config.origin_names,
            .redemption_window = config.redemption_window,
            .require_redemption_context = config.require_redemption_context,
        }) {}

    bool check_and_add_nonce(const Nonce& nonce) {
        auto now = std::chrono::steady_clock::now();
        auto cutoff = now - config.replay_window;

        // Prune expired from front — O(k) where k = expired entries, amortized O(1)
        while (!nonce_entries.empty() && nonce_entries.front().timestamp < cutoff) {
            redeemed_nonces.erase(nonce_entries.front().nonce);
            nonce_entries.pop_front();
        }

        // Enforce maximum size by removing oldest entries if at capacity
        size_t max_size = config.max_replay_cache_size > 0 ? config.max_replay_cache_size : DEFAULT_MAX_AUTHENTICATOR_CACHE_SIZE;
        while (redeemed_nonces.size() >= max_size && !nonce_entries.empty()) {
            redeemed_nonces.erase(nonce_entries.front().nonce);
            nonce_entries.pop_front();
        }

        // Single hash lookup: insert returns whether element was new
        auto [it, inserted] = redeemed_nonces.insert(nonce);
        if (!inserted) {
            return false;
        }

        nonce_entries.push_back({nonce, now});
        return true;
    }
};

TokenAuthenticator::TokenAuthenticator(TokenAuthenticatorConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

TokenAuthenticator::~TokenAuthenticator() = default;
TokenAuthenticator::TokenAuthenticator(TokenAuthenticator&&) noexcept = default;
TokenAuthenticator& TokenAuthenticator::operator=(TokenAuthenticator&&) noexcept = default;

void TokenAuthenticator::add_trusted_key(
    std::string_view issuer_name,
    crypto::BlindRsaPublicKey key) {

    std::lock_guard<std::mutex> lock(impl_->mutex);

    // Add to origin for verification
    auto spki = key.to_spki();
    if (spki) {
        auto key_copy = crypto::BlindRsaPublicKey::from_spki(
            ByteView(spki->data(), spki->size()));
        if (key_copy) {
            impl_->origin.add_blind_rsa_key(std::move(*key_copy));
        }
    }

    auto it = impl_->rsa_keys.find(issuer_name);
    if (it != impl_->rsa_keys.end()) {
        it->second.push_back(std::move(key));
    } else {
        impl_->rsa_keys[std::string(issuer_name)].push_back(std::move(key));
    }
}

void TokenAuthenticator::add_trusted_key(
    std::string_view issuer_name,
    crypto::VoprfPublicKey key) {

    std::lock_guard<std::mutex> lock(impl_->mutex);

    auto bytes = key.to_bytes();
    if (bytes) {
        auto key_copy = crypto::VoprfPublicKey::from_bytes(
            ByteView(bytes->data(), bytes->size()));
        if (key_copy) {
            impl_->origin.add_voprf_key(std::move(*key_copy));
        }
    }

    auto it = impl_->voprf_keys.find(issuer_name);
    if (it != impl_->voprf_keys.end()) {
        it->second.push_back(std::move(key));
    } else {
        impl_->voprf_keys[std::string(issuer_name)].push_back(std::move(key));
    }
}

void TokenAuthenticator::remove_trusted_issuer(std::string_view issuer_name) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto rsa_it = impl_->rsa_keys.find(issuer_name);
    if (rsa_it != impl_->rsa_keys.end()) impl_->rsa_keys.erase(rsa_it);
    auto voprf_it = impl_->voprf_keys.find(issuer_name);
    if (voprf_it != impl_->voprf_keys.end()) impl_->voprf_keys.erase(voprf_it);
}

bool TokenAuthenticator::is_trusted(std::string_view issuer_name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->rsa_keys.find(issuer_name) != impl_->rsa_keys.end() ||
           impl_->voprf_keys.find(issuer_name) != impl_->voprf_keys.end();
}

Result<TokenChallenge> TokenAuthenticator::create_challenge(
    TokenType type,
    std::optional<ChallengeDigest> redemption_context,
    std::vector<std::string> additional_origin_info) const {

    std::lock_guard<std::mutex> lock(impl_->mutex);

    std::vector<std::string> origin_info = std::move(additional_origin_info);
    for (const auto& name : impl_->config.origin_names) {
        origin_info.push_back(name);
    }

    return TokenChallenge::create(
        type,
        impl_->config.issuer_name,
        redemption_context,
        origin_info);
}

ValidationResult TokenAuthenticator::validate(
    const Token& token,
    const TokenChallenge& expected_challenge) const {

    std::lock_guard<std::mutex> lock(impl_->mutex);

    // Validate token structure
    auto valid = token.validate();
    if (!valid) {
        return ValidationResult::failure(valid.error().code, valid.error().message);
    }

    // Verify challenge digest
    auto expected_digest = expected_challenge.digest();
    if (!expected_digest) {
        return ValidationResult::failure(
            ErrorCode::CRYPTO_ERROR,
            "Failed to compute challenge digest");
    }

    if (!constant_time_equal(
            ByteView(token.challenge_digest.data(), token.challenge_digest.size()),
            ByteView(expected_digest->data(), expected_digest->size()))) {
        return ValidationResult::failure(
            ErrorCode::INVALID_CHALLENGE,
            "Challenge digest mismatch");
    }

    // Verify signature
    auto verify_result = impl_->origin.verify(token, expected_challenge);
    if (!verify_result) {
        return ValidationResult::failure(
            verify_result.error().code,
            verify_result.error().message);
    }

    if (!*verify_result) {
        return ValidationResult::failure(
            ErrorCode::TOKEN_INVALID,
            "Signature verification failed");
    }

    return ValidationResult::success(*expected_digest);
}

ValidationResult TokenAuthenticator::validate_and_redeem(
    const Token& token,
    const TokenChallenge& expected_challenge) {

    std::lock_guard<std::mutex> lock(impl_->mutex);

    // Check if this would be a replay (without adding to cache yet)
    if (impl_->redeemed_nonces.find(token.nonce) != impl_->redeemed_nonces.end()) {
        return ValidationResult::failure(
            ErrorCode::TOKEN_REPLAYED,
            "Token has already been redeemed");
    }

    // Validate token structure
    auto valid = token.validate();
    if (!valid) {
        return ValidationResult::failure(valid.error().code, valid.error().message);
    }

    // Verify challenge digest
    auto expected_digest = expected_challenge.digest();
    if (!expected_digest) {
        return ValidationResult::failure(
            ErrorCode::CRYPTO_ERROR,
            "Failed to compute challenge digest");
    }

    if (!constant_time_equal(
            ByteView(token.challenge_digest.data(), token.challenge_digest.size()),
            ByteView(expected_digest->data(), expected_digest->size()))) {
        return ValidationResult::failure(
            ErrorCode::INVALID_CHALLENGE,
            "Challenge digest mismatch");
    }

    // Verify signature
    auto verify_result = impl_->origin.verify(token, expected_challenge);
    if (!verify_result) {
        return ValidationResult::failure(
            verify_result.error().code,
            verify_result.error().message);
    }

    if (!*verify_result) {
        return ValidationResult::failure(
            ErrorCode::TOKEN_INVALID,
            "Signature verification failed");
    }

    // Only add to replay cache after successful verification
    if (!impl_->check_and_add_nonce(token.nonce)) {
        // Race condition: another thread redeemed the same token
        return ValidationResult::failure(
            ErrorCode::TOKEN_REPLAYED,
            "Token has already been redeemed");
    }

    return ValidationResult::success(*expected_digest);
}

bool TokenAuthenticator::would_be_replay(const Token& token) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->redeemed_nonces.find(token.nonce) != impl_->redeemed_nonces.end();
}

void TokenAuthenticator::mark_redeemed(const Token& token) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->check_and_add_nonce(token.nonce);
}

size_t TokenAuthenticator::redemption_cache_size() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->redeemed_nonces.size();
}

void TokenAuthenticator::prune_redemption_cache() {
    std::lock_guard<std::mutex> lock(impl_->mutex);

    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - impl_->config.replay_window;

    while (!impl_->nonce_entries.empty() && impl_->nonce_entries.front().timestamp < cutoff) {
        impl_->redeemed_nonces.erase(impl_->nonce_entries.front().nonce);
        impl_->nonce_entries.pop_front();
    }
}

const TokenAuthenticatorConfig& TokenAuthenticator::config() const {
    return impl_->config;
}

}  // namespace privacy_pass
