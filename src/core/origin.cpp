// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/core/origin.hpp>
#include <privacy_pass/crypto/random.hpp>

#include <spdlog/spdlog.h>
#include <chrono>
#include <mutex>
#include <unordered_set>

namespace privacy_pass {

namespace {

struct NonceHash {
    size_t operator()(const Nonce& nonce) const {
        size_t hash = 0;
        for (size_t i = 0; i < nonce.size(); i += sizeof(size_t)) {
            size_t chunk = 0;
            std::memcpy(&chunk, nonce.data() + i, std::min(sizeof(size_t), nonce.size() - i));
            hash ^= chunk + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        }
        return hash;
    }
};

}  // namespace

// Default maximum replay cache size to prevent memory exhaustion
constexpr size_t DEFAULT_MAX_REPLAY_CACHE_SIZE = 100000;

// ReplayCache implementation
struct ReplayCache::Impl {
    struct NonceEntry {
        Nonce nonce;
        std::chrono::steady_clock::time_point timestamp;
    };

    std::unordered_set<Nonce, NonceHash> nonces;
    std::vector<NonceEntry> entries;
    std::chrono::seconds window;
    size_t max_size;
    mutable std::mutex mutex;

    explicit Impl(std::chrono::seconds w, size_t max = DEFAULT_MAX_REPLAY_CACHE_SIZE)
        : window(w), max_size(max) {
        entries.reserve(std::min(max_size, size_t(10000)));
    }
};

ReplayCache::ReplayCache(std::chrono::seconds window, size_t max_size)
    : impl_(std::make_unique<Impl>(window, max_size)) {}

ReplayCache::~ReplayCache() = default;
ReplayCache::ReplayCache(ReplayCache&&) noexcept = default;
ReplayCache& ReplayCache::operator=(ReplayCache&&) noexcept = default;

bool ReplayCache::check_and_add(const Nonce& nonce) {
    std::lock_guard<std::mutex> lock(impl_->mutex);

    // Prune expired entries first
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - impl_->window;

    impl_->entries.erase(
        std::remove_if(impl_->entries.begin(), impl_->entries.end(),
            [&](const Impl::NonceEntry& entry) {
                if (entry.timestamp < cutoff) {
                    impl_->nonces.erase(entry.nonce);
                    return true;
                }
                return false;
            }),
        impl_->entries.end());

    // Enforce maximum size by removing oldest entries if at capacity
    while (impl_->nonces.size() >= impl_->max_size && !impl_->entries.empty()) {
        impl_->nonces.erase(impl_->entries.front().nonce);
        impl_->entries.erase(impl_->entries.begin());
    }

    // Check if nonce exists
    if (impl_->nonces.count(nonce) > 0) {
        return false;  // Replay detected
    }

    // Add new nonce
    impl_->nonces.insert(nonce);
    impl_->entries.push_back({nonce, now});

    return true;  // Not a replay
}

bool ReplayCache::contains(const Nonce& nonce) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->nonces.count(nonce) > 0;
}

void ReplayCache::prune() {
    std::lock_guard<std::mutex> lock(impl_->mutex);

    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - impl_->window;

    impl_->entries.erase(
        std::remove_if(impl_->entries.begin(), impl_->entries.end(),
            [&](const Impl::NonceEntry& entry) {
                if (entry.timestamp < cutoff) {
                    impl_->nonces.erase(entry.nonce);
                    return true;
                }
                return false;
            }),
        impl_->entries.end());
}

size_t ReplayCache::size() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->nonces.size();
}

// PublicOrigin implementation
struct PublicOrigin::Impl {
    OriginConfig config;
    std::vector<crypto::BlindRsaPublicKey> issuer_keys;
    std::unordered_map<uint8_t, size_t> key_index_by_truncated_id;
    ReplayCache replay_cache;

    explicit Impl(OriginConfig cfg)
        : config(std::move(cfg))
        , replay_cache(config.redemption_window, config.max_replay_cache_size) {}
};

PublicOrigin::PublicOrigin(
    OriginConfig config,
    std::vector<crypto::BlindRsaPublicKey> issuer_keys)
    : impl_(std::make_unique<Impl>(std::move(config))) {

    for (auto& key : issuer_keys) {
        add_issuer_key(std::move(key));
    }
}

PublicOrigin::~PublicOrigin() = default;
PublicOrigin::PublicOrigin(PublicOrigin&&) noexcept = default;
PublicOrigin& PublicOrigin::operator=(PublicOrigin&&) noexcept = default;

Result<TokenChallenge> PublicOrigin::create_challenge(
    std::optional<ChallengeDigest> redemption_context) const {

    if (impl_->config.require_redemption_context && !redemption_context) {
        // Generate random context
        auto random = crypto::random_bytes(32);
        if (!random) {
            return std::unexpected(random.error());
        }
        ChallengeDigest context{};
        std::copy(random->begin(), random->end(), context.begin());
        redemption_context = context;
    }

    return TokenChallenge::create(
        TokenType::BLIND_RSA,
        impl_->config.issuer_name,
        redemption_context,
        impl_->config.origin_names);
}

Result<bool> PublicOrigin::verify(
    const Token& token,
    const TokenChallenge& expected_challenge) const {

    // Validate token structure
    auto valid = token.validate();
    if (!valid) {
        return std::unexpected(valid.error());
    }

    // Check token type
    if (token.token_type != TokenType::BLIND_RSA &&
        token.token_type != TokenType::PARTIALLY_BLIND_RSA) {
        return std::unexpected(Error{ErrorCode::UNSUPPORTED_TOKEN_TYPE,
            "PublicOrigin only supports Blind RSA tokens"});
    }

    // Verify challenge digest matches
    auto expected_digest = expected_challenge.digest();
    if (!expected_digest) {
        return std::unexpected(expected_digest.error());
    }

    if (token.challenge_digest != *expected_digest) {
        return std::unexpected(Error{ErrorCode::INVALID_CHALLENGE,
            "Challenge digest mismatch"});
    }

    // Find issuer key by truncated ID
    uint8_t truncated_id = token.token_key_id[31];
    auto it = impl_->key_index_by_truncated_id.find(truncated_id);
    if (it == impl_->key_index_by_truncated_id.end()) {
        return std::unexpected(Error{ErrorCode::ISSUER_UNKNOWN,
            "Unknown issuer key"});
    }

    const auto& key = impl_->issuer_keys[it->second];

    // Verify full key ID matches
    auto key_id = key.key_id();
    if (!key_id || *key_id != token.token_key_id) {
        return std::unexpected(Error{ErrorCode::ISSUER_UNKNOWN,
            "Key ID mismatch"});
    }

    // Build authenticator input
    auto auth_input = token.authenticator_input();
    auto auth_input_bytes = auth_input.serialize();
    if (!auth_input_bytes) {
        return std::unexpected(auth_input_bytes.error());
    }

    // Verify signature
    return key.verify(
        ByteView(auth_input_bytes->data(), auth_input_bytes->size()),
        ByteView(token.authenticator.data(), token.authenticator.size()));
}

Result<bool> PublicOrigin::verify_and_redeem(
    const Token& token,
    const TokenChallenge& expected_challenge) {

    // Check if this would be a replay (without adding to cache yet)
    if (impl_->replay_cache.contains(token.nonce)) {
        return std::unexpected(Error{ErrorCode::TOKEN_REPLAYED,
            "Token has already been redeemed"});
    }

    // Verify the token first
    auto verify_result = verify(token, expected_challenge);
    if (!verify_result) {
        return std::unexpected(verify_result.error());
    }

    if (!*verify_result) {
        return false;
    }

    // Only add to replay cache after successful verification
    if (!impl_->replay_cache.check_and_add(token.nonce)) {
        // Race condition: another thread redeemed the same token
        return std::unexpected(Error{ErrorCode::TOKEN_REPLAYED,
            "Token has already been redeemed"});
    }

    return true;
}

void PublicOrigin::add_issuer_key(crypto::BlindRsaPublicKey key) {
    auto key_id = key.key_id();
    if (key_id) {
        size_t index = impl_->issuer_keys.size();
        impl_->key_index_by_truncated_id[(*key_id)[31]] = index;
        impl_->issuer_keys.push_back(std::move(key));
    }
}

void PublicOrigin::remove_issuer_key(const TokenKeyId& key_id) {
    impl_->key_index_by_truncated_id.erase(key_id[31]);
    // Note: This doesn't remove from vector to keep indices stable
    // A production implementation might want to handle this differently
}

// PrivateOrigin implementation
struct PrivateOrigin::Impl {
    OriginConfig config;
    std::vector<crypto::VoprfPublicKey> issuer_keys;
    ReplayCache replay_cache;

    explicit Impl(OriginConfig cfg)
        : config(std::move(cfg))
        , replay_cache(config.redemption_window, config.max_replay_cache_size) {}
};

PrivateOrigin::PrivateOrigin(
    OriginConfig config,
    std::vector<crypto::VoprfPublicKey> issuer_keys)
    : impl_(std::make_unique<Impl>(std::move(config))) {

    impl_->issuer_keys = std::move(issuer_keys);
}

PrivateOrigin::~PrivateOrigin() = default;
PrivateOrigin::PrivateOrigin(PrivateOrigin&&) noexcept = default;
PrivateOrigin& PrivateOrigin::operator=(PrivateOrigin&&) noexcept = default;

Result<TokenChallenge> PrivateOrigin::create_challenge(
    std::optional<ChallengeDigest> redemption_context) const {

    if (impl_->config.require_redemption_context && !redemption_context) {
        auto random = crypto::random_bytes(32);
        if (!random) {
            return std::unexpected(random.error());
        }
        ChallengeDigest context{};
        std::copy(random->begin(), random->end(), context.begin());
        redemption_context = context;
    }

    return TokenChallenge::create(
        TokenType::VOPRF_P384_SHA384,
        impl_->config.issuer_name,
        redemption_context,
        impl_->config.origin_names);
}

Result<bool> PrivateOrigin::validate_structure(
    const Token& token,
    const TokenChallenge& expected_challenge) const {

    auto valid = token.validate();
    if (!valid) {
        return std::unexpected(valid.error());
    }

    if (token.token_type != TokenType::VOPRF_P384_SHA384) {
        return std::unexpected(Error{ErrorCode::UNSUPPORTED_TOKEN_TYPE,
            "PrivateOrigin only supports VOPRF tokens"});
    }

    auto expected_digest = expected_challenge.digest();
    if (!expected_digest) {
        return std::unexpected(expected_digest.error());
    }

    if (token.challenge_digest != *expected_digest) {
        return std::unexpected(Error{ErrorCode::INVALID_CHALLENGE,
            "Challenge digest mismatch"});
    }

    return true;
}

bool PrivateOrigin::would_be_replay(const Token& token) const {
    return impl_->replay_cache.contains(token.nonce);
}

void PrivateOrigin::mark_redeemed(const Token& token) {
    (void)impl_->replay_cache.check_and_add(token.nonce);
}

// Unified Origin implementation
struct Origin::Impl {
    OriginConfig config;
    std::unique_ptr<PublicOrigin> public_origin;
    std::unique_ptr<PrivateOrigin> private_origin;
    std::vector<crypto::BlindRsaPublicKey> rsa_keys;
    std::vector<crypto::VoprfPublicKey> voprf_keys;
    ReplayCache replay_cache;

    explicit Impl(OriginConfig cfg)
        : config(std::move(cfg))
        , replay_cache(config.redemption_window, config.max_replay_cache_size) {}
};

Origin::Origin(OriginConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

Origin::~Origin() = default;
Origin::Origin(Origin&&) noexcept = default;
Origin& Origin::operator=(Origin&&) noexcept = default;

void Origin::add_blind_rsa_key(crypto::BlindRsaPublicKey key) {
    impl_->rsa_keys.push_back(std::move(key));

    // Recreate public origin with updated keys
    std::vector<crypto::BlindRsaPublicKey> keys_copy;
    for (const auto& k : impl_->rsa_keys) {
        auto spki = k.to_spki();
        if (spki) {
            auto copy = crypto::BlindRsaPublicKey::from_spki(
                ByteView(spki->data(), spki->size()));
            if (copy) {
                keys_copy.push_back(std::move(*copy));
            }
        }
    }

    impl_->public_origin = std::make_unique<PublicOrigin>(
        impl_->config, std::move(keys_copy));
}

void Origin::add_voprf_key(crypto::VoprfPublicKey key) {
    impl_->voprf_keys.push_back(std::move(key));

    std::vector<crypto::VoprfPublicKey> keys_copy;
    for (const auto& k : impl_->voprf_keys) {
        auto bytes = k.to_bytes();
        if (bytes) {
            auto copy = crypto::VoprfPublicKey::from_bytes(
                ByteView(bytes->data(), bytes->size()));
            if (copy) {
                keys_copy.push_back(std::move(*copy));
            }
        }
    }

    impl_->private_origin = std::make_unique<PrivateOrigin>(
        impl_->config, std::move(keys_copy));
}

Result<TokenChallenge> Origin::create_challenge(
    TokenType type,
    std::optional<ChallengeDigest> redemption_context) const {

    if (impl_->config.require_redemption_context && !redemption_context) {
        auto random = crypto::random_bytes(32);
        if (!random) {
            return std::unexpected(random.error());
        }
        ChallengeDigest context{};
        std::copy(random->begin(), random->end(), context.begin());
        redemption_context = context;
    }

    return TokenChallenge::create(
        type,
        impl_->config.issuer_name,
        redemption_context,
        impl_->config.origin_names);
}

Result<bool> Origin::verify(
    const Token& token,
    const TokenChallenge& expected_challenge) const {

    switch (token.token_type) {
        case TokenType::BLIND_RSA:
        case TokenType::PARTIALLY_BLIND_RSA:
            if (impl_->public_origin) {
                return impl_->public_origin->verify(token, expected_challenge);
            }
            return std::unexpected(Error{ErrorCode::ISSUER_UNKNOWN,
                "No RSA keys configured"});

        case TokenType::VOPRF_P384_SHA384:
            if (impl_->private_origin) {
                return impl_->private_origin->validate_structure(token, expected_challenge);
            }
            return std::unexpected(Error{ErrorCode::ISSUER_UNKNOWN,
                "No VOPRF keys configured"});

        default:
            return std::unexpected(Error{ErrorCode::UNSUPPORTED_TOKEN_TYPE,
                "Unsupported token type"});
    }
}

Result<bool> Origin::verify_and_redeem(
    const Token& token,
    const TokenChallenge& expected_challenge) {

    // Check if this would be a replay (without adding to cache yet)
    if (impl_->replay_cache.contains(token.nonce)) {
        return std::unexpected(Error{ErrorCode::TOKEN_REPLAYED,
            "Token has already been redeemed"});
    }

    // Verify the token first
    auto verify_result = verify(token, expected_challenge);
    if (!verify_result) {
        return std::unexpected(verify_result.error());
    }

    if (!*verify_result) {
        return false;
    }

    // Only add to replay cache after successful verification
    if (!impl_->replay_cache.check_and_add(token.nonce)) {
        // Race condition: another thread redeemed the same token
        return std::unexpected(Error{ErrorCode::TOKEN_REPLAYED,
            "Token has already been redeemed"});
    }

    return true;
}

const OriginConfig& Origin::config() const {
    return impl_->config;
}

}  // namespace privacy_pass
