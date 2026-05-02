// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/client.hpp>
#include <privacy_pass/core/token.hpp>
#include <privacy_pass/core/token_challenge.hpp>
#include <privacy_pass/core/token_request.hpp>
#include <privacy_pass/core/token_response.hpp>
#include <privacy_pass/core/types.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <optional>

namespace privacy_pass {

// Result of creating a token request
struct TokenRequestContext {
    TokenRequest request;
    FinalizationData finalization_data;
    ChallengeDigest challenge_digest;
};

// Configuration for token provider
struct TokenProviderConfig {
    size_t max_cached_tokens{100};
    std::chrono::seconds token_prefetch_threshold{60};
    bool allow_token_reuse{false};  // For testing only
};

// Callback for async token fetching
using TokenFetchCallback = std::function<void(Result<std::vector<Token>>)>;

// TokenProvider - entity that obtains and presents tokens
//
// This abstraction handles:
// - Processing challenges from authenticators
// - Creating blinded token requests
// - Finalizing tokens from issuer responses
// - Caching tokens for reuse (when appropriate)
// - Selecting appropriate tokens for specific challenges
//
// Usage:
//   TokenProvider provider(config);
//   provider.add_issuer_key(issuer_name, public_key);
//
//   // When receiving a challenge:
//   auto ctx = provider.prepare_request(challenge);
//   // Send ctx.request to issuer, receive response
//   auto token = provider.finalize(response, std::move(ctx));
//
//   // Or if tokens are pre-cached:
//   auto token = provider.get_token(challenge);
class TokenProvider {
public:
    explicit TokenProvider(TokenProviderConfig config = {});
    ~TokenProvider();

    TokenProvider(const TokenProvider&) = delete;
    TokenProvider& operator=(const TokenProvider&) = delete;
    TokenProvider(TokenProvider&&) noexcept;
    TokenProvider& operator=(TokenProvider&&) noexcept;

    // Add a trusted issuer's public key
    void add_issuer_key(std::string_view issuer_name, PublicKey key);

    // Remove an issuer
    void remove_issuer(std::string_view issuer_name);

    // Check if we have a key for an issuer
    [[nodiscard]] bool has_issuer(std::string_view issuer_name) const;

    // Get issuer public key
    [[nodiscard]] std::optional<PublicKey> get_issuer_key(
        std::string_view issuer_name,
        TokenType type) const;

    // Prepare a token request for a challenge
    // Returns the request to send to the issuer and context for finalization
    [[nodiscard]] Result<TokenRequestContext> prepare_request(
        const TokenChallenge& challenge) const;

    // Prepare multiple token requests (batch)
    [[nodiscard]] Result<std::vector<TokenRequestContext>> prepare_batch_request(
        const TokenChallenge& challenge,
        size_t count) const;

    // Finalize a token from issuer response
    [[nodiscard]] Result<Token> finalize(
        const TokenResponse& response,
        TokenRequestContext context) const;

    // Finalize multiple tokens from batch response
    [[nodiscard]] Result<std::vector<Token>> finalize_batch(
        const std::vector<TokenResponse>& responses,
        std::vector<TokenRequestContext> contexts) const;

    // Store pre-obtained tokens for later use
    void store_tokens(
        const ChallengeDigest& challenge_digest,
        std::vector<Token> tokens);

    // Get a token for a challenge (from cache or creates new request context)
    // Returns nullopt if no cached token and caller needs to fetch
    [[nodiscard]] std::optional<Token> get_cached_token(
        const ChallengeDigest& challenge_digest);

    // Check how many tokens are cached for a challenge
    [[nodiscard]] size_t cached_token_count(
        const ChallengeDigest& challenge_digest) const;

    // Clear cached tokens
    void clear_cache();

    // Get configuration
    [[nodiscard]] const TokenProviderConfig& config() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace privacy_pass
