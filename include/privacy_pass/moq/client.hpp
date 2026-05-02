// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/client.hpp>
#include <privacy_pass/core/token.hpp>
#include <privacy_pass/core/token_challenge.hpp>
#include <privacy_pass/moq/authorization_info.hpp>

#include <memory>

namespace privacy_pass::moq {

// MOQ-specific token request with authorization info
struct MoqTokenRequestResult {
    TokenRequest request;
    FinalizationData finalization_data;
    AuthorizationInfo authorization_info;
};

// MoQ Privacy Pass Client
// Wraps the base Privacy Pass client with MOQ-specific functionality
class MoqClient {
public:
    MoqClient();
    ~MoqClient();

    MoqClient(const MoqClient&) = delete;
    MoqClient& operator=(const MoqClient&) = delete;
    MoqClient(MoqClient&&) noexcept;
    MoqClient& operator=(MoqClient&&) noexcept;

    // Parse a token challenge and extract MOQ authorization info
    [[nodiscard]] Result<AuthorizationInfo> parse_authorization_info(
        const TokenChallenge& challenge) const;

    // Create a token request for a MOQ operation
    [[nodiscard]] Result<MoqTokenRequestResult> create_token_request(
        const TokenChallenge& challenge,
        const PublicKey& issuer_key) const;

    // Create a batch of token requests for multiple scopes
    [[nodiscard]] Result<std::vector<MoqTokenRequestResult>> create_batch_requests(
        const std::vector<TokenChallenge>& challenges,
        const PublicKey& issuer_key) const;

    // Finalize a token
    [[nodiscard]] Result<Token> finalize(
        const TokenResponse& response,
        FinalizationData finalization_data,
        const PublicKey& issuer_key) const;

    // Check if a token authorizes a specific action
    [[nodiscard]] Result<bool> token_authorizes(
        const Token& token,
        const TokenChallenge& original_challenge,
        Action action,
        const Namespace& ns,
        const TrackName& track) const;

    // Get the underlying base client
    [[nodiscard]] Client& base_client();
    [[nodiscard]] const Client& base_client() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace privacy_pass::moq
