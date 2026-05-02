// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/moq/client.hpp>

#include <spdlog/spdlog.h>

namespace privacy_pass::moq {

struct MoqClient::Impl {
    Client base_client;
};

MoqClient::MoqClient() : impl_(std::make_unique<Impl>()) {}
MoqClient::~MoqClient() = default;
MoqClient::MoqClient(MoqClient&&) noexcept = default;
MoqClient& MoqClient::operator=(MoqClient&&) noexcept = default;

Result<AuthorizationInfo> MoqClient::parse_authorization_info(
    const TokenChallenge& challenge) const {

    if (challenge.origin_info.empty()) {
        return std::unexpected(Error{ErrorCode::MALFORMED_DATA,
            "No origin_info in challenge"});
    }

    // MOQ embeds authorization info in the first origin_info entry
    return AuthorizationInfo::decode_from_origin_info(challenge.origin_info[0]);
}

Result<MoqTokenRequestResult> MoqClient::create_token_request(
    const TokenChallenge& challenge,
    const PublicKey& issuer_key) const {

    // Parse authorization info from challenge
    auto auth_info = parse_authorization_info(challenge);
    if (!auth_info) {
        return std::unexpected(auth_info.error());
    }

    // Create base token request
    auto base_result = impl_->base_client.create_token_request(challenge, issuer_key);
    if (!base_result) {
        return std::unexpected(base_result.error());
    }

    return MoqTokenRequestResult{
        .request = std::move(base_result->request),
        .finalization_data = std::move(base_result->finalization_data),
        .authorization_info = std::move(*auth_info),
    };
}

Result<std::vector<MoqTokenRequestResult>> MoqClient::create_batch_requests(
    const std::vector<TokenChallenge>& challenges,
    const PublicKey& issuer_key) const {

    std::vector<MoqTokenRequestResult> results;
    results.reserve(challenges.size());

    for (const auto& challenge : challenges) {
        auto result = create_token_request(challenge, issuer_key);
        if (!result) {
            return std::unexpected(result.error());
        }
        results.push_back(std::move(*result));
    }

    return results;
}

Result<Token> MoqClient::finalize(
    const TokenResponse& response,
    FinalizationData finalization_data,
    const PublicKey& issuer_key) const {

    return impl_->base_client.finalize(response, std::move(finalization_data), issuer_key);
}

Result<bool> MoqClient::token_authorizes(
    const Token& token,
    const TokenChallenge& original_challenge,
    Action action,
    const Namespace& ns,
    const TrackName& track) const {

    // Verify challenge digest matches
    auto expected_digest = original_challenge.digest();
    if (!expected_digest) {
        return std::unexpected(expected_digest.error());
    }

    if (token.challenge_digest != *expected_digest) {
        return std::unexpected(Error{ErrorCode::INVALID_CHALLENGE,
            "Token challenge digest mismatch"});
    }

    // Parse authorization info from challenge
    auto auth_info = parse_authorization_info(original_challenge);
    if (!auth_info) {
        return std::unexpected(auth_info.error());
    }

    return auth_info->authorizes(action, ns, track);
}

Client& MoqClient::base_client() {
    return impl_->base_client;
}

const Client& MoqClient::base_client() const {
    return impl_->base_client;
}

}  // namespace privacy_pass::moq
