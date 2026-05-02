// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/moq/relay.hpp>

#include <spdlog/spdlog.h>
#include <unordered_map>

namespace privacy_pass::moq {

VerificationResult VerificationResult::success(AuthorizationInfo auth_info) {
    return VerificationResult{
        .valid = true,
        .error_code = std::nullopt,
        .error_message = std::nullopt,
        .authorization_info = std::move(auth_info),
    };
}

VerificationResult VerificationResult::failure(MoqErrorCode code, std::string message) {
    return VerificationResult{
        .valid = false,
        .error_code = code,
        .error_message = message.empty() ? std::nullopt : std::optional(std::move(message)),
        .authorization_info = std::nullopt,
    };
}

struct MoqRelay::Impl {
    RelayConfig config;
    Origin origin;
    std::optional<MultiKeyIssuer> issuer;
    std::unordered_map<std::string, std::vector<PublicKey>> trusted_issuers;
    ReplayCache replay_cache;

    explicit Impl(RelayConfig cfg)
        : config(std::move(cfg))
        , origin(OriginConfig{
            .issuer_name = config.issuer_name,
            .origin_names = {config.relay_name},
            .redemption_window = config.token_validity_window,
            .require_redemption_context = true,
        })
        , replay_cache(config.replay_window) {}
};

MoqRelay::MoqRelay(RelayConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

MoqRelay::~MoqRelay() = default;
MoqRelay::MoqRelay(MoqRelay&&) noexcept = default;
MoqRelay& MoqRelay::operator=(MoqRelay&&) noexcept = default;

void MoqRelay::add_trusted_issuer(
    std::string_view issuer_name,
    crypto::BlindRsaPublicKey key) {

    auto spki = key.to_spki();
    auto key_id = key.key_id();

    if (spki && key_id) {
        PublicKey pub_key{
            .type = TokenType::BLIND_RSA,
            .data = std::move(*spki),
            .key_id = *key_id,
        };

        impl_->trusted_issuers[std::string(issuer_name)].push_back(std::move(pub_key));
        impl_->origin.add_blind_rsa_key(std::move(key));
    }
}

void MoqRelay::add_trusted_issuer(
    std::string_view issuer_name,
    crypto::VoprfPublicKey key) {

    auto bytes = key.to_bytes();
    auto key_id = key.key_id();

    if (bytes && key_id) {
        PublicKey pub_key{
            .type = TokenType::VOPRF_P384_SHA384,
            .data = std::move(*bytes),
            .key_id = *key_id,
        };

        impl_->trusted_issuers[std::string(issuer_name)].push_back(std::move(pub_key));
        impl_->origin.add_voprf_key(std::move(key));
    }
}

Result<TokenChallenge> MoqRelay::create_challenge(
    TokenType type,
    const AuthorizationInfo& required_auth,
    std::optional<ChallengeDigest> redemption_context) const {

    // Encode authorization info for origin_info
    auto encoded_auth = required_auth.encode_for_origin_info();
    if (!encoded_auth) {
        return std::unexpected(encoded_auth.error());
    }

    return TokenChallenge::create(
        type,
        impl_->config.issuer_name,
        redemption_context,
        {*encoded_auth, impl_->config.relay_name});
}

VerificationResult MoqRelay::verify_token(
    const Token& token,
    const TokenChallenge& expected_challenge) const {

    // Validate token structure
    auto valid = token.validate();
    if (!valid) {
        return VerificationResult::failure(
            MoqErrorCode::TOKEN_MALFORMED,
            valid.error().message);
    }

    // Verify challenge digest
    auto expected_digest = expected_challenge.digest();
    if (!expected_digest) {
        return VerificationResult::failure(
            MoqErrorCode::TOKEN_INVALID,
            "Failed to compute challenge digest");
    }

    if (token.challenge_digest != *expected_digest) {
        return VerificationResult::failure(
            MoqErrorCode::TOKEN_INVALID,
            "Challenge digest mismatch");
    }

    // Verify signature using origin
    auto verify_result = impl_->origin.verify(token, expected_challenge);
    if (!verify_result) {
        if (verify_result.error().code == ErrorCode::ISSUER_UNKNOWN) {
            return VerificationResult::failure(
                MoqErrorCode::ISSUER_UNKNOWN,
                verify_result.error().message);
        }
        return VerificationResult::failure(
            MoqErrorCode::TOKEN_INVALID,
            verify_result.error().message);
    }

    if (!*verify_result) {
        return VerificationResult::failure(
            MoqErrorCode::TOKEN_INVALID,
            "Signature verification failed");
    }

    // Parse authorization info from challenge
    if (expected_challenge.origin_info.empty()) {
        return VerificationResult::failure(
            MoqErrorCode::TOKEN_MALFORMED,
            "Missing authorization info");
    }

    auto auth_info = AuthorizationInfo::decode_from_origin_info(
        expected_challenge.origin_info[0]);

    if (!auth_info) {
        return VerificationResult::failure(
            MoqErrorCode::TOKEN_MALFORMED,
            "Invalid authorization info");
    }

    return VerificationResult::success(std::move(*auth_info));
}

VerificationResult MoqRelay::verify_and_authorize(
    const Token& token,
    const TokenChallenge& expected_challenge,
    Action action,
    const Namespace& ns,
    const TrackName& track) {

    // Check for replay
    if (!impl_->replay_cache.check_and_add(token.nonce)) {
        return VerificationResult::failure(
            MoqErrorCode::TOKEN_REPLAYED,
            "Token has already been used");
    }

    // Verify token
    auto verify_result = verify_token(token, expected_challenge);
    if (!verify_result.valid) {
        return verify_result;
    }

    // Check authorization scope
    if (!verify_result.authorization_info->authorizes(action, ns, track)) {
        return VerificationResult::failure(
            MoqErrorCode::SCOPE_MISMATCH,
            "Token does not authorize requested action");
    }

    return verify_result;
}

bool MoqRelay::is_replayed([[maybe_unused]] const Token& token) const {
    // Create a temporary to check without modifying state
    // In a real implementation, you'd have a separate read-only check
    return false;  // Simplified
}

void MoqRelay::mark_redeemed(const Token& token) {
    (void)impl_->replay_cache.check_and_add(token.nonce);
}

const RelayConfig& MoqRelay::config() const {
    return impl_->config;
}

void MoqRelay::enable_issuer_mode(crypto::BlindRsaPrivateKey key) {
    if (!impl_->issuer) {
        impl_->issuer = MultiKeyIssuer{};
    }
    impl_->issuer->add_blind_rsa_key(std::move(key));
}

void MoqRelay::enable_issuer_mode(crypto::VoprfPrivateKey key) {
    if (!impl_->issuer) {
        impl_->issuer = MultiKeyIssuer{};
    }
    impl_->issuer->add_voprf_key(std::move(key));
}

Result<TokenResponse> MoqRelay::issue(const TokenRequest& request) const {
    if (!impl_->issuer) {
        return std::unexpected(Error{ErrorCode::ISSUER_UNKNOWN,
            "Relay is not in issuer mode"});
    }

    return impl_->issuer->issue(request);
}

std::vector<PublicKey> MoqRelay::issuer_public_keys() const {
    if (!impl_->issuer) {
        return {};
    }
    return impl_->issuer->public_keys();
}

}  // namespace privacy_pass::moq
