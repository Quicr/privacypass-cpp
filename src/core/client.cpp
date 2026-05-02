// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/core/client.hpp>
#include <privacy_pass/crypto/random.hpp>

#include <spdlog/spdlog.h>

namespace privacy_pass {

// PublicClient implementation
struct PublicClient::Impl {};

PublicClient::PublicClient() : impl_(std::make_unique<Impl>()) {}
PublicClient::~PublicClient() = default;
PublicClient::PublicClient(PublicClient&&) noexcept = default;
PublicClient& PublicClient::operator=(PublicClient&&) noexcept = default;

Result<TokenRequestResult> PublicClient::create_token_request(
    const TokenChallenge& challenge,
    const crypto::BlindRsaPublicKey& issuer_key) const {

    // Generate random nonce
    auto nonce_result = crypto::random_nonce();
    if (!nonce_result) {
        return std::unexpected(nonce_result.error());
    }

    // Compute challenge digest
    auto digest_result = challenge.digest();
    if (!digest_result) {
        return std::unexpected(digest_result.error());
    }

    // Get key ID
    auto key_id_result = issuer_key.key_id();
    if (!key_id_result) {
        return std::unexpected(key_id_result.error());
    }

    // Build authenticator input
    AuthenticatorInput auth_input{
        .token_type = challenge.token_type,
        .nonce = *nonce_result,
        .challenge_digest = *digest_result,
        .token_key_id = *key_id_result,
    };

    auto auth_input_bytes = auth_input.serialize();
    if (!auth_input_bytes) {
        return std::unexpected(auth_input_bytes.error());
    }

    // Blind the authenticator input
    auto blinding_result = issuer_key.blind(
        ByteView(auth_input_bytes->data(), auth_input_bytes->size()));
    if (!blinding_result) {
        return std::unexpected(blinding_result.error());
    }

    // Create token request
    TokenRequest request = TokenRequest::create(
        challenge.token_type,
        key_id_result->at(31),  // Truncated key ID (LSB)
        std::move(blinding_result->blinded_msg));

    // Prepare finalization data
    FinalizationData finalization;
    finalization.token_type = challenge.token_type;
    finalization.nonce = *nonce_result;
    finalization.challenge_digest = *digest_result;
    finalization.token_key_id = *key_id_result;
    finalization.data = std::move(*blinding_result);

    return TokenRequestResult{
        .request = std::move(request),
        .finalization_data = std::move(finalization),
    };
}

Result<Token> PublicClient::finalize(
    const TokenResponse& response,
    FinalizationData finalization_data,
    const crypto::BlindRsaPublicKey& issuer_key) const {

    const auto* rsa_response = response.as_blind_rsa();
    if (!rsa_response) {
        return std::unexpected(Error{ErrorCode::TOKEN_MALFORMED,
            "Expected Blind RSA response"});
    }

    auto* blinding_data = std::get_if<crypto::BlindingData>(&finalization_data.data);
    if (!blinding_data) {
        return std::unexpected(Error{ErrorCode::TOKEN_MALFORMED,
            "Invalid finalization data"});
    }

    // Build authenticator input for verification
    AuthenticatorInput auth_input{
        .token_type = finalization_data.token_type,
        .nonce = finalization_data.nonce,
        .challenge_digest = finalization_data.challenge_digest,
        .token_key_id = finalization_data.token_key_id,
    };

    auto auth_input_bytes = auth_input.serialize();
    if (!auth_input_bytes) {
        return std::unexpected(auth_input_bytes.error());
    }

    // Unblind the signature
    auto authenticator = issuer_key.finalize(
        ByteView(rsa_response->blind_sig.data(), rsa_response->blind_sig.size()),
        *blinding_data,
        ByteView(auth_input_bytes->data(), auth_input_bytes->size()));

    if (!authenticator) {
        return std::unexpected(authenticator.error());
    }

    // Verify the signature before returning
    auto verify_result = issuer_key.verify(
        ByteView(auth_input_bytes->data(), auth_input_bytes->size()),
        ByteView(authenticator->data(), authenticator->size()));

    if (!verify_result || !*verify_result) {
        return std::unexpected(Error{ErrorCode::VERIFICATION_FAILED,
            "Signature verification failed"});
    }

    return Token::create(
        finalization_data.token_type,
        finalization_data.nonce,
        finalization_data.challenge_digest,
        finalization_data.token_key_id,
        std::move(*authenticator));
}

// PrivateClient implementation
struct PrivateClient::Impl {};

PrivateClient::PrivateClient() : impl_(std::make_unique<Impl>()) {}
PrivateClient::~PrivateClient() = default;
PrivateClient::PrivateClient(PrivateClient&&) noexcept = default;
PrivateClient& PrivateClient::operator=(PrivateClient&&) noexcept = default;

Result<TokenRequestResult> PrivateClient::create_token_request(
    const TokenChallenge& challenge,
    const crypto::VoprfPublicKey& issuer_key) const {

    // Generate random nonce
    auto nonce_result = crypto::random_nonce();
    if (!nonce_result) {
        return std::unexpected(nonce_result.error());
    }

    // Compute challenge digest
    auto digest_result = challenge.digest();
    if (!digest_result) {
        return std::unexpected(digest_result.error());
    }

    // Get key ID
    auto key_id_result = issuer_key.key_id();
    if (!key_id_result) {
        return std::unexpected(key_id_result.error());
    }

    // Build authenticator input
    AuthenticatorInput auth_input{
        .token_type = challenge.token_type,
        .nonce = *nonce_result,
        .challenge_digest = *digest_result,
        .token_key_id = *key_id_result,
    };

    auto auth_input_bytes = auth_input.serialize();
    if (!auth_input_bytes) {
        return std::unexpected(auth_input_bytes.error());
    }

    // Create VOPRF client and blind
    crypto::VoprfPublicKey key_copy;
    auto key_bytes = issuer_key.to_bytes();
    if (!key_bytes) {
        return std::unexpected(key_bytes.error());
    }
    auto key_copy_result = crypto::VoprfPublicKey::from_bytes(
        ByteView(key_bytes->data(), key_bytes->size()));
    if (!key_copy_result) {
        return std::unexpected(key_copy_result.error());
    }

    crypto::VoprfClient voprf_client(std::move(*key_copy_result));
    auto blind_result = voprf_client.blind(
        ByteView(auth_input_bytes->data(), auth_input_bytes->size()));

    if (!blind_result) {
        return std::unexpected(blind_result.error());
    }

    // Create token request
    TokenRequest request = TokenRequest::create(
        challenge.token_type,
        key_id_result->at(31),
        std::move(blind_result->blinded_element));

    // Prepare finalization data
    FinalizationData finalization;
    finalization.token_type = challenge.token_type;
    finalization.nonce = *nonce_result;
    finalization.challenge_digest = *digest_result;
    finalization.token_key_id = *key_id_result;
    finalization.data = std::move(*blind_result);

    return TokenRequestResult{
        .request = std::move(request),
        .finalization_data = std::move(finalization),
    };
}

Result<Token> PrivateClient::finalize(
    const TokenResponse& response,
    FinalizationData finalization_data,
    const crypto::VoprfPublicKey& issuer_key) const {

    const auto* voprf_response = response.as_voprf();
    if (!voprf_response) {
        return std::unexpected(Error{ErrorCode::TOKEN_MALFORMED,
            "Expected VOPRF response"});
    }

    auto* voprf_data = std::get_if<crypto::VoprfFinalizationData>(&finalization_data.data);
    if (!voprf_data) {
        return std::unexpected(Error{ErrorCode::TOKEN_MALFORMED,
            "Invalid finalization data"});
    }

    // Create VOPRF client for finalization
    auto key_bytes = issuer_key.to_bytes();
    if (!key_bytes) {
        return std::unexpected(key_bytes.error());
    }
    auto key_copy = crypto::VoprfPublicKey::from_bytes(
        ByteView(key_bytes->data(), key_bytes->size()));
    if (!key_copy) {
        return std::unexpected(key_copy.error());
    }

    crypto::VoprfClient voprf_client(std::move(*key_copy));

    crypto::VoprfEvaluation evaluation{
        .evaluated_element = voprf_response->evaluate_msg,
        .proof = voprf_response->evaluate_proof,
    };

    auto authenticator = voprf_client.finalize(*voprf_data, evaluation);
    if (!authenticator) {
        return std::unexpected(authenticator.error());
    }

    return Token::create(
        finalization_data.token_type,
        finalization_data.nonce,
        finalization_data.challenge_digest,
        finalization_data.token_key_id,
        std::move(*authenticator));
}

// Unified Client implementation
struct Client::Impl {
    PublicClient public_client;
    PrivateClient private_client;
};

Client::Client() : impl_(std::make_unique<Impl>()) {}
Client::~Client() = default;
Client::Client(Client&&) noexcept = default;
Client& Client::operator=(Client&&) noexcept = default;

Result<TokenRequestResult> Client::create_token_request(
    const TokenChallenge& challenge,
    const PublicKey& issuer_key) const {

    if (challenge.token_type != issuer_key.type) {
        return std::unexpected(Error{ErrorCode::UNSUPPORTED_TOKEN_TYPE,
            "Token type mismatch between challenge and key"});
    }

    switch (challenge.token_type) {
        case TokenType::BLIND_RSA:
        case TokenType::PARTIALLY_BLIND_RSA: {
            auto rsa_key = crypto::BlindRsaPublicKey::from_spki(issuer_key.view());
            if (!rsa_key) {
                return std::unexpected(rsa_key.error());
            }
            return impl_->public_client.create_token_request(challenge, *rsa_key);
        }
        case TokenType::VOPRF_P384_SHA384: {
            auto voprf_key = crypto::VoprfPublicKey::from_bytes(issuer_key.view());
            if (!voprf_key) {
                return std::unexpected(voprf_key.error());
            }
            return impl_->private_client.create_token_request(challenge, *voprf_key);
        }
        default:
            return std::unexpected(Error{ErrorCode::UNSUPPORTED_TOKEN_TYPE,
                "Unsupported token type"});
    }
}

Result<Token> Client::finalize(
    const TokenResponse& response,
    FinalizationData finalization_data,
    const PublicKey& issuer_key) const {

    switch (finalization_data.token_type) {
        case TokenType::BLIND_RSA:
        case TokenType::PARTIALLY_BLIND_RSA: {
            auto rsa_key = crypto::BlindRsaPublicKey::from_spki(issuer_key.view());
            if (!rsa_key) {
                return std::unexpected(rsa_key.error());
            }
            return impl_->public_client.finalize(response, std::move(finalization_data), *rsa_key);
        }
        case TokenType::VOPRF_P384_SHA384: {
            auto voprf_key = crypto::VoprfPublicKey::from_bytes(issuer_key.view());
            if (!voprf_key) {
                return std::unexpected(voprf_key.error());
            }
            return impl_->private_client.finalize(response, std::move(finalization_data), *voprf_key);
        }
        default:
            return std::unexpected(Error{ErrorCode::UNSUPPORTED_TOKEN_TYPE,
                "Unsupported token type"});
    }
}

}  // namespace privacy_pass
