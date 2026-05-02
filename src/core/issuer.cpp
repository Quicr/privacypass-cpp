// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/core/issuer.hpp>

#include <spdlog/spdlog.h>
#include <unordered_map>

namespace privacy_pass {

// PublicIssuer implementation
struct PublicIssuer::Impl {
    crypto::BlindRsaPrivateKey private_key;
    crypto::BlindRsaPublicKey public_key;
    TokenKeyId key_id;
    uint8_t truncated_key_id;
};

PublicIssuer::PublicIssuer(crypto::BlindRsaPrivateKey private_key)
    : impl_(std::make_unique<Impl>()) {
    impl_->private_key = std::move(private_key);

    auto pub = impl_->private_key.public_key();
    if (pub) {
        auto key_id = pub->key_id();
        if (key_id) {
            impl_->key_id = *key_id;
            impl_->truncated_key_id = impl_->key_id[31];
        }
        impl_->public_key = std::move(*pub);
    }
}

PublicIssuer::~PublicIssuer() = default;
PublicIssuer::PublicIssuer(PublicIssuer&&) noexcept = default;
PublicIssuer& PublicIssuer::operator=(PublicIssuer&&) noexcept = default;

Result<PublicIssuer> PublicIssuer::generate() {
    auto keypair = crypto::BlindRsaPrivateKey::generate();
    if (!keypair) {
        return std::unexpected(keypair.error());
    }

    return PublicIssuer(std::move(keypair->first));
}

Result<TokenResponse> PublicIssuer::issue(const TokenRequest& request) const {
    if (request.token_type != TokenType::BLIND_RSA &&
        request.token_type != TokenType::PARTIALLY_BLIND_RSA) {
        return std::unexpected(Error{ErrorCode::UNSUPPORTED_TOKEN_TYPE,
            "PublicIssuer only supports Blind RSA"});
    }

    if (request.truncated_token_key_id != impl_->truncated_key_id) {
        return std::unexpected(Error{ErrorCode::ISSUER_UNKNOWN,
            "Unknown key ID"});
    }

    auto blind_sig = impl_->private_key.blind_sign(
        ByteView(request.blinded_msg.data(), request.blinded_msg.size()));

    if (!blind_sig) {
        return std::unexpected(blind_sig.error());
    }

    return TokenResponse::create_blind_rsa(std::move(*blind_sig));
}

Result<BatchedTokenResponse> PublicIssuer::issue_batch(
    const BatchedTokenRequest& requests) const {

    BatchedTokenResponse response;
    response.responses.reserve(requests.requests.size());

    for (const auto& req : requests.requests) {
        auto resp = issue(req);

        OptionalTokenResponse opt_resp;
        if (resp) {
            opt_resp.present = true;
            opt_resp.response = std::move(*resp);
        } else {
            opt_resp.present = false;
            spdlog::warn("Failed to issue token: {}", resp.error().message);
        }

        response.responses.push_back(std::move(opt_resp));
    }

    return response;
}

Result<crypto::BlindRsaPublicKey> PublicIssuer::public_key() const {
    return impl_->private_key.public_key();
}

uint8_t PublicIssuer::truncated_key_id() const {
    return impl_->truncated_key_id;
}

// PrivateIssuer implementation
struct PrivateIssuer::Impl {
    crypto::VoprfPrivateKey private_key;
    crypto::VoprfServer server;
    TokenKeyId key_id;
    uint8_t truncated_key_id;

    Impl(crypto::VoprfPrivateKey key)
        : private_key(std::move(key)), server(crypto::VoprfPrivateKey{}) {
        // Need to reconstruct server with proper key
    }
};

PrivateIssuer::PrivateIssuer(crypto::VoprfPrivateKey private_key)
    : impl_(std::make_unique<Impl>(std::move(private_key))) {

    // Reconstruct server with the key
    auto key_bytes = impl_->private_key.to_bytes();
    if (key_bytes) {
        auto key_copy = crypto::VoprfPrivateKey::from_bytes(key_bytes->view());
        if (key_copy) {
            impl_->server = crypto::VoprfServer(std::move(*key_copy));
        }
    }

    auto pub = impl_->private_key.public_key();
    if (pub) {
        auto key_id = pub->key_id();
        if (key_id) {
            impl_->key_id = *key_id;
            impl_->truncated_key_id = impl_->key_id[31];
        }
    }
}

PrivateIssuer::~PrivateIssuer() = default;
PrivateIssuer::PrivateIssuer(PrivateIssuer&&) noexcept = default;
PrivateIssuer& PrivateIssuer::operator=(PrivateIssuer&&) noexcept = default;

Result<PrivateIssuer> PrivateIssuer::generate() {
    auto keypair = crypto::VoprfPrivateKey::generate();
    if (!keypair) {
        return std::unexpected(keypair.error());
    }

    return PrivateIssuer(std::move(keypair->first));
}

Result<TokenResponse> PrivateIssuer::issue(const TokenRequest& request) const {
    if (request.token_type != TokenType::VOPRF_P384_SHA384) {
        return std::unexpected(Error{ErrorCode::UNSUPPORTED_TOKEN_TYPE,
            "PrivateIssuer only supports VOPRF"});
    }

    if (request.truncated_token_key_id != impl_->truncated_key_id) {
        return std::unexpected(Error{ErrorCode::ISSUER_UNKNOWN,
            "Unknown key ID"});
    }

    auto evaluation = impl_->server.blind_evaluate(
        ByteView(request.blinded_msg.data(), request.blinded_msg.size()));

    if (!evaluation) {
        return std::unexpected(evaluation.error());
    }

    return TokenResponse::create_voprf(
        std::move(evaluation->evaluated_element),
        std::move(evaluation->proof));
}

Result<BatchedTokenResponse> PrivateIssuer::issue_batch(
    const BatchedTokenRequest& requests) const {

    BatchedTokenResponse response;
    response.responses.reserve(requests.requests.size());

    for (const auto& req : requests.requests) {
        auto resp = issue(req);

        OptionalTokenResponse opt_resp;
        if (resp) {
            opt_resp.present = true;
            opt_resp.response = std::move(*resp);
        } else {
            opt_resp.present = false;
        }

        response.responses.push_back(std::move(opt_resp));
    }

    return response;
}

Result<crypto::VoprfPublicKey> PrivateIssuer::public_key() const {
    return impl_->private_key.public_key();
}

uint8_t PrivateIssuer::truncated_key_id() const {
    return impl_->truncated_key_id;
}

Result<bool> PrivateIssuer::verify(const Token& token) const {
    if (token.token_type != TokenType::VOPRF_P384_SHA384) {
        return std::unexpected(Error{ErrorCode::UNSUPPORTED_TOKEN_TYPE,
            "Can only verify VOPRF tokens"});
    }

    // Reconstruct authenticator input
    auto auth_input = token.authenticator_input();
    auto auth_input_bytes = auth_input.serialize();
    if (!auth_input_bytes) {
        return std::unexpected(auth_input_bytes.error());
    }

    return impl_->server.verify_finalize(
        ByteView(auth_input_bytes->data(), auth_input_bytes->size()),
        ByteView(token.authenticator.data(), token.authenticator.size()));
}

// MultiKeyIssuer implementation
struct MultiKeyIssuer::Impl {
    std::unordered_map<uint8_t, std::unique_ptr<PublicIssuer>> rsa_issuers;
    std::unordered_map<uint8_t, std::unique_ptr<PrivateIssuer>> voprf_issuers;
};

MultiKeyIssuer::MultiKeyIssuer() : impl_(std::make_unique<Impl>()) {}
MultiKeyIssuer::~MultiKeyIssuer() = default;
MultiKeyIssuer::MultiKeyIssuer(MultiKeyIssuer&&) noexcept = default;
MultiKeyIssuer& MultiKeyIssuer::operator=(MultiKeyIssuer&&) noexcept = default;

Result<void> MultiKeyIssuer::add_blind_rsa_key(crypto::BlindRsaPrivateKey key) {
    auto issuer = std::make_unique<PublicIssuer>(std::move(key));
    uint8_t truncated_id = issuer->truncated_key_id();
    impl_->rsa_issuers[truncated_id] = std::move(issuer);
    return {};
}

Result<void> MultiKeyIssuer::add_voprf_key(crypto::VoprfPrivateKey key) {
    auto issuer = std::make_unique<PrivateIssuer>(std::move(key));
    uint8_t truncated_id = issuer->truncated_key_id();
    impl_->voprf_issuers[truncated_id] = std::move(issuer);
    return {};
}

void MultiKeyIssuer::remove_key(uint8_t truncated_key_id) {
    impl_->rsa_issuers.erase(truncated_key_id);
    impl_->voprf_issuers.erase(truncated_key_id);
}

Result<TokenResponse> MultiKeyIssuer::issue(const TokenRequest& request) const {
    switch (request.token_type) {
        case TokenType::BLIND_RSA:
        case TokenType::PARTIALLY_BLIND_RSA: {
            auto it = impl_->rsa_issuers.find(request.truncated_token_key_id);
            if (it == impl_->rsa_issuers.end()) {
                return std::unexpected(Error{ErrorCode::ISSUER_UNKNOWN,
                    "Unknown RSA key ID"});
            }
            return it->second->issue(request);
        }
        case TokenType::VOPRF_P384_SHA384: {
            auto it = impl_->voprf_issuers.find(request.truncated_token_key_id);
            if (it == impl_->voprf_issuers.end()) {
                return std::unexpected(Error{ErrorCode::ISSUER_UNKNOWN,
                    "Unknown VOPRF key ID"});
            }
            return it->second->issue(request);
        }
        default:
            return std::unexpected(Error{ErrorCode::UNSUPPORTED_TOKEN_TYPE,
                "Unsupported token type"});
    }
}

std::vector<PublicKey> MultiKeyIssuer::public_keys() const {
    std::vector<PublicKey> keys;

    for (const auto& [id, issuer] : impl_->rsa_issuers) {
        auto pub = issuer->public_key();
        if (pub) {
            auto spki = pub->to_spki();
            auto key_id = pub->key_id();
            if (spki && key_id) {
                keys.push_back(PublicKey{
                    .type = TokenType::BLIND_RSA,
                    .data = std::move(*spki),
                    .key_id = *key_id,
                });
            }
        }
    }

    for (const auto& [id, issuer] : impl_->voprf_issuers) {
        auto pub = issuer->public_key();
        if (pub) {
            auto bytes = pub->to_bytes();
            auto key_id = pub->key_id();
            if (bytes && key_id) {
                keys.push_back(PublicKey{
                    .type = TokenType::VOPRF_P384_SHA384,
                    .data = std::move(*bytes),
                    .key_id = *key_id,
                });
            }
        }
    }

    return keys;
}

IssuerConfig MultiKeyIssuer::config(std::string_view request_uri) const {
    IssuerConfig config;
    config.issuer_request_uri = std::string(request_uri);
    config.token_keys = public_keys();
    return config;
}

}  // namespace privacy_pass
