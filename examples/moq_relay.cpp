// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
// Example: MOQ Relay using TokenAuthenticator with MOQ authorization scopes
//
// This demonstrates how to build a MOQ relay that:
// 1. Creates token challenges for clients
// 2. Validates presented tokens
// 3. Authorizes MOQ operations based on token scopes

#include <privacy_pass/privacy_pass.hpp>
#include <privacy_pass/extensions/moq.hpp>

#include <iostream>
#include <iomanip>

using namespace privacy_pass;
using namespace privacy_pass::moq;

void print_hex(const std::string& label, ByteView data, size_t max_bytes = 16) {
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(data.size(), max_bytes); ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<int>(data[i]);
    }
    if (data.size() > max_bytes) std::cout << "...";
    std::cout << " (" << std::dec << data.size() << " bytes)" << std::endl;
}

// MOQ-specific verification result
struct MoqVerificationResult {
    bool valid{false};
    MoqErrorCode error_code{MoqErrorCode::TOKEN_INVALID};
    std::string error_message;
    std::optional<AuthorizationInfo> auth_info;

    static MoqVerificationResult success(AuthorizationInfo info) {
        return {true, {}, {}, std::move(info)};
    }

    static MoqVerificationResult failure(MoqErrorCode code, std::string msg) {
        return {false, code, std::move(msg), std::nullopt};
    }
};

// Example MOQ Relay built on TokenAuthenticator
class MoqRelay {
public:
    explicit MoqRelay(const std::string& relay_name, const std::string& issuer_name)
        : relay_name_(relay_name)
        , issuer_name_(issuer_name)
        , authenticator_(TokenAuthenticatorConfig{
            .issuer_name = issuer_name,
            .origin_names = {relay_name},
            .redemption_window = std::chrono::seconds(3600),
            .replay_window = std::chrono::seconds(3600),
            .require_redemption_context = false,
        }) {}

    void add_trusted_issuer(crypto::BlindRsaPublicKey key) {
        authenticator_.add_trusted_key(issuer_name_, std::move(key));
    }

    // Create a challenge for a specific authorization scope
    Result<TokenChallenge> create_challenge(const AuthorizationInfo& required_auth) {
        auto encoded = required_auth.encode_for_origin_info();
        if (!encoded) {
            return std::unexpected(encoded.error());
        }

        return authenticator_.create_challenge(
            TokenType::BLIND_RSA,
            std::nullopt,
            {*encoded});
    }

    // Verify a token and extract authorization info
    MoqVerificationResult verify_token(
        const Token& token,
        const TokenChallenge& challenge) {

        auto result = authenticator_.validate(token, challenge);
        if (!result.valid) {
            auto code = MoqErrorCode::TOKEN_INVALID;
            if (result.error_code == ErrorCode::TOKEN_REPLAYED) {
                code = MoqErrorCode::TOKEN_REPLAYED;
            } else if (result.error_code == ErrorCode::ISSUER_UNKNOWN) {
                code = MoqErrorCode::ISSUER_UNKNOWN;
            }
            return MoqVerificationResult::failure(code,
                result.error_message.value_or("Validation failed"));
        }

        // Parse authorization info
        if (challenge.origin_info.empty()) {
            return MoqVerificationResult::failure(
                MoqErrorCode::TOKEN_MALFORMED, "Missing authorization info");
        }

        auto auth_info = AuthorizationInfo::decode_from_origin_info(
            challenge.origin_info[0]);
        if (!auth_info) {
            return MoqVerificationResult::failure(
                MoqErrorCode::TOKEN_MALFORMED, "Invalid authorization info");
        }

        return MoqVerificationResult::success(std::move(*auth_info));
    }

    // Verify token and check if it authorizes a specific action
    MoqVerificationResult verify_and_authorize(
        const Token& token,
        const TokenChallenge& challenge,
        Action action,
        const Namespace& ns,
        const TrackName& track) {

        // First validate and redeem
        auto result = authenticator_.validate_and_redeem(token, challenge);
        if (!result.valid) {
            auto code = MoqErrorCode::TOKEN_INVALID;
            if (result.error_code == ErrorCode::TOKEN_REPLAYED) {
                code = MoqErrorCode::TOKEN_REPLAYED;
            }
            return MoqVerificationResult::failure(code,
                result.error_message.value_or("Validation failed"));
        }

        // Parse and check authorization
        if (challenge.origin_info.empty()) {
            return MoqVerificationResult::failure(
                MoqErrorCode::TOKEN_MALFORMED, "Missing authorization info");
        }

        auto auth_info = AuthorizationInfo::decode_from_origin_info(
            challenge.origin_info[0]);
        if (!auth_info) {
            return MoqVerificationResult::failure(
                MoqErrorCode::TOKEN_MALFORMED, "Invalid authorization info");
        }

        if (!auth_info->authorizes(action, ns, track)) {
            return MoqVerificationResult::failure(
                MoqErrorCode::SCOPE_MISMATCH,
                "Token does not authorize " + std::string(action_name(action)));
        }

        return MoqVerificationResult::success(std::move(*auth_info));
    }

    const std::string& relay_name() const { return relay_name_; }
    const std::string& issuer_name() const { return issuer_name_; }

private:
    std::string relay_name_;
    std::string issuer_name_;
    TokenAuthenticator authenticator_;
};

int main() {
    std::cout << "=== MOQ Relay Example ===" << std::endl << std::endl;

    if (auto result = initialize(); !result) {
        std::cerr << "Failed to initialize library" << std::endl;
        return 1;
    }

    // Setup: Generate issuer
    std::cout << "1. Setting up issuer..." << std::endl;
    auto issuer = PublicIssuer::generate();
    if (!issuer) {
        std::cerr << "Failed to generate issuer" << std::endl;
        return 1;
    }

    auto pub_key = issuer->public_key();
    auto spki = pub_key->to_spki();
    std::cout << "  Issuer ready" << std::endl << std::endl;

    // Create MOQ relay
    std::cout << "2. Creating MOQ relay..." << std::endl;
    MoqRelay relay("relay.example.com", "issuer.example.com");

    auto issuer_key = crypto::BlindRsaPublicKey::from_spki(
        ByteView(spki->data(), spki->size()));
    relay.add_trusted_issuer(std::move(*issuer_key));
    std::cout << "  Relay configured: " << relay.relay_name() << std::endl << std::endl;

    // Relay creates a challenge for publisher
    std::cout << "3. Creating challenge for publisher..." << std::endl;
    Namespace pub_ns = {
        Bytes{'l', 'i', 'v', 'e'},
        Bytes{'s', 't', 'r', 'e', 'a', 'm'},
    };

    auto pub_auth = AuthorizationInfo::for_publisher(pub_ns);
    auto challenge = relay.create_challenge(pub_auth);
    if (!challenge) {
        std::cerr << "Failed to create challenge" << std::endl;
        return 1;
    }
    std::cout << "  Challenge created" << std::endl << std::endl;

    // Simulate client getting a token
    std::cout << "4. Simulating client token acquisition..." << std::endl;

    auto client_key = crypto::BlindRsaPublicKey::from_spki(
        ByteView(spki->data(), spki->size()));
    PublicClient client;
    auto req_result = client.create_token_request(*challenge, *client_key);
    if (!req_result) {
        std::cerr << "Failed to create request" << std::endl;
        return 1;
    }

    auto response = issuer->issue(req_result->request);
    if (!response) {
        std::cerr << "Issuer failed" << std::endl;
        return 1;
    }

    auto finalize_key = crypto::BlindRsaPublicKey::from_spki(
        ByteView(spki->data(), spki->size()));
    auto token = client.finalize(*response, std::move(req_result->finalization_data), *finalize_key);
    if (!token) {
        std::cerr << "Failed to finalize token" << std::endl;
        return 1;
    }
    std::cout << "  Client obtained token" << std::endl;
    print_hex("  Token nonce", ByteView(token->nonce.data(), token->nonce.size()));
    std::cout << std::endl;

    // Relay verifies token
    std::cout << "5. Relay verifies token..." << std::endl;
    auto verify_result = relay.verify_token(*token, *challenge);
    std::cout << "  Valid: " << (verify_result.valid ? "YES" : "NO") << std::endl;
    if (verify_result.auth_info) {
        std::cout << "  Authorization scopes: " << verify_result.auth_info->scopes.size() << std::endl;
    }
    std::cout << std::endl;

    // Test authorization for different actions
    std::cout << "6. Testing authorization..." << std::endl;
    TrackName video_track = {'v', 'i', 'd', 'e', 'o'};

    auto publish_result = relay.verify_and_authorize(
        *token, *challenge, Action::PUBLISH, pub_ns, video_track);
    std::cout << "  PUBLISH live/stream/video: "
              << (publish_result.valid ? "ALLOWED" : "DENIED") << std::endl;

    // Get a new token for subscribe test (previous was redeemed)
    req_result = client.create_token_request(*challenge, *client_key);
    response = issuer->issue(req_result->request);
    finalize_key = crypto::BlindRsaPublicKey::from_spki(ByteView(spki->data(), spki->size()));
    token = client.finalize(*response, std::move(req_result->finalization_data), *finalize_key);

    auto subscribe_result = relay.verify_and_authorize(
        *token, *challenge, Action::SUBSCRIBE, pub_ns, video_track);
    std::cout << "  SUBSCRIBE live/stream/video: "
              << (subscribe_result.valid ? "ALLOWED" : "DENIED");
    if (!subscribe_result.valid) {
        std::cout << " (" << subscribe_result.error_message << ")";
    }
    std::cout << std::endl << std::endl;

    // Test replay protection
    std::cout << "7. Testing replay protection..." << std::endl;
    auto replay_result = relay.verify_and_authorize(
        *token, *challenge, Action::PUBLISH, pub_ns, video_track);
    std::cout << "  Replay attempt: " << (replay_result.valid ? "ACCEPTED (bad!)" : "REJECTED (good!)") << std::endl;
    if (!replay_result.valid) {
        std::cout << "  Error: " << replay_result.error_message << std::endl;
    }
    std::cout << std::endl;

    std::cout << "=== Example completed ===" << std::endl;

    shutdown();
    return 0;
}
