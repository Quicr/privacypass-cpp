// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
// Example: MOQ Client using TokenProvider with MOQ authorization scopes
//
// This demonstrates how to build a MOQ client that:
// 1. Receives token challenges from a relay
// 2. Requests tokens from an issuer
// 3. Presents tokens for MOQ operations

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

// Example MOQ Client built on TokenProvider
class MoqClient {
public:
    MoqClient() : provider_(TokenProviderConfig{.max_cached_tokens = 10, .origin_name = "origin.example.com"}) {}

    void add_issuer(const std::string& name, const PublicKey& key) {
        provider_.add_issuer_key(name, key);
    }

    // Prepare a token request for a challenge
    Result<TokenRequestContext> prepare_request(const TokenChallenge& challenge) {
        return provider_.prepare_request(challenge);
    }

    // Finalize a token from issuer response
    Result<Token> finalize(const TokenResponse& response, TokenRequestContext ctx) {
        return provider_.finalize(response, std::move(ctx));
    }

    // Parse authorization info from a challenge
    Result<AuthorizationInfo> parse_auth_info(const TokenChallenge& challenge) const {
        if (challenge.origin_info.empty()) {
            return std::unexpected(Error{ErrorCode::MALFORMED_DATA, "No origin_info"});
        }
        return AuthorizationInfo::decode_from_origin_info(challenge.origin_info[0]);
    }

    // Check if a token authorizes a specific MOQ action
    bool token_authorizes(
        const TokenChallenge& challenge,
        Action action,
        const Namespace& ns,
        const TrackName& track) const {

        auto auth_info = parse_auth_info(challenge);
        if (!auth_info) {
            return false;
        }
        return auth_info->authorizes(action, ns, track);
    }

private:
    TokenProvider provider_;
};

int main() {
    std::cout << "=== MOQ Client Example ===" << std::endl << std::endl;

    if (auto result = initialize(); !result) {
        std::cerr << "Failed to initialize library" << std::endl;
        return 1;
    }

    // Setup: Generate issuer (normally provided by the system)
    std::cout << "1. Setting up issuer..." << std::endl;
    auto issuer = PublicIssuer::generate();
    if (!issuer) {
        std::cerr << "Failed to generate issuer" << std::endl;
        return 1;
    }

    auto pub_key = issuer->public_key();
    auto spki = pub_key->to_spki();
    auto key_id = pub_key->key_id();

    PublicKey issuer_pub{
        .type = TokenType::BLIND_RSA,
        .data = *spki,
        .key_id = *key_id,
    };
    std::cout << "  Issuer ready" << std::endl << std::endl;

    // Create MOQ client
    std::cout << "2. Creating MOQ client..." << std::endl;
    MoqClient client;
    client.add_issuer("issuer.example.com", issuer_pub);
    std::cout << "  Client configured" << std::endl << std::endl;

    // Simulate: Relay creates a challenge for SUBSCRIBE action
    std::cout << "3. Relay creates challenge for SUBSCRIBE..." << std::endl;

    Namespace test_ns = {
        Bytes{'t', 'e', 's', 't'},
        Bytes{'s', 't', 'r', 'e', 'a', 'm'},
    };
    TrackName test_track = {'v', 'i', 'd', 'e', 'o'};

    auto auth_info = AuthorizationInfo::for_subscriber(test_ns, test_track);
    auto encoded_auth = auth_info.encode_for_origin_info();
    if (!encoded_auth) {
        std::cerr << "Failed to encode auth info" << std::endl;
        return 1;
    }

    auto challenge = TokenChallenge::create(
        TokenType::BLIND_RSA,
        "issuer.example.com",
        std::nullopt,
        {*encoded_auth, "relay.example.com"});
    std::cout << "  Challenge created for issuer: " << challenge.issuer_name << std::endl;

    // Client parses authorization info
    auto parsed_auth = client.parse_auth_info(challenge);
    if (!parsed_auth) {
        std::cerr << "Failed to parse auth info" << std::endl;
        return 1;
    }
    std::cout << "  Authorization scopes: " << parsed_auth->scopes.size() << std::endl << std::endl;

    // Client prepares token request
    std::cout << "4. Client prepares token request..." << std::endl;
    auto ctx = client.prepare_request(challenge);
    if (!ctx) {
        std::cerr << "Failed to prepare request: " << ctx.error().message << std::endl;
        return 1;
    }
    std::cout << "  Request prepared, sending to issuer..." << std::endl;

    // Simulate: Send request to issuer and get response
    auto response = issuer->issue(ctx->request);
    if (!response) {
        std::cerr << "Issuer failed: " << response.error().message << std::endl;
        return 1;
    }
    std::cout << "  Issuer responded" << std::endl;

    // Finalize the token
    auto token = client.finalize(*response, std::move(*ctx));
    if (!token) {
        std::cerr << "Failed to finalize token: " << token.error().message << std::endl;
        return 1;
    }
    std::cout << "  Token obtained!" << std::endl;
    print_hex("  Token nonce", ByteView(token->nonce.data(), token->nonce.size()));
    std::cout << std::endl;

    // Check if token authorizes SUBSCRIBE
    std::cout << "5. Checking token authorization..." << std::endl;
    bool can_subscribe = client.token_authorizes(challenge, Action::SUBSCRIBE, test_ns, test_track);
    std::cout << "  Can SUBSCRIBE to test/stream/video: " << (can_subscribe ? "YES" : "NO") << std::endl;

    bool can_publish = client.token_authorizes(challenge, Action::PUBLISH, test_ns, test_track);
    std::cout << "  Can PUBLISH to test/stream/video: " << (can_publish ? "YES" : "NO") << std::endl;
    std::cout << std::endl;

    std::cout << "=== Example completed ===" << std::endl;

    shutdown();
    return 0;
}
