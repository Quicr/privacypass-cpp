// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
// Basic Privacy Pass flow example
// Build: cmake --build build --target example_basic_flow
// Run:   ./build/example_basic_flow

#include <privacy_pass/privacy_pass.hpp>
#include <iostream>
#include <iomanip>

using namespace privacy_pass;

void print_hex(const std::string& label, ByteView data, size_t max_bytes = 16) {
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(data.size(), max_bytes); ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<int>(data[i]);
    }
    if (data.size() > max_bytes) std::cout << "...";
    std::cout << " (" << std::dec << data.size() << " bytes)" << std::endl;
}

int main() {
    std::cout << "=== Privacy Pass C++ Example ===" << std::endl << std::endl;

    // Initialize library
    if (auto result = initialize(); !result) {
        std::cerr << "Failed to initialize library" << std::endl;
        return 1;
    }

    // ========================================
    // SETUP: Generate Issuer Keys
    // ========================================
    std::cout << "1. Generating issuer keys..." << std::endl;

    auto issuer_result = PublicIssuer::generate();
    if (!issuer_result) {
        std::cerr << "Failed to generate issuer: " << issuer_result.error().message << std::endl;
        return 1;
    }
    auto& issuer = *issuer_result;

    auto pub_key = issuer.public_key();
    if (!pub_key) {
        std::cerr << "Failed to get public key" << std::endl;
        return 1;
    }

    auto spki = pub_key->to_spki();
    auto key_id = pub_key->key_id();
    std::cout << "   Issuer key generated" << std::endl;
    print_hex("   Key ID", ByteView(key_id->data(), key_id->size()));
    std::cout << "   Truncated Key ID: 0x" << std::hex << static_cast<int>(issuer.truncated_key_id())
              << std::dec << std::endl << std::endl;

    // ========================================
    // SETUP: Configure Origin
    // ========================================
    std::cout << "2. Setting up origin..." << std::endl;

    OriginConfig origin_config{
        .issuer_name = "issuer.example.com",
        .origin_names = {"origin.example.com"},
        .redemption_window = std::chrono::seconds(3600),
        .require_redemption_context = true,
    };

    auto origin_key = crypto::BlindRsaPublicKey::from_spki(ByteView(spki->data(), spki->size()));
    if (!origin_key) {
        std::cerr << "Failed to parse origin key" << std::endl;
        return 1;
    }

    std::vector<crypto::BlindRsaPublicKey> origin_keys;
    origin_keys.push_back(std::move(*origin_key));
    PublicOrigin origin(origin_config, std::move(origin_keys));
    std::cout << "   Origin configured for: " << origin_config.issuer_name << std::endl << std::endl;

    // ========================================
    // STEP 1: Origin creates challenge
    // ========================================
    std::cout << "3. Origin creates token challenge..." << std::endl;

    auto challenge = origin.create_challenge();
    if (!challenge) {
        std::cerr << "Failed to create challenge: " << challenge.error().message << std::endl;
        return 1;
    }

    auto challenge_digest = challenge->digest();
    std::cout << "   Token type: " << token_type_name(challenge->token_type) << std::endl;
    std::cout << "   Issuer: " << challenge->issuer_name << std::endl;
    print_hex("   Challenge digest", ByteView(challenge_digest->data(), challenge_digest->size()));
    std::cout << std::endl;

    // ========================================
    // STEP 2: Client creates blinded token request
    // ========================================
    std::cout << "4. Client creates token request (blinding)..." << std::endl;

    PublicClient client;

    auto client_key = crypto::BlindRsaPublicKey::from_spki(ByteView(spki->data(), spki->size()));
    if (!client_key) {
        std::cerr << "Failed to parse client key" << std::endl;
        return 1;
    }

    auto request_result = client.create_token_request(*challenge, *client_key);
    if (!request_result) {
        std::cerr << "Failed to create token request: " << request_result.error().message << std::endl;
        return 1;
    }

    std::cout << "   Blinded message created" << std::endl;
    print_hex("   Blinded msg", ByteView(request_result->request.blinded_msg.data(),
                                          request_result->request.blinded_msg.size()));
    std::cout << std::endl;

    // ========================================
    // STEP 3: Issuer signs blinded request
    // ========================================
    std::cout << "5. Issuer signs blinded request..." << std::endl;

    auto response = issuer.issue(request_result->request);
    if (!response) {
        std::cerr << "Failed to issue token: " << response.error().message << std::endl;
        return 1;
    }

    auto* rsa_resp = response->as_blind_rsa();
    std::cout << "   Blind signature created" << std::endl;
    print_hex("   Blind sig", ByteView(rsa_resp->blind_sig.data(), rsa_resp->blind_sig.size()));
    std::cout << std::endl;

    // ========================================
    // STEP 4: Client unblinds and creates token
    // ========================================
    std::cout << "6. Client finalizes token (unblinding)..." << std::endl;

    auto finalize_key = crypto::BlindRsaPublicKey::from_spki(ByteView(spki->data(), spki->size()));
    auto token = client.finalize(*response, std::move(request_result->finalization_data), *finalize_key);
    if (!token) {
        std::cerr << "Failed to finalize token: " << token.error().message << std::endl;
        return 1;
    }

    std::cout << "   Token created successfully!" << std::endl;
    print_hex("   Nonce", ByteView(token->nonce.data(), token->nonce.size()));
    print_hex("   Authenticator", ByteView(token->authenticator.data(), token->authenticator.size()));
    std::cout << std::endl;

    // ========================================
    // STEP 5: Origin verifies token
    // ========================================
    std::cout << "7. Origin verifies token..." << std::endl;

    auto valid = origin.verify(*token, *challenge);
    if (!valid) {
        std::cerr << "Verification failed: " << valid.error().message << std::endl;
        return 1;
    }

    std::cout << "   Signature valid: " << (*valid ? "YES" : "NO") << std::endl << std::endl;

    // ========================================
    // STEP 6: Origin redeems token (with replay protection)
    // ========================================
    std::cout << "8. Origin redeems token..." << std::endl;

    auto redeem1 = origin.verify_and_redeem(*token, *challenge);
    if (!redeem1) {
        std::cerr << "Redemption failed: " << redeem1.error().message << std::endl;
        return 1;
    }
    std::cout << "   First redemption: " << (*redeem1 ? "SUCCESS" : "FAILED") << std::endl;

    // Try to replay
    auto redeem2 = origin.verify_and_redeem(*token, *challenge);
    std::cout << "   Replay attempt: " << (redeem2 ? "ACCEPTED (bad!)" : "REJECTED (good!)") << std::endl;
    if (!redeem2) {
        std::cout << "   Replay error: " << error_code_name(redeem2.error().code) << std::endl;
    }
    std::cout << std::endl;

    // ========================================
    // HTTP Headers
    // ========================================
    std::cout << "9. HTTP header formatting..." << std::endl;

    auto www_auth = http::build_www_authenticate(*challenge, ByteView(spki->data(), spki->size()), 600);
    std::cout << "   WWW-Authenticate: " << www_auth->substr(0, 60) << "..." << std::endl;

    auto auth_header = http::build_authorization(*token);
    std::cout << "   Authorization: " << auth_header->substr(0, 60) << "..." << std::endl;
    std::cout << std::endl;

    std::cout << "=== Example completed successfully! ===" << std::endl;

    shutdown();
    return 0;
}
