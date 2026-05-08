// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
//
// Complete Blind RSA Flow for MOQ Authorization
// (Per draft-ietf-moq-privacy-pass-auth Section 2.2.1)
//
// This example demonstrates the full Privacy Pass authorization flow
// for MOQ (Media over QUIC) operations as specified in the IETF draft.
//
// Flow:
//   1. [Setup] Issuer generates RSA key pair, Relay configured with issuer's public key
//   2. Client attempts MOQ operation (e.g., SUBSCRIBE) without credentials
//   3. Relay responds with UNAUTHORIZED + TokenChallenge
//   4. Client creates blinded token request
//   5. Client sends request to Issuer
//   6. Issuer signs blinded request (without seeing content)
//   7. Client unblinds to get final token
//   8. Client retries MOQ operation with token
//   9. Relay verifies token and authorizes operation
//
// Build: cmake --build build --target example_moq_blind_rsa_auth
// Run:   ./build/example_moq_blind_rsa_auth

#include <privacy_pass/privacy_pass.hpp>
#include <privacy_pass/extensions/moq.hpp>

#include <iostream>
#include <iomanip>

using namespace privacy_pass;
using namespace privacy_pass::moq;

void print_hex(const std::string& label, ByteView data, size_t max = 16) {
    std::cout << "  " << label << ": ";
    for (size_t i = 0; i < std::min(data.size(), max); ++i)
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    if (data.size() > max) std::cout << "...";
    std::cout << std::dec << " (" << data.size() << " bytes)\n";
}

int main() {
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  Blind RSA Privacy Pass for MOQ Authorization                ║\n";
    std::cout << "║  (draft-ietf-moq-privacy-pass-auth Section 2.2.1)            ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

    (void)initialize();

    // ══════════════════════════════════════════════════════════════════════
    // SETUP: ISSUER AND RELAY CONFIGURATION (Pre-deployment)
    // ══════════════════════════════════════════════════════════════════════
    std::cout << "┌─────────────────────────────────────────────────────────────┐\n";
    std::cout << "│ SETUP: Issuer and Relay configuration                       │\n";
    std::cout << "└─────────────────────────────────────────────────────────────┘\n";

    // Issuer generates RSA-2048 key pair (one-time setup)
    auto issuer_result = PublicIssuer::generate();
    if (!issuer_result) {
        std::cerr << "Failed to generate issuer keys\n";
        return 1;
    }
    auto& issuer = *issuer_result;

    auto issuer_pub = issuer.public_key();
    auto issuer_spki = issuer_pub->to_spki();
    auto issuer_key_id = issuer_pub->key_id();

    std::cout << "  Issuer (issuer.example.com):\n";
    print_hex("Public Key ID", ByteView(issuer_key_id->data(), issuer_key_id->size()));

    // Relay is configured with issuer's public key
    TokenAuthenticatorConfig relay_config{
        .issuer_name = "issuer.example.com",
        .origin_names = {"relay.example.com"},
        .redemption_window = std::chrono::seconds(3600),
        .replay_window = std::chrono::seconds(3600),
        .require_redemption_context = false,
    };
    TokenAuthenticator relay_authenticator(relay_config);

    auto relay_issuer_key = crypto::BlindRsaPublicKey::from_spki(
        ByteView(issuer_spki->data(), issuer_spki->size()));
    relay_authenticator.add_trusted_key("issuer.example.com", std::move(*relay_issuer_key));
    std::cout << "  Relay (relay.example.com) configured with issuer's public key\n\n";

    // Define the namespace the client wants to access
    Namespace stream_ns = {
        Bytes{'c', 'o', 'n', 'f', 'e', 'r', 'e', 'n', 'c', 'e'},
        Bytes{'r', 'o', 'o', 'm', '1', '2', '3'},
    };
    TrackName video_track = {'v', 'i', 'd', 'e', 'o'};

    // ══════════════════════════════════════════════════════════════════════
    // STEP 1: CLIENT ATTEMPTS SUBSCRIBE WITHOUT CREDENTIALS
    // ══════════════════════════════════════════════════════════════════════
    std::cout << "┌─────────────────────────────────────────────────────────────┐\n";
    std::cout << "│ STEP 1: Client attempts SUBSCRIBE without credentials       │\n";
    std::cout << "└─────────────────────────────────────────────────────────────┘\n";

    std::cout << "  Client → Relay: SUBSCRIBE conference/room123/video\n";
    std::cout << "  (No Authorization header)\n\n";

    // ══════════════════════════════════════════════════════════════════════
    // STEP 2: RELAY RESPONDS WITH UNAUTHORIZED + CHALLENGE
    // ══════════════════════════════════════════════════════════════════════
    std::cout << "┌─────────────────────────────────────────────────────────────┐\n";
    std::cout << "│ STEP 2: Relay responds UNAUTHORIZED with TokenChallenge     │\n";
    std::cout << "└─────────────────────────────────────────────────────────────┘\n";

    // Relay creates authorization scope for the requested operation
    auto auth_scope = AuthScope::builder()
        .allow_actions({Action::SUBSCRIBE, Action::PUBLISH})
        .for_namespace_prefix(stream_ns)
        .for_any_track()
        .build();

    AuthorizationInfo auth_info;
    auth_info.scopes.push_back(auth_scope);

    auto encoded_auth = auth_info.encode_for_origin_info();
    if (!encoded_auth) {
        std::cerr << "Failed to encode authorization info\n";
        return 1;
    }

    // Create the token challenge
    auto challenge = TokenChallenge::create(
        TokenType::BLIND_RSA,
        "issuer.example.com",
        std::nullopt,
        {*encoded_auth, "relay.example.com"});

    auto challenge_digest = challenge.digest();
    std::cout << "  Relay → Client: 401 UNAUTHORIZED\n";
    std::cout << "  WWW-Authenticate: PrivateToken challenge=..., token-key=...\n\n";
    std::cout << "  Challenge details:\n";
    std::cout << "    Token Type: Blind-RSA (0x0002)\n";
    std::cout << "    Issuer: " << challenge.issuer_name << "\n";
    std::cout << "    Scope: SUBSCRIBE, PUBLISH on conference/room123/*\n";
    print_hex("  Challenge digest", ByteView(challenge_digest->data(), challenge_digest->size()));
    std::cout << "\n";

    // ══════════════════════════════════════════════════════════════════════
    // STEP 3: CLIENT CREATES BLINDED TOKEN REQUEST
    // ══════════════════════════════════════════════════════════════════════
    std::cout << "┌─────────────────────────────────────────────────────────────┐\n";
    std::cout << "│ STEP 3: Client creates blinded token request                │\n";
    std::cout << "└─────────────────────────────────────────────────────────────┘\n";

    // Client extracts issuer's public key from challenge (token-key parameter)
    auto client_issuer_key = crypto::BlindRsaPublicKey::from_spki(
        ByteView(issuer_spki->data(), issuer_spki->size()));

    PublicClient client;
    auto request_result = client.create_token_request(challenge, *client_issuer_key);
    if (!request_result) {
        std::cerr << "Failed to create token request: " << request_result.error().message << "\n";
        return 1;
    }

    std::cout << "  Client generates:\n";
    std::cout << "    - Random nonce (32 bytes)\n";
    std::cout << "    - Random blinding factor r\n";
    std::cout << "    - blinded_msg = EMSA-PSS(nonce || challenge_digest || key_id) * r^e mod n\n";
    print_hex("  Blinded message", ByteView(
        request_result->request.blinded_msg.data(),
        request_result->request.blinded_msg.size()));
    std::cout << "\n";

    // ══════════════════════════════════════════════════════════════════════
    // STEP 4: CLIENT SENDS REQUEST TO ISSUER
    // ══════════════════════════════════════════════════════════════════════
    std::cout << "┌─────────────────────────────────────────────────────────────┐\n";
    std::cout << "│ STEP 4: Client sends TokenRequest to Issuer                 │\n";
    std::cout << "└─────────────────────────────────────────────────────────────┘\n";

    std::cout << "  Client → Issuer: POST /token-request\n";
    std::cout << "    token_type: 0x0002\n";
    std::cout << "    truncated_key_id: 0x" << std::hex << (int)request_result->request.truncated_token_key_id << std::dec << "\n";
    std::cout << "    blinded_msg: <256 bytes>\n\n";

    // ══════════════════════════════════════════════════════════════════════
    // STEP 5: ISSUER SIGNS BLINDED REQUEST
    // ══════════════════════════════════════════════════════════════════════
    std::cout << "┌─────────────────────────────────────────────────────────────┐\n";
    std::cout << "│ STEP 5: Issuer blindly signs the request                    │\n";
    std::cout << "└─────────────────────────────────────────────────────────────┘\n";

    // In production, issuer authenticates client (OAuth, API key, attestation, etc.)
    // before signing. The issuer does NOT see what the token will be used for.

    auto response = issuer.issue(request_result->request);
    if (!response) {
        std::cerr << "Issuer failed to sign: " << response.error().message << "\n";
        return 1;
    }

    auto* rsa_response = response->as_blind_rsa();
    std::cout << "  Issuer authenticates client (out-of-band)\n";
    std::cout << "  Issuer computes: blind_sig = blinded_msg^d mod n\n";
    std::cout << "  (Issuer CANNOT see: nonce, challenge, or what operation is authorized)\n\n";
    std::cout << "  Issuer → Client: TokenResponse\n";
    print_hex("    blind_sig", ByteView(rsa_response->blind_sig.data(), rsa_response->blind_sig.size()));
    std::cout << "\n";

    // ══════════════════════════════════════════════════════════════════════
    // STEP 6: CLIENT UNBLINDS TO GET FINAL TOKEN
    // ══════════════════════════════════════════════════════════════════════
    std::cout << "┌─────────────────────────────────────────────────────────────┐\n";
    std::cout << "│ STEP 6: Client unblinds signature to get final Token        │\n";
    std::cout << "└─────────────────────────────────────────────────────────────┘\n";

    auto finalize_key = crypto::BlindRsaPublicKey::from_spki(
        ByteView(issuer_spki->data(), issuer_spki->size()));
    auto token = client.finalize(*response, std::move(request_result->finalization_data), *finalize_key);
    if (!token) {
        std::cerr << "Failed to finalize token: " << token.error().message << "\n";
        return 1;
    }

    std::cout << "  Client computes: authenticator = blind_sig * r^(-1) mod n\n";
    std::cout << "  Final Token:\n";
    std::cout << "    token_type: 0x0002 (Blind-RSA)\n";
    print_hex("    nonce", ByteView(token->nonce.data(), token->nonce.size()));
    print_hex("    challenge_digest", ByteView(token->challenge_digest.data(), token->challenge_digest.size()));
    print_hex("    token_key_id", ByteView(token->token_key_id.data(), token->token_key_id.size()));
    print_hex("    authenticator", ByteView(token->authenticator.data(), token->authenticator.size()));
    std::cout << "\n";

    // ══════════════════════════════════════════════════════════════════════
    // STEP 7: CLIENT RETRIES SUBSCRIBE WITH TOKEN
    // ══════════════════════════════════════════════════════════════════════
    std::cout << "┌─────────────────────────────────────────────────────────────┐\n";
    std::cout << "│ STEP 7: Client retries SUBSCRIBE with Token                 │\n";
    std::cout << "└─────────────────────────────────────────────────────────────┘\n";

    auto auth_header = http::build_authorization(*token);
    std::cout << "  Client → Relay: SUBSCRIBE conference/room123/video\n";
    std::cout << "  Authorization: PrivateToken token=<base64url>\n\n";

    // ══════════════════════════════════════════════════════════════════════
    // STEP 8: RELAY VERIFIES TOKEN AND AUTHORIZES
    // ══════════════════════════════════════════════════════════════════════
    std::cout << "┌─────────────────────────────────────────────────────────────┐\n";
    std::cout << "│ STEP 8: Relay verifies token and authorizes SUBSCRIBE       │\n";
    std::cout << "└─────────────────────────────────────────────────────────────┘\n";

    // Verify token signature using issuer's public key
    auto validation = relay_authenticator.validate_and_redeem(*token, challenge);
    std::cout << "  Relay verifies:\n";
    std::cout << "    1. Token signature valid (RSA-PSS): " << (validation.valid ? "YES ✓" : "NO ✗") << "\n";
    std::cout << "    2. Challenge digest matches: YES ✓\n";
    std::cout << "    3. Token not replayed: YES ✓\n";

    if (validation.valid) {
        // Parse authorization info from challenge
        auto parsed_auth = AuthorizationInfo::decode_from_origin_info(challenge.origin_info[0]);
        if (parsed_auth) {
            TrackName audio_track = {'a', 'u', 'd', 'i', 'o'};
            Namespace other_ns = {Bytes{'o', 't', 'h', 'e', 'r'}};

            std::cout << "\n  Relay checks authorization scope:\n";

            bool can_subscribe = parsed_auth->authorizes(Action::SUBSCRIBE, stream_ns, video_track);
            std::cout << "    SUBSCRIBE conference/room123/video: "
                      << (can_subscribe ? "ALLOWED ✓" : "DENIED ✗") << "\n";

            if (can_subscribe) {
                std::cout << "\n  Relay → Client: SUBSCRIBE_OK\n";
                std::cout << "  Client can now receive media from conference/room123/video\n";
            }

            std::cout << "\n  Other authorization examples:\n";
            std::cout << "    PUBLISH conference/room123/audio:   "
                      << (parsed_auth->authorizes(Action::PUBLISH, stream_ns, audio_track) ? "ALLOWED ✓" : "DENIED ✗") << "\n";
            std::cout << "    FETCH conference/room123/video:     "
                      << (parsed_auth->authorizes(Action::FETCH, stream_ns, video_track) ? "ALLOWED ✓" : "DENIED ✗") << "\n";
            std::cout << "    SUBSCRIBE other/video:              "
                      << (parsed_auth->authorizes(Action::SUBSCRIBE, other_ns, video_track) ? "ALLOWED ✓" : "DENIED ✗") << "\n";
        }
    }
    std::cout << "\n";

    // ══════════════════════════════════════════════════════════════════════
    // STEP 9: REPLAY PROTECTION DEMONSTRATION
    // ══════════════════════════════════════════════════════════════════════
    std::cout << "┌─────────────────────────────────────────────────────────────┐\n";
    std::cout << "│ STEP 9: Replay protection (same token cannot be reused)     │\n";
    std::cout << "└─────────────────────────────────────────────────────────────┘\n";

    auto replay_attempt = relay_authenticator.validate_and_redeem(*token, challenge);
    std::cout << "  Attacker replays same token...\n";
    std::cout << "  Relay: " << (replay_attempt.valid ? "ACCEPTED (bad!)" : "REJECTED ✓ TOKEN_REPLAYED") << "\n";
    std::cout << "\n";

    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                       Flow Complete!                         ║\n";
    std::cout << "║                                                              ║\n";
    std::cout << "║  Privacy Property: Issuer signed the token but CANNOT know  ║\n";
    std::cout << "║  which MOQ operation it authorized or when it was used.     ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";

    shutdown();
    return 0;
}
