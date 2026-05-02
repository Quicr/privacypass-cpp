// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/core/token.hpp>

#include <spdlog/spdlog.h>

namespace privacy_pass {

// AuthenticatorInput implementation
size_t AuthenticatorInput::serialized_size() const noexcept {
    return 2 + 32 + 32 + 32;  // type + nonce + challenge_digest + token_key_id
}

Result<Bytes> AuthenticatorInput::serialize() const {
    ByteWriter writer(serialized_size());

    writer.write_u16(static_cast<uint16_t>(token_type));
    writer.write_array(nonce);
    writer.write_array(challenge_digest);
    writer.write_array(token_key_id);

    return writer.take();
}

Result<AuthenticatorInput> AuthenticatorInput::deserialize(ByteView data) {
    ByteReader reader(data);

    auto type = reader.read_u16();
    if (!type) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read token_type"});
    }

    auto nonce = reader.read_array<32>();
    if (!nonce) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read nonce"});
    }

    auto digest = reader.read_array<32>();
    if (!digest) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read challenge_digest"});
    }

    auto key_id = reader.read_array<32>();
    if (!key_id) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read token_key_id"});
    }

    return AuthenticatorInput{
        .token_type = static_cast<TokenType>(*type),
        .nonce = *nonce,
        .challenge_digest = *digest,
        .token_key_id = *key_id,
    };
}

// Token implementation
Token Token::create(
    TokenType type,
    Nonce nonce,
    ChallengeDigest digest,
    TokenKeyId key_id,
    Bytes auth) {

    return Token{
        .token_type = type,
        .nonce = nonce,
        .challenge_digest = digest,
        .token_key_id = key_id,
        .authenticator = std::move(auth),
    };
}

size_t Token::serialized_size() const noexcept {
    return 2 + 32 + 32 + 32 + authenticator.size();
}

Result<Bytes> Token::serialize() const {
    ByteWriter writer(serialized_size());

    writer.write_u16(static_cast<uint16_t>(token_type));
    writer.write_array(nonce);
    writer.write_array(challenge_digest);
    writer.write_array(token_key_id);
    writer.write_bytes(ByteView(authenticator.data(), authenticator.size()));

    return writer.take();
}

Result<Token> Token::deserialize(ByteView data) {
    ByteReader reader(data);

    auto type = reader.read_u16();
    if (!type) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read token_type"});
    }

    Token token;
    token.token_type = static_cast<TokenType>(*type);

    auto nonce = reader.read_array<32>();
    if (!nonce) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read nonce"});
    }
    token.nonce = *nonce;

    auto digest = reader.read_array<32>();
    if (!digest) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read challenge_digest"});
    }
    token.challenge_digest = *digest;

    auto key_id = reader.read_array<32>();
    if (!key_id) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read token_key_id"});
    }
    token.token_key_id = *key_id;

    // Read authenticator based on token type
    auto info = TokenTypeInfo::for_type(token.token_type);
    if (reader.remaining() < info.authenticator_size) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Insufficient data for authenticator"});
    }

    auto auth = reader.read_bytes(info.authenticator_size);
    if (!auth) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read authenticator"});
    }
    token.authenticator.assign(auth->begin(), auth->end());

    return token;
}

AuthenticatorInput Token::authenticator_input() const {
    return AuthenticatorInput{
        .token_type = token_type,
        .nonce = nonce,
        .challenge_digest = challenge_digest,
        .token_key_id = token_key_id,
    };
}

Result<void> Token::validate() const {
    auto info = TokenTypeInfo::for_type(token_type);

    if (info.authenticator_size == 0) {
        return std::unexpected(Error{ErrorCode::UNSUPPORTED_TOKEN_TYPE,
            "Unknown token type"});
    }

    if (authenticator.size() != info.authenticator_size) {
        return std::unexpected(Error{ErrorCode::TOKEN_MALFORMED,
            "Invalid authenticator size"});
    }

    return {};
}

}  // namespace privacy_pass
