// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/http/auth_scheme.hpp>

#include <spdlog/spdlog.h>
#include <regex>

namespace privacy_pass::http {

namespace {

// Helper to parse auth-param format: key="value" or key=token
// Implements RFC 7230 quoted-string parsing with escape handling
std::optional<std::pair<std::string, std::string>> parse_auth_param(std::string_view& input) {
    // Skip whitespace (OWS)
    while (!input.empty() && (input[0] == ' ' || input[0] == '\t')) {
        input.remove_prefix(1);
    }

    if (input.empty()) {
        return std::nullopt;
    }

    // Find key (token characters per RFC 7230)
    size_t eq_pos = input.find('=');
    if (eq_pos == std::string_view::npos || eq_pos == 0) {
        return std::nullopt;
    }

    std::string key(input.substr(0, eq_pos));
    // Trim trailing whitespace from key
    while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) {
        key.pop_back();
    }
    input.remove_prefix(eq_pos + 1);

    // Skip whitespace after '='
    while (!input.empty() && (input[0] == ' ' || input[0] == '\t')) {
        input.remove_prefix(1);
    }

    if (input.empty()) {
        return std::nullopt;
    }

    std::string value;
    if (input[0] == '"') {
        // Quoted string with escape handling per RFC 7230 Section 3.2.6
        input.remove_prefix(1);
        bool escaped = false;

        while (!input.empty()) {
            char c = input[0];
            input.remove_prefix(1);

            if (escaped) {
                // Per RFC 7230, quoted-pair is "\" HTAB / SP / VCHAR / obs-text
                value.push_back(c);
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                // End of quoted string
                break;
            } else {
                value.push_back(c);
            }
        }

        if (escaped) {
            // Trailing backslash without following character
            return std::nullopt;
        }
    } else {
        // Token (unquoted)
        size_t end = 0;
        while (end < input.size() && input[end] != ',' && input[end] != ' ' && input[end] != '\t') {
            end++;
        }
        value = std::string(input.substr(0, end));
        input.remove_prefix(end);
    }

    // Skip OWS and comma
    while (!input.empty() && (input[0] == ' ' || input[0] == '\t')) {
        input.remove_prefix(1);
    }
    if (!input.empty() && input[0] == ',') {
        input.remove_prefix(1);
    }
    while (!input.empty() && (input[0] == ' ' || input[0] == '\t')) {
        input.remove_prefix(1);
    }

    return std::make_pair(std::move(key), std::move(value));
}

}  // namespace

// ChallengeHeader implementation
std::string ChallengeHeader::format() const {
    std::string result = "PrivateToken challenge=\"";
    result += challenge;
    result += "\", token-key=\"";
    result += token_key;
    result += "\"";

    if (max_age) {
        result += ", max-age=";
        result += std::to_string(*max_age);
    }

    return result;
}

Result<ChallengeHeader> ChallengeHeader::parse(std::string_view header) {
    // Check for PrivateToken scheme
    if (!header.starts_with("PrivateToken ")) {
        return std::unexpected(Error{ErrorCode::INVALID_HEADER,
            "Not a PrivateToken header"});
    }

    header.remove_prefix(13);  // "PrivateToken "

    ChallengeHeader result;

    while (!header.empty()) {
        auto param = parse_auth_param(header);
        if (!param) {
            break;
        }

        if (param->first == "challenge") {
            result.challenge = std::move(param->second);
        } else if (param->first == "token-key") {
            result.token_key = std::move(param->second);
        } else if (param->first == "max-age") {
            try {
                result.max_age = static_cast<uint32_t>(std::stoul(param->second));
            } catch (...) {
                // Ignore invalid max-age
            }
        }
    }

    if (result.challenge.empty()) {
        return std::unexpected(Error{ErrorCode::MISSING_PARAMETER,
            "Missing challenge parameter"});
    }

    if (result.token_key.empty()) {
        return std::unexpected(Error{ErrorCode::MISSING_PARAMETER,
            "Missing token-key parameter"});
    }

    return result;
}

Result<TokenChallenge> ChallengeHeader::decode_challenge() const {
    auto decoded = base64url::decode(challenge);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }

    return TokenChallenge::deserialize(ByteView(decoded->data(), decoded->size()));
}

Result<Bytes> ChallengeHeader::decode_token_key() const {
    return base64url::decode(token_key);
}

// AuthorizationHeader implementation
std::string AuthorizationHeader::format() const {
    return "PrivateToken token=\"" + token + "\"";
}

Result<AuthorizationHeader> AuthorizationHeader::parse(std::string_view header) {
    if (!header.starts_with("PrivateToken ")) {
        return std::unexpected(Error{ErrorCode::INVALID_HEADER,
            "Not a PrivateToken header"});
    }

    header.remove_prefix(13);

    AuthorizationHeader result;

    while (!header.empty()) {
        auto param = parse_auth_param(header);
        if (!param) {
            break;
        }

        if (param->first == "token") {
            result.token = std::move(param->second);
        }
    }

    if (result.token.empty()) {
        return std::unexpected(Error{ErrorCode::MISSING_PARAMETER,
            "Missing token parameter"});
    }

    return result;
}

Result<Token> AuthorizationHeader::decode_token() const {
    auto decoded = base64url::decode(token);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }

    return Token::deserialize(ByteView(decoded->data(), decoded->size()));
}

// Helper functions
Result<std::string> build_www_authenticate(
    const TokenChallenge& challenge,
    ByteView token_key,
    std::optional<uint32_t> max_age) {

    auto serialized = challenge.serialize();
    if (!serialized) {
        return std::unexpected(serialized.error());
    }

    ChallengeHeader header;
    header.challenge = base64url::encode(ByteView(serialized->data(), serialized->size()));
    header.token_key = base64url::encode(token_key);
    header.max_age = max_age;

    return header.format();
}

Result<std::string> build_authorization(const Token& token) {
    auto serialized = token.serialize();
    if (!serialized) {
        return std::unexpected(serialized.error());
    }

    AuthorizationHeader header;
    header.token = base64url::encode(ByteView(serialized->data(), serialized->size()));

    return header.format();
}

Result<Token> parse_authorization(std::string_view header) {
    auto parsed = AuthorizationHeader::parse(header);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }

    return parsed->decode_token();
}

}  // namespace privacy_pass::http
