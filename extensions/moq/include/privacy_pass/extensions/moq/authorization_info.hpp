// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/serialization.hpp>
#include <privacy_pass/extensions/moq/auth_scope.hpp>

#include <vector>

namespace privacy_pass::moq {

// MoQAuthorizationInfo - collection of authorization scopes
// Embedded in TokenChallenge.origin_info field
struct AuthorizationInfo {
    std::vector<AuthScope> scopes;

    // Builder pattern
    class Builder {
    public:
        Builder& add_scope(AuthScope scope);
        Builder& add_scopes(std::vector<AuthScope> scopes);
        [[nodiscard]] AuthorizationInfo build() const;

    private:
        std::vector<AuthScope> scopes_;
    };

    // Check if any scope authorizes a specific action
    [[nodiscard]] bool authorizes(
        Action action,
        const Namespace& ns,
        const TrackName& track) const;

    // Check if all required actions are authorized
    [[nodiscard]] bool authorizes_all(
        const std::vector<Action>& actions,
        const Namespace& ns,
        const TrackName& track) const;

    // Serialize to wire format
    [[nodiscard]] Result<Bytes> serialize() const;

    // Deserialize from wire format
    [[nodiscard]] static Result<AuthorizationInfo> deserialize(ByteView data);

    // Encode for embedding in origin_info (as comma-separated base64url)
    [[nodiscard]] Result<std::string> encode_for_origin_info() const;

    // Decode from origin_info
    [[nodiscard]] static Result<AuthorizationInfo> decode_from_origin_info(
        std::string_view origin_info);

    // Create a builder
    [[nodiscard]] static Builder builder();

    // Common presets
    [[nodiscard]] static AuthorizationInfo for_subscriber(
        const Namespace& ns,
        const TrackName& track);

    [[nodiscard]] static AuthorizationInfo for_publisher(
        const Namespace& ns);

    [[nodiscard]] static AuthorizationInfo for_relay();
};

}  // namespace privacy_pass::moq
