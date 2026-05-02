// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/extensions/moq/authorization_info.hpp>

#include <spdlog/spdlog.h>

namespace privacy_pass::moq {

// AuthorizationInfo::Builder implementation
AuthorizationInfo::Builder& AuthorizationInfo::Builder::add_scope(AuthScope scope) {
    scopes_.push_back(std::move(scope));
    return *this;
}

AuthorizationInfo::Builder& AuthorizationInfo::Builder::add_scopes(std::vector<AuthScope> scopes) {
    for (auto& scope : scopes) {
        scopes_.push_back(std::move(scope));
    }
    return *this;
}

AuthorizationInfo AuthorizationInfo::Builder::build() const {
    return AuthorizationInfo{.scopes = scopes_};
}

// AuthorizationInfo implementation
AuthorizationInfo::Builder AuthorizationInfo::builder() {
    return Builder{};
}

bool AuthorizationInfo::authorizes(
    Action action,
    const Namespace& ns,
    const TrackName& track) const {

    for (const auto& scope : scopes) {
        if (scope.authorizes(action, ns, track)) {
            return true;
        }
    }
    return false;
}

bool AuthorizationInfo::authorizes_all(
    const std::vector<Action>& actions,
    const Namespace& ns,
    const TrackName& track) const {

    for (auto action : actions) {
        if (!authorizes(action, ns, track)) {
            return false;
        }
    }
    return true;
}

Result<Bytes> AuthorizationInfo::serialize() const {
    ByteWriter writer;

    // Scope count (1 byte)
    writer.write_u8(static_cast<uint8_t>(scopes.size()));

    // Each scope
    for (const auto& scope : scopes) {
        auto scope_bytes = scope.serialize();
        if (!scope_bytes) {
            return std::unexpected(scope_bytes.error());
        }

        // Length-prefixed scope data
        writer.write_u16(static_cast<uint16_t>(scope_bytes->size()));
        writer.write_bytes(ByteView(scope_bytes->data(), scope_bytes->size()));
    }

    return writer.take();
}

Result<AuthorizationInfo> AuthorizationInfo::deserialize(ByteView data) {
    ByteReader reader(data);

    auto scope_count = reader.read_u8();
    if (!scope_count) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read scope count"});
    }

    AuthorizationInfo info;
    info.scopes.reserve(*scope_count);

    for (uint8_t i = 0; i < *scope_count; ++i) {
        auto scope_len = reader.read_u16();
        if (!scope_len) {
            return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read scope length"});
        }

        auto scope_data = reader.read_bytes(*scope_len);
        if (!scope_data) {
            return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read scope data"});
        }

        auto scope = AuthScope::deserialize(*scope_data);
        if (!scope) {
            return std::unexpected(scope.error());
        }

        info.scopes.push_back(std::move(*scope));
    }

    return info;
}

Result<std::string> AuthorizationInfo::encode_for_origin_info() const {
    auto serialized = serialize();
    if (!serialized) {
        return std::unexpected(serialized.error());
    }

    return base64url::encode(ByteView(serialized->data(), serialized->size()));
}

Result<AuthorizationInfo> AuthorizationInfo::decode_from_origin_info(std::string_view origin_info) {
    auto decoded = base64url::decode(origin_info);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }

    return deserialize(ByteView(decoded->data(), decoded->size()));
}

// Common presets
AuthorizationInfo AuthorizationInfo::for_subscriber(
    const Namespace& ns,
    const TrackName& track) {

    return AuthorizationInfo::builder()
        .add_scope(AuthScope::builder()
            .allow_actions({
                Action::CLIENT_SETUP,
                Action::SUBSCRIBE,
                Action::FETCH,
                Action::TRACK_STATUS,
            })
            .for_namespace_exact(ns)
            .for_track_exact(track)
            .build())
        .build();
}

AuthorizationInfo AuthorizationInfo::for_publisher(const Namespace& ns) {
    return AuthorizationInfo::builder()
        .add_scope(AuthScope::builder()
            .allow_actions({
                Action::CLIENT_SETUP,
                Action::PUBLISH_NAMESPACE,
                Action::PUBLISH,
            })
            .for_namespace_exact(ns)
            .for_any_track()
            .build())
        .build();
}

AuthorizationInfo AuthorizationInfo::for_relay() {
    return AuthorizationInfo::builder()
        .add_scope(AuthScope::builder()
            .allow_actions({
                Action::CLIENT_SETUP,
                Action::SERVER_SETUP,
                Action::PUBLISH_NAMESPACE,
                Action::SUBSCRIBE_NAMESPACE,
                Action::SUBSCRIBE,
                Action::REQUEST_UPDATE,
                Action::PUBLISH,
                Action::FETCH,
                Action::TRACK_STATUS,
            })
            .for_any_namespace()
            .for_any_track()
            .build())
        .build();
}

}  // namespace privacy_pass::moq
