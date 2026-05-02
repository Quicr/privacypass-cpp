// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/serialization.hpp>
#include <privacy_pass/extensions/moq/types.hpp>

#include <vector>

namespace privacy_pass::moq {

// MoQAuthScope - defines what actions are authorized on which resources
struct AuthScope {
    std::vector<Action> actions;  // Authorized actions
    NamespaceMatch namespace_match;
    TrackNameMatch track_name_match;

    // Builder pattern for constructing scopes
    class Builder {
    public:
        Builder& allow_action(Action action);
        Builder& allow_actions(std::initializer_list<Action> actions);
        Builder& for_namespace_exact(Namespace ns);
        Builder& for_namespace_prefix(Namespace prefix);
        Builder& for_namespace_suffix(Namespace suffix);
        Builder& for_namespace_containing(Namespace pattern);
        Builder& for_any_namespace();
        Builder& for_track_exact(TrackName name);
        Builder& for_track_prefix(TrackName prefix);
        Builder& for_track_suffix(TrackName suffix);
        Builder& for_track_containing(TrackName pattern);
        Builder& for_any_track();
        [[nodiscard]] AuthScope build() const;

    private:
        std::vector<Action> actions_;
        NamespaceMatch namespace_match_{WildcardMatch{}};
        TrackNameMatch track_name_match_{WildcardMatch{}};
    };

    // Check if this scope authorizes a specific action on a resource
    [[nodiscard]] bool authorizes(
        Action action,
        const Namespace& ns,
        const TrackName& track) const;

    // Serialize to wire format (for embedding in origin_info)
    [[nodiscard]] Result<Bytes> serialize() const;

    // Deserialize from wire format
    [[nodiscard]] static Result<AuthScope> deserialize(ByteView data);

    // Create a builder
    [[nodiscard]] static Builder builder();
};

}  // namespace privacy_pass::moq
