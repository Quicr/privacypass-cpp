// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/moq/auth_scope.hpp>

#include <spdlog/spdlog.h>
#include <algorithm>

namespace privacy_pass::moq {

// NamespaceMatchRule implementation
bool NamespaceMatchRule::matches(const Namespace& ns) const {
    switch (match_type) {
        case MatchType::MATCH_EXACT:
            if (ns.size() != pattern.size()) return false;
            for (size_t i = 0; i < ns.size(); ++i) {
                if (ns[i] != pattern[i]) return false;
            }
            return true;

        case MatchType::MATCH_PREFIX:
            if (ns.size() < pattern.size()) return false;
            for (size_t i = 0; i < pattern.size(); ++i) {
                if (ns[i] != pattern[i]) return false;
            }
            return true;

        case MatchType::MATCH_SUFFIX:
            if (ns.size() < pattern.size()) return false;
            for (size_t i = 0; i < pattern.size(); ++i) {
                if (ns[ns.size() - pattern.size() + i] != pattern[i]) return false;
            }
            return true;

        case MatchType::MATCH_CONTAINS:
            for (size_t start = 0; start + pattern.size() <= ns.size(); ++start) {
                bool found = true;
                for (size_t i = 0; i < pattern.size() && found; ++i) {
                    if (ns[start + i] != pattern[i]) found = false;
                }
                if (found) return true;
            }
            return false;
    }
    return false;
}

// TrackNameMatchRule implementation
bool TrackNameMatchRule::matches(const TrackName& name) const {
    switch (match_type) {
        case MatchType::MATCH_EXACT:
            return name == pattern;

        case MatchType::MATCH_PREFIX:
            if (name.size() < pattern.size()) return false;
            return std::equal(pattern.begin(), pattern.end(), name.begin());

        case MatchType::MATCH_SUFFIX:
            if (name.size() < pattern.size()) return false;
            return std::equal(pattern.rbegin(), pattern.rend(), name.rbegin());

        case MatchType::MATCH_CONTAINS:
            return std::search(name.begin(), name.end(),
                pattern.begin(), pattern.end()) != name.end();
    }
    return false;
}

// AuthScope::Builder implementation
AuthScope::Builder& AuthScope::Builder::allow_action(Action action) {
    actions_.push_back(action);
    return *this;
}

AuthScope::Builder& AuthScope::Builder::allow_actions(std::initializer_list<Action> actions) {
    for (auto action : actions) {
        actions_.push_back(action);
    }
    return *this;
}

AuthScope::Builder& AuthScope::Builder::for_namespace_exact(Namespace ns) {
    namespace_match_ = NamespaceMatchRule{MatchType::MATCH_EXACT, std::move(ns)};
    return *this;
}

AuthScope::Builder& AuthScope::Builder::for_namespace_prefix(Namespace prefix) {
    namespace_match_ = NamespaceMatchRule{MatchType::MATCH_PREFIX, std::move(prefix)};
    return *this;
}

AuthScope::Builder& AuthScope::Builder::for_namespace_suffix(Namespace suffix) {
    namespace_match_ = NamespaceMatchRule{MatchType::MATCH_SUFFIX, std::move(suffix)};
    return *this;
}

AuthScope::Builder& AuthScope::Builder::for_namespace_containing(Namespace pattern) {
    namespace_match_ = NamespaceMatchRule{MatchType::MATCH_CONTAINS, std::move(pattern)};
    return *this;
}

AuthScope::Builder& AuthScope::Builder::for_any_namespace() {
    namespace_match_ = WildcardMatch{};
    return *this;
}

AuthScope::Builder& AuthScope::Builder::for_track_exact(TrackName name) {
    track_name_match_ = TrackNameMatchRule{MatchType::MATCH_EXACT, std::move(name)};
    return *this;
}

AuthScope::Builder& AuthScope::Builder::for_track_prefix(TrackName prefix) {
    track_name_match_ = TrackNameMatchRule{MatchType::MATCH_PREFIX, std::move(prefix)};
    return *this;
}

AuthScope::Builder& AuthScope::Builder::for_track_suffix(TrackName suffix) {
    track_name_match_ = TrackNameMatchRule{MatchType::MATCH_SUFFIX, std::move(suffix)};
    return *this;
}

AuthScope::Builder& AuthScope::Builder::for_track_containing(TrackName pattern) {
    track_name_match_ = TrackNameMatchRule{MatchType::MATCH_CONTAINS, std::move(pattern)};
    return *this;
}

AuthScope::Builder& AuthScope::Builder::for_any_track() {
    track_name_match_ = WildcardMatch{};
    return *this;
}

AuthScope AuthScope::Builder::build() const {
    return AuthScope{
        .actions = actions_,
        .namespace_match = namespace_match_,
        .track_name_match = track_name_match_,
    };
}

// AuthScope implementation
AuthScope::Builder AuthScope::builder() {
    return Builder{};
}

bool AuthScope::authorizes(
    Action action,
    const Namespace& ns,
    const TrackName& track) const {

    // Check if action is in allowed list
    bool action_allowed = std::find(actions.begin(), actions.end(), action) != actions.end();
    if (!action_allowed) {
        return false;
    }

    // Check namespace match
    bool ns_matches = std::visit([&ns](const auto& match) {
        using T = std::decay_t<decltype(match)>;
        if constexpr (std::is_same_v<T, WildcardMatch>) {
            return true;
        } else {
            return match.matches(ns);
        }
    }, namespace_match);

    if (!ns_matches) {
        return false;
    }

    // Check track name match
    bool track_matches = std::visit([&track](const auto& match) {
        using T = std::decay_t<decltype(match)>;
        if constexpr (std::is_same_v<T, WildcardMatch>) {
            return true;
        } else {
            return match.matches(track);
        }
    }, track_name_match);

    return track_matches;
}

Result<Bytes> AuthScope::serialize() const {
    ByteWriter writer;

    // Actions count (1 byte) + actions
    writer.write_u8(static_cast<uint8_t>(actions.size()));
    for (auto action : actions) {
        writer.write_u8(static_cast<uint8_t>(action));
    }

    // Namespace match
    std::visit([&writer](const auto& match) {
        using T = std::decay_t<decltype(match)>;
        if constexpr (std::is_same_v<T, WildcardMatch>) {
            writer.write_u8(0xFF);  // Wildcard marker
        } else {
            writer.write_u8(static_cast<uint8_t>(match.match_type));
            writer.write_u8(static_cast<uint8_t>(match.pattern.size()));
            for (const auto& elem : match.pattern) {
                writer.write_u16(static_cast<uint16_t>(elem.size()));
                writer.write_bytes(ByteView(elem.data(), elem.size()));
            }
        }
    }, namespace_match);

    // Track name match
    std::visit([&writer](const auto& match) {
        using T = std::decay_t<decltype(match)>;
        if constexpr (std::is_same_v<T, WildcardMatch>) {
            writer.write_u8(0xFF);
        } else {
            writer.write_u8(static_cast<uint8_t>(match.match_type));
            writer.write_u16(static_cast<uint16_t>(match.pattern.size()));
            writer.write_bytes(ByteView(match.pattern.data(), match.pattern.size()));
        }
    }, track_name_match);

    return writer.take();
}

Result<AuthScope> AuthScope::deserialize(ByteView data) {
    ByteReader reader(data);

    AuthScope scope;

    // Read actions
    auto actions_count = reader.read_u8();
    if (!actions_count) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read actions count"});
    }

    for (uint8_t i = 0; i < *actions_count; ++i) {
        auto action = reader.read_u8();
        if (!action) {
            return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read action"});
        }
        scope.actions.push_back(static_cast<Action>(*action));
    }

    // Read namespace match
    auto ns_type = reader.read_u8();
    if (!ns_type) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read namespace match type"});
    }

    if (*ns_type == 0xFF) {
        scope.namespace_match = WildcardMatch{};
    } else {
        NamespaceMatchRule rule;
        rule.match_type = static_cast<MatchType>(*ns_type);

        auto ns_count = reader.read_u8();
        if (!ns_count) {
            return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read namespace count"});
        }

        for (uint8_t i = 0; i < *ns_count; ++i) {
            auto elem_len = reader.read_u16();
            if (!elem_len) {
                return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read element length"});
            }

            auto elem_data = reader.read_bytes(*elem_len);
            if (!elem_data) {
                return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read element"});
            }

            rule.pattern.push_back(Bytes(elem_data->begin(), elem_data->end()));
        }

        scope.namespace_match = std::move(rule);
    }

    // Read track name match
    auto track_type = reader.read_u8();
    if (!track_type) {
        return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read track match type"});
    }

    if (*track_type == 0xFF) {
        scope.track_name_match = WildcardMatch{};
    } else {
        TrackNameMatchRule rule;
        rule.match_type = static_cast<MatchType>(*track_type);

        auto track_len = reader.read_u16();
        if (!track_len) {
            return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read track length"});
        }

        auto track_data = reader.read_bytes(*track_len);
        if (!track_data) {
            return std::unexpected(Error{ErrorCode::UNEXPECTED_END, "Failed to read track pattern"});
        }

        rule.pattern.assign(track_data->begin(), track_data->end());
        scope.track_name_match = std::move(rule);
    }

    return scope;
}

}  // namespace privacy_pass::moq
