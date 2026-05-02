// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/types.hpp>

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace privacy_pass::moq {

// MoQ Actions (from draft-ietf-moq-privacy-pass-auth)
enum class Action : uint8_t {
    CLIENT_SETUP = 0,
    SERVER_SETUP = 1,
    PUBLISH_NAMESPACE = 2,
    SUBSCRIBE_NAMESPACE = 3,
    SUBSCRIBE = 4,
    REQUEST_UPDATE = 5,
    PUBLISH = 6,
    FETCH = 7,
    TRACK_STATUS = 8,
};

// Match types for namespace and track name filtering
enum class MatchType : uint8_t {
    MATCH_EXACT = 0,
    MATCH_PREFIX = 1,
    MATCH_SUFFIX = 2,
    MATCH_CONTAINS = 3,
};

// MoQ-specific error codes
enum class MoqErrorCode : uint16_t {
    TOKEN_MISSING = 0x0100,
    TOKEN_INVALID = 0x0101,
    TOKEN_EXPIRED = 0x0102,
    TOKEN_REPLAYED = 0x0103,
    SCOPE_MISMATCH = 0x0104,
    ISSUER_UNKNOWN = 0x0105,
    TOKEN_MALFORMED = 0x0106,
};

// Namespace tuple element
using NamespaceElement = Bytes;

// Namespace tuple (sequence of byte strings)
using Namespace = std::vector<NamespaceElement>;

// Track name (byte string)
using TrackName = Bytes;

// Match rule for namespace
struct NamespaceMatchRule {
    MatchType match_type;
    Namespace pattern;  // Elements to match against

    [[nodiscard]] bool matches(const Namespace& ns) const;
};

// Match rule for track name
struct TrackNameMatchRule {
    MatchType match_type;
    TrackName pattern;

    [[nodiscard]] bool matches(const TrackName& name) const;
};

// Wildcard match (matches anything)
struct WildcardMatch {};

// Match rule that can be either specific or wildcard
using NamespaceMatch = std::variant<NamespaceMatchRule, WildcardMatch>;
using TrackNameMatch = std::variant<TrackNameMatchRule, WildcardMatch>;

// String conversion utilities
[[nodiscard]] constexpr std::string_view action_name(Action action) noexcept {
    switch (action) {
        case Action::CLIENT_SETUP:
            return "CLIENT_SETUP";
        case Action::SERVER_SETUP:
            return "SERVER_SETUP";
        case Action::PUBLISH_NAMESPACE:
            return "PUBLISH_NAMESPACE";
        case Action::SUBSCRIBE_NAMESPACE:
            return "SUBSCRIBE_NAMESPACE";
        case Action::SUBSCRIBE:
            return "SUBSCRIBE";
        case Action::REQUEST_UPDATE:
            return "REQUEST_UPDATE";
        case Action::PUBLISH:
            return "PUBLISH";
        case Action::FETCH:
            return "FETCH";
        case Action::TRACK_STATUS:
            return "TRACK_STATUS";
        default:
            return "UNKNOWN";
    }
}

[[nodiscard]] constexpr std::string_view match_type_name(MatchType type) noexcept {
    switch (type) {
        case MatchType::MATCH_EXACT:
            return "EXACT";
        case MatchType::MATCH_PREFIX:
            return "PREFIX";
        case MatchType::MATCH_SUFFIX:
            return "SUFFIX";
        case MatchType::MATCH_CONTAINS:
            return "CONTAINS";
        default:
            return "UNKNOWN";
    }
}

}  // namespace privacy_pass::moq
