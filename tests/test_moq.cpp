// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/moq/client.hpp>
#include <privacy_pass/moq/relay.hpp>

using namespace privacy_pass;
using namespace privacy_pass::moq;

TEST_SUITE("MOQ Types") {
    TEST_CASE("Action names") {
        CHECK(action_name(Action::CLIENT_SETUP) == "CLIENT_SETUP");
        CHECK(action_name(Action::SUBSCRIBE) == "SUBSCRIBE");
        CHECK(action_name(Action::PUBLISH) == "PUBLISH");
    }

    TEST_CASE("Match type names") {
        CHECK(match_type_name(MatchType::MATCH_EXACT) == "EXACT");
        CHECK(match_type_name(MatchType::MATCH_PREFIX) == "PREFIX");
    }
}

TEST_SUITE("NamespaceMatchRule") {
    TEST_CASE("Exact match") {
        Namespace ns = {{0x01, 0x02}, {0x03, 0x04}};
        NamespaceMatchRule rule{MatchType::MATCH_EXACT, ns};

        CHECK(rule.matches(ns));

        Namespace different = {{0x01, 0x02}, {0x03, 0x05}};
        CHECK(!rule.matches(different));

        Namespace shorter = {{0x01, 0x02}};
        CHECK(!rule.matches(shorter));
    }

    TEST_CASE("Prefix match") {
        Namespace prefix = {{0x01, 0x02}};
        NamespaceMatchRule rule{MatchType::MATCH_PREFIX, prefix};

        Namespace exact = {{0x01, 0x02}};
        CHECK(rule.matches(exact));

        Namespace longer = {{0x01, 0x02}, {0x03, 0x04}};
        CHECK(rule.matches(longer));

        Namespace different = {{0xFF, 0xFF}};
        CHECK(!rule.matches(different));
    }

    TEST_CASE("Suffix match") {
        Namespace suffix = {{0x03, 0x04}};
        NamespaceMatchRule rule{MatchType::MATCH_SUFFIX, suffix};

        Namespace matching = {{0x01, 0x02}, {0x03, 0x04}};
        CHECK(rule.matches(matching));

        Namespace not_matching = {{0x01, 0x02}, {0x05, 0x06}};
        CHECK(!rule.matches(not_matching));
    }
}

TEST_SUITE("TrackNameMatchRule") {
    TEST_CASE("Exact match") {
        TrackName track = {0x74, 0x65, 0x73, 0x74};  // "test"
        TrackNameMatchRule rule{MatchType::MATCH_EXACT, track};

        CHECK(rule.matches(track));
        CHECK(!rule.matches({0x6F, 0x74, 0x68, 0x65, 0x72}));  // "other"
    }

    TEST_CASE("Prefix match") {
        TrackName prefix = {0x74, 0x65};  // "te"
        TrackNameMatchRule rule{MatchType::MATCH_PREFIX, prefix};

        CHECK(rule.matches({0x74, 0x65, 0x73, 0x74}));  // "test"
        CHECK(!rule.matches({0x6F, 0x74, 0x68, 0x65, 0x72}));  // "other"
    }

    TEST_CASE("Contains match") {
        TrackName pattern = {0x65, 0x73};  // "es"
        TrackNameMatchRule rule{MatchType::MATCH_CONTAINS, pattern};

        CHECK(rule.matches({0x74, 0x65, 0x73, 0x74}));  // "test"
        CHECK(!rule.matches({0x66, 0x6F, 0x6F}));  // "foo"
    }
}

TEST_SUITE("AuthScope") {
    TEST_CASE("Builder pattern") {
        auto scope = AuthScope::builder()
            .allow_action(Action::SUBSCRIBE)
            .allow_action(Action::FETCH)
            .for_namespace_exact({{0x01}})
            .for_track_prefix({0x74})
            .build();

        CHECK(scope.actions.size() == 2);
    }

    TEST_CASE("Authorization check") {
        auto scope = AuthScope::builder()
            .allow_actions({Action::SUBSCRIBE, Action::FETCH})
            .for_any_namespace()
            .for_any_track()
            .build();

        Namespace ns = {{0x01}};
        TrackName track = {0x74};

        CHECK(scope.authorizes(Action::SUBSCRIBE, ns, track));
        CHECK(scope.authorizes(Action::FETCH, ns, track));
        CHECK(!scope.authorizes(Action::PUBLISH, ns, track));
    }

    TEST_CASE("Serialization roundtrip") {
        auto original = AuthScope::builder()
            .allow_actions({Action::SUBSCRIBE, Action::PUBLISH})
            .for_namespace_prefix({{0x01, 0x02}})
            .for_track_exact({0x74, 0x65, 0x73, 0x74})
            .build();

        auto serialized = original.serialize();
        REQUIRE(serialized.has_value());

        auto restored = AuthScope::deserialize(
            ByteView(serialized->data(), serialized->size()));
        REQUIRE(restored.has_value());

        CHECK(restored->actions.size() == 2);
    }
}

TEST_SUITE("AuthorizationInfo") {
    TEST_CASE("Builder pattern") {
        auto info = AuthorizationInfo::builder()
            .add_scope(AuthScope::builder()
                .allow_action(Action::SUBSCRIBE)
                .for_any_namespace()
                .for_any_track()
                .build())
            .add_scope(AuthScope::builder()
                .allow_action(Action::PUBLISH)
                .for_namespace_exact({{0x01}})
                .for_any_track()
                .build())
            .build();

        CHECK(info.scopes.size() == 2);
    }

    TEST_CASE("Authorization across scopes") {
        auto info = AuthorizationInfo::builder()
            .add_scope(AuthScope::builder()
                .allow_action(Action::SUBSCRIBE)
                .for_namespace_exact({{0x01}})
                .for_any_track()
                .build())
            .add_scope(AuthScope::builder()
                .allow_action(Action::PUBLISH)
                .for_namespace_exact({{0x02}})
                .for_any_track()
                .build())
            .build();

        Namespace ns1 = {{0x01}};
        Namespace ns2 = {{0x02}};
        TrackName track = {0x00};

        CHECK(info.authorizes(Action::SUBSCRIBE, ns1, track));
        CHECK(!info.authorizes(Action::SUBSCRIBE, ns2, track));
        CHECK(info.authorizes(Action::PUBLISH, ns2, track));
        CHECK(!info.authorizes(Action::PUBLISH, ns1, track));
    }

    TEST_CASE("Presets") {
        SUBCASE("for_subscriber") {
            Namespace ns = {{0x6D, 0x6F, 0x71}};
            TrackName track = {0x76, 0x69, 0x64, 0x65, 0x6F};

            auto info = AuthorizationInfo::for_subscriber(ns, track);

            CHECK(info.authorizes(Action::CLIENT_SETUP, ns, track));
            CHECK(info.authorizes(Action::SUBSCRIBE, ns, track));
            CHECK(info.authorizes(Action::FETCH, ns, track));
            CHECK(!info.authorizes(Action::PUBLISH, ns, track));
        }

        SUBCASE("for_publisher") {
            Namespace ns = {{0x6D, 0x6F, 0x71}};
            TrackName track = {0x00};

            auto info = AuthorizationInfo::for_publisher(ns);

            CHECK(info.authorizes(Action::CLIENT_SETUP, ns, track));
            CHECK(info.authorizes(Action::PUBLISH_NAMESPACE, ns, track));
            CHECK(info.authorizes(Action::PUBLISH, ns, track));
            CHECK(!info.authorizes(Action::SUBSCRIBE, ns, track));
        }

        SUBCASE("for_relay") {
            Namespace ns = {{0x00}};
            TrackName track = {0x00};

            auto info = AuthorizationInfo::for_relay();

            // Relay can do everything
            CHECK(info.authorizes(Action::CLIENT_SETUP, ns, track));
            CHECK(info.authorizes(Action::SERVER_SETUP, ns, track));
            CHECK(info.authorizes(Action::SUBSCRIBE, ns, track));
            CHECK(info.authorizes(Action::PUBLISH, ns, track));
        }
    }

    TEST_CASE("Serialization roundtrip") {
        auto original = AuthorizationInfo::for_subscriber({{0x01}}, {0x02});

        auto serialized = original.serialize();
        REQUIRE(serialized.has_value());

        auto restored = AuthorizationInfo::deserialize(
            ByteView(serialized->data(), serialized->size()));
        REQUIRE(restored.has_value());

        CHECK(restored->scopes.size() == original.scopes.size());
    }

    TEST_CASE("Encode/decode for origin_info") {
        auto original = AuthorizationInfo::for_relay();

        auto encoded = original.encode_for_origin_info();
        REQUIRE(encoded.has_value());

        auto decoded = AuthorizationInfo::decode_from_origin_info(*encoded);
        REQUIRE(decoded.has_value());

        // Check it still authorizes the same actions
        Namespace ns = {{0x00}};
        TrackName track = {0x00};
        CHECK(decoded->authorizes(Action::SUBSCRIBE, ns, track));
    }
}

TEST_SUITE("VerificationResult") {
    TEST_CASE("Success") {
        auto info = AuthorizationInfo::for_relay();
        auto result = VerificationResult::success(std::move(info));

        CHECK(result.valid);
        CHECK(!result.error_code.has_value());
        CHECK(result.authorization_info.has_value());
    }

    TEST_CASE("Failure") {
        auto result = VerificationResult::failure(
            MoqErrorCode::TOKEN_INVALID,
            "Invalid signature");

        CHECK(!result.valid);
        REQUIRE(result.error_code.has_value());
        CHECK(*result.error_code == MoqErrorCode::TOKEN_INVALID);
        CHECK(result.error_message.has_value());
    }
}

TEST_SUITE("MoqRelay") {
    TEST_CASE("Create challenge with authorization") {
        RelayConfig config{
            .relay_name = "relay.example.com",
            .issuer_name = "issuer.example.com",
        };

        MoqRelay relay(config);

        auto auth_info = AuthorizationInfo::for_subscriber({{0x01}}, {0x02});

        auto challenge = relay.create_challenge(
            TokenType::BLIND_RSA,
            auth_info);

        REQUIRE(challenge.has_value());
        CHECK(challenge->token_type == TokenType::BLIND_RSA);
        CHECK(challenge->issuer_name == "issuer.example.com");
        CHECK(!challenge->origin_info.empty());
    }

    TEST_CASE("Issuer mode") {
        RelayConfig config{
            .relay_name = "relay.example.com",
            .issuer_name = "issuer.example.com",
        };

        MoqRelay relay(config);

        // Enable issuer mode
        auto keypair = crypto::BlindRsaPrivateKey::generate();
        REQUIRE(keypair.has_value());

        relay.enable_issuer_mode(std::move(keypair->first));

        auto keys = relay.issuer_public_keys();
        CHECK(!keys.empty());
    }

    TEST_CASE("Config access") {
        RelayConfig config{
            .relay_name = "relay.example.com",
            .issuer_name = "issuer.example.com",
            .token_validity_window = std::chrono::seconds(7200),
        };

        MoqRelay relay(config);

        CHECK(relay.config().relay_name == "relay.example.com");
        CHECK(relay.config().issuer_name == "issuer.example.com");
        CHECK(relay.config().token_validity_window == std::chrono::seconds(7200));
    }
}

TEST_SUITE("MoqClient") {
    TEST_CASE("Base client access") {
        MoqClient client;

        auto& base = client.base_client();
        (void)base;  // Just verify it compiles and doesn't crash
    }
}
