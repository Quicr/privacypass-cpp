// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <doctest/doctest.h>
#include <privacy_pass/extensions/moq.hpp>
#include <privacy_pass/core/token_provider.hpp>
#include <privacy_pass/core/token_authenticator.hpp>

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

TEST_SUITE("TokenProvider") {
    TEST_CASE("Configuration") {
        TokenProviderConfig config{
            .max_cached_tokens = 50,
            .token_prefetch_threshold = std::chrono::seconds(120),
            .origin_name = "origin.example.com",
        };

        TokenProvider provider(config);
        CHECK(provider.config().max_cached_tokens == 50);
    }

    TEST_CASE("Issuer management") {
        TokenProvider provider;

        CHECK(!provider.has_issuer("test.example.com"));

        PublicKey key{
            .type = TokenType::BLIND_RSA,
            .data = {0x01, 0x02, 0x03},
            .key_id = {},
        };

        provider.add_issuer_key("test.example.com", key);
        CHECK(provider.has_issuer("test.example.com"));

        provider.remove_issuer("test.example.com");
        CHECK(!provider.has_issuer("test.example.com"));
    }

    TEST_CASE("Token caching") {
        TokenProvider provider;

        ChallengeDigest digest{};
        digest.fill(0x42);

        CHECK(provider.cached_token_count(digest) == 0);

        // Create a dummy token
        Token token{
            .token_type = TokenType::BLIND_RSA,
            .nonce = {},
            .challenge_digest = digest,
            .token_key_id = {},
            .authenticator = {},
        };

        provider.store_tokens(digest, {token});
        CHECK(provider.cached_token_count(digest) == 1);

        auto retrieved = provider.get_cached_token(digest);
        CHECK(retrieved.has_value());
        CHECK(provider.cached_token_count(digest) == 0);

        provider.clear_cache();
    }
}

TEST_SUITE("TokenAuthenticator") {
    TEST_CASE("Configuration") {
        TokenAuthenticatorConfig config{
            .issuer_name = "issuer.example.com",
            .origin_names = {"origin.example.com"},
            .redemption_window = std::chrono::seconds(7200),
        };

        TokenAuthenticator auth(config);
        CHECK(auth.config().issuer_name == "issuer.example.com");
        CHECK(auth.config().redemption_window == std::chrono::seconds(7200));
    }

    TEST_CASE("Challenge creation") {
        TokenAuthenticatorConfig config{
            .issuer_name = "issuer.example.com",
            .origin_names = {"origin.example.com"},
        };

        TokenAuthenticator auth(config);

        auto challenge = auth.create_challenge(TokenType::BLIND_RSA);
        REQUIRE(challenge.has_value());
        CHECK(challenge->token_type == TokenType::BLIND_RSA);
        CHECK(challenge->issuer_name == "issuer.example.com");
    }

    TEST_CASE("Challenge with additional origin_info") {
        TokenAuthenticatorConfig config{
            .issuer_name = "issuer.example.com",
            .origin_names = {"origin.example.com"},
        };

        TokenAuthenticator auth(config);

        // Encode MOQ authorization info
        auto moq_auth = AuthorizationInfo::for_subscriber({{0x01}}, {0x02});
        auto encoded = moq_auth.encode_for_origin_info();
        REQUIRE(encoded.has_value());

        auto challenge = auth.create_challenge(
            TokenType::BLIND_RSA,
            std::nullopt,
            {*encoded});

        REQUIRE(challenge.has_value());
        CHECK(!challenge->origin_info.empty());

        // Verify we can decode the auth info back
        auto decoded = AuthorizationInfo::decode_from_origin_info(challenge->origin_info[0]);
        REQUIRE(decoded.has_value());
    }

    TEST_CASE("Redemption cache") {
        TokenAuthenticatorConfig config{
            .issuer_name = "issuer.example.com",
            .origin_names = {"origin.example.com"},
        };

        TokenAuthenticator auth(config);

        Token token{
            .token_type = TokenType::BLIND_RSA,
            .nonce = {},
            .challenge_digest = {},
            .token_key_id = {},
            .authenticator = {},
        };
        token.nonce.fill(0x42);

        CHECK(!auth.would_be_replay(token));

        auth.mark_redeemed(token);
        CHECK(auth.would_be_replay(token));
        CHECK(auth.redemption_cache_size() == 1);

        auth.prune_redemption_cache();
    }
}

TEST_SUITE("ValidationResult") {
    TEST_CASE("Success") {
        ChallengeDigest digest{};
        digest.fill(0x42);

        auto result = ValidationResult::success(digest);

        CHECK(result.valid);
        CHECK(result);  // operator bool
        CHECK(!result.error_code.has_value());
        CHECK(result.challenge_digest.has_value());
    }

    TEST_CASE("Failure") {
        auto result = ValidationResult::failure(
            ErrorCode::TOKEN_INVALID,
            "Invalid signature");

        CHECK(!result.valid);
        CHECK(!result);  // operator bool
        REQUIRE(result.error_code.has_value());
        CHECK(*result.error_code == ErrorCode::TOKEN_INVALID);
        CHECK(result.error_message.has_value());
    }
}
