// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/types.hpp>

#include <memory>

namespace privacy_pass::crypto {

// VOPRF implementation (RFC 9497)
// Supports P-384 with SHA-384

// P-384 constants
constexpr size_t P384_ELEMENT_SIZE = 49;   // Compressed point (1 + 48)
constexpr size_t P384_SCALAR_SIZE = 48;
constexpr size_t P384_OUTPUT_SIZE = 48;
constexpr size_t P384_PROOF_SIZE = 96;     // 2 * scalar size

// Client finalization data
struct VoprfFinalizationData {
    SecureBytes blind_scalar;     // The blinding scalar
    Bytes blinded_element;        // The blinded element sent to server
    Bytes input;                  // Original input (for finalization)

    VoprfFinalizationData() = default;
    VoprfFinalizationData(VoprfFinalizationData&&) noexcept = default;
    VoprfFinalizationData& operator=(VoprfFinalizationData&&) noexcept = default;
};

// VOPRF evaluation result from server
struct VoprfEvaluation {
    Bytes evaluated_element;  // The evaluated (blinded) element
    Bytes proof;              // DLEQ proof
};

// VOPRF public key (P-384)
class VoprfPublicKey {
public:
    VoprfPublicKey();
    ~VoprfPublicKey();

    VoprfPublicKey(const VoprfPublicKey&) = delete;
    VoprfPublicKey& operator=(const VoprfPublicKey&) = delete;
    VoprfPublicKey(VoprfPublicKey&&) noexcept;
    VoprfPublicKey& operator=(VoprfPublicKey&&) noexcept;

    // Import from compressed point
    [[nodiscard]] static Result<VoprfPublicKey> from_bytes(ByteView data);

    // Export to compressed point
    [[nodiscard]] Result<Bytes> to_bytes() const;

    // Compute token key ID (SHA-256 of serialized public key)
    [[nodiscard]] Result<TokenKeyId> key_id() const;

    // Check if key is valid
    [[nodiscard]] bool is_valid() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend class VoprfPrivateKey;
    friend class VoprfClient;
};

// VOPRF private key (P-384)
class VoprfPrivateKey {
public:
    VoprfPrivateKey();
    ~VoprfPrivateKey();

    VoprfPrivateKey(const VoprfPrivateKey&) = delete;
    VoprfPrivateKey& operator=(const VoprfPrivateKey&) = delete;
    VoprfPrivateKey(VoprfPrivateKey&&) noexcept;
    VoprfPrivateKey& operator=(VoprfPrivateKey&&) noexcept;

    // Generate a new key pair
    [[nodiscard]] static Result<std::pair<VoprfPrivateKey, VoprfPublicKey>> generate();

    // Import from scalar bytes
    [[nodiscard]] static Result<VoprfPrivateKey> from_bytes(ByteView data);

    // Export to scalar bytes
    [[nodiscard]] Result<SecureBytes> to_bytes() const;

    // Get the corresponding public key
    [[nodiscard]] Result<VoprfPublicKey> public_key() const;

    // Check if key is valid
    [[nodiscard]] bool is_valid() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend class VoprfServer;
};

// VOPRF Client (for token requesters)
class VoprfClient {
public:
    explicit VoprfClient(VoprfPublicKey public_key);
    ~VoprfClient();

    VoprfClient(const VoprfClient&) = delete;
    VoprfClient& operator=(const VoprfClient&) = delete;
    VoprfClient(VoprfClient&&) noexcept;
    VoprfClient& operator=(VoprfClient&&) noexcept;

    // Blind an input for evaluation
    [[nodiscard]] Result<VoprfFinalizationData> blind(ByteView input) const;

    // Finalize the evaluation to get the output
    [[nodiscard]] Result<Bytes> finalize(
        const VoprfFinalizationData& finalization_data,
        const VoprfEvaluation& evaluation) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// VOPRF Server (for token issuers)
class VoprfServer {
public:
    explicit VoprfServer(VoprfPrivateKey private_key);
    ~VoprfServer();

    VoprfServer(const VoprfServer&) = delete;
    VoprfServer& operator=(const VoprfServer&) = delete;
    VoprfServer(VoprfServer&&) noexcept;
    VoprfServer& operator=(VoprfServer&&) noexcept;

    // Blind evaluate a blinded element
    [[nodiscard]] Result<VoprfEvaluation> blind_evaluate(ByteView blinded_element) const;

    // Verify a finalized output (server-side verification for privately verifiable tokens)
    [[nodiscard]] Result<bool> verify_finalize(ByteView input, ByteView output) const;

    // Get the public key
    [[nodiscard]] Result<VoprfPublicKey> public_key() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace privacy_pass::crypto
