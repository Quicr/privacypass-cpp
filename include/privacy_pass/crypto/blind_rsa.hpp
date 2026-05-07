// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/types.hpp>

#include <memory>

namespace privacy_pass::crypto {

// Blind RSA implementation (RFC 9474)
// Uses RSA-2048 with RSASSA-PSS and SHA-384

// RSA key size constants
constexpr size_t RSA_MODULUS_SIZE = 256;   // 2048 bits = 256 bytes
constexpr size_t RSA_PUBLIC_EXPONENT = 65537;

// Blinding data that must be kept secret until finalization
struct BlindingData {
    SecureBytes inverse;  // Blinding inverse for unblinding
    Bytes blinded_msg;    // The blinded message to send to issuer

    BlindingData() = default;
    BlindingData(BlindingData&&) noexcept = default;
    BlindingData& operator=(BlindingData&&) noexcept = default;
};

// Blind RSA public key
class BlindRsaPublicKey {
public:
    BlindRsaPublicKey();
    ~BlindRsaPublicKey();

    BlindRsaPublicKey(const BlindRsaPublicKey&) = delete;
    BlindRsaPublicKey& operator=(const BlindRsaPublicKey&) = delete;
    BlindRsaPublicKey(BlindRsaPublicKey&&) noexcept;
    BlindRsaPublicKey& operator=(BlindRsaPublicKey&&) noexcept;

    // Import from DER-encoded SubjectPublicKeyInfo
    [[nodiscard]] static Result<BlindRsaPublicKey> from_spki(ByteView spki);

    // Import from raw modulus and exponent
    [[nodiscard]] static Result<BlindRsaPublicKey> from_components(
        ByteView modulus, ByteView exponent);

    // Export to DER-encoded SubjectPublicKeyInfo
    [[nodiscard]] Result<Bytes> to_spki() const;

    // Compute token key ID (SHA-256 of SPKI)
    [[nodiscard]] Result<TokenKeyId> key_id() const;

    // Blind a message for signing
    [[nodiscard]] Result<BlindingData> blind(ByteView msg) const;

    // Finalize: unblind the signature
    // Note: blinding_data.inverse is cleared after successful finalization
    [[nodiscard]] Result<Bytes> finalize(
        ByteView blind_sig,
        BlindingData& blinding_data,
        ByteView msg) const;

    // Verify a signature (for publicly verifiable tokens)
    [[nodiscard]] Result<bool> verify(ByteView msg, ByteView signature) const;

    // Check if key is valid
    [[nodiscard]] bool is_valid() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Blind RSA private key
class BlindRsaPrivateKey {
public:
    BlindRsaPrivateKey();
    ~BlindRsaPrivateKey();

    BlindRsaPrivateKey(const BlindRsaPrivateKey&) = delete;
    BlindRsaPrivateKey& operator=(const BlindRsaPrivateKey&) = delete;
    BlindRsaPrivateKey(BlindRsaPrivateKey&&) noexcept;
    BlindRsaPrivateKey& operator=(BlindRsaPrivateKey&&) noexcept;

    // Generate a new key pair
    [[nodiscard]] static Result<std::pair<BlindRsaPrivateKey, BlindRsaPublicKey>> generate();

    // Import from DER-encoded PKCS#8
    [[nodiscard]] static Result<BlindRsaPrivateKey> from_pkcs8(ByteView pkcs8);

    // Export to DER-encoded PKCS#8
    [[nodiscard]] Result<SecureBytes> to_pkcs8() const;

    // Get the corresponding public key
    [[nodiscard]] Result<BlindRsaPublicKey> public_key() const;

    // Blind sign a blinded message
    [[nodiscard]] Result<Bytes> blind_sign(ByteView blinded_msg) const;

    // Sign a message directly (for testing)
    [[nodiscard]] Result<Bytes> sign(ByteView msg) const;

    // Check if key is valid
    [[nodiscard]] bool is_valid() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace privacy_pass::crypto
