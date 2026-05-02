// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/types.hpp>

namespace privacy_pass::crypto {

// Generate cryptographically secure random bytes
[[nodiscard]] Result<Bytes> random_bytes(size_t count);

// Fill buffer with random bytes
[[nodiscard]] Result<void> random_fill(MutableByteView buffer);

// Generate a random nonce
[[nodiscard]] Result<Nonce> random_nonce();

// Generate a random uint64
[[nodiscard]] Result<uint64_t> random_u64();

}  // namespace privacy_pass::crypto
