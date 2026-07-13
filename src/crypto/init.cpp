// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#include <privacy_pass/core/types.hpp>
#include "compat.hpp"

namespace privacy_pass {

void secure_clear(void* ptr, size_t len) noexcept {
    OPENSSL_cleanse(ptr, len);
}

namespace crypto::detail {

void backend_init() { compat::backend_init(); }
void backend_shutdown() { compat::backend_shutdown(); }

}  // namespace crypto::detail
}  // namespace privacy_pass
