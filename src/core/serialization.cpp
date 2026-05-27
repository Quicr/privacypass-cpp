// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <privacy_pass/core/serialization.hpp>

namespace privacy_pass {

namespace base64url {

namespace {

constexpr char ENCODE_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

constexpr uint8_t DECODE_TABLE[] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  62, 255, 255,
     52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255, 255, 255, 255, 255,
    255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255,  63,
    255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
     41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
};

}  // namespace

std::string encode(ByteView data) {
    if (data.empty()) {
        return {};
    }

    size_t output_len = ((data.size() + 2) / 3) * 4;
    std::string result;
    result.reserve(output_len);

    size_t i = 0;
    while (i + 3 <= data.size()) {
        uint32_t chunk = (static_cast<uint32_t>(data[i]) << 16) |
                         (static_cast<uint32_t>(data[i + 1]) << 8) |
                         static_cast<uint32_t>(data[i + 2]);

        result.push_back(ENCODE_TABLE[(chunk >> 18) & 0x3F]);
        result.push_back(ENCODE_TABLE[(chunk >> 12) & 0x3F]);
        result.push_back(ENCODE_TABLE[(chunk >> 6) & 0x3F]);
        result.push_back(ENCODE_TABLE[chunk & 0x3F]);

        i += 3;
    }

    size_t remaining = data.size() - i;
    if (remaining == 1) {
        uint32_t chunk = static_cast<uint32_t>(data[i]) << 16;
        result.push_back(ENCODE_TABLE[(chunk >> 18) & 0x3F]);
        result.push_back(ENCODE_TABLE[(chunk >> 12) & 0x3F]);
    } else if (remaining == 2) {
        uint32_t chunk = (static_cast<uint32_t>(data[i]) << 16) |
                         (static_cast<uint32_t>(data[i + 1]) << 8);
        result.push_back(ENCODE_TABLE[(chunk >> 18) & 0x3F]);
        result.push_back(ENCODE_TABLE[(chunk >> 12) & 0x3F]);
        result.push_back(ENCODE_TABLE[(chunk >> 6) & 0x3F]);
    }

    return result;
}

std::string encode_padded(ByteView data) {
    std::string result = encode(data);
    while ((result.size() % 4) != 0) {
        result.push_back('=');
    }
    return result;
}

Result<Bytes> decode(std::string_view encoded) {
    if (encoded.empty()) {
        return Bytes{};
    }

    size_t padding = 0;
    while (!encoded.empty() && encoded.back() == '=') {
        encoded.remove_suffix(1);
        ++padding;
    }

    if (padding > 2 || encoded.find('=') != std::string_view::npos || encoded.size() % 4 == 1) {
        return std::unexpected(Error{ErrorCode::INVALID_BASE64,
            "Invalid base64url padding"});
    }

    if (encoded.empty()) {
        return Bytes{};
    }

    size_t output_len = (encoded.size() * 3) / 4;
    Bytes result;
    result.reserve(output_len);

    uint32_t buffer = 0;
    int bits = 0;

    for (char c : encoded) {
        uint8_t val = DECODE_TABLE[static_cast<uint8_t>(c)];
        if (val == 255) {
            return std::unexpected(Error{ErrorCode::INVALID_BASE64,
                "Invalid base64url character"});
        }

        buffer = (buffer << 6) | val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            result.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }

    return result;
}

}  // namespace base64url

}  // namespace privacy_pass
