// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/types.hpp>

#include <nlohmann/json.hpp>

#include <array>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace privacy_pass::test_vectors {

inline nlohmann::json load_json(std::string_view file_name) {
    const auto path = std::filesystem::path(PRIVACY_PASS_TEST_DATA_DIR) / file_name;
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("failed to open test vector file: " + path.string());
    }

    nlohmann::json json;
    input >> json;
    return json;
}

inline uint8_t hex_nibble(char c) {
    const auto uc = static_cast<unsigned char>(c);
    if (std::isdigit(uc) != 0) {
        return static_cast<uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<uint8_t>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<uint8_t>(c - 'A' + 10);
    }
    throw std::runtime_error("invalid hex digit");
}

inline Bytes hex_to_bytes(std::string_view hex) {
    if ((hex.size() % 2) != 0) {
        throw std::runtime_error("odd-length hex string");
    }

    Bytes bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<uint8_t>((hex_nibble(hex[i]) << 4) | hex_nibble(hex[i + 1])));
    }
    return bytes;
}

inline Bytes hex_field(const nlohmann::json& vector, std::string_view field) {
    return hex_to_bytes(vector.at(std::string(field)).get<std::string>());
}

template <size_t N>
inline std::array<uint8_t, N> fixed_bytes(const Bytes& bytes) {
    if (bytes.size() != N) {
        throw std::runtime_error("unexpected fixed byte length");
    }

    std::array<uint8_t, N> result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

inline std::string bytes_to_string(const Bytes& bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

inline TokenType token_type_from_bytes(const Bytes& bytes) {
    if (bytes.size() != 2) {
        throw std::runtime_error("token type must be two bytes");
    }
    return static_cast<TokenType>((static_cast<uint16_t>(bytes[0]) << 8) | bytes[1]);
}

inline ByteView view(const Bytes& bytes) {
    return ByteView(bytes.data(), bytes.size());
}

}  // namespace privacy_pass::test_vectors
