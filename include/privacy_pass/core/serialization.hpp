// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <privacy_pass/core/types.hpp>

#include <bit>
#include <optional>

namespace privacy_pass {

// Zero-copy byte reader for parsing serialized data
class ByteReader {
public:
    explicit ByteReader(ByteView data) noexcept : data_(data), pos_(0) {}

    [[nodiscard]] size_t remaining() const noexcept { return data_.size() - pos_; }
    [[nodiscard]] size_t position() const noexcept { return pos_; }
    [[nodiscard]] bool empty() const noexcept { return pos_ >= data_.size(); }
    [[nodiscard]] ByteView data() const noexcept { return data_; }

    // Read a single byte
    [[nodiscard]] std::optional<uint8_t> read_u8() noexcept {
        if (remaining() < 1) return std::nullopt;
        return data_[pos_++];
    }

    // Read big-endian uint16
    [[nodiscard]] std::optional<uint16_t> read_u16() noexcept {
        if (remaining() < 2) return std::nullopt;
        uint16_t value = (static_cast<uint16_t>(data_[pos_]) << 8) |
                         static_cast<uint16_t>(data_[pos_ + 1]);
        pos_ += 2;
        return value;
    }

    // Read big-endian uint32
    [[nodiscard]] std::optional<uint32_t> read_u32() noexcept {
        if (remaining() < 4) return std::nullopt;
        uint32_t value = (static_cast<uint32_t>(data_[pos_]) << 24) |
                         (static_cast<uint32_t>(data_[pos_ + 1]) << 16) |
                         (static_cast<uint32_t>(data_[pos_ + 2]) << 8) |
                         static_cast<uint32_t>(data_[pos_ + 3]);
        pos_ += 4;
        return value;
    }

    // Read varint (variable-length integer encoding)
    [[nodiscard]] std::optional<uint64_t> read_varint() noexcept {
        if (remaining() < 1) return std::nullopt;

        uint8_t first = data_[pos_];
        uint8_t prefix = first >> 6;

        switch (prefix) {
            case 0:  // 1 byte
                pos_++;
                return first & 0x3F;
            case 1:  // 2 bytes
                if (remaining() < 2) return std::nullopt;
                {
                    uint16_t value = ((static_cast<uint16_t>(first & 0x3F) << 8) |
                                      static_cast<uint16_t>(data_[pos_ + 1]));
                    pos_ += 2;
                    return value;
                }
            case 2:  // 4 bytes
                if (remaining() < 4) return std::nullopt;
                {
                    uint32_t value = ((static_cast<uint32_t>(first & 0x3F) << 24) |
                                      (static_cast<uint32_t>(data_[pos_ + 1]) << 16) |
                                      (static_cast<uint32_t>(data_[pos_ + 2]) << 8) |
                                      static_cast<uint32_t>(data_[pos_ + 3]));
                    pos_ += 4;
                    return value;
                }
            case 3:  // 8 bytes
                if (remaining() < 8) return std::nullopt;
                {
                    uint64_t value = ((static_cast<uint64_t>(first & 0x3F) << 56) |
                                      (static_cast<uint64_t>(data_[pos_ + 1]) << 48) |
                                      (static_cast<uint64_t>(data_[pos_ + 2]) << 40) |
                                      (static_cast<uint64_t>(data_[pos_ + 3]) << 32) |
                                      (static_cast<uint64_t>(data_[pos_ + 4]) << 24) |
                                      (static_cast<uint64_t>(data_[pos_ + 5]) << 16) |
                                      (static_cast<uint64_t>(data_[pos_ + 6]) << 8) |
                                      static_cast<uint64_t>(data_[pos_ + 7]));
                    pos_ += 8;
                    return value;
                }
        }
        return std::nullopt;
    }

    // Read fixed-size bytes (zero-copy view)
    [[nodiscard]] std::optional<ByteView> read_bytes(size_t count) noexcept {
        if (remaining() < count) return std::nullopt;
        ByteView result = data_.subspan(pos_, count);
        pos_ += count;
        return result;
    }

    // Read length-prefixed bytes with 1-byte length
    [[nodiscard]] std::optional<ByteView> read_bytes_u8() noexcept {
        auto len = read_u8();
        if (!len) return std::nullopt;
        return read_bytes(*len);
    }

    // Read length-prefixed bytes with 2-byte length
    [[nodiscard]] std::optional<ByteView> read_bytes_u16() noexcept {
        auto len = read_u16();
        if (!len) return std::nullopt;
        return read_bytes(*len);
    }

    // Read into fixed-size array
    template <size_t N>
    [[nodiscard]] std::optional<std::array<uint8_t, N>> read_array() noexcept {
        auto bytes = read_bytes(N);
        if (!bytes) return std::nullopt;
        std::array<uint8_t, N> result;
        std::copy(bytes->begin(), bytes->end(), result.begin());
        return result;
    }

    // Peek without consuming
    [[nodiscard]] std::optional<uint8_t> peek_u8() const noexcept {
        if (remaining() < 1) return std::nullopt;
        return data_[pos_];
    }

    // Skip bytes
    bool skip(size_t count) noexcept {
        if (remaining() < count) return false;
        pos_ += count;
        return true;
    }

    // Reset to beginning
    void reset() noexcept { pos_ = 0; }

    // Get remaining data as view
    [[nodiscard]] ByteView remaining_data() const noexcept {
        return data_.subspan(pos_);
    }

private:
    ByteView data_;
    size_t pos_;
};

// Byte writer for serializing data
class ByteWriter {
public:
    ByteWriter() = default;
    explicit ByteWriter(size_t reserve) { data_.reserve(reserve); }

    // Write directly to existing buffer (zero-copy mode)
    explicit ByteWriter(MutableByteView buffer) noexcept
        : external_buffer_(buffer), pos_(0), use_external_(true) {}

    [[nodiscard]] size_t size() const noexcept {
        return use_external_ ? pos_ : data_.size();
    }

    [[nodiscard]] ByteView view() const noexcept {
        return use_external_ ? ByteView(external_buffer_.data(), pos_)
                             : ByteView(data_.data(), data_.size());
    }

    [[nodiscard]] Bytes take() {
        if (use_external_) {
            return Bytes(external_buffer_.data(), external_buffer_.data() + pos_);
        }
        return std::move(data_);
    }

    // Write single byte
    bool write_u8(uint8_t value) {
        if (use_external_) {
            if (pos_ >= external_buffer_.size()) return false;
            external_buffer_[pos_++] = value;
        } else {
            data_.push_back(value);
        }
        return true;
    }

    // Write big-endian uint16
    bool write_u16(uint16_t value) {
        if (use_external_) {
            if (pos_ + 2 > external_buffer_.size()) return false;
            external_buffer_[pos_++] = static_cast<uint8_t>(value >> 8);
            external_buffer_[pos_++] = static_cast<uint8_t>(value);
        } else {
            data_.push_back(static_cast<uint8_t>(value >> 8));
            data_.push_back(static_cast<uint8_t>(value));
        }
        return true;
    }

    // Write big-endian uint32
    bool write_u32(uint32_t value) {
        if (use_external_) {
            if (pos_ + 4 > external_buffer_.size()) return false;
            external_buffer_[pos_++] = static_cast<uint8_t>(value >> 24);
            external_buffer_[pos_++] = static_cast<uint8_t>(value >> 16);
            external_buffer_[pos_++] = static_cast<uint8_t>(value >> 8);
            external_buffer_[pos_++] = static_cast<uint8_t>(value);
        } else {
            data_.push_back(static_cast<uint8_t>(value >> 24));
            data_.push_back(static_cast<uint8_t>(value >> 16));
            data_.push_back(static_cast<uint8_t>(value >> 8));
            data_.push_back(static_cast<uint8_t>(value));
        }
        return true;
    }

    // Write varint
    bool write_varint(uint64_t value) {
        if (value <= 0x3F) {
            return write_u8(static_cast<uint8_t>(value));
        } else if (value <= 0x3FFF) {
            return write_u8(static_cast<uint8_t>(0x40 | (value >> 8))) &&
                   write_u8(static_cast<uint8_t>(value));
        } else if (value <= 0x3FFFFFFF) {
            return write_u8(static_cast<uint8_t>(0x80 | (value >> 24))) &&
                   write_u8(static_cast<uint8_t>(value >> 16)) &&
                   write_u8(static_cast<uint8_t>(value >> 8)) &&
                   write_u8(static_cast<uint8_t>(value));
        } else {
            return write_u8(static_cast<uint8_t>(0xC0 | (value >> 56))) &&
                   write_u8(static_cast<uint8_t>(value >> 48)) &&
                   write_u8(static_cast<uint8_t>(value >> 40)) &&
                   write_u8(static_cast<uint8_t>(value >> 32)) &&
                   write_u8(static_cast<uint8_t>(value >> 24)) &&
                   write_u8(static_cast<uint8_t>(value >> 16)) &&
                   write_u8(static_cast<uint8_t>(value >> 8)) &&
                   write_u8(static_cast<uint8_t>(value));
        }
    }

    // Write bytes
    bool write_bytes(ByteView bytes) {
        if (use_external_) {
            if (pos_ + bytes.size() > external_buffer_.size()) return false;
            std::copy(bytes.begin(), bytes.end(), external_buffer_.data() + pos_);
            pos_ += bytes.size();
        } else {
            data_.insert(data_.end(), bytes.begin(), bytes.end());
        }
        return true;
    }

    // Write length-prefixed bytes with 1-byte length
    bool write_bytes_u8(ByteView bytes) {
        if (bytes.size() > 255) return false;
        return write_u8(static_cast<uint8_t>(bytes.size())) && write_bytes(bytes);
    }

    // Write length-prefixed bytes with 2-byte length
    bool write_bytes_u16(ByteView bytes) {
        if (bytes.size() > 65535) return false;
        return write_u16(static_cast<uint16_t>(bytes.size())) && write_bytes(bytes);
    }

    // Write fixed-size array
    template <size_t N>
    bool write_array(const std::array<uint8_t, N>& arr) {
        return write_bytes(ByteView(arr.data(), arr.size()));
    }

    // Reserve space
    void reserve(size_t size) {
        if (!use_external_) {
            data_.reserve(size);
        }
    }

    // Clear
    void clear() {
        if (use_external_) {
            pos_ = 0;
        } else {
            data_.clear();
        }
    }

private:
    Bytes data_;
    MutableByteView external_buffer_;
    size_t pos_ = 0;
    bool use_external_ = false;
};

// Base64url encoding/decoding (RFC 4648)
namespace base64url {

[[nodiscard]] std::string encode(ByteView data);
[[nodiscard]] std::string encode_padded(ByteView data);
[[nodiscard]] Result<Bytes> decode(std::string_view encoded);

}  // namespace base64url

// Compute required varint size for a value
[[nodiscard]] constexpr size_t varint_size(uint64_t value) noexcept {
    if (value <= 0x3F) return 1;
    if (value <= 0x3FFF) return 2;
    if (value <= 0x3FFFFFFF) return 4;
    return 8;
}

}  // namespace privacy_pass
