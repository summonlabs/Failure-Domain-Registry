// Failure Domain Registry - bounded, explicit binary codec.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every field on the wire and on disk is written with an explicit width and
// read back through a bounds-checked reader. A reader never allocates from a
// length it has not first proven to be inside the remaining buffer, and every
// decode ends with a trailing-byte check so that a payload can never carry
// hidden extra content.

#ifndef FAILURE_DOMAIN_REGISTRY_SRC_BYTE_CODEC_HPP
#define FAILURE_DOMAIN_REGISTRY_SRC_BYTE_CODEC_HPP

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include "failure_domain_registry/digest.hpp"
#include "failure_domain_registry/errors.hpp"

namespace failure_domain_registry {
namespace codec {

class Writer {
 public:
  void u8(std::uint8_t value) { bytes_.push_back(static_cast<char>(value)); }

  void u16(std::uint16_t value) {
    for (unsigned shift = 0; shift < 16; shift += 8) {
      bytes_.push_back(static_cast<char>((value >> shift) & 0xffu));
    }
  }

  void u32(std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8) {
      bytes_.push_back(static_cast<char>((value >> shift) & 0xffu));
    }
  }

  void u64(std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8) {
      bytes_.push_back(static_cast<char>((value >> shift) & 0xffu));
    }
  }

  void bytes(std::string_view value) {
    u32(static_cast<std::uint32_t>(value.size()));
    bytes_.append(value.data(), value.size());
  }

  void fixed(const std::uint8_t* data, std::size_t size) {
    bytes_.append(reinterpret_cast<const char*>(data), size);
  }

  std::string& buffer() { return bytes_; }
  const std::string& buffer() const { return bytes_; }
  std::size_t size() const { return bytes_.size(); }

 private:
  std::string bytes_;
};

class Reader {
 public:
  Reader(const char* data, std::size_t size) : data_(data), size_(size) {}
  explicit Reader(std::string_view view) : data_(view.data()), size_(view.size()) {}

  bool u8(std::uint8_t* out) {
    if (remaining() < 1) {
      return false;
    }
    *out = static_cast<std::uint8_t>(static_cast<unsigned char>(data_[offset_++]));
    return true;
  }

  bool u16(std::uint16_t* out) {
    if (remaining() < 2) {
      return false;
    }
    std::uint16_t value = 0;
    for (unsigned shift = 0; shift < 16; shift += 8) {
      value |= static_cast<std::uint16_t>(static_cast<unsigned char>(data_[offset_++])) << shift;
    }
    *out = value;
    return true;
  }

  bool u32(std::uint32_t* out) {
    if (remaining() < 4) {
      return false;
    }
    std::uint32_t value = 0;
    for (unsigned shift = 0; shift < 32; shift += 8) {
      value |= static_cast<std::uint32_t>(static_cast<unsigned char>(data_[offset_++])) << shift;
    }
    *out = value;
    return true;
  }

  bool u64(std::uint64_t* out) {
    if (remaining() < 8) {
      return false;
    }
    std::uint64_t value = 0;
    for (unsigned shift = 0; shift < 64; shift += 8) {
      value |= static_cast<std::uint64_t>(static_cast<unsigned char>(data_[offset_++])) << shift;
    }
    *out = value;
    return true;
  }

  /// Reads a length-prefixed string. The declared length must fit inside the
  /// remaining buffer, and must not exceed the bound the caller supplies.
  bool bytes(std::string* out, std::size_t max_bytes) {
    std::uint32_t length = 0;
    if (!u32(&length)) {
      return false;
    }
    if (static_cast<std::size_t>(length) > max_bytes) {
      return false;
    }
    if (remaining() < static_cast<std::size_t>(length)) {
      return false;
    }
    out->assign(data_ + offset_, static_cast<std::size_t>(length));
    offset_ += static_cast<std::size_t>(length);
    return true;
  }

  bool fixed(std::uint8_t* out, std::size_t size) {
    if (remaining() < size) {
      return false;
    }
    std::memcpy(out, data_ + offset_, size);
    offset_ += size;
    return true;
  }

  bool skip(std::size_t size) {
    if (remaining() < size) {
      return false;
    }
    offset_ += size;
    return true;
  }

  std::size_t remaining() const { return size_ - offset_; }
  std::size_t offset() const { return offset_; }
  bool exhausted() const { return offset_ == size_; }

  /// Reads a count and proves that it can possibly be satisfied by the bytes
  /// that remain: every element costs at least `minimum_element_bytes`.
  bool count(std::uint32_t* out, std::size_t minimum_element_bytes, std::size_t max_elements) {
    std::uint32_t value = 0;
    if (!u32(&value)) {
      return false;
    }
    if (static_cast<std::size_t>(value) > max_elements) {
      return false;
    }
    if (minimum_element_bytes > 0 &&
        static_cast<std::size_t>(value) > remaining() / minimum_element_bytes) {
      return false;
    }
    *out = value;
    return true;
  }

 private:
  const char* data_;
  std::size_t size_;
  std::size_t offset_{0};
};

inline std::string encode_u32(std::uint32_t value) {
  Writer writer;
  writer.u32(value);
  return writer.buffer();
}

} // namespace codec
} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_SRC_BYTE_CODEC_HPP
