// Failure Domain Registry — hexadecimal identity codec.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/ids.hpp"

namespace failure_domain_registry {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

constexpr int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

} // namespace

void render_hex(const std::uint8_t* data, std::size_t size, char* out) noexcept {
  for (std::size_t i = 0; i < size; ++i) {
    const std::uint8_t byte = data[i];
    out[i * 2] = kHexDigits[(byte >> 4) & 0x0fu];
    out[i * 2 + 1] = kHexDigits[byte & 0x0fu];
  }
}

bool parse_hex(const char* text, std::size_t size, std::uint8_t* out) noexcept {
  if ((size % 2) != 0) {
    return false;
  }
  for (std::size_t i = 0; i < size; i += 2) {
    const int high = hex_value(text[i]);
    const int low = hex_value(text[i + 1]);
    if (high < 0 || low < 0) {
      return false;
    }
    out[i / 2] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return true;
}

} // namespace failure_domain_registry
