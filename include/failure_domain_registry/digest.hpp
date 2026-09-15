// Failure Domain Registry — SHA-256 and canonical digesting.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The semantic digest of the registry state is a SHA-256 over a canonical byte
// string: records sorted by identity, containers written in a fixed order,
// process-local fields excluded. Two registries holding the same classification
// produce the same digest regardless of the order the classification arrived
// in.

#ifndef FAILURE_DOMAIN_REGISTRY_DIGEST_HPP
#define FAILURE_DOMAIN_REGISTRY_DIGEST_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"

namespace failure_domain_registry {

/// Streaming SHA-256. Used for state digests, request digests, persisted
/// container integrity and frame integrity.
class FDR_API Sha256 {
public:
  static constexpr std::size_t block_size = 64;
  static constexpr std::size_t digest_size = kDigestBytes;

  Sha256() noexcept;

  void update(const void* data, std::size_t size) noexcept;
  void update(std::string_view text) noexcept { update(text.data(), text.size()); }
  /// Finalises and returns the digest. The object is not reusable afterwards
  /// unless reset() is called.
  DigestBytes finish() noexcept;
  void reset() noexcept;

private:
  void compress(const std::uint8_t* block) noexcept;

  std::uint32_t state_[8];
  std::uint64_t bit_count_;
  std::uint8_t buffer_[block_size];
  std::size_t buffered_;
};

/// One-shot SHA-256 over a byte range.
FDR_API DigestBytes sha256(const void* data, std::size_t size) noexcept;
FDR_API DigestBytes sha256(std::string_view text) noexcept;

/// Lowercase hexadecimal rendering of an arbitrary byte range.
FDR_API std::string to_hex(const std::uint8_t* data, std::size_t size);

/// Length-prefixed canonical framing helpers. Every variable-length field in a
/// canonical form or a persisted record is framed with a fixed-width length so
/// that no two distinct values can produce the same byte string.
FDR_API void append_u8(std::string& out, std::uint8_t value);
FDR_API void append_u32(std::string& out, std::uint32_t value);
FDR_API void append_u64(std::string& out, std::uint64_t value);
FDR_API void append_bytes(std::string& out, std::string_view value);

/// Computes the canonical RequestDigest of a mutation request from its
/// canonical form.
FDR_API RequestDigest request_digest_of(std::string_view canonical_form) noexcept;

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_DIGEST_HPP
