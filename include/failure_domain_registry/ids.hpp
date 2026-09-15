// Failure Domain Registry — strongly typed identifiers.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every identity domain in Failure Domain Registry has its own C++ type. Ids
// from different domains are not convertible, not comparable and not
// interchangeable as map keys. Opaque ids are 128-bit values rendered as 32
// lowercase hexadecimal characters; counters are 64-bit monotonic values
// rendered as decimal.
//
// The all-zero value of every id type is the null (absent) id and is rejected
// wherever an operation requires a real identity. Failure Domain Registry mints
// deterministic ids by truncating a SHA-256 over a domain-separated canonical
// byte string, so the same logical identity always renders the same id and a
// replay cannot invent a second one.

#ifndef FAILURE_DOMAIN_REGISTRY_IDS_HPP
#define FAILURE_DOMAIN_REGISTRY_IDS_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <compare>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include "failure_domain_registry/export.hpp"

namespace failure_domain_registry {

/// Width of every opaque identifier.
inline constexpr std::size_t kOpaqueIdBytes = 16;

/// Width of the 32-character lowercase hex rendering of an opaque id.
inline constexpr std::size_t kOpaqueIdTextLength = kOpaqueIdBytes * 2;

/// Width of a SHA-256 digest in bytes.
inline constexpr std::size_t kDigestBytes = 32;

using IdBytes = std::array<std::uint8_t, kOpaqueIdBytes>;
using DigestBytes = std::array<std::uint8_t, kDigestBytes>;

/// Renders bytes as lowercase hex into a caller-owned buffer of size*2 bytes.
FDR_API void render_hex(const std::uint8_t* data, std::size_t size, char* out) noexcept;

/// Parses exactly `size * 2` hexadecimal characters into `out`. Accepts upper
/// and lower case; returns false for any other length or character.
FDR_API bool parse_hex(const char* text, std::size_t size, std::uint8_t* out) noexcept;

/// A 128-bit opaque identifier belonging to the identity domain named by Tag.
template <class Tag>
class OpaqueId {
public:
  using tag_type = Tag;
  static constexpr std::size_t byte_size = kOpaqueIdBytes;

  constexpr OpaqueId() noexcept = default;

  static constexpr OpaqueId from_bytes(const IdBytes& value) noexcept {
    OpaqueId result;
    result.bytes_ = value;
    return result;
  }

  /// Interprets the first 16 bytes of a digest as an identifier. Used for
  /// deterministic identity derivation; never to mint process incarnations.
  static constexpr OpaqueId from_digest(const DigestBytes& digest) noexcept {
    OpaqueId result;
    for (std::size_t i = 0; i < kOpaqueIdBytes; ++i) {
      result.bytes_[i] = digest[i];
    }
    return result;
  }

  /// Parses exactly 32 hexadecimal characters. Returns nullopt for any other
  /// length or character; never guesses and never truncates.
  static std::optional<OpaqueId> parse(std::string_view text) noexcept {
    if (text.size() != kOpaqueIdTextLength) {
      return std::nullopt;
    }
    IdBytes value{};
    if (!parse_hex(text.data(), text.size(), value.data())) {
      return std::nullopt;
    }
    return OpaqueId::from_bytes(value);
  }

  constexpr bool is_null() const noexcept {
    for (std::size_t i = 0; i < kOpaqueIdBytes; ++i) {
      if (bytes_[i] != 0) {
        return false;
      }
    }
    return true;
  }

  constexpr const IdBytes& bytes() const noexcept { return bytes_; }
  constexpr const std::uint8_t* data() const noexcept { return bytes_.data(); }

  std::string to_string() const {
    std::string out(kOpaqueIdTextLength, '0');
    render_hex(bytes_.data(), bytes_.size(), out.data());
    return out;
  }

  friend constexpr bool operator==(const OpaqueId&, const OpaqueId&) noexcept = default;
  friend constexpr auto operator<=>(const OpaqueId&, const OpaqueId&) noexcept = default;

private:
  IdBytes bytes_{};
};

// Identity domains of this runtime. The tags are incomplete types on purpose:
// they exist only to give each OpaqueId instantiation a distinct C++ type.
#define FAILURE_DOMAIN_REGISTRY_DECLARE_TAG(tag_name) \
  struct tag_name##Tag;                               \
  using tag_name##Id = OpaqueId<tag_name##Tag>

FAILURE_DOMAIN_REGISTRY_DECLARE_TAG(FailureDomain);
FAILURE_DOMAIN_REGISTRY_DECLARE_TAG(Membership);
FAILURE_DOMAIN_REGISTRY_DECLARE_TAG(CorrelationClass);
FAILURE_DOMAIN_REGISTRY_DECLARE_TAG(RiskGroup);
FAILURE_DOMAIN_REGISTRY_DECLARE_TAG(DomainRelation);
FAILURE_DOMAIN_REGISTRY_DECLARE_TAG(Publication);
FAILURE_DOMAIN_REGISTRY_DECLARE_TAG(MutationAttempt);
FAILURE_DOMAIN_REGISTRY_DECLARE_TAG(Snapshot);
FAILURE_DOMAIN_REGISTRY_DECLARE_TAG(Publisher);
FAILURE_DOMAIN_REGISTRY_DECLARE_TAG(WorkerBoot);
FAILURE_DOMAIN_REGISTRY_DECLARE_TAG(DerivationRule);
FAILURE_DOMAIN_REGISTRY_DECLARE_TAG(Evidence);

#undef FAILURE_DOMAIN_REGISTRY_DECLARE_TAG

// ---------------------------------------------------------------------------
// Monotonic counters
// ---------------------------------------------------------------------------

struct CoordinatorEpochTag;
struct RegistryGenerationTag;
struct DomainGenerationTag;
struct MembershipGenerationTag;
struct EvidenceGenerationTag;
struct DerivationGenerationTag;
struct PublisherGenerationTag;
struct SnapshotSequenceTag;
struct EntityGenerationTag;
struct TopologyGenerationTag;

/// A 64-bit unsigned counter with checked increment. next() returns nullopt
/// instead of wrapping, so overflow is surfaced as a failure rather than
/// silently restarting a generation space.
template <class Tag>
class Counter {
public:
  using tag_type = Tag;

  constexpr Counter() noexcept = default;
  constexpr explicit Counter(std::uint64_t value) noexcept : value_(value) {}

  static constexpr Counter first() noexcept { return Counter(1); }
  static constexpr Counter max() noexcept { return Counter(UINT64_MAX); }

  static std::optional<Counter> parse(std::string_view text) noexcept {
    if (text.empty() || text.size() > 20) {
      return std::nullopt;
    }
    std::uint64_t value = 0;
    for (char c : text) {
      if (c < '0' || c > '9') {
        return std::nullopt;
      }
      const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
      if (value > (UINT64_MAX - digit) / 10u) {
        return std::nullopt;
      }
      value = value * 10u + digit;
    }
    return Counter(value);
  }

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool is_zero() const noexcept { return value_ == 0; }

  std::optional<Counter> next() const noexcept {
    if (value_ == UINT64_MAX) {
      return std::nullopt;
    }
    return Counter(value_ + 1u);
  }

  std::string to_string() const {
    char buffer[24] = {};
    std::size_t index = sizeof(buffer);
    std::uint64_t value = value_;
    do {
      buffer[--index] = static_cast<char>('0' + static_cast<int>(value % 10u));
      value /= 10u;
    } while (value != 0);
    return std::string(buffer + index, sizeof(buffer) - index);
  }

  friend constexpr bool operator==(const Counter&, const Counter&) noexcept = default;
  friend constexpr auto operator<=>(const Counter&, const Counter&) noexcept = default;

private:
  std::uint64_t value_{0};
};

/// Incarnation of the coordinating process. Advances on every coordinator
/// start; traffic carrying an older epoch is rejected before mutation.
using CoordinatorEpoch = Counter<CoordinatorEpochTag>;
/// Monotonic counter advanced by every committed state change.
using RegistryGeneration = Counter<RegistryGenerationTag>;
/// Generation of one failure-domain record.
using FailureDomainGeneration = Counter<DomainGenerationTag>;
/// Generation of one membership record.
using MembershipGeneration = Counter<MembershipGenerationTag>;
/// Generation of the evidence a record rests on.
using EvidenceGeneration = Counter<EvidenceGenerationTag>;
/// Generation of a derived-membership recomputation.
using DerivationGeneration = Counter<DerivationGenerationTag>;
/// Generation of a publisher's authority grant.
using PublisherGeneration = Counter<PublisherGenerationTag>;
/// Monotonic sequence of snapshots taken by one registry instance.
using SnapshotSequence = Counter<SnapshotSequenceTag>;
/// Generation of an entity as reported by Fabric Registry.
using EntityGeneration = Counter<EntityGenerationTag>;
/// Generation of the structural facts Fabric Topology owns. Failure Domain
/// Registry never computes topology; it only records which generation a
/// derivation read.
using TopologyGeneration = Counter<TopologyGenerationTag>;

// ---------------------------------------------------------------------------
// Digest values
// ---------------------------------------------------------------------------

/// A 32-byte digest belonging to the semantic domain named by Tag.
template <class Tag>
class DigestValue {
public:
  using tag_type = Tag;
  static constexpr std::size_t byte_size = kDigestBytes;

  constexpr DigestValue() noexcept = default;

  static constexpr DigestValue from_bytes(const DigestBytes& value) noexcept {
    DigestValue result;
    result.bytes_ = value;
    return result;
  }

  static std::optional<DigestValue> parse(std::string_view text) noexcept {
    if (text.size() != kDigestBytes * 2) {
      return std::nullopt;
    }
    DigestBytes value{};
    if (!parse_hex(text.data(), text.size(), value.data())) {
      return std::nullopt;
    }
    return DigestValue::from_bytes(value);
  }

  constexpr bool is_null() const noexcept {
    for (std::size_t i = 0; i < kDigestBytes; ++i) {
      if (bytes_[i] != 0) {
        return false;
      }
    }
    return true;
  }

  constexpr const DigestBytes& bytes() const noexcept { return bytes_; }
  constexpr const std::uint8_t* data() const noexcept { return bytes_.data(); }

  std::string to_string() const {
    std::string out(kDigestBytes * 2, '0');
    render_hex(bytes_.data(), bytes_.size(), out.data());
    return out;
  }

  friend constexpr bool operator==(const DigestValue&, const DigestValue&) noexcept = default;
  friend constexpr auto operator<=>(const DigestValue&, const DigestValue&) noexcept = default;

private:
  DigestBytes bytes_{};
};

struct StateDigestTag;
struct RequestDigestTag;
struct SnapshotDigestTag;

/// Digest over the complete canonical registry state.
using StateDigest = DigestValue<StateDigestTag>;
/// Digest over the exact semantic content of a mutation request, used to
/// separate an exact replay from a conflicting one.
using RequestDigest = DigestValue<RequestDigestTag>;
/// Digest bound to a snapshot.
using SnapshotDigest = DigestValue<SnapshotDigestTag>;

// ---------------------------------------------------------------------------
// Mutation attempt identity
// ---------------------------------------------------------------------------

/// Caller-supplied attempt identity. Two attempts with the same id and the same
/// request digest are an exact replay; the same id with a different digest is a
/// conflicting replay and is rejected.
class FDR_API MutationAttempt {
public:
  constexpr MutationAttempt() noexcept = default;
  constexpr MutationAttempt(MutationAttemptId id, RequestDigest digest) noexcept
      : id_(id), digest_(digest) {}
  constexpr MutationAttemptId id() const noexcept { return id_; }
  constexpr const RequestDigest& digest() const noexcept { return digest_; }
  constexpr bool is_null() const noexcept { return id_.is_null(); }
  friend constexpr bool operator==(const MutationAttempt&, const MutationAttempt&) noexcept = default;
  friend constexpr auto operator<=>(const MutationAttempt&, const MutationAttempt&) noexcept = default;

private:
  MutationAttemptId id_{};
  RequestDigest digest_{};
};

} // namespace failure_domain_registry

namespace std {

template <class Tag>
struct hash<failure_domain_registry::OpaqueId<Tag>> {
  std::size_t operator()(const failure_domain_registry::OpaqueId<Tag>& value) const noexcept {
    // FNV-1a over the 16 identifier bytes. Keys are validated 128-bit values
    // chosen by the caller of a public API, not attacker-selected hash buckets.
    std::size_t accumulator = 1469598103934665603ull;
    for (std::uint8_t byte : value.bytes()) {
      accumulator ^= static_cast<std::size_t>(byte);
      accumulator *= 1099511628211ull;
    }
    return accumulator;
  }
};

template <class Tag>
struct hash<failure_domain_registry::Counter<Tag>> {
  std::size_t operator()(const failure_domain_registry::Counter<Tag>& value) const noexcept {
    return std::hash<std::uint64_t>{}(value.value());
  }
};

template <class Tag>
struct hash<failure_domain_registry::DigestValue<Tag>> {
  std::size_t operator()(const failure_domain_registry::DigestValue<Tag>& value) const noexcept {
    std::size_t accumulator = 1469598103934665603ull;
    for (std::uint8_t byte : value.bytes()) {
      accumulator ^= static_cast<std::size_t>(byte);
      accumulator *= 1099511628211ull;
    }
    return accumulator;
  }
};

} // namespace std

#endif // FAILURE_DOMAIN_REGISTRY_IDS_HPP
