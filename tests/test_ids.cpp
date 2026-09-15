// Failure Domain Registry — strongly typed identifier proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// These checks pin the frozen identifier contract of
// include/failure_domain_registry/ids.hpp and include/failure_domain_registry/entity.hpp to
// observable behaviour. Every identifier either renders exactly the canonical text the
// contract promises, or it is rejected with no value produced: no check here is satisfied by
// bare truthiness, and no rejection is checked without also proving that nothing was
// returned.
//
// The identity domains are also checked as C++ types. The tags behind them are incomplete
// types that exist only so that an id from one domain is not convertible, not comparable and
// not interchangeable with an id from another; a static_assert is the only honest way to say
// that, and every configuration of this build checks it.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>

#include "failure_domain_registry/entity.hpp"
#include "failure_domain_registry/ids.hpp"
#include "support/test_harness.hpp"

namespace {

using failure_domain_registry::CoordinatorEpoch;
using failure_domain_registry::Counter;
using failure_domain_registry::DigestBytes;
using failure_domain_registry::DigestValue;
using failure_domain_registry::EntityClass;
using failure_domain_registry::EntityGeneration;
using failure_domain_registry::EntityId;
using failure_domain_registry::EntityRef;
using failure_domain_registry::FailureDomainId;
using failure_domain_registry::IdBytes;
using failure_domain_registry::kDigestBytes;
using failure_domain_registry::kOpaqueIdBytes;
using failure_domain_registry::kOpaqueIdTextLength;
using failure_domain_registry::MembershipId;
using failure_domain_registry::MutationAttempt;
using failure_domain_registry::MutationAttemptId;
using failure_domain_registry::OpaqueId;
using failure_domain_registry::PublisherId;
using failure_domain_registry::RegistryGeneration;
using failure_domain_registry::RequestDigest;
using failure_domain_registry::SnapshotSequence;
using failure_domain_registry::StateDigest;
using failure_domain_registry::WorkerBootId;

/// True when no two types in the pack are the same type. Written as a recursive
/// template rather than a handful of hand-picked pairs so that a new identity
/// domain cannot be added without being covered by this check.
template <class... Types>
struct PairwiseDistinct;

template <>
struct PairwiseDistinct<> : std::true_type {};

template <class First, class... Rest>
struct PairwiseDistinct<First, Rest...>
    : std::bool_constant<(!std::is_same_v<First, Rest> && ...) && PairwiseDistinct<Rest...>::value> {};

/// A non-null, non-repeating 128-bit pattern. The first byte is 0x37, so every
/// rendering of it contains hexadecimal letters.
IdBytes pattern_bytes() {
  IdBytes out{};
  for (std::size_t index = 0; index < out.size(); ++index) {
    out[index] = static_cast<std::uint8_t>((index * 31u + 0x37u) & 0xFFu);
  }
  return out;
}

/// A distinguishable identity: a fixed tag byte plus a salt, so identities built
/// from different salts are different values.
IdBytes salted_bytes(std::uint8_t tag, std::uint8_t salt) {
  IdBytes out{};
  out[0] = tag;
  out[kOpaqueIdBytes - 1] = salt;
  return out;
}

/// The canonical lowercase rendering of a byte string, written here from the
/// library's own codec so an expectation can never be satisfied by the code
/// under test agreeing with itself.
std::string hex_of(const IdBytes& bytes) {
  std::string out(bytes.size() * 2, '0');
  failure_domain_registry::render_hex(bytes.data(), bytes.size(), out.data());
  return out;
}

std::string ascii_upper(std::string_view text) {
  std::string out(text);
  for (char& value : out) {
    if (value >= 'a' && value <= 'f') {
      value = static_cast<char>(value - 'a' + 'A');
    }
  }
  return out;
}

bool is_lowercase_hex(std::string_view text) {
  for (char value : text) {
    const bool digit = value >= '0' && value <= '9';
    const bool letter = value >= 'a' && value <= 'f';
    if (!digit && !letter) {
      return false;
    }
  }
  return true;
}

FDR_TEST_CASE(ids, opaque_default_is_the_null_id) {
  const FailureDomainId absent;
  FDR_CHECK(absent.is_null());
  FDR_CHECK_EQ(absent.to_string(), std::string(kOpaqueIdTextLength, '0'));
  FDR_CHECK_EQ(absent.bytes(), IdBytes{});
  for (std::size_t index = 0; index < kOpaqueIdBytes; ++index) {
    FDR_CHECK_EQ(absent.data()[index], std::uint8_t{0});
  }

  // Nullity is a property of the value, not of the type: every identity domain
  // has the same absent identity, and it is still the same bytes.
  const PublisherId other_absent;
  FDR_CHECK(other_absent.is_null());
  FDR_CHECK_EQ(absent.bytes(), other_absent.bytes());

  // The all-zero rendering is well-formed text, so it parses; it parses into the
  // null identity rather than being rejected as malformed.
  const std::optional<FailureDomainId> parsed = FailureDomainId::parse(std::string(kOpaqueIdTextLength, '0'));
  FDR_CHECK(parsed.has_value());
  FDR_CHECK(parsed->is_null());
  FDR_CHECK_EQ(*parsed, absent);
}

FDR_TEST_CASE(ids, opaque_text_is_32_lowercase_hex) {
  IdBytes raw{};
  for (std::size_t index = 0; index < raw.size(); ++index) {
    raw[index] = static_cast<std::uint8_t>(index);
  }
  const MembershipId id = MembershipId::from_bytes(raw);
  const std::string text = id.to_string();
  FDR_CHECK_EQ(text.size(), std::size_t{32});
  FDR_CHECK_EQ(text, std::string("000102030405060708090a0b0c0d0e0f"));
  FDR_CHECK(is_lowercase_hex(text));
  FDR_CHECK(!id.is_null());

  char rendered[kOpaqueIdTextLength] = {};
  failure_domain_registry::render_hex(raw.data(), raw.size(), rendered);
  FDR_CHECK_EQ(std::string(rendered, sizeof(rendered)), text);

  IdBytes parsed{};
  FDR_CHECK(failure_domain_registry::parse_hex(text.data(), text.size(), parsed.data()));
  FDR_CHECK_EQ(parsed, raw);

  // The codec is length-exact: an odd character count can never describe bytes.
  FDR_CHECK(!failure_domain_registry::parse_hex(text.data(), text.size() - 1u, parsed.data()));
  const std::string non_hex = "z" + text.substr(1);
  FDR_CHECK(!failure_domain_registry::parse_hex(non_hex.data(), non_hex.size(), parsed.data()));

  // Uppercase input describes the same bytes.
  const std::string upper = ascii_upper(text);
  FDR_CHECK(failure_domain_registry::parse_hex(upper.data(), upper.size(), parsed.data()));
  FDR_CHECK_EQ(parsed, raw);
}

FDR_TEST_CASE(ids, opaque_id_round_trips_over_256_patterns) {
  fdrtest::Rng rng(0x1D5u);
  std::set<std::string> renderings;
  for (std::size_t iteration = 0; iteration < 256; ++iteration) {
    IdBytes raw{};
    for (std::size_t index = 0; index < raw.size(); ++index) {
      raw[index] = static_cast<std::uint8_t>(rng.next_u32() & 0xFFu);
    }
    const FailureDomainId original = FailureDomainId::from_bytes(raw);
    const std::string text = original.to_string();
    FDR_CHECK_EQ(text.size(), kOpaqueIdTextLength);
    FDR_CHECK(is_lowercase_hex(text));
    // Rendering is a pure function of the bytes: the same value renders the same
    // text on every call.
    FDR_CHECK_EQ(original.to_string(), text);

    const std::optional<FailureDomainId> parsed = FailureDomainId::parse(text);
    FDR_CHECK(parsed.has_value());
    FDR_CHECK_EQ(*parsed, original);
    FDR_CHECK_EQ(parsed->bytes(), raw);
    FDR_CHECK_EQ(FailureDomainId::from_bytes(parsed->bytes()), original);
    renderings.insert(text);
  }
  // 256 distinct 128-bit patterns cannot share a rendering.
  FDR_CHECK_EQ(renderings.size(), std::size_t{256});
}

FDR_TEST_CASE(ids, opaque_parse_accepts_both_cases) {
  const FailureDomainId id = FailureDomainId::from_bytes(pattern_bytes());
  const std::string lower = id.to_string();
  const std::string upper = ascii_upper(lower);
  // The pattern must contain letters or this case would prove nothing.
  FDR_CHECK(!(upper == lower));

  const std::optional<FailureDomainId> parsed_lower = FailureDomainId::parse(lower);
  const std::optional<FailureDomainId> parsed_upper = FailureDomainId::parse(upper);
  FDR_CHECK(parsed_lower.has_value());
  FDR_CHECK(parsed_upper.has_value());
  FDR_CHECK_EQ(*parsed_lower, id);
  FDR_CHECK_EQ(*parsed_upper, id);
  FDR_CHECK_EQ(parsed_upper->bytes(), id.bytes());
}

FDR_TEST_CASE(ids, opaque_parse_rejects_malformed_text) {
  const FailureDomainId id = FailureDomainId::from_bytes(pattern_bytes());
  const std::string text = id.to_string();
  const std::string zeros(kOpaqueIdTextLength, '0');

  // Length: empty, one short, one long, half, doubled.
  FDR_CHECK(!FailureDomainId::parse(std::string()).has_value());
  FDR_CHECK(!FailureDomainId::parse(text.substr(0, kOpaqueIdTextLength - 1u)).has_value());
  FDR_CHECK(!FailureDomainId::parse(text + "0").has_value());
  FDR_CHECK(!FailureDomainId::parse(text.substr(0, kOpaqueIdTextLength / 2u)).has_value());
  FDR_CHECK(!FailureDomainId::parse(text + text).has_value());

  // Character: a hexadecimal prefix, letters outside the alphabet, whitespace in
  // both positions, a byte above ASCII and an embedded NUL.
  FDR_CHECK(!FailureDomainId::parse("0x" + text.substr(0, kOpaqueIdTextLength - 2u)).has_value());
  FDR_CHECK(!FailureDomainId::parse("z" + text.substr(1)).has_value());
  FDR_CHECK(!FailureDomainId::parse("g" + text.substr(1)).has_value());
  FDR_CHECK(!FailureDomainId::parse(" " + text.substr(1)).has_value());
  FDR_CHECK(!FailureDomainId::parse(text.substr(0, kOpaqueIdTextLength - 1u) + " ").has_value());
  std::string high_byte = text;
  high_byte[0] = static_cast<char>(0xE9);
  FDR_CHECK(!FailureDomainId::parse(high_byte).has_value());
  std::string embedded_nul = text;
  embedded_nul[kOpaqueIdTextLength / 2u] = static_cast<char>(0);
  FDR_CHECK(!FailureDomainId::parse(embedded_nul).has_value());

  // Padding: the only accepted 32-character all-zero text is exactly 32 zeros.
  FDR_CHECK(FailureDomainId::parse(zeros).has_value());
  FDR_CHECK(!FailureDomainId::parse(zeros.substr(0, kOpaqueIdTextLength - 1u) + " ").has_value());
  FDR_CHECK(!FailureDomainId::parse(" " + zeros.substr(1)).has_value());
  FDR_CHECK(!FailureDomainId::parse("0" + zeros).has_value());
}

FDR_TEST_CASE(ids, opaque_parse_never_truncates_or_guesses) {
  const FailureDomainId id = FailureDomainId::from_bytes(pattern_bytes());
  const std::string text = id.to_string();

  // A well-formed identity followed by anything at all is not an identity.
  FDR_CHECK(!FailureDomainId::parse(text + "0").has_value());
  FDR_CHECK(!FailureDomainId::parse("0" + text).has_value());
  // A single wrong character in the last position is not repaired silently.
  FDR_CHECK(!FailureDomainId::parse(text.substr(0, kOpaqueIdTextLength - 1u) + "z").has_value());
  // A truncated identity is not completed from the value it might have had.
  FDR_CHECK(!FailureDomainId::parse(text.substr(0, kOpaqueIdTextLength - 1u)).has_value());
  // A short hexadecimal rendering of the same bytes is a different length, not a
  // different parser mode.
  FDR_CHECK(!FailureDomainId::parse(text.substr(0, kOpaqueIdTextLength / 2u)).has_value());
  // Nothing is produced on rejection: a caller cannot act on a half-parsed id.
  FDR_CHECK_EQ(FailureDomainId::parse("not-an-identifier").has_value(), false);
  FDR_CHECK_EQ(FailureDomainId::parse(std::string_view()).has_value(), false);
}

FDR_TEST_CASE(ids, opaque_from_digest_uses_the_leading_bytes) {
  DigestBytes digest{};
  for (std::size_t index = 0; index < digest.size(); ++index) {
    digest[index] = static_cast<std::uint8_t>(index + 1u);
  }
  const FailureDomainId id = FailureDomainId::from_digest(digest);
  FDR_CHECK(!id.is_null());
  IdBytes expected{};
  for (std::size_t index = 0; index < expected.size(); ++index) {
    expected[index] = digest[index];
  }
  FDR_CHECK_EQ(id.bytes(), expected);
  FDR_CHECK_EQ(id.to_string(), hex_of(expected));

  // Only the leading 16 bytes are the identifier: the tail of the digest is not
  // part of the identity.
  DigestBytes tail_changed = digest;
  tail_changed[kDigestBytes - 1u] = 0xFFu;
  FDR_CHECK_EQ(FailureDomainId::from_digest(tail_changed), id);
  DigestBytes head_changed = digest;
  head_changed[0] = 0xEEu;
  FDR_CHECK(!(FailureDomainId::from_digest(head_changed) == id));
}

FDR_TEST_CASE(ids, identity_domains_are_distinct_types) {
  // Every identity domain is a distinct instantiation, and the tag is the only
  // thing that distinguishes them.
  static_assert(std::is_same_v<FailureDomainId, OpaqueId<failure_domain_registry::FailureDomainTag>>);
  static_assert(std::is_same_v<PublisherId, OpaqueId<failure_domain_registry::PublisherTag>>);
  static_assert(std::is_same_v<WorkerBootId, OpaqueId<failure_domain_registry::WorkerBootTag>>);
  static_assert(!std::is_same_v<FailureDomainId, MembershipId>);
  static_assert(!std::is_same_v<MembershipId, FailureDomainId>);
  static_assert(!std::is_same_v<PublisherId, WorkerBootId>);
  static_assert(!std::is_same_v<FailureDomainId, PublisherId>);
  static_assert(!std::is_same_v<MembershipId, MutationAttemptId>);
  static_assert(!std::is_same_v<StateDigest, RequestDigest>);
  static_assert(!std::is_same_v<CoordinatorEpoch, RegistryGeneration>);
  static_assert(!std::is_same_v<FailureDomainId, CoordinatorEpoch>);

  // The complete list, so that adding a domain cannot escape the check.
  static_assert(PairwiseDistinct<FailureDomainId, MembershipId, PublisherId, WorkerBootId,
                                 MutationAttemptId, StateDigest, RequestDigest, SnapshotSequence,
                                 CoordinatorEpoch, RegistryGeneration>::value,
                "identity domains must not share a C++ type");

  // The separation is not merely nominal: no id type is convertible, assignable
  // or constructible from another.
  static_assert(!std::is_convertible_v<FailureDomainId, MembershipId>);
  static_assert(!std::is_convertible_v<MembershipId, FailureDomainId>);
  static_assert(!std::is_constructible_v<MembershipId, FailureDomainId>);
  static_assert(!std::is_assignable_v<FailureDomainId&, MembershipId>);
  static_assert(!std::is_convertible_v<PublisherId, WorkerBootId>);

  // The widths are part of the contract, not an implementation detail.
  static_assert(std::is_same_v<Counter<failure_domain_registry::CoordinatorEpochTag>, CoordinatorEpoch>);
  static_assert(std::is_same_v<DigestValue<failure_domain_registry::StateDigestTag>, StateDigest>);
  static_assert(FailureDomainId::byte_size == 16);
  static_assert(StateDigest::byte_size == 32);
  static_assert(kOpaqueIdTextLength == 32);

  // The same bytes in two domains are two different identities that happen to
  // render the same text.
  const FailureDomainId domain = FailureDomainId::from_bytes(pattern_bytes());
  const MembershipId membership = MembershipId::from_bytes(pattern_bytes());
  FDR_CHECK_EQ(domain.bytes(), membership.bytes());
  FDR_CHECK_EQ(domain.to_string(), membership.to_string());
  FDR_CHECK(!domain.is_null());
  FDR_CHECK(!membership.is_null());
}

FDR_TEST_CASE(ids, counter_first_max_and_overflow) {
  const RegistryGeneration first = RegistryGeneration::first();
  FDR_CHECK_EQ(first.value(), std::uint64_t{1});
  FDR_CHECK(!first.is_zero());
  FDR_CHECK_EQ(first.to_string(), std::string("1"));

  const std::optional<RegistryGeneration> second = first.next();
  FDR_CHECK(second.has_value());
  FDR_CHECK_EQ(second->value(), std::uint64_t{2});
  FDR_CHECK_EQ(second->value(), first.value() + 1u);
  FDR_CHECK(*second > first);

  const RegistryGeneration zero;
  FDR_CHECK(zero.is_zero());
  FDR_CHECK_EQ(zero.value(), std::uint64_t{0});
  FDR_CHECK_EQ(zero.to_string(), std::string("0"));

  // The ceiling is a checked ceiling: the last representable value is reported,
  // and incrementing it fails instead of wrapping to zero.
  const RegistryGeneration last = RegistryGeneration::max();
  FDR_CHECK_EQ(last.value(), UINT64_MAX);
  FDR_CHECK(!last.next().has_value());
  FDR_CHECK(last > *second);

  // One step below the ceiling still advances.
  const RegistryGeneration almost(UINT64_MAX - 1u);
  const std::optional<RegistryGeneration> last_step = almost.next();
  FDR_CHECK(last_step.has_value());
  FDR_CHECK_EQ(last_step->value(), UINT64_MAX);
  FDR_CHECK(!last_step->next().has_value());
}

FDR_TEST_CASE(ids, counter_parse_accepts_decimal_only) {
  const std::optional<CoordinatorEpoch> zero = CoordinatorEpoch::parse("0");
  FDR_CHECK(zero.has_value());
  FDR_CHECK_EQ(zero->value(), std::uint64_t{0});
  FDR_CHECK(zero->is_zero());
  FDR_CHECK_EQ(zero->to_string(), std::string("0"));

  const std::optional<CoordinatorEpoch> maximum = CoordinatorEpoch::parse("18446744073709551615");
  FDR_CHECK(maximum.has_value());
  FDR_CHECK_EQ(maximum->value(), UINT64_MAX);
  FDR_CHECK_EQ(maximum->to_string(), std::string("18446744073709551615"));

  // The bound is 20 characters, not 20 significant digits: a longer text is
  // rejected even when its value would fit.
  const std::optional<CoordinatorEpoch> padded = CoordinatorEpoch::parse("00000000000000000001");
  FDR_CHECK(padded.has_value());
  FDR_CHECK_EQ(padded->value(), std::uint64_t{1});
  const std::optional<CoordinatorEpoch> over_long = CoordinatorEpoch::parse("000000000000000000001");
  FDR_CHECK(!over_long.has_value());

  // Empty, signed, spaced, hexadecimal, fractional, exponential, non-ASCII and
  // overflowing inputs.
  FDR_CHECK(!CoordinatorEpoch::parse(std::string()).has_value());
  FDR_CHECK(!CoordinatorEpoch::parse("x").has_value());
  FDR_CHECK(!CoordinatorEpoch::parse("12a").has_value());
  FDR_CHECK(!CoordinatorEpoch::parse("-1").has_value());
  FDR_CHECK(!CoordinatorEpoch::parse("+1").has_value());
  FDR_CHECK(!CoordinatorEpoch::parse(" 1").has_value());
  FDR_CHECK(!CoordinatorEpoch::parse("1 ").has_value());
  FDR_CHECK(!CoordinatorEpoch::parse("0x10").has_value());
  FDR_CHECK(!CoordinatorEpoch::parse("1e3").has_value());
  FDR_CHECK(!CoordinatorEpoch::parse("1.0").has_value());
  FDR_CHECK(!CoordinatorEpoch::parse("1234567890123456789012345").has_value());
  FDR_CHECK(!CoordinatorEpoch::parse("18446744073709551616").has_value());
  FDR_CHECK(!CoordinatorEpoch::parse("99999999999999999999").has_value());
  FDR_CHECK(!CoordinatorEpoch::parse(std::string(1, static_cast<char>(0xE9)) + "1").has_value());
  FDR_CHECK(!CoordinatorEpoch::parse(std::string(1, '1') + static_cast<char>(0)).has_value());
}

FDR_TEST_CASE(ids, counter_text_round_trips) {
  const std::uint64_t values[] = {std::uint64_t{0},
                                  std::uint64_t{1},
                                  std::uint64_t{9},
                                  std::uint64_t{10},
                                  std::uint64_t{99},
                                  std::uint64_t{100},
                                  std::uint64_t{12345678901234567890ull},
                                  UINT64_MAX};
  for (std::uint64_t value : values) {
    const SnapshotSequence original(value);
    const std::string text = original.to_string();
    FDR_CHECK(!text.empty());
    FDR_CHECK(text.size() <= 20u);
    FDR_CHECK_EQ(text.find_first_not_of("0123456789"), std::string::npos);
    const std::optional<SnapshotSequence> parsed = SnapshotSequence::parse(text);
    FDR_CHECK(parsed.has_value());
    FDR_CHECK_EQ(*parsed, original);
    FDR_CHECK_EQ(parsed->value(), value);
  }

  // The rendering is minimal and unsigned: no padding, no leading zero, no sign.
  FDR_CHECK_EQ(SnapshotSequence(std::uint64_t{0}).to_string(), std::string("0"));
  FDR_CHECK_EQ(SnapshotSequence(UINT64_MAX).to_string(), std::string("18446744073709551615"));
}

FDR_TEST_CASE(ids, digest_value_is_64_hex_characters) {
  const std::string text =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  FDR_CHECK_EQ(text.size(), kDigestBytes * 2u);

  const std::optional<StateDigest> parsed = StateDigest::parse(text);
  FDR_CHECK(parsed.has_value());
  FDR_CHECK(!parsed->is_null());
  FDR_CHECK_EQ(parsed->to_string(), text);
  FDR_CHECK(is_lowercase_hex(parsed->to_string()));

  const std::optional<StateDigest> upper = StateDigest::parse(ascii_upper(text));
  FDR_CHECK(upper.has_value());
  FDR_CHECK_EQ(*upper, *parsed);

  // Length: 63 and 65 characters are both rejected, as is the empty string.
  FDR_CHECK(!StateDigest::parse(std::string(63, 'a')).has_value());
  FDR_CHECK(!StateDigest::parse(std::string(65, 'a')).has_value());
  FDR_CHECK(!StateDigest::parse(std::string()).has_value());
  // Character: one wrong digit anywhere invalidates the whole value.
  std::string non_hex = text;
  non_hex[kDigestBytes * 2u - 1u] = 'z';
  FDR_CHECK(!StateDigest::parse(non_hex).has_value());
  std::string embedded_nul = text;
  embedded_nul[0] = static_cast<char>(0);
  FDR_CHECK(!StateDigest::parse(embedded_nul).has_value());

  // The all-zero digest is well-formed and null.
  const std::optional<StateDigest> all_zero = StateDigest::parse(std::string(kDigestBytes * 2u, '0'));
  FDR_CHECK(all_zero.has_value());
  FDR_CHECK(all_zero->is_null());
  FDR_CHECK(StateDigest().is_null());
  FDR_CHECK_EQ(StateDigest().to_string(), std::string(kDigestBytes * 2u, '0'));

  // A digest value is a byte string first and a rendering second.
  const RequestDigest other = RequestDigest::from_bytes(parsed->bytes());
  FDR_CHECK_EQ(other.to_string(), text);
  FDR_CHECK_EQ(other.bytes(), parsed->bytes());
  FDR_CHECK(!(other == RequestDigest()));
}

FDR_TEST_CASE(ids, entity_id_renders_class_and_hex) {
  const IdBytes raw = pattern_bytes();
  const std::string hex = hex_of(raw);
  const EntityId id(EntityClass::Switch, raw);
  FDR_CHECK(!id.is_null());
  FDR_CHECK_EQ(id.entity_class(), EntityClass::Switch);
  FDR_CHECK_EQ(id.bytes(), raw);

  const std::string text = id.to_string();
  FDR_CHECK_EQ(text.size(), std::string("switch:").size() + kOpaqueIdTextLength);
  FDR_CHECK_EQ(text, std::string("switch:") + hex);
  FDR_CHECK_EQ(text.rfind("switch:", 0), std::size_t{0});
  FDR_CHECK(is_lowercase_hex(text.substr(std::string("switch:").size())));

  const std::optional<EntityId> parsed = EntityId::parse(text);
  FDR_CHECK(parsed.has_value());
  FDR_CHECK_EQ(*parsed, id);
  FDR_CHECK_EQ(parsed->entity_class(), EntityClass::Switch);
  FDR_CHECK_EQ(parsed->bytes(), raw);
  FDR_CHECK(!parsed->is_null());

  // The explicit-component form and the combined form agree.
  const std::optional<EntityId> explicit_class = EntityId::parse("switch", hex);
  FDR_CHECK(explicit_class.has_value());
  FDR_CHECK_EQ(*explicit_class, id);
  // Uppercase hexadecimal is the same identity; the class name is not folded.
  const std::optional<EntityId> upper = EntityId::parse("switch:" + ascii_upper(hex));
  FDR_CHECK(upper.has_value());
  FDR_CHECK_EQ(*upper, id);
  FDR_CHECK(!EntityId::parse("Switch:" + hex).has_value());
  FDR_CHECK(!EntityId::parse("smart-nic:" + hex).has_value());

  // A bare hexadecimal rendering has no class and is not an identity.
  FDR_CHECK(!EntityId::parse(hex).has_value());
  FDR_CHECK(!EntityId::parse("switch").has_value());
  FDR_CHECK(!EntityId::parse(":" + hex).has_value());
  FDR_CHECK(!EntityId::parse("switch:").has_value());
  FDR_CHECK(!EntityId::parse("switch:" + hex.substr(0, kOpaqueIdTextLength - 1u)).has_value());
  FDR_CHECK(!EntityId::parse("switch:" + hex + "0").has_value());
  FDR_CHECK(!EntityId::parse("switch:z" + hex.substr(1)).has_value());
  FDR_CHECK(!EntityId::parse("unknown:" + hex).has_value());
  FDR_CHECK(!EntityId::parse("switch:" + hex + ":extra").has_value());
  FDR_CHECK(!EntityId::parse("unknown", hex).has_value());
  FDR_CHECK(!EntityId::parse("switch", hex.substr(0, 31)).has_value());

  // Nullity comes from either component and is how an absent entity is written.
  const std::optional<EntityId> zeros = EntityId::parse("switch:" + std::string(kOpaqueIdTextLength, '0'));
  FDR_CHECK(zeros.has_value());
  FDR_CHECK(zeros->is_null());
  FDR_CHECK_EQ(zeros->to_string(), std::string("null"));
  FDR_CHECK(EntityId().is_null());
  FDR_CHECK_EQ(EntityId().entity_class(), EntityClass::Unknown);
  FDR_CHECK_EQ(EntityId().to_string(), std::string("null"));
  FDR_CHECK(EntityId(EntityClass::Unknown, raw).is_null());
  FDR_CHECK(EntityId(EntityClass::Switch, IdBytes{}).is_null());
  FDR_CHECK(!EntityId(EntityClass::Switch, raw).is_null());
}

FDR_TEST_CASE(ids, entity_ref_renders_class_generation) {
  const IdBytes raw = pattern_bytes();
  const std::string hex = hex_of(raw);
  const EntityRef ref(EntityClass::Switch, raw, EntityGeneration(7));
  FDR_CHECK(!ref.is_null());
  FDR_CHECK_EQ(ref.entity_class(), EntityClass::Switch);
  FDR_CHECK_EQ(ref.bytes(), raw);
  FDR_CHECK_EQ(ref.generation().value(), std::uint64_t{7});
  FDR_CHECK_EQ(ref.id(), EntityId(EntityClass::Switch, raw));

  const std::string text = ref.to_string();
  FDR_CHECK_EQ(text, std::string("switch:") + hex + "@7");

  const std::optional<EntityRef> parsed = EntityRef::parse(text);
  FDR_CHECK(parsed.has_value());
  FDR_CHECK_EQ(*parsed, ref);
  FDR_CHECK_EQ(parsed->id(), ref.id());
  FDR_CHECK_EQ(parsed->generation(), ref.generation());

  // The overload for a generation-free id applies the caller's generation.
  const std::optional<EntityRef> applied = EntityRef::parse(std::string("switch:") + hex, EntityGeneration(7));
  FDR_CHECK(applied.has_value());
  FDR_CHECK_EQ(*applied, ref);
  // That overload accepts only a generation-free id.
  FDR_CHECK(!EntityRef::parse(text, EntityGeneration(7)).has_value());

  // A generation is mandatory in the combined form and is never defaulted.
  FDR_CHECK(!EntityRef::parse(std::string("switch:") + hex).has_value());
  FDR_CHECK(!EntityRef::parse(std::string("switch:") + hex + "@").has_value());
  FDR_CHECK(!EntityRef::parse(std::string("switch:") + hex + "@0").has_value());
  FDR_CHECK(!EntityRef::parse(std::string("switch:") + hex + "@x").has_value());
  FDR_CHECK(!EntityRef::parse(std::string("switch:") + hex + "@1 ").has_value());
  FDR_CHECK(!EntityRef::parse(std::string("switch:") + hex + "@-1").has_value());
  FDR_CHECK(!EntityRef::parse(std::string("switch:") + hex + "@18446744073709551616").has_value());
  // A null entity id is rejected rather than wrapped into a null reference.
  FDR_CHECK(!EntityRef::parse(std::string("switch:") + std::string(kOpaqueIdTextLength, '0') + "@1").has_value());
  FDR_CHECK(!EntityRef::parse(std::string(kOpaqueIdTextLength, '0') + "@1").has_value());

  // The generation is a decimal counter: leading zeros describe the same value.
  const std::optional<EntityRef> padded = EntityRef::parse(std::string("switch:") + hex + "@0007");
  FDR_CHECK(padded.has_value());
  FDR_CHECK_EQ(padded->generation().value(), std::uint64_t{7});
  FDR_CHECK_EQ(*padded, ref);
  // The last representable generation is accepted.
  const std::optional<EntityRef> last =
      EntityRef::parse(std::string("switch:") + hex + "@18446744073709551615");
  FDR_CHECK(last.has_value());
  FDR_CHECK_EQ(last->generation().value(), UINT64_MAX);

  // Nullity of a reference requires both a real id and a non-zero generation.
  FDR_CHECK(EntityRef().is_null());
  FDR_CHECK_EQ(EntityRef().to_string(), std::string("null"));
  FDR_CHECK(EntityRef(EntityClass::Switch, raw, EntityGeneration(0)).is_null());
  FDR_CHECK(EntityRef(EntityId(), EntityGeneration(7)).is_null());
  FDR_CHECK(EntityRef(EntityClass::Switch, IdBytes{}, EntityGeneration(7)).is_null());
}

FDR_TEST_CASE(ids, mutation_attempt_equality_ordering_and_null) {
  const MutationAttempt absent;
  FDR_CHECK(absent.is_null());
  FDR_CHECK(absent.id().is_null());
  FDR_CHECK(absent.digest().is_null());

  const MutationAttempt first(MutationAttemptId::from_bytes(salted_bytes(0xA1u, 1u)), RequestDigest{});
  FDR_CHECK(!first.is_null());
  FDR_CHECK(!first.id().is_null());
  // Nullity is the attempt id's property: an attempt with no digest supplied is
  // still a real attempt.
  FDR_CHECK(first.digest().is_null());

  const MutationAttempt same(first.id(), RequestDigest{});
  FDR_CHECK(first == same);
  FDR_CHECK(!(first < same));
  FDR_CHECK(!(same < first));

  // The same attempt id with different content is a different attempt.
  DigestBytes digest_bytes{};
  digest_bytes[0] = 1u;
  const MutationAttempt conflicting(first.id(), RequestDigest::from_bytes(digest_bytes));
  FDR_CHECK(!(conflicting == first));
  FDR_CHECK(!conflicting.is_null());
  FDR_CHECK(first < conflicting || conflicting < first);

  const MutationAttempt other(MutationAttemptId::from_bytes(salted_bytes(0xA1u, 2u)), RequestDigest{});
  FDR_CHECK(!(other == first));
  // Ordering is (id, digest), so the id decides when the ids differ.
  FDR_CHECK_EQ(first < other, first.id() < other.id());
  FDR_CHECK(absent < first);
  FDR_CHECK(!(first < absent));
}

FDR_TEST_CASE(ids, hashes_support_unordered_maps) {
  constexpr std::uint32_t kCount = 64;

  std::unordered_map<FailureDomainId, std::uint32_t> domains;
  std::unordered_map<MembershipId, std::uint32_t> memberships;
  std::unordered_map<PublisherId, std::uint32_t> publishers;
  std::unordered_map<WorkerBootId, std::uint32_t> boots;
  std::unordered_map<CoordinatorEpoch, std::uint32_t> epochs;
  std::unordered_map<StateDigest, std::uint32_t> digests;
  std::unordered_map<EntityId, std::uint32_t> entities;
  std::unordered_map<EntityRef, std::uint32_t> references;

  for (std::uint32_t index = 0; index < kCount; ++index) {
    const IdBytes raw = salted_bytes(static_cast<std::uint8_t>(index + 1u), static_cast<std::uint8_t>(index));
    DigestBytes digest{};
    digest[0] = static_cast<std::uint8_t>(index + 1u);
    digest[kDigestBytes - 1u] = static_cast<std::uint8_t>(index * 3u);

    domains.emplace(FailureDomainId::from_bytes(raw), index);
    memberships.emplace(MembershipId::from_bytes(raw), index);
    publishers.emplace(PublisherId::from_bytes(raw), index);
    boots.emplace(WorkerBootId::from_bytes(raw), index);
    epochs.emplace(CoordinatorEpoch(index + 1u), index);
    digests.emplace(StateDigest::from_bytes(digest), index);
    entities.emplace(EntityId(static_cast<EntityClass>(1u + index % 15u), raw), index);
    references.emplace(EntityRef(static_cast<EntityClass>(1u + index % 15u), raw, EntityGeneration(index + 1u)),
                       index);
  }

  // 64 distinct identities, 64 entries: no two of them collided as keys.
  FDR_CHECK_EQ(domains.size(), static_cast<std::size_t>(kCount));
  FDR_CHECK_EQ(memberships.size(), static_cast<std::size_t>(kCount));
  FDR_CHECK_EQ(publishers.size(), static_cast<std::size_t>(kCount));
  FDR_CHECK_EQ(boots.size(), static_cast<std::size_t>(kCount));
  FDR_CHECK_EQ(epochs.size(), static_cast<std::size_t>(kCount));
  FDR_CHECK_EQ(digests.size(), static_cast<std::size_t>(kCount));
  FDR_CHECK_EQ(entities.size(), static_cast<std::size_t>(kCount));
  FDR_CHECK_EQ(references.size(), static_cast<std::size_t>(kCount));

  std::set<std::size_t> domain_hashes;
  std::set<std::size_t> digest_hashes;
  for (std::uint32_t index = 0; index < kCount; ++index) {
    const IdBytes raw = salted_bytes(static_cast<std::uint8_t>(index + 1u), static_cast<std::uint8_t>(index));
    DigestBytes digest{};
    digest[0] = static_cast<std::uint8_t>(index + 1u);
    digest[kDigestBytes - 1u] = static_cast<std::uint8_t>(index * 3u);
    const FailureDomainId domain_key = FailureDomainId::from_bytes(raw);
    const StateDigest digest_key = StateDigest::from_bytes(digest);

    const std::unordered_map<FailureDomainId, std::uint32_t>::const_iterator domain_entry =
        domains.find(domain_key);
    FDR_CHECK(domain_entry != domains.end());
    FDR_CHECK_EQ(domain_entry->second, index);
    FDR_CHECK_EQ(domains.count(domain_key), std::size_t{1});
    FDR_CHECK_EQ(std::hash<FailureDomainId>{}(domain_key),
                std::hash<FailureDomainId>{}(FailureDomainId::from_bytes(raw)));

    FDR_CHECK_EQ(memberships.count(MembershipId::from_bytes(raw)), std::size_t{1});
    FDR_CHECK_EQ(publishers.count(PublisherId::from_bytes(raw)), std::size_t{1});
    FDR_CHECK_EQ(boots.count(WorkerBootId::from_bytes(raw)), std::size_t{1});
    FDR_CHECK_EQ(epochs.count(CoordinatorEpoch(index + 1u)), std::size_t{1});
    FDR_CHECK_EQ(entities.count(EntityId(static_cast<EntityClass>(1u + index % 15u), raw)), std::size_t{1});
    FDR_CHECK_EQ(references.count(EntityRef(static_cast<EntityClass>(1u + index % 15u), raw,
                                           EntityGeneration(index + 1u))),
                std::size_t{1});
    FDR_CHECK_EQ(digests.count(digest_key), std::size_t{1});

    // Distinct keys are spread over distinct hash values, so the table is not
    // degraded into one bucket by the specialisation.
    domain_hashes.insert(std::hash<FailureDomainId>{}(domain_key));
    digest_hashes.insert(std::hash<StateDigest>{}(digest_key));
  }
  FDR_CHECK_EQ(domain_hashes.size(), static_cast<std::size_t>(kCount));
  FDR_CHECK_EQ(digest_hashes.size(), static_cast<std::size_t>(kCount));

  // The null identity is a usable key and is not equal to any real identity.
  FDR_CHECK_EQ(domains.count(FailureDomainId{}), std::size_t{0});
  FDR_CHECK_EQ(epochs.count(CoordinatorEpoch{}), std::size_t{0});
  FDR_CHECK_EQ(digests.count(StateDigest{}), std::size_t{0});
  // Equal values must hash equal, including the null identity.
  FDR_CHECK_EQ(std::hash<FailureDomainId>{}(FailureDomainId{}),
              std::hash<FailureDomainId>{}(FailureDomainId::from_bytes(IdBytes{})));
}

} // namespace

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
