// Failure Domain Registry — SHA-256, canonical framing and the semantic digest.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// These checks pin the byte-level contract the semantic digest rests on. The
// SHA-256 implementation is compared against the published NIST vectors, the
// canonical framing helpers are proven length-prefixed (so distinct values can
// never produce the same byte string), and the state digest is proven to depend
// on the classification rather than on the order the classification arrived in.
// Every rejection is checked twice: for its outcome code and for the digest that
// must not have moved.

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "failure_domain_registry/failure_domain_registry.hpp"
#include "support/test_harness.hpp"

namespace {

using failure_domain_registry::append_bytes;
using failure_domain_registry::append_u8;
using failure_domain_registry::append_u32;
using failure_domain_registry::append_u64;
using failure_domain_registry::parse_hex;
using failure_domain_registry::render_hex;
using failure_domain_registry::request_digest_of;
using failure_domain_registry::sha256;
using failure_domain_registry::to_hex;
using failure_domain_registry::AttachMemberRequest;
using failure_domain_registry::AuthorityContext;
using failure_domain_registry::AuthorityScope;
using failure_domain_registry::CoordinatorEpoch;
using failure_domain_registry::CoverageState;
using failure_domain_registry::CreateDomainRequest;
using failure_domain_registry::DeclareCoverageRequest;
using failure_domain_registry::DerivationGeneration;
using failure_domain_registry::DerivationRuleId;
using failure_domain_registry::DigestBytes;
using failure_domain_registry::DomainClass;
using failure_domain_registry::DomainClassRef;
using failure_domain_registry::DomainLifecycle;
using failure_domain_registry::DomainRelation;
using failure_domain_registry::DomainRelationId;
using failure_domain_registry::DomainRelationType;
using failure_domain_registry::EntityClass;
using failure_domain_registry::EntityGeneration;
using failure_domain_registry::EntityId;
using failure_domain_registry::EntityRef;
using failure_domain_registry::EvidenceClass;
using failure_domain_registry::EvidenceGeneration;
using failure_domain_registry::FailureDomain;
using failure_domain_registry::FailureDomainGeneration;
using failure_domain_registry::FailureDomainId;
using failure_domain_registry::IdBytes;
using failure_domain_registry::Membership;
using failure_domain_registry::MembershipEvidence;
using failure_domain_registry::MembershipGeneration;
using failure_domain_registry::MembershipId;
using failure_domain_registry::MembershipKind;
using failure_domain_registry::MembershipLifecycle;
using failure_domain_registry::MembershipRole;
using failure_domain_registry::MetadataEntry;
using failure_domain_registry::MutationAttempt;
using failure_domain_registry::MutationAttemptId;
using failure_domain_registry::Outcome;
using failure_domain_registry::OutcomeCode;
using failure_domain_registry::Provenance;
using failure_domain_registry::ProvenanceSource;
using failure_domain_registry::PublisherId;
using failure_domain_registry::PublisherRegistration;
using failure_domain_registry::Registry;
using failure_domain_registry::RegistryGeneration;
using failure_domain_registry::RegistryLimits;
using failure_domain_registry::ReplaceMembershipRequest;
using failure_domain_registry::RequestDigest;
using failure_domain_registry::RetireDomainRequest;
using failure_domain_registry::Sha256;
using failure_domain_registry::StateDigest;
using failure_domain_registry::TruthClass;
using failure_domain_registry::UpdateDomainRequest;
using failure_domain_registry::WorkerBootId;

// ---------------------------------------------------------------------------
// Deterministic identity helpers
// ---------------------------------------------------------------------------

/// A non-null, seed-dependent 128-bit pattern: every byte is derived from the
/// seed with a non-zero constant, so no helper can mint the null id by accident.
IdBytes pattern_bytes(std::uint8_t seed) {
  IdBytes out{};
  for (std::size_t index = 0; index < out.size(); ++index) {
    out[index] = static_cast<std::uint8_t>((index * 37u + seed * 11u + 1u) & 0xFFu);
  }
  return out;
}

PublisherId publisher_from(std::uint8_t seed) { return PublisherId::from_bytes(pattern_bytes(seed)); }
WorkerBootId boot_from(std::uint8_t seed) { return WorkerBootId::from_bytes(pattern_bytes(seed)); }

MutationAttemptId attempt_from(std::uint8_t seed) {
  return MutationAttemptId::from_bytes(pattern_bytes(static_cast<std::uint8_t>(seed + 0x40u)));
}

FailureDomainId domain_from(std::uint8_t seed) {
  return FailureDomainId::from_bytes(pattern_bytes(static_cast<std::uint8_t>(seed + 0x80u)));
}

MembershipId membership_from(std::uint8_t seed) {
  return MembershipId::from_bytes(pattern_bytes(static_cast<std::uint8_t>(seed + 0xC0u)));
}

EntityRef entity_ref(EntityClass klass, std::uint8_t seed, EntityGeneration generation) {
  return EntityRef(klass, pattern_bytes(seed), generation);
}

EntityId entity_id(EntityClass klass, std::uint8_t seed) {
  return EntityId(klass, pattern_bytes(seed));
}

Provenance provenance_of(ProvenanceSource source, EvidenceClass evidence, TruthClass truth,
                         std::string source_identity) {
  Provenance provenance;
  provenance.source = source;
  provenance.evidence = evidence;
  provenance.truth = truth;
  provenance.source_identity = std::move(source_identity);
  return provenance;
}

std::string ascii_upper(std::string text) {
  for (char& value : text) {
    if (value >= 'a' && value <= 'f') {
      value = static_cast<char>(value - 'a' + 'A');
    }
  }
  return text;
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

std::string digest_hex(std::string_view text) {
  const DigestBytes bytes = sha256(text);
  return to_hex(bytes.data(), bytes.size());
}

/// Little-endian byte string built from explicit values, so no hex escape in a
/// string literal can be swallowed by its greedy neighbour.
std::string le_bytes(std::initializer_list<unsigned> values) {
  std::string out;
  for (unsigned value : values) {
    out.push_back(static_cast<char>(value & 0xFFu));
  }
  return out;
}

std::size_t common_prefix(std::string_view left, std::string_view right) {
  const std::size_t limit = left.size() < right.size() ? left.size() : right.size();
  std::size_t index = 0;
  while (index < limit && left[index] == right[index]) {
    ++index;
  }
  return index;
}

// ---------------------------------------------------------------------------
// A fresh registry with one bootstrap publisher attached
// ---------------------------------------------------------------------------

struct Session {
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  CoordinatorEpoch epoch{};
};

AuthorityContext authority_of(const Session& session, EvidenceClass evidence) {
  AuthorityContext context;
  context.publisher = session.publisher;
  context.worker_boot = session.worker_boot;
  context.epoch = session.epoch;
  context.evidence = evidence;
  return context;
}

/// Installs one unrestricted publisher, advances the epoch once and attaches a
/// live incarnation. Every case that needs a mutable registry starts here: a
/// mutation needs a registered publisher, a live incarnation and a non-zero
/// epoch, and a fresh registry has none of the three.
void bootstrap(Registry& registry, Session& session) {
  session.publisher = publisher_from(0x11);
  session.worker_boot = boot_from(0x11);

  PublisherRegistration registration;
  registration.publisher = session.publisher;
  registration.name = "digest-publisher";
  registration.scope = AuthorityScope::unrestricted();
  FDR_CHECK_EQ(registry.grant_publisher(registration, AuthorityContext{}).code,
               OutcomeCode::Committed);

  CoordinatorEpoch epoch;
  FDR_CHECK_EQ(registry.advance_epoch(CoordinatorEpoch{}, &epoch).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(epoch.value(), std::uint64_t{1});

  FDR_CHECK_EQ(registry
                   .attach_worker(session.publisher, session.worker_boot, epoch, "digest-worker",
                                  EvidenceClass::DirectAuthoritativeInfrastructure)
                   .code,
               OutcomeCode::Committed);
  session.epoch = epoch;
}

// ---------------------------------------------------------------------------
// Request builders. They never assert: the case asserts the outcome code and the
// ids the outcome carries, so a silently rejected request cannot hide.
// ---------------------------------------------------------------------------

CreateDomainRequest create_request(const Session& session, DomainClass klass, std::string scope,
                                   std::string identity_key, std::string name,
                                   Provenance provenance, std::uint8_t attempt_seed,
                                   bool activate = true,
                                   std::vector<MetadataEntry> metadata = {}) {
  CreateDomainRequest request;
  request.attempt = MutationAttempt(attempt_from(attempt_seed), RequestDigest{});
  request.authority = authority_of(session, provenance.evidence);
  request.domain_class = DomainClassRef(klass);
  request.administrative_scope = std::move(scope);
  request.identity_key = std::move(identity_key);
  request.name = std::move(name);
  request.provenance = std::move(provenance);
  request.activate = activate;
  request.metadata = std::move(metadata);
  return request;
}

AttachMemberRequest attach_request(const Session& session, const FailureDomainId& domain,
                                   const EntityRef& member, MembershipRole role,
                                   Provenance provenance, std::uint8_t attempt_seed) {
  AttachMemberRequest request;
  request.attempt = MutationAttempt(attempt_from(attempt_seed), RequestDigest{});
  request.authority = authority_of(session, provenance.evidence);
  request.domain = domain;
  request.member = member;
  request.kind = MembershipKind::Direct;
  request.role = role;
  request.provenance = std::move(provenance);
  return request;
}

DeclareCoverageRequest coverage_request(const Session& session, std::string scope, DomainClass klass,
                                        CoverageState state, Provenance provenance,
                                        std::uint8_t attempt_seed) {
  DeclareCoverageRequest request;
  request.attempt = MutationAttempt(attempt_from(attempt_seed), RequestDigest{});
  request.authority = authority_of(session, provenance.evidence);
  request.administrative_scope = std::move(scope);
  request.domain_class = DomainClassRef(klass);
  request.state = state;
  request.provenance = std::move(provenance);
  return request;
}

/// The canonical form of every domain in the registry, ordered by identity, so
/// two registries can be compared without depending on table iteration order.
std::vector<std::string> domain_forms(const Registry& registry) {
  std::vector<std::string> out;
  for (const FailureDomain& domain : registry.domains(64)) {
    out.push_back(domain.canonical_form());
  }
  return out;
}

std::vector<std::string> membership_forms(const Registry& registry, const FailureDomainId& domain) {
  std::vector<std::string> out;
  for (const Membership& membership : registry.members_of(domain)) {
    out.push_back(membership.canonical_form());
  }
  return out;
}

// ---------------------------------------------------------------------------
// Record fixtures for the canonical-form cases
// ---------------------------------------------------------------------------

FailureDomain domain_fixture() {
  FailureDomain record;
  record.id = domain_from(1);
  record.domain_class = DomainClassRef(DomainClass::Rack);
  record.generation = FailureDomainGeneration(3);
  record.lifecycle = DomainLifecycle::Current;
  record.name = "rack-r7";
  record.administrative_scope = "dc1";
  record.provenance = provenance_of(ProvenanceSource::OperatorInventory,
                                    EvidenceClass::DirectAuthoritativeInfrastructure,
                                    TruthClass::Real, "inv-42");
  record.created_generation = FailureDomainGeneration(1);
  record.created_at = RegistryGeneration(9);
  record.created_epoch = CoordinatorEpoch(4);
  record.metadata = {MetadataEntry{"floor", "2"}, MetadataEntry{"aisle", "a"}};
  return record;
}

Membership membership_fixture() {
  Membership record;
  record.id = membership_from(1);
  record.domain = domain_from(1);
  record.domain_generation = FailureDomainGeneration(3);
  record.member = entity_ref(EntityClass::Host, 0x22, EntityGeneration(5));
  record.generation = MembershipGeneration(2);
  record.lifecycle = MembershipLifecycle::Current;
  record.kind = MembershipKind::Direct;
  record.role = MembershipRole::Primary;
  record.provenance = provenance_of(ProvenanceSource::Cmdb, EvidenceClass::ImportedStaticInventory,
                                    TruthClass::Real, "cmdb-7");
  record.provenance.publisher = publisher_from(0x31);
  record.provenance.worker_boot = boot_from(0x31);
  record.provenance.evidence_generation = EvidenceGeneration(6);
  record.evidence_generation = EvidenceGeneration(6);
  record.created_at = RegistryGeneration(9);
  record.created_epoch = CoordinatorEpoch(4);
  MembershipEvidence evidence;
  evidence.provenance = record.provenance;
  evidence.live = true;
  record.evidence.push_back(evidence);
  record.metadata = {MetadataEntry{"nic", "0"}, MetadataEntry{"slot", "1"}};
  return record;
}

DomainRelation relation_fixture() {
  DomainRelation record;
  record.id = DomainRelationId::from_bytes(pattern_bytes(0x51));
  record.source = domain_from(1);
  record.target = domain_from(2);
  record.type = DomainRelationType::ContainedBy;
  record.provenance = provenance_of(ProvenanceSource::TopologyDerivation,
                                    EvidenceClass::DerivedTopology, TruthClass::Real, "");
  record.created_at = RegistryGeneration(9);
  record.created_epoch = CoordinatorEpoch(4);
  return record;
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

struct KnownVector {
  std::string_view label;
  std::string message;
  std::string_view digest;
};

std::vector<KnownVector> known_vectors() {
  return {
      KnownVector{"empty", std::string(),
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      KnownVector{"abc", "abc",
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      KnownVector{"nist-448-bit", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
      KnownVector{"nist-896-bit",
                  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrl"
                  "mnopqrsmnopqrstnopqrstu",
                  "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
      KnownVector{"64-a", std::string(64, 'a'),
                  "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"},
      KnownVector{"1000000-a", std::string(1000000, 'a'),
                  "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
  };
}

} // namespace

FDR_TEST_CASE(digest, sha256_matches_the_published_vectors) {
  const std::vector<KnownVector> vectors = known_vectors();
  FDR_CHECK_EQ(vectors.size(), std::size_t{6});
  for (const KnownVector& vector : vectors) {
    const DigestBytes digest = sha256(vector.message);
    FDR_CHECK_MSG(digest_hex(vector.message) == std::string(vector.digest),
                  "SHA-256 mismatch for the " + std::string(vector.label) + " vector: got " +
                      digest_hex(vector.message));
    // The byte-range overload and the string_view overload are the same hash.
    FDR_CHECK_EQ(sha256(vector.message.data(), vector.message.size()), digest);
    FDR_CHECK_EQ(digest.size(), std::size_t{32});
    FDR_CHECK(sha256(vector.message).data() != nullptr);
  }

  FDR_CHECK_EQ(digest_hex(""),
               std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  FDR_CHECK_EQ(digest_hex("abc"),
               std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  FDR_CHECK_EQ(digest_hex(std::string(64, 'a')),
               std::string("ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"));
  FDR_CHECK_EQ(digest_hex(std::string(1000000, 'a')),
               std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

FDR_TEST_CASE(digest, sha256_streaming_matches_one_shot_at_every_boundary) {
  fdrtest::Rng rng(0x5A17u);
  const std::string message = fdrtest::random_text(rng, 300);
  const DigestBytes expected = sha256(message);

  // Splits chosen around the 64-byte block and the 56-byte length field: a
  // buffer-management bug shows up at one of these and nowhere else.
  const std::size_t splits[] = {0, 1, 55, 56, 57, 63, 64, 65, 119, 127, 128, 129, 192, 255, 256, 299, 300};
  for (std::size_t split : splits) {
    Sha256 hasher;
    hasher.update(std::string_view(message).substr(0, split));
    hasher.update(std::string_view(message).substr(split));
    FDR_CHECK_EQ(hasher.finish(), expected);
  }

  // Three-way split with degenerate empty updates in between.
  {
    Sha256 hasher;
    hasher.update(std::string_view());
    hasher.update(std::string_view(message).substr(0, 64));
    hasher.update(std::string_view(message).substr(64, 64));
    hasher.update(message.data() + 128, message.size() - 128);
    FDR_CHECK_EQ(hasher.finish(), expected);
  }

  // One byte at a time exercises the buffer refill path hardest.
  {
    Sha256 hasher;
    for (char value : message) {
      hasher.update(&value, 1);
    }
    FDR_CHECK_EQ(hasher.finish(), expected);
  }

  // reset() restores the documented initial state, so a reused hasher produces
  // the same digest as a fresh one.
  {
    Sha256 hasher;
    hasher.update("abc");
    const DigestBytes first = hasher.finish();
    FDR_CHECK_EQ(first, sha256("abc"));
    hasher.reset();
    hasher.update("abc");
    FDR_CHECK_EQ(hasher.finish(), first);
  }

  // The one-million-byte vector is also streamed: identical bytes, different
  // arrival path, identical digest.
  {
    const std::string big(1000000, 'a');
    Sha256 hasher;
    for (std::size_t offset = 0; offset < big.size(); offset += 4096) {
      const std::size_t remaining = big.size() - offset;
      const std::size_t take = remaining < 4096 ? remaining : 4096;
      hasher.update(big.data() + offset, take);
    }
    const DigestBytes digest = hasher.finish();
    FDR_CHECK_EQ(to_hex(digest.data(), digest.size()),
                 std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
  }
}

FDR_TEST_CASE(digest, hex_helpers_round_trip_and_reject_malformed_text) {
  const IdBytes bytes = pattern_bytes(3);
  const std::string rendered = to_hex(bytes.data(), bytes.size());
  FDR_CHECK_EQ(rendered.size(), failure_domain_registry::kOpaqueIdTextLength);
  FDR_CHECK(is_lowercase_hex(rendered));

  char buffer[failure_domain_registry::kOpaqueIdTextLength] = {};
  render_hex(bytes.data(), bytes.size(), buffer);
  FDR_CHECK_EQ(std::string(buffer, sizeof(buffer)), rendered);

  IdBytes parsed{};
  FDR_CHECK(parse_hex(rendered.data(), rendered.size(), parsed.data()));
  FDR_CHECK_EQ(parsed, bytes);

  // Uppercase is accepted because the rendered form of an id is defined to be
  // readable back in either case.
  const std::string upper = ascii_upper(rendered);
  FDR_CHECK(!(upper == rendered));
  FDR_CHECK(parse_hex(upper.data(), upper.size(), parsed.data()));
  FDR_CHECK_EQ(parsed, bytes);

  // Malformed input is rejected instead of guessed: odd length, a non-hex
  // character anywhere, an 0x prefix and embedded whitespace.
  FDR_CHECK(!parse_hex(rendered.data(), rendered.size() - 1, parsed.data()));
  std::string non_hex = rendered;
  non_hex[0] = 'z';
  FDR_CHECK(!parse_hex(non_hex.data(), non_hex.size(), parsed.data()));
  non_hex = rendered;
  non_hex[rendered.size() - 1] = ' ';
  FDR_CHECK(!parse_hex(non_hex.data(), non_hex.size(), parsed.data()));
  const std::string prefixed = "0x" + rendered.substr(2);
  FDR_CHECK_EQ(prefixed.size(), rendered.size());
  FDR_CHECK(!parse_hex(prefixed.data(), prefixed.size(), parsed.data()));

  // An empty range parses vacuously and writes nothing; the id types never call
  // it with a wrong size, and 32 bytes is the only size a digest is read at.
  IdBytes untouched{};
  FDR_CHECK(parse_hex("", std::size_t{0}, untouched.data()));
  FDR_CHECK_EQ(untouched, IdBytes{});
}

FDR_TEST_CASE(digest, framing_helpers_are_length_prefixed_and_injective) {
  // Exact widths: a u8 is one byte, a u32 four little-endian bytes, a u64 eight.
  std::string single;
  append_u8(single, 0x7Fu);
  FDR_CHECK_EQ(single, le_bytes({0x7F}));

  std::string word;
  append_u32(word, 0x01020304u);
  FDR_CHECK_EQ(word, le_bytes({4, 3, 2, 1}));

  std::string wide;
  append_u64(wide, 0x0102030405060708ull);
  FDR_CHECK_EQ(wide, le_bytes({8, 7, 6, 5, 4, 3, 2, 1}));

  std::string framed;
  append_bytes(framed, "abc");
  FDR_CHECK_EQ(framed.size(), std::size_t{7});
  FDR_CHECK_EQ(framed.substr(0, 4), le_bytes({3, 0, 0, 0}));
  FDR_CHECK_EQ(framed.substr(4), std::string("abc"));

  // The classic ambiguity a bare concatenation would have: "a" then "bc" must
  // not encode to the same bytes as "ab" then "c".
  std::string left;
  append_bytes(left, "a");
  append_bytes(left, "bc");
  std::string right;
  append_bytes(right, "ab");
  append_bytes(right, "c");
  FDR_CHECK(!(left == right));
  FDR_CHECK_EQ(left, le_bytes({1, 0, 0, 0}) + std::string("a") + le_bytes({2, 0, 0, 0}) +
                         std::string("bc"));
  FDR_CHECK_EQ(right, le_bytes({2, 0, 0, 0}) + std::string("ab") + le_bytes({1, 0, 0, 0}) +
                          std::string("c"));

  // Within one encoding discipline every distinct input produces a distinct
  // byte string, including the empty text and texts that are prefixes of each
  // other.
  std::set<std::string> framed_texts;
  const std::string_view texts[] = {"", "a", "ab", "abc", "b", "ba", "bc", "c"};
  for (std::string_view text : texts) {
    std::string encoded;
    append_bytes(encoded, text);
    FDR_CHECK_MSG(framed_texts.insert(encoded).second,
                  "two distinct texts framed to the same encoding");
  }
  FDR_CHECK_EQ(framed_texts.size(), std::size_t{8});

  std::set<std::string> singles;
  std::set<std::string> words;
  std::set<std::string> wide_words;
  for (std::uint8_t value = 0; value < 16; ++value) {
    std::string encoded;
    append_u8(encoded, value);
    FDR_CHECK(singles.insert(encoded).second);
    std::string encoded32;
    append_u32(encoded32, value);
    FDR_CHECK(words.insert(encoded32).second);
    std::string encoded64;
    append_u64(encoded64, value);
    FDR_CHECK(wide_words.insert(encoded64).second);
  }
  FDR_CHECK_EQ(singles.size(), std::size_t{16});
  FDR_CHECK_EQ(words.size(), std::size_t{16});
  FDR_CHECK_EQ(wide_words.size(), std::size_t{16});

  // Concatenated framed texts are injective as sequences: every sequence over a
  // two-letter alphabet up to length three has its own byte string, which is the
  // property the canonical forms rely on.
  std::set<std::string> sequences;
  const std::string_view letters[] = {"a", "b"};
  std::size_t expected_sequences = 0;
  for (std::size_t length = 0; length <= 3; ++length) {
    const std::size_t combinations = std::size_t{1} << length;
    for (std::size_t mask = 0; mask < combinations; ++mask) {
      std::string encoded;
      for (std::size_t index = 0; index < length; ++index) {
        append_bytes(encoded, letters[(mask >> index) & 1u]);
      }
      FDR_CHECK(sequences.insert(encoded).second);
      ++expected_sequences;
    }
  }
  FDR_CHECK_EQ(sequences.size(), expected_sequences);
  FDR_CHECK_EQ(expected_sequences, std::size_t{15});

  // A four-byte length prefix of zero is byte-identical to a bare u32 zero; the
  // two are only used in different positions, so this is pinned rather than
  // denied.
  std::string bare;
  append_u32(bare, 0);
  std::string length_only;
  append_bytes(length_only, "");
  FDR_CHECK_EQ(bare, length_only);
  FDR_CHECK_EQ(length_only, le_bytes({0, 0, 0, 0}));
}

// ---------------------------------------------------------------------------
// Canonical forms
// ---------------------------------------------------------------------------

FDR_TEST_CASE(digest, canonical_forms_are_deterministic_and_field_sensitive) {
  const FailureDomain domain = domain_fixture();
  const std::string domain_form = domain.canonical_form();
  FDR_CHECK_EQ(domain.canonical_form(), domain_form);
  FDR_CHECK_EQ(domain.canonical_form(), domain_form);
  std::string domain_tag;
  append_bytes(domain_tag, "fdr/domain/v1");
  FDR_CHECK_EQ(domain_form.rfind(domain_tag, 0), std::size_t{0});

  const auto domain_changes = [&domain_form](const FailureDomain& other) {
    return !(other.canonical_form() == domain_form);
  };
  {
    FailureDomain other = domain;
    other.id = domain_from(2);
    FDR_CHECK(domain_changes(other));
  }
  {
    FailureDomain other = domain;
    other.domain_class = DomainClassRef(DomainClass::Pod);
    FDR_CHECK(domain_changes(other));
  }
  {
    FailureDomain other = domain;
    other.generation = FailureDomainGeneration(4);
    FDR_CHECK(domain_changes(other));
  }
  {
    FailureDomain other = domain;
    other.lifecycle = DomainLifecycle::Retired;
    FDR_CHECK(domain_changes(other));
  }
  {
    FailureDomain other = domain;
    other.created_generation = FailureDomainGeneration(2);
    FDR_CHECK(domain_changes(other));
  }
  {
    FailureDomain other = domain;
    other.name = "rack-r8";
    FDR_CHECK(domain_changes(other));
  }
  {
    FailureDomain other = domain;
    other.administrative_scope = "dc2";
    FDR_CHECK(domain_changes(other));
  }
  {
    FailureDomain other = domain;
    other.provenance = provenance_of(ProvenanceSource::Cmdb, EvidenceClass::Inferred,
                                     TruthClass::Synthetic, "inv-42");
    FDR_CHECK(domain_changes(other));
  }
  {
    FailureDomain other = domain;
    other.superseded_by = domain_from(3);
    FDR_CHECK(domain_changes(other));
  }
  {
    FailureDomain other = domain;
    other.metadata.push_back(MetadataEntry{"row", "9"});
    FDR_CHECK(domain_changes(other));
  }
  {
    // created_at and created_epoch are process-local bookkeeping: two registries
    // that reached the same classification by different paths must digest
    // identically, so those two fields are deliberately outside the form.
    FailureDomain other = domain;
    other.created_at = RegistryGeneration(999);
    other.created_epoch = CoordinatorEpoch(77);
    FDR_CHECK_EQ(other.canonical_form(), domain_form);
  }

  const Membership membership = membership_fixture();
  const std::string membership_form = membership.canonical_form();
  FDR_CHECK_EQ(membership.canonical_form(), membership_form);
  FDR_CHECK_EQ(membership.canonical_form(), membership_form);
  std::string membership_tag;
  append_bytes(membership_tag, "fdr/membership/v1");
  FDR_CHECK_EQ(membership_form.rfind(membership_tag, 0), std::size_t{0});

  const auto membership_changes = [&membership_form](const Membership& other) {
    return !(other.canonical_form() == membership_form);
  };
  {
    Membership other = membership;
    other.id = membership_from(2);
    FDR_CHECK(membership_changes(other));
  }
  {
    Membership other = membership;
    other.domain = domain_from(4);
    FDR_CHECK(membership_changes(other));
  }
  {
    Membership other = membership;
    other.domain_generation = FailureDomainGeneration(4);
    FDR_CHECK(membership_changes(other));
  }
  {
    Membership other = membership;
    other.member = entity_ref(EntityClass::Switch, 0x22, EntityGeneration(5));
    FDR_CHECK(membership_changes(other));
  }
  {
    Membership other = membership;
    other.member = entity_ref(EntityClass::Host, 0x22, EntityGeneration(6));
    FDR_CHECK(membership_changes(other));
  }
  {
    Membership other = membership;
    other.generation = MembershipGeneration(3);
    FDR_CHECK(membership_changes(other));
  }
  {
    Membership other = membership;
    other.lifecycle = MembershipLifecycle::RevalidationRequired;
    FDR_CHECK(membership_changes(other));
  }
  {
    Membership other = membership;
    other.kind = MembershipKind::Asserted;
    FDR_CHECK(membership_changes(other));
  }
  {
    Membership other = membership;
    other.role = MembershipRole::SharedRisk;
    FDR_CHECK(membership_changes(other));
  }
  {
    Membership other = membership;
    other.dependency = failure_domain_registry::DependencySemantics::RedundantSource;
    FDR_CHECK(membership_changes(other));
  }
  {
    Membership other = membership;
    other.evidence_generation = EvidenceGeneration(7);
    FDR_CHECK(membership_changes(other));
  }
  {
    Membership other = membership;
    other.evidence[0].live = false;
    FDR_CHECK(membership_changes(other));
  }
  {
    Membership other = membership;
    other.derivation.rule = DerivationRuleId::from_bytes(pattern_bytes(0x61));
    other.derivation.generation = DerivationGeneration(2);
    other.derivation.valid = true;
    FDR_CHECK(membership_changes(other));
  }
  {
    Membership other = membership;
    other.metadata.push_back(MetadataEntry{"row", "9"});
    FDR_CHECK(membership_changes(other));
  }
  {
    Membership other = membership;
    other.provenance.evidence_generation = EvidenceGeneration(9);
    FDR_CHECK(membership_changes(other));
  }
  {
    Membership other = membership;
    other.created_at = RegistryGeneration(999);
    other.created_epoch = CoordinatorEpoch(77);
    FDR_CHECK_EQ(other.canonical_form(), membership_form);
  }

  const Provenance provenance = provenance_of(ProvenanceSource::Cmdb,
                                              EvidenceClass::ImportedStaticInventory,
                                              TruthClass::Real, "cmdb-7");
  const std::string provenance_form = provenance.canonical_form();
  FDR_CHECK_EQ(provenance.canonical_form(), provenance_form);
  FDR_CHECK_EQ(provenance.canonical_form(), provenance_form);
  const auto provenance_changes = [&provenance_form](const Provenance& other) {
    return !(other.canonical_form() == provenance_form);
  };
  {
    Provenance other = provenance;
    other.source = ProvenanceSource::DiscoveryAgent;
    FDR_CHECK(provenance_changes(other));
  }
  {
    Provenance other = provenance;
    other.evidence = EvidenceClass::Inferred;
    FDR_CHECK(provenance_changes(other));
  }
  {
    Provenance other = provenance;
    other.truth = TruthClass::Synthetic;
    FDR_CHECK(provenance_changes(other));
  }
  {
    Provenance other = provenance;
    other.publisher = publisher_from(0x31);
    FDR_CHECK(provenance_changes(other));
  }
  {
    Provenance other = provenance;
    other.worker_boot = boot_from(0x31);
    FDR_CHECK(provenance_changes(other));
  }
  {
    Provenance other = provenance;
    other.evidence_generation = EvidenceGeneration(3);
    FDR_CHECK(provenance_changes(other));
  }
  {
    Provenance other = provenance;
    other.source_identity = "cmdb-8";
    FDR_CHECK(provenance_changes(other));
  }
  {
    Provenance other = provenance;
    other.derivation_rule = DerivationRuleId::from_bytes(pattern_bytes(0x71));
    FDR_CHECK(provenance_changes(other));
  }
  {
    Provenance other = provenance;
    other.derivation_context = "switch:1@2;";
    FDR_CHECK(provenance_changes(other));
  }

  const DomainRelation relation = relation_fixture();
  const std::string relation_form = relation.canonical_form();
  FDR_CHECK_EQ(relation.canonical_form(), relation_form);
  FDR_CHECK_EQ(relation.canonical_form(), relation_form);
  const auto relation_changes = [&relation_form](const DomainRelation& other) {
    return !(other.canonical_form() == relation_form);
  };
  {
    DomainRelation other = relation;
    other.source = domain_from(5);
    FDR_CHECK(relation_changes(other));
  }
  {
    DomainRelation other = relation;
    other.target = domain_from(6);
    FDR_CHECK(relation_changes(other));
  }
  {
    DomainRelation other = relation;
    other.type = DomainRelationType::PoweredBy;
    FDR_CHECK(relation_changes(other));
  }
  {
    DomainRelation other = relation;
    other.provenance = provenance_of(ProvenanceSource::Cmdb, EvidenceClass::Inferred,
                                     TruthClass::Synthetic, "");
    FDR_CHECK(relation_changes(other));
  }
  {
    DomainRelation other = relation;
    other.id = DomainRelationId::from_bytes(pattern_bytes(0x52));
    FDR_CHECK(relation_changes(other));
  }
  {
    // Unlike a domain or a membership, a relation's canonical form includes the
    // registry generation and epoch it was created at. That is the behaviour
    // this build has, so it is pinned rather than assumed away.
    DomainRelation other = relation;
    other.created_at = RegistryGeneration(10);
    FDR_CHECK(relation_changes(other));
  }
}

FDR_TEST_CASE(digest, canonical_metadata_is_sorted_and_the_layout_is_stable) {
  FailureDomain domain = domain_fixture();
  domain.metadata = {MetadataEntry{"zeta", "1"}, MetadataEntry{"alpha", "2"},
                     MetadataEntry{"mid", "3"}};
  FailureDomain reordered = domain;
  reordered.metadata = {MetadataEntry{"mid", "3"}, MetadataEntry{"alpha", "2"},
                        MetadataEntry{"zeta", "1"}};
  FDR_CHECK_EQ(reordered.canonical_form(), domain.canonical_form());

  // Metadata is only order-insensitive: its content and its entry count are
  // both visible.
  FailureDomain changed = reordered;
  changed.metadata[2].value = "4";
  FDR_CHECK(!(changed.canonical_form() == domain.canonical_form()));
  FailureDomain fewer = reordered;
  fewer.metadata.pop_back();
  FDR_CHECK(!(fewer.canonical_form() == domain.canonical_form()));

  Membership membership = membership_fixture();
  membership.metadata = {MetadataEntry{"zeta", "1"}, MetadataEntry{"alpha", "2"}};
  Membership membership_reordered = membership;
  membership_reordered.metadata = {MetadataEntry{"alpha", "2"}, MetadataEntry{"zeta", "1"}};
  FDR_CHECK_EQ(membership_reordered.canonical_form(), membership.canonical_form());
  Membership membership_changed = membership_reordered;
  membership_changed.metadata[0].value = "9";
  FDR_CHECK(!(membership_changed.canonical_form() == membership.canonical_form()));

  // Field order is fixed: the name is written after a known prefix, so two
  // different names leave exactly the same prefix intact. A reordered encoder
  // would move that boundary.
  std::string layout;
  append_bytes(layout, "fdr/domain/v1");
  append_bytes(layout, domain.id.to_string());
  append_bytes(layout, domain.domain_class.to_string());
  append_u64(layout, domain.generation.value());
  append_u8(layout, static_cast<std::uint8_t>(domain.lifecycle));
  append_u64(layout, domain.created_generation.value());
  // superseded_by, supersedes and merged_into are written before the name, so
  // three framed ids belong to the prefix.
  append_bytes(layout, domain.superseded_by.to_string());
  append_bytes(layout, domain.supersedes.to_string());
  append_bytes(layout, domain.merged_into.to_string());
  const std::size_t name_offset = layout.size();
  FDR_CHECK(name_offset > 0);

  FailureDomain first = domain;
  first.name = "a";
  FailureDomain second = domain;
  second.name = "a-much-longer-name";
  FDR_CHECK_EQ(common_prefix(domain.canonical_form(), first.canonical_form()), name_offset);
  FDR_CHECK_EQ(common_prefix(domain.canonical_form(), second.canonical_form()), name_offset);
  // The name really is inside the form: a longer name makes a longer form.
  FDR_CHECK_EQ(second.canonical_form().size() > domain.canonical_form().size(), true);
}

// ---------------------------------------------------------------------------
// Request digests
// ---------------------------------------------------------------------------

FDR_TEST_CASE(digest, request_digest_is_deterministic_and_covers_the_whole_form) {
  std::string form;
  append_bytes(form, "fdr/req/create-domain/v1");
  append_bytes(form, DomainClassRef(DomainClass::Rack).to_string());
  append_bytes(form, "dc1");
  append_bytes(form, "rack-r7");
  append_bytes(form, "rack seven");
  append_u8(form, 1u);

  const RequestDigest digest = request_digest_of(form);
  FDR_CHECK(!digest.is_null());
  FDR_CHECK_EQ(request_digest_of(form), digest);
  FDR_CHECK_EQ(request_digest_of(std::string_view(form)), digest);

  // Every byte of the canonical form participates: a changed, added, removed or
  // case-flipped byte produces a different request digest, which is what makes
  // an exact replay distinguishable from a conflicting one.
  std::set<std::string> digests;
  FDR_CHECK(digests.insert(digest.to_string()).second);

  const std::string variants[] = {
      form + " ",
      " " + form,
      form.substr(1),
      form.substr(0, form.size() - 1),
      ascii_upper(form),
      std::string(form).append(1, '\0'),
  };
  const std::size_t variant_count = sizeof(variants) / sizeof(variants[0]);
  for (std::size_t index = 0; index < variant_count; ++index) {
    const std::string& variant = variants[index];
    FDR_CHECK_MSG(!(variant == form), "variant " + std::to_string(index) + " is not a change");
    const RequestDigest other = request_digest_of(variant);
    FDR_CHECK(!(other == digest));
    FDR_CHECK(digests.insert(other.to_string()).second);
  }
  FDR_CHECK_EQ(digests.size(), variant_count + 1);

  // The empty form has a digest too, and it is the empty-string SHA-256.
  const RequestDigest empty = request_digest_of("");
  FDR_CHECK(!empty.is_null());
  FDR_CHECK(!(empty == digest));
  FDR_CHECK_EQ(empty.to_string(),
               std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

// ---------------------------------------------------------------------------
// The registry state digest
// ---------------------------------------------------------------------------

namespace {

/// Builds one classification. The reversed flag changes the arrival order of the
/// domains, of each domain's metadata entries and of the coverage declarations;
/// membership publication order is held fixed because the evidence counter is
/// consumed per publication, which the case below pins separately.
void build_state(Registry& registry, const Session& session, bool reversed) {
  const Provenance durable = provenance_of(ProvenanceSource::OperatorInventory,
                                           EvidenceClass::DirectAuthoritativeInfrastructure,
                                           TruthClass::Real, "inv-1");
  const MetadataEntry rack_metadata[] = {MetadataEntry{"aisle", "a"}, MetadataEntry{"floor", "2"}};

  const DomainClass classes[] = {DomainClass::Rack, DomainClass::Pdu, DomainClass::Conduit};
  const char* keys[] = {"rack-r7", "pdu-p3", "conduit-c1"};
  const char* names[] = {"rack seven", "pdu three", "conduit one"};
  const char* scopes[] = {"dc1", "dc1", "dc2"};

  FailureDomainId rack;
  FailureDomainId pdu;
  for (std::size_t step = 0; step < 3; ++step) {
    const std::size_t index = reversed ? (2 - step) : step;
    std::vector<MetadataEntry> metadata;
    if (index == 0) {
      if (reversed) {
        metadata.assign(rack_metadata + 1, rack_metadata + 2);
        metadata.push_back(rack_metadata[0]);
      } else {
        metadata.assign(rack_metadata, rack_metadata + 2);
      }
    }
    const CreateDomainRequest request =
        create_request(session, classes[index], scopes[index], keys[index], names[index], durable,
                       static_cast<std::uint8_t>(0x10u + index), true, metadata);
    const Outcome outcome = registry.create_domain(request);
    FDR_CHECK_MSG(outcome.code == OutcomeCode::Committed,
                  "domain " + std::string(keys[index]) + " was rejected: " + outcome.message);
    FDR_CHECK(outcome.domain.has_value());
    const FailureDomainId id = *outcome.domain;
    if (index == 0) {
      rack = id;
    } else if (index == 1) {
      pdu = id;
    }
  }
  FDR_CHECK(!rack.is_null());
  FDR_CHECK(!pdu.is_null());

  const AttachMemberRequest first =
      attach_request(session, rack, entity_ref(EntityClass::Host, 0x22, EntityGeneration(1)),
                     MembershipRole::Primary, durable, 0x31);
  FDR_CHECK_EQ(registry.attach_member(first).code, OutcomeCode::Committed);
  const AttachMemberRequest second =
      attach_request(session, pdu, entity_ref(EntityClass::Port, 0x23, EntityGeneration(1)),
                     MembershipRole::SharedRisk, durable, 0x32);
  FDR_CHECK_EQ(registry.attach_member(second).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{3});
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{2});

  const DeclareCoverageRequest coverage[] = {
      coverage_request(session, "dc1", DomainClass::Rack, CoverageState::Complete, durable, 0x41),
      coverage_request(session, "dc2", DomainClass::Conduit, CoverageState::Partial, durable, 0x42),
  };
  for (std::size_t step = 0; step < 2; ++step) {
    const std::size_t index = reversed ? (1 - step) : step;
    FDR_CHECK_EQ(registry.declare_coverage(coverage[index]).code, OutcomeCode::Committed);
  }
}

} // namespace

FDR_TEST_CASE(digest, state_digest_is_independent_of_arrival_order) {
  Registry first(RegistryLimits::defaults());
  Session first_session;
  bootstrap(first, first_session);
  build_state(first, first_session, false);

  Registry second(RegistryLimits::defaults());
  Session second_session;
  bootstrap(second, second_session);
  build_state(second, second_session, true);

  // The two registries reached the same classification by different paths: the
  // same counts and the same per-record canonical forms.
  FDR_CHECK_EQ(first.domain_count(), second.domain_count());
  FDR_CHECK_EQ(first.membership_count(), second.membership_count());
  FDR_CHECK_EQ(domain_forms(first), domain_forms(second));
  FDR_CHECK_EQ(first.domains(8).size(), std::size_t{3});
  FDR_CHECK_EQ(membership_forms(first, first.domains(8)[0].id),
               membership_forms(second, second.domains(8)[0].id));

  const StateDigest first_digest = first.state_digest();
  const StateDigest second_digest = second.state_digest();
  FDR_CHECK(!first_digest.is_null());
  FDR_CHECK_EQ(first_digest, second_digest);
  FDR_CHECK_EQ(first.state_digest(), first_digest);

  std::string why;
  FDR_CHECK_MSG(first.validate_state(&why), "first registry is inconsistent: " + why);
  why.clear();
  FDR_CHECK_MSG(second.validate_state(&why), "second registry is inconsistent: " + why);
}

FDR_TEST_CASE(digest, state_digest_is_order_sensitive_to_evidence_publication) {
  // The same two memberships published in opposite order. The evidence
  // generation is handed out by one per-registry counter and is part of the
  // membership canonical form, so this build reaches two different digests -
  // which contradicts the arrival-order sentence in digest.hpp. The divergence
  // is pinned here instead of being papered over.
  const Provenance durable = provenance_of(ProvenanceSource::OperatorInventory,
                                           EvidenceClass::DirectAuthoritativeInfrastructure,
                                           TruthClass::Real, "inv-1");
  const EntityRef first_member = entity_ref(EntityClass::Host, 0x22, EntityGeneration(1));
  const EntityRef second_member = entity_ref(EntityClass::Switch, 0x23, EntityGeneration(1));

  Registry forward(RegistryLimits::defaults());
  Session forward_session;
  bootstrap(forward, forward_session);
  const Outcome forward_domain = forward.create_domain(
      create_request(forward_session, DomainClass::Rack, "dc1", "rack-r7", "rack seven", durable, 0x10));
  FDR_CHECK_EQ(forward_domain.code, OutcomeCode::Committed);
  FDR_CHECK(forward_domain.domain.has_value());
  const FailureDomainId domain = *forward_domain.domain;
  FDR_CHECK_EQ(forward.attach_member(attach_request(forward_session, domain, first_member,
                                                    MembershipRole::Primary, durable, 0x31))
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(forward.attach_member(attach_request(forward_session, domain, second_member,
                                                    MembershipRole::Primary, durable, 0x32))
                   .code,
               OutcomeCode::Committed);
  const std::vector<std::string> forward_forms = membership_forms(forward, domain);
  FDR_CHECK_EQ(forward_forms.size(), std::size_t{2});

  Registry backward(RegistryLimits::defaults());
  Session backward_session;
  bootstrap(backward, backward_session);
  FDR_CHECK_EQ(backward.create_domain(create_request(backward_session, DomainClass::Rack, "dc1",
                                                     "rack-r7", "rack seven", durable, 0x10))
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(backward.attach_member(attach_request(backward_session, domain, second_member,
                                                     MembershipRole::Primary, durable, 0x31))
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(backward.attach_member(attach_request(backward_session, domain, first_member,
                                                     MembershipRole::Primary, durable, 0x32))
                   .code,
               OutcomeCode::Committed);
  const std::vector<std::string> backward_forms = membership_forms(backward, domain);
  FDR_CHECK_EQ(backward_forms.size(), std::size_t{2});

  // Same records, same counts, same classification: only arrival order differs.
  FDR_CHECK_EQ(forward.domain_count(), backward.domain_count());
  FDR_CHECK_EQ(forward.membership_count(), backward.membership_count());
  FDR_CHECK_EQ(forward.members_of(domain).size(), backward.members_of(domain).size());
  FDR_CHECK(!(forward.state_digest() == backward.state_digest()));
  FDR_CHECK(!(forward_forms == backward_forms));
  FDR_CHECK_EQ(forward_forms[0].size(), backward_forms[0].size());

  std::string why;
  FDR_CHECK_MSG(forward.validate_state(&why), "forward registry is inconsistent: " + why);
  why.clear();
  FDR_CHECK_MSG(backward.validate_state(&why), "backward registry is inconsistent: " + why);
}

FDR_TEST_CASE(digest, one_semantic_change_moves_the_state_digest) {
  // One reference classification and four variants that are identical to it
  // except for a single semantic field, so a digest difference can only come
  // from that field and never from a difference in how much was classified.
  const Provenance durable = provenance_of(ProvenanceSource::OperatorInventory,
                                           EvidenceClass::DirectAuthoritativeInfrastructure,
                                           TruthClass::Real, "inv-1");
  // Same source, same truth, same source identity: only the evidence class
  // differs, which is the field the case is about.
  const Provenance weaker = provenance_of(ProvenanceSource::OperatorInventory,
                                          EvidenceClass::AdministrativeDeclaration,
                                          TruthClass::Real, "inv-1");

  struct Variant {
    const char* label;
    std::string name;
    Provenance provenance;
    bool activate;
    MembershipRole role;
  };
  const std::vector<Variant> variants = {
      {"reference", "rack seven", durable, true, MembershipRole::Primary},
      {"name", "rack seven (renamed)", durable, true, MembershipRole::Primary},
      {"evidence-class", "rack seven", weaker, true, MembershipRole::Primary},
      {"lifecycle", "rack seven", durable, false, MembershipRole::Primary},
      {"membership-role", "rack seven", durable, true, MembershipRole::Backup},
  };
  // A run-time size, so the assertion is a check and not a constant expression.
  FDR_CHECK_EQ(variants.size(), std::size_t{5});

  std::set<std::string> digests;
  for (std::size_t index = 0; index < variants.size(); ++index) {
    Registry registry(RegistryLimits::defaults());
    Session session;
    bootstrap(registry, session);
    const CreateDomainRequest request =
        create_request(session, DomainClass::Rack, "dc1", "rack-r7", variants[index].name,
                       variants[index].provenance, static_cast<std::uint8_t>(0x10u + index),
                       variants[index].activate);
    const Outcome created = registry.create_domain(request);
    FDR_CHECK_MSG(created.code == OutcomeCode::Committed,
                  std::string(variants[index].label) + " was rejected: " + created.message);
    FDR_CHECK(created.domain.has_value());
    // The membership always carries the durable provenance, so the variant that
    // changes the domain's evidence class changes exactly that one field.
    const Outcome attached = registry.attach_member(
        attach_request(session, *created.domain,
                       entity_ref(EntityClass::Host, 0x22, EntityGeneration(1)),
                       variants[index].role, durable, 0x31));
    FDR_CHECK_MSG(attached.code == OutcomeCode::Committed,
                  std::string(variants[index].label) + " attach was rejected: " + attached.message);
    FDR_CHECK(attached.membership.has_value());

    // Every variant holds exactly the same records; only the field differs.
    FDR_CHECK_EQ(registry.domain_count(), std::size_t{1});
    FDR_CHECK_EQ(registry.membership_count(), std::size_t{1});
    FDR_CHECK(registry.domain(*created.domain).has_value());
    FDR_CHECK_EQ(registry.domain(*created.domain)->lifecycle,
                 variants[index].activate ? DomainLifecycle::Current : DomainLifecycle::Candidate);
    FDR_CHECK(registry.membership(*attached.membership).has_value());
    FDR_CHECK_EQ(registry.membership(*attached.membership)->role, variants[index].role);

    // One field different means one different digest, and no two variants
    // collide.
    FDR_CHECK_MSG(digests.insert(registry.state_digest().to_string()).second,
                  std::string(variants[index].label) + " reached a digest another variant had");
    std::string why;
    FDR_CHECK_MSG(registry.validate_state(&why),
                  std::string(variants[index].label) + " is inconsistent: " + why);
  }
  FDR_CHECK_EQ(digests.size(), variants.size());
}

FDR_TEST_CASE(digest, state_digest_moves_on_every_commit_and_never_on_a_query) {
  Registry registry(RegistryLimits::defaults());
  Session session;
  bootstrap(registry, session);
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{0});
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{0});

  const Provenance durable = provenance_of(ProvenanceSource::OperatorInventory,
                                           EvidenceClass::DirectAuthoritativeInfrastructure,
                                           TruthClass::Real, "inv-1");
  StateDigest digest = registry.state_digest();
  FDR_CHECK(!digest.is_null());
  FDR_CHECK_EQ(registry.state_digest(), digest);
  // The bootstrap grant, the epoch advance and the attach each advanced the
  // registry generation once; every expectation below is relative to that.
  const std::uint64_t start = registry.generation().value();
  FDR_CHECK_EQ(start, std::uint64_t{3});

  // Queries never change the digest.
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "fresh registry is inconsistent: " + why);
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{0});
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{0});
  FDR_CHECK_EQ(registry.publishers().size(), std::size_t{1});
  FDR_CHECK_EQ(registry.live_sessions().size(), std::size_t{1});
  FDR_CHECK_EQ(registry.fences().size(), std::size_t{0});
  FDR_CHECK_EQ(registry.derivation_rules().size(), std::size_t{0});
  FDR_CHECK_EQ(registry.domains(8).size(), std::size_t{0});
  FDR_CHECK_EQ(registry.domains_of_class(DomainClassRef(DomainClass::Rack)).size(), std::size_t{0});
  FDR_CHECK_EQ(registry.domains_in_scope("dc1").size(), std::size_t{0});
  FDR_CHECK_EQ(registry.domains_in_lifecycle(DomainLifecycle::Current).size(), std::size_t{0});
  FDR_CHECK_EQ(registry.members_of(domain_from(9)).size(), std::size_t{0});
  FDR_CHECK_EQ(registry.memberships_of(entity_id(EntityClass::Host, 0x22)).size(), std::size_t{0});
  FDR_CHECK_EQ(registry.memberships_of_publisher(session.publisher).size(), std::size_t{0});
  FDR_CHECK_EQ(registry.recent_outcomes(8).empty(), false);
  FDR_CHECK_EQ(registry.snapshot("digest").domains.size(), std::size_t{0});
  FDR_CHECK_EQ(registry.state_digest(), digest);

  // A committed create moves the digest and advances the registry generation by
  // exactly one.
  const CreateDomainRequest create =
      create_request(session, DomainClass::Rack, "dc1", "rack-r7", "rack seven", durable, 0x10);
  FDR_CHECK_EQ(registry.generation().value(), start);
  const Outcome created = registry.create_domain(create);
  FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
  FDR_CHECK(created.domain.has_value());
  const FailureDomainId domain = *created.domain;
  FDR_CHECK_EQ(registry.generation().value(), start + 1u);
  const StateDigest after_create = registry.state_digest();
  FDR_CHECK(!(after_create == digest));
  FDR_CHECK_EQ(registry.state_digest(), after_create);

  // An exact replay is Idempotent: no new generation, no new digest.
  const Outcome replay = registry.create_domain(create);
  FDR_CHECK_EQ(replay.code, OutcomeCode::Idempotent);
  FDR_CHECK_EQ(registry.generation().value(), start + 1u);
  FDR_CHECK_EQ(registry.state_digest(), after_create);

  // A rejected mutation changes nothing either: a fresh attempt id, a stale
  // expected generation, and a digest that must not move.
  UpdateDomainRequest stale;
  stale.attempt = MutationAttempt(attempt_from(0x77), RequestDigest{});
  stale.authority = authority_of(session, EvidenceClass::DirectAuthoritativeInfrastructure);
  stale.domain = domain;
  stale.expected_generation = FailureDomainGeneration(99);
  stale.name = std::string("rack seven (stale)");
  const Outcome rejected = registry.update_domain(stale);
  FDR_CHECK_EQ(rejected.code, OutcomeCode::StaleGeneration);
  FDR_CHECK_EQ(registry.generation().value(), start + 1u);
  FDR_CHECK_EQ(registry.state_digest(), after_create);
  FDR_CHECK(registry.domain(domain).has_value());
  FDR_CHECK_EQ(registry.domain(domain)->name, std::string("rack seven"));

  // A committed update moves it.
  UpdateDomainRequest rename;
  rename.attempt = MutationAttempt(attempt_from(0x78), RequestDigest{});
  rename.authority = authority_of(session, EvidenceClass::DirectAuthoritativeInfrastructure);
  rename.domain = domain;
  FDR_CHECK(registry.domain(domain).has_value());
  rename.expected_generation = registry.domain(domain)->generation;
  rename.name = std::string("rack seven (renamed)");
  FDR_CHECK_EQ(registry.update_domain(rename).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.generation().value(), start + 2u);
  const StateDigest after_update = registry.state_digest();
  FDR_CHECK(!(after_update == after_create));

  // A committed attach moves it.
  const Outcome attached = registry.attach_member(
      attach_request(session, domain, entity_ref(EntityClass::Host, 0x22, EntityGeneration(1)),
                     MembershipRole::Primary, durable, 0x31));
  FDR_CHECK_EQ(attached.code, OutcomeCode::Committed);
  FDR_CHECK(attached.membership.has_value());
  FDR_CHECK_EQ(registry.generation().value(), start + 3u);
  const StateDigest after_attach = registry.state_digest();
  FDR_CHECK(!(after_attach == after_update));

  // A committed role replacement moves it.
  ReplaceMembershipRequest replace;
  replace.attempt = MutationAttempt(attempt_from(0x79), RequestDigest{});
  replace.authority = authority_of(session, EvidenceClass::DirectAuthoritativeInfrastructure);
  replace.membership = *attached.membership;
  replace.role = MembershipRole::Redundant;
  FDR_CHECK_EQ(registry.replace_membership(replace).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.generation().value(), start + 4u);
  const StateDigest after_replace = registry.state_digest();
  FDR_CHECK(!(after_replace == after_attach));

  // A committed coverage declaration moves it.
  FDR_CHECK_EQ(registry
                   .declare_coverage(coverage_request(session, "dc1", DomainClass::Rack,
                                                      CoverageState::Complete, durable, 0x41))
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.generation().value(), start + 5u);
  const StateDigest after_coverage = registry.state_digest();
  FDR_CHECK(!(after_coverage == after_replace));

  // A committed retire moves it and closes the record.
  RetireDomainRequest retire;
  retire.attempt = MutationAttempt(attempt_from(0x7A), RequestDigest{});
  retire.authority = authority_of(session, EvidenceClass::DirectAuthoritativeInfrastructure);
  retire.domain = domain;
  FDR_CHECK(registry.domain(domain).has_value());
  retire.expected_generation = registry.domain(domain)->generation;
  retire.reason = "test retired";
  FDR_CHECK_EQ(registry.retire_domain(retire).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.generation().value(), start + 6u);
  const StateDigest after_retire = registry.state_digest();
  FDR_CHECK(!(after_retire == after_coverage));
  FDR_CHECK(registry.domain(domain).has_value());
  FDR_CHECK_EQ(registry.domain(domain)->lifecycle, DomainLifecycle::Retired);

  // Retiring an already retired domain is Idempotent even with a fresh attempt:
  // no new generation, no new digest.
  RetireDomainRequest again = retire;
  again.attempt = MutationAttempt(attempt_from(0x7B), RequestDigest{});
  FDR_CHECK_EQ(registry.retire_domain(again).code, OutcomeCode::Idempotent);
  FDR_CHECK_EQ(registry.generation().value(), start + 6u);
  FDR_CHECK_EQ(registry.state_digest(), after_retire);

  why.clear();
  FDR_CHECK_MSG(registry.validate_state(&why), "registry is inconsistent: " + why);
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
