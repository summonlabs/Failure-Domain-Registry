// Failure Domain Registry — the persistence corruption matrix and every
// truncation of a real image.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every byte position of a real image is examined here. The container layout is
// decoded from src/persistence.cpp rather than guessed: magic, version, flags,
// declared payload length, payload digest, header digest, payload, trailer. Each
// record-level mutation is produced by walking that layout to the exact field,
// changing it, and recomputing both digests so the image is otherwise valid -
// a rejection therefore has to come from the decoder's own cross-checks. The two
// mutations this build accepts are pinned as accepted, with the reason, instead
// of being asserted as rejections. Every image lives in its own temporary
// directory that a guard removes even when a check aborts the case.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "failure_domain_registry/failure_domain_registry.hpp"
#include "support/test_harness.hpp"

namespace {

using failure_domain_registry::append_u32;
using failure_domain_registry::append_u64;
using failure_domain_registry::inspect_persistence;
using failure_domain_registry::kStateFormatVersion;
using failure_domain_registry::kStateHeaderBytes;
using failure_domain_registry::kStateTrailerBytes;
using failure_domain_registry::sha256;
using failure_domain_registry::to_hex;
using failure_domain_registry::AttachMemberRequest;
using failure_domain_registry::AuthorityContext;
using failure_domain_registry::AuthorityScope;
using failure_domain_registry::CoordinatorEpoch;
using failure_domain_registry::CoverageState;
using failure_domain_registry::CreateDomainRequest;
using failure_domain_registry::DeclareCoverageRequest;
using failure_domain_registry::DomainClass;
using failure_domain_registry::DomainClassRef;
using failure_domain_registry::DomainRelationType;
using failure_domain_registry::EntityClass;
using failure_domain_registry::EntityGeneration;
using failure_domain_registry::EntityRef;
using failure_domain_registry::EvidenceClass;
using failure_domain_registry::FailureDomainId;
using failure_domain_registry::FenceReason;
using failure_domain_registry::MembershipId;
using failure_domain_registry::IdBytes;
using failure_domain_registry::MutationAttempt;
using failure_domain_registry::MutationAttemptId;
using failure_domain_registry::Outcome;
using failure_domain_registry::OutcomeCode;
using failure_domain_registry::PersistenceConfig;
using failure_domain_registry::Provenance;
using failure_domain_registry::ProvenanceSource;
using failure_domain_registry::PublisherId;
using failure_domain_registry::PublisherRegistration;
using failure_domain_registry::Registry;
using failure_domain_registry::RegistryLimits;
using failure_domain_registry::RequestDigest;
using failure_domain_registry::TruthClass;
using failure_domain_registry::WorkerBootId;

// ---------------------------------------------------------------------------
// The container layout, exactly as src/persistence.cpp writes it
// ---------------------------------------------------------------------------

constexpr std::size_t kMagicOffset = 0;
constexpr std::size_t kVersionOffset = 8;
constexpr std::size_t kFlagsOffset = 12;
constexpr std::size_t kDeclaredLengthOffset = 16;
constexpr std::size_t kPayloadDigestOffset = 24;
constexpr std::size_t kHeaderDigestOffset = 56;
constexpr std::size_t kHeaderDigestBytes = kHeaderDigestOffset - kPayloadDigestOffset;
constexpr char kMagicText[] = "FDRSTATE";
constexpr char kTrailerText[] = "FDREND";

constexpr std::size_t kNoOffset = std::string_view::npos;

std::uint32_t read_u32(std::string_view bytes, std::size_t offset) {
  std::uint32_t value = 0;
  for (unsigned shift = 0; shift < 32; shift += 8) {
    value |= static_cast<std::uint32_t>(
                 static_cast<unsigned char>(bytes[offset + shift / 8u]))
             << shift;
  }
  return value;
}

std::uint64_t read_u64(std::string_view bytes, std::size_t offset) {
  std::uint64_t value = 0;
  for (unsigned shift = 0; shift < 64; shift += 8) {
    value |= static_cast<std::uint64_t>(
                 static_cast<unsigned char>(bytes[offset + shift / 8u]))
             << shift;
  }
  return value;
}

void write_u32(std::string& bytes, std::size_t offset, std::uint32_t value) {
  for (unsigned shift = 0; shift < 32; shift += 8) {
    bytes[offset + shift / 8u] = static_cast<char>((value >> shift) & 0xFFu);
  }
}

void write_u64(std::string& bytes, std::size_t offset, std::uint64_t value) {
  for (unsigned shift = 0; shift < 64; shift += 8) {
    bytes[offset + shift / 8u] = static_cast<char>((value >> shift) & 0xFFu);
  }
}

/// Writes a fresh container around a payload, recomputing the payload digest and
/// the header digest so that a mutated payload is otherwise a valid image.
std::string build_container(std::string_view payload, std::uint32_t version = kStateFormatVersion,
                            std::uint32_t flags = 0) {
  std::string container;
  container.reserve(kStateHeaderBytes + payload.size() + kStateTrailerBytes);
  container.append(kMagicText, 8);
  append_u32(container, version);
  append_u32(container, flags);
  append_u64(container, static_cast<std::uint64_t>(payload.size()));
  const auto payload_digest = sha256(payload);
  container.append(reinterpret_cast<const char*>(payload_digest.data()), payload_digest.size());
  const auto header_digest = sha256(container.data(), kHeaderDigestOffset);
  container.append(reinterpret_cast<const char*>(header_digest.data()), header_digest.size());
  container.append(payload);
  container.append(kTrailerText, kStateTrailerBytes);
  return container;
}

/// Recomputes only the header digest, used after a mutation that the header
/// digest covers (the declared length and the payload digest).
void refresh_header_digest(std::string& container) {
  const auto header_digest = sha256(container.data(), kHeaderDigestOffset);
  for (std::size_t index = 0; index < header_digest.size(); ++index) {
    container[kHeaderDigestOffset + index] = static_cast<char>(header_digest[index]);
  }
}

std::string_view payload_of(std::string_view container) {
  return container.substr(kStateHeaderBytes, container.size() - kStateHeaderBytes -
                                                 kStateTrailerBytes);
}

// ---------------------------------------------------------------------------
// The payload layout, walked exactly as src/persistence.cpp encodes it
// ---------------------------------------------------------------------------

constexpr std::uint32_t kAbsurdCount = 1'000'000u;

/// One record's byte range inside the payload.
struct Span {
  std::size_t begin{0};
  std::size_t end{0};

  std::size_t size() const { return end - begin; }
};

/// A bounds-checked reader for the fields this file walks past. Every skip
/// mirrors the matching reader in src/persistence.cpp; a walk that would run
/// past the buffer clears ok instead of reading out of bounds.
struct Cursor {
  std::string_view bytes;
  std::size_t offset{0};
  bool ok{true};

  bool need(std::size_t count) {
    if (!ok || count > bytes.size() || offset > bytes.size() - count) {
      ok = false;
      return false;
    }
    return true;
  }

  std::uint8_t u8() {
    if (!need(1)) {
      return 0;
    }
    return static_cast<std::uint8_t>(static_cast<unsigned char>(bytes[offset++]));
  }

  std::uint32_t u32() {
    if (!need(4)) {
      return 0;
    }
    const std::uint32_t value = read_u32(bytes, offset);
    offset += 4;
    return value;
  }

  std::uint64_t u64() {
    if (!need(8)) {
      return 0;
    }
    const std::uint64_t value = read_u64(bytes, offset);
    offset += 8;
    return value;
  }

  std::string_view text() {
    const std::uint32_t length = u32();
    if (!ok || !need(length)) {
      return std::string_view();
    }
    const std::string_view out = bytes.substr(offset, length);
    offset += length;
    return out;
  }

  void skip_provenance() {
    u8();
    u8();
    u8();
    text();
    text();
    u64();
    text();
    text();
    text();
  }

  void skip_metadata() {
    const std::uint32_t count = u32();
    for (std::uint32_t index = 0; index < count && ok; ++index) {
      if (count > kAbsurdCount) {
        ok = false;
        return;
      }
      text();
      text();
    }
  }

  void skip_history() {
    const std::uint32_t count = u32();
    for (std::uint32_t index = 0; index < count && ok; ++index) {
      if (count > kAbsurdCount) {
        ok = false;
        return;
      }
      u64();
      u64();
      u8();
      text();
      u8();
      u64();
      u64();
    }
  }

  void skip_domain() {
    text();
    text();
    u64();
    u8();
    text();
    text();
    skip_provenance();
    u64();
    u64();
    u64();
    text();
    text();
    text();
    skip_metadata();
    skip_history();
  }

  void skip_membership() {
    text();
    text();
    u64();
    text();
    u64();
    u8();
    u8();
    u8();
    u8();
    u64();
    u64();
    u64();
    text();
    text();
    skip_provenance();
    text();
    u64();
    const std::uint32_t sources = u32();
    if (sources > kAbsurdCount) {
      ok = false;
      return;
    }
    for (std::uint32_t index = 0; index < sources && ok; ++index) {
      text();
    }
    const std::uint32_t generations = u32();
    if (generations > kAbsurdCount) {
      ok = false;
      return;
    }
    for (std::uint32_t index = 0; index < generations && ok; ++index) {
      u64();
    }
    text();
    u8();
    const std::uint32_t evidence = u32();
    if (evidence > kAbsurdCount) {
      ok = false;
      return;
    }
    for (std::uint32_t index = 0; index < evidence && ok; ++index) {
      skip_provenance();
      u8();
    }
    skip_metadata();
    skip_history();
  }

  void skip_relation() {
    text();
    text();
    text();
    u8();
    skip_provenance();
    u64();
    u64();
  }

  void skip_coverage() {
    text();
    text();
    u8();
    skip_provenance();
    u64();
    u64();
  }

  void skip_publisher() {
    text();
    text();
    const std::uint32_t classes = u32();
    if (classes > kAbsurdCount) {
      ok = false;
      return;
    }
    for (std::uint32_t index = 0; index < classes && ok; ++index) {
      u8();
    }
    text();
    u8();
    u64();
  }

  void skip_fence() {
    text();
    text();
    u8();
    u64();
    u64();
  }

  void skip_rule() {
    text();
    text();
    u8();
    text();
    text();
    u8();
    u8();
    u8();
    u32();
    text();
    u64();
    u8();
  }

  /// Walks past the payload header the encoder writes first.
  void skip_payload_header() {
    text();
    u64();
    u64();
    u64();
    u64();
  }
};

enum class Container { Domains, Memberships, Relations, Coverage, Publishers, Fences, Rules };

/// Payload-relative offset of a container's u32 count.
std::size_t count_offset(std::string_view payload, Container container) {
  Cursor cursor{payload, 0, true};
  cursor.skip_payload_header();
  if (!cursor.ok) {
    return kNoOffset;
  }
  if (container == Container::Domains) {
    return cursor.offset;
  }
  const std::uint32_t domains = cursor.u32();
  for (std::uint32_t index = 0; index < domains && cursor.ok; ++index) {
    cursor.skip_domain();
  }
  if (!cursor.ok || container == Container::Memberships) {
    return cursor.ok ? cursor.offset : kNoOffset;
  }
  const std::uint32_t memberships = cursor.u32();
  for (std::uint32_t index = 0; index < memberships && cursor.ok; ++index) {
    cursor.skip_membership();
  }
  if (!cursor.ok || container == Container::Relations) {
    return cursor.ok ? cursor.offset : kNoOffset;
  }
  const std::uint32_t relations = cursor.u32();
  for (std::uint32_t index = 0; index < relations && cursor.ok; ++index) {
    cursor.skip_relation();
  }
  if (!cursor.ok || container == Container::Coverage) {
    return cursor.ok ? cursor.offset : kNoOffset;
  }
  const std::uint32_t coverage = cursor.u32();
  for (std::uint32_t index = 0; index < coverage && cursor.ok; ++index) {
    cursor.skip_coverage();
  }
  if (!cursor.ok || container == Container::Publishers) {
    return cursor.ok ? cursor.offset : kNoOffset;
  }
  const std::uint32_t publishers = cursor.u32();
  for (std::uint32_t index = 0; index < publishers && cursor.ok; ++index) {
    cursor.skip_publisher();
  }
  if (!cursor.ok || container == Container::Fences) {
    return cursor.ok ? cursor.offset : kNoOffset;
  }
  const std::uint32_t fences = cursor.u32();
  for (std::uint32_t index = 0; index < fences && cursor.ok; ++index) {
    cursor.skip_fence();
  }
  if (!cursor.ok || container == Container::Rules) {
    return cursor.ok ? cursor.offset : kNoOffset;
  }
  return kNoOffset;
}

/// Every offset inside one domain record that this file mutates.
struct DomainOffsets {
  Span span{};
  std::size_t id{kNoOffset};
  std::size_t klass{kNoOffset};
  std::size_t generation{kNoOffset};
  std::size_t lifecycle{kNoOffset};
  std::size_t scope{kNoOffset};
  std::size_t metadata_count{kNoOffset};
};

DomainOffsets domain_offsets(std::string_view payload, std::size_t index) {
  DomainOffsets out;
  Cursor cursor{payload, 0, true};
  cursor.skip_payload_header();
  const std::uint32_t count = cursor.u32();
  for (std::uint32_t position = 0; position < count && cursor.ok; ++position) {
    DomainOffsets current;
    current.span.begin = cursor.offset;
    current.id = cursor.offset;
    cursor.text();
    current.klass = cursor.offset;
    cursor.text();
    current.generation = cursor.offset;
    cursor.u64();
    current.lifecycle = cursor.offset;
    cursor.u8();
    cursor.text();
    current.scope = cursor.offset;
    cursor.text();
    cursor.skip_provenance();
    cursor.u64();
    cursor.u64();
    cursor.u64();
    cursor.text();
    cursor.text();
    cursor.text();
    current.metadata_count = cursor.offset;
    cursor.skip_metadata();
    cursor.skip_history();
    current.span.end = cursor.offset;
    if (position == index) {
      return current;
    }
  }
  return out;
}

struct MembershipOffsets {
  Span span{};
  std::size_t id{kNoOffset};
  std::size_t domain{kNoOffset};
  std::size_t domain_generation{kNoOffset};
  std::size_t member{kNoOffset};
  std::size_t generation{kNoOffset};
  std::size_t lifecycle{kNoOffset};
  std::size_t derivation_source_count{kNoOffset};
};

MembershipOffsets membership_offsets(std::string_view payload, std::size_t index) {
  MembershipOffsets out;
  Cursor cursor{payload, 0, true};
  cursor.skip_payload_header();
  const std::uint32_t domains = cursor.u32();
  for (std::uint32_t position = 0; position < domains && cursor.ok; ++position) {
    cursor.skip_domain();
  }
  const std::uint32_t count = cursor.u32();
  for (std::uint32_t position = 0; position < count && cursor.ok; ++position) {
    MembershipOffsets current;
    current.span.begin = cursor.offset;
    current.id = cursor.offset;
    cursor.text();
    current.domain = cursor.offset;
    cursor.text();
    current.domain_generation = cursor.offset;
    cursor.u64();
    current.member = cursor.offset;
    cursor.text();
    current.generation = cursor.offset;
    cursor.u64();
    current.lifecycle = cursor.offset;
    cursor.u8();
    cursor.u8();
    cursor.u8();
    cursor.u8();
    cursor.u64();
    cursor.u64();
    cursor.u64();
    cursor.text();
    cursor.text();
    cursor.skip_provenance();
    cursor.text();
    cursor.u64();
    current.derivation_source_count = cursor.offset;
    const std::uint32_t sources = cursor.u32();
    for (std::uint32_t source = 0; source < sources && cursor.ok; ++source) {
      cursor.text();
    }
    const std::uint32_t generations = cursor.u32();
    for (std::uint32_t generation = 0; generation < generations && cursor.ok; ++generation) {
      cursor.u64();
    }
    cursor.text();
    cursor.u8();
    const std::uint32_t evidence = cursor.u32();
    for (std::uint32_t entry = 0; entry < evidence && cursor.ok; ++entry) {
      cursor.skip_provenance();
      cursor.u8();
    }
    cursor.skip_metadata();
    cursor.skip_history();
    current.span.end = cursor.offset;
    if (position == index) {
      return current;
    }
  }
  return out;
}

struct RelationOffsets {
  Span span{};
  std::size_t id{kNoOffset};
  std::size_t source{kNoOffset};
  std::size_t target{kNoOffset};
  std::size_t type{kNoOffset};
};

RelationOffsets relation_offsets(std::string_view payload, std::size_t index) {
  RelationOffsets out;
  Cursor cursor{payload, 0, true};
  cursor.skip_payload_header();
  const std::uint32_t domains = cursor.u32();
  for (std::uint32_t position = 0; position < domains && cursor.ok; ++position) {
    cursor.skip_domain();
  }
  const std::uint32_t memberships = cursor.u32();
  for (std::uint32_t position = 0; position < memberships && cursor.ok; ++position) {
    cursor.skip_membership();
  }
  const std::uint32_t count = cursor.u32();
  for (std::uint32_t position = 0; position < count && cursor.ok; ++position) {
    RelationOffsets current;
    current.span.begin = cursor.offset;
    current.id = cursor.offset;
    cursor.text();
    current.source = cursor.offset;
    cursor.text();
    current.target = cursor.offset;
    cursor.text();
    current.type = cursor.offset;
    cursor.u8();
    cursor.skip_provenance();
    cursor.u64();
    cursor.u64();
    current.span.end = cursor.offset;
    if (position == index) {
      return current;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Payload mutation helpers
// ---------------------------------------------------------------------------

/// Replaces the length-prefixed text starting at offset, adjusting the length
/// prefix as the encoder would.
std::string replace_text(std::string payload, std::size_t offset, std::string_view replacement) {
  const std::uint32_t length = read_u32(payload, offset);
  std::string out;
  out.reserve(payload.size() - length + replacement.size());
  out.append(payload, 0, offset);
  const std::string prefix = [replacement] {
    std::string bytes(4, '\0');
    write_u32(bytes, 0, static_cast<std::uint32_t>(replacement.size()));
    return bytes;
  }();
  out.append(prefix);
  out.append(replacement);
  out.append(payload, offset + 4 + length, std::string::npos);
  return out;
}

/// Copies one record into a second position and bumps the container count, which
/// is how a duplicate identity is planted.
std::string duplicate_record(std::string payload, Span span, std::size_t count_position) {
  std::string out;
  out.reserve(payload.size() + span.size());
  out.append(payload, 0, span.end);
  out.append(payload, span.begin, span.size());
  out.append(payload, span.end, std::string::npos);
  write_u32(out, count_position, read_u32(payload, count_position) + 1u);
  return out;
}

std::string hex_text(std::size_t length, char digit) { return std::string(length, digit); }

// ---------------------------------------------------------------------------
// File helpers and the per-case temporary directory
// ---------------------------------------------------------------------------

std::string slurp(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return std::string();
  }
  stream.seekg(0, std::ios::end);
  const std::streamoff size = stream.tellg();
  if (size < 0) {
    return std::string();
  }
  std::string out(static_cast<std::size_t>(size), '\0');
  stream.seekg(0, std::ios::beg);
  if (!out.empty()) {
    stream.read(out.data(), static_cast<std::streamsize>(out.size()));
    if (!stream) {
      return std::string();
    }
  }
  return out;
}

bool spit(const std::filesystem::path& path, std::string_view bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    return false;
  }
  if (!bytes.empty()) {
    stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }
  stream.close();
  return !stream.fail();
}

std::string join(const std::vector<std::string>& parts) {
  std::string out;
  for (const std::string& part : parts) {
    if (!out.empty()) {
      out.append(", ");
    }
    out.append(part);
  }
  return out;
}

/// Removes the directory it owns, including when a case aborts.
struct TempDirectory {
  std::filesystem::path path;

  explicit TempDirectory(const std::string& label) {
    path = std::filesystem::temp_directory_path() / ("fdr-corruption-" + label);
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
    std::filesystem::create_directories(path, ignored);
  }

  ~TempDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
  }

  TempDirectory(const TempDirectory&) = delete;
  TempDirectory& operator=(const TempDirectory&) = delete;

  std::filesystem::path file(const std::string& label) const { return path / (label + ".fdr"); }
};

PersistenceConfig config_for(const std::filesystem::path& path) {
  PersistenceConfig config;
  config.path = path.string();
  config.durable = true;
  config.atomic = true;
  return config;
}

/// The verdict of one rejected-image attempt.
struct Verdict {
  bool accepted{false};
  bool internal{false};
  bool silent{false};
  bool inconsistent{false};
  OutcomeCode code{OutcomeCode::InternalFailure};
  std::string message;
};

/// Loads one image into a fresh registry and reports how it was refused.
Verdict try_load(const std::filesystem::path& path) {
  Verdict verdict;
  Registry registry(RegistryLimits::defaults());
  const Outcome outcome = registry.load(config_for(path));
  verdict.code = outcome.code;
  verdict.message = outcome.message;
  verdict.accepted = outcome.committed() || outcome.code == OutcomeCode::Idempotent;
  verdict.internal = outcome.code == OutcomeCode::InternalFailure;
  verdict.silent = outcome.message.empty();
  std::string why;
  const bool consistent = registry.validate_state(&why);
  verdict.inconsistent = !consistent || registry.domain_count() != 0 ||
                         registry.membership_count() != 0;
  if (!consistent) {
    verdict.message.append(" | inconsistent: ").append(why);
  }
  return verdict;
}

/// Writes one image into its own file, loads it into a fresh registry, and
/// records the label when the load was accepted, blamed on InternalFailure,
/// silent or left an inconsistent registry.
void check_rejected(const TempDirectory& directory, const std::string& label,
                    const std::string& image, std::vector<std::string>& accepted,
                    std::vector<std::string>& internal, std::vector<std::string>& silent,
                    std::vector<std::string>& inconsistent) {
  const std::filesystem::path path = directory.file(label);
  FDR_CHECK_MSG(spit(path, image), label + ": the image could not be written");
  const Verdict verdict = try_load(path);
  if (verdict.accepted) {
    accepted.push_back(label + " -> " + std::string(failure_domain_registry::to_string(verdict.code)));
  }
  if (verdict.internal) {
    internal.push_back(label);
  }
  if (verdict.silent) {
    silent.push_back(label);
  }
  if (verdict.inconsistent) {
    inconsistent.push_back(label + " (" + verdict.message + ")");
  }
}

// ---------------------------------------------------------------------------
// The registry that produces both representative images
// ---------------------------------------------------------------------------

struct Fixture {
  Registry registry{RegistryLimits::defaults()};
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  CoordinatorEpoch epoch{};
  FailureDomainId rack{};
  FailureDomainId pdu{};
  FailureDomainId conduit{};
  FailureDomainId row{};
  EntityRef host_aa{};
  EntityRef host_bb{};
};

IdBytes pattern_bytes(std::uint8_t seed) {
  IdBytes out{};
  for (std::size_t index = 0; index < out.size(); ++index) {
    out[index] = static_cast<std::uint8_t>((index * 19u + seed * 23u + 1u) & 0xFFu);
  }
  return out;
}

MutationAttemptId attempt_from(std::uint8_t seed) {
  return MutationAttemptId::from_bytes(pattern_bytes(static_cast<std::uint8_t>(seed + 0x10u)));
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

AuthorityContext authority_of(const Fixture& fixture, EvidenceClass evidence) {
  AuthorityContext context;
  context.publisher = fixture.publisher;
  context.worker_boot = fixture.worker_boot;
  context.epoch = fixture.epoch;
  context.evidence = evidence;
  return context;
}

CreateDomainRequest create_request(const Fixture& fixture, DomainClass klass, std::string scope,
                                   std::string identity_key, std::string name,
                                   Provenance provenance, std::uint8_t attempt_seed) {
  CreateDomainRequest request;
  request.attempt = MutationAttempt(attempt_from(attempt_seed), RequestDigest{});
  request.authority = authority_of(fixture, provenance.evidence);
  request.domain_class = DomainClassRef(klass);
  request.administrative_scope = std::move(scope);
  request.identity_key = std::move(identity_key);
  request.name = std::move(name);
  request.provenance = std::move(provenance);
  return request;
}

/// Builds the representative classification: four domains of four classes, two
/// memberships with evidence, one relation, one coverage declaration, two
/// publisher grants and one fence.
void build_fixture(Fixture& fixture) {
  fixture.publisher = PublisherId::from_bytes(pattern_bytes(0x41));
  fixture.worker_boot = WorkerBootId::from_bytes(pattern_bytes(0x42));

  PublisherRegistration registration;
  registration.publisher = fixture.publisher;
  registration.name = "corruption-publisher";
  registration.scope = AuthorityScope::unrestricted();
  FDR_CHECK_EQ(fixture.registry.grant_publisher(registration, AuthorityContext{}).code,
               OutcomeCode::Committed);
  CoordinatorEpoch epoch;
  FDR_CHECK_EQ(fixture.registry.advance_epoch(CoordinatorEpoch{}, &epoch).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(fixture.registry
                   .attach_worker(fixture.publisher, fixture.worker_boot, epoch,
                                  "corruption-worker",
                                  EvidenceClass::DirectAuthoritativeInfrastructure)
                   .code,
               OutcomeCode::Committed);
  fixture.epoch = epoch;

  const Provenance provenance = provenance_of(ProvenanceSource::OperatorInventory,
                                              EvidenceClass::DirectAuthoritativeInfrastructure,
                                              TruthClass::Real, "inv-1");
  fixture.rack = *fixture.registry
                      .create_domain(create_request(fixture, DomainClass::Rack, "dc1", "rack-r1",
                                                    "rack one", provenance, 0x20))
                      .domain;
  fixture.pdu = *fixture.registry
                     .create_domain(create_request(fixture, DomainClass::Pdu, "dc1", "pdu-p1",
                                                   "pdu one", provenance, 0x21))
                     .domain;
  fixture.conduit = *fixture.registry
                         .create_domain(create_request(fixture, DomainClass::Conduit, "dc2",
                                                       "conduit-c1", "conduit one", provenance,
                                                       0x22))
                         .domain;
  fixture.row = *fixture.registry
                     .create_domain(create_request(fixture, DomainClass::Row, "dc1", "row-1",
                                                   "row one", provenance, 0x23))
                     .domain;

  fixture.host_aa = EntityRef(EntityClass::Host, pattern_bytes(0x51), EntityGeneration(1));
  fixture.host_bb = EntityRef(EntityClass::Host, pattern_bytes(0x52), EntityGeneration(1));
  AttachMemberRequest first;
  first.attempt = MutationAttempt(attempt_from(0x24), RequestDigest{});
  first.authority = authority_of(fixture, EvidenceClass::DirectAuthoritativeInfrastructure);
  first.domain = fixture.rack;
  first.member = fixture.host_aa;
  first.role = failure_domain_registry::MembershipRole::Primary;
  first.provenance = provenance;
  FDR_CHECK_EQ(fixture.registry.attach_member(first).code, OutcomeCode::Committed);
  AttachMemberRequest second = first;
  second.attempt = MutationAttempt(attempt_from(0x25), RequestDigest{});
  second.domain = fixture.pdu;
  second.member = fixture.host_bb;
  FDR_CHECK_EQ(fixture.registry.attach_member(second).code, OutcomeCode::Committed);

  failure_domain_registry::AddRelationRequest contained;
  contained.attempt = MutationAttempt(attempt_from(0x26), RequestDigest{});
  contained.authority = authority_of(fixture, EvidenceClass::DirectAuthoritativeInfrastructure);
  contained.source = fixture.rack;
  contained.target = fixture.row;
  contained.type = DomainRelationType::ContainedBy;
  contained.provenance = provenance_of(ProvenanceSource::TopologyDerivation,
                                       EvidenceClass::DerivedTopology, TruthClass::Real, "");
  FDR_CHECK_EQ(fixture.registry.add_relation(contained).code, OutcomeCode::Committed);

  DeclareCoverageRequest coverage;
  coverage.attempt = MutationAttempt(attempt_from(0x27), RequestDigest{});
  coverage.authority = authority_of(fixture, EvidenceClass::DirectAuthoritativeInfrastructure);
  coverage.administrative_scope = "dc1";
  coverage.domain_class = DomainClassRef(DomainClass::Rack);
  coverage.state = CoverageState::Complete;
  coverage.provenance = provenance;
  FDR_CHECK_EQ(fixture.registry.declare_coverage(coverage).code, OutcomeCode::Committed);

  // A second publisher with its own incarnation, fenced again: the image carries
  // a second publisher grant and one fence record, and the classification above
  // stays exactly as it was published (a fresh incarnation of the first
  // publisher would have fenced its predecessor and withdrawn its evidence).
  const PublisherId second_publisher = PublisherId::from_bytes(pattern_bytes(0x43));
  const WorkerBootId second_boot = WorkerBootId::from_bytes(pattern_bytes(0x44));
  PublisherRegistration second_registration;
  second_registration.publisher = second_publisher;
  second_registration.name = "fenced-publisher";
  second_registration.scope = AuthorityScope::unrestricted();
  FDR_CHECK_EQ(fixture.registry
                   .grant_publisher(second_registration,
                                    authority_of(fixture,
                                                 EvidenceClass::DirectAuthoritativeInfrastructure))
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(fixture.registry
                   .attach_worker(second_publisher, second_boot, fixture.epoch, "fenced-worker",
                                  EvidenceClass::DirectAuthoritativeInfrastructure)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(fixture.registry
                   .fence_worker(second_publisher, second_boot, FenceReason::Administrative,
                                 fixture.epoch)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(fixture.registry.fences().size(), std::size_t{1});
  FDR_CHECK_EQ(fixture.registry.publishers().size(), std::size_t{2});
  // The first incarnation is still live and its classification still current.
  FDR_CHECK(fixture.registry.is_worker_live(fixture.publisher, fixture.worker_boot));
  FDR_CHECK_EQ(fixture.registry.domain(fixture.rack)->lifecycle,
               failure_domain_registry::DomainLifecycle::Current);
  FDR_CHECK(fixture.registry.membership(fixture.registry.members_of(fixture.rack)[0].id).has_value());
  FDR_CHECK_EQ(fixture.registry.domain_count(), std::size_t{4});
  FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{2});
}

} // namespace

// ---------------------------------------------------------------------------
// Container-level corruption
// ---------------------------------------------------------------------------

FDR_TEST_CASE(corruption, container_level_corruption_is_rejected_with_a_specific_outcome) {
  const TempDirectory directory("container");
  const std::filesystem::path path = directory.file("valid");

  Fixture fixture;
  build_fixture(fixture);
  FDR_CHECK_EQ(fixture.registry.save(config_for(path)).code, OutcomeCode::Committed);
  const std::string good = slurp(path);
  FDR_CHECK(good.size() > kStateHeaderBytes + kStateTrailerBytes);
  const std::string_view payload = payload_of(good);
  FDR_CHECK(!payload.empty());

  // Control: the untouched image loads.
  {
    Registry registry(RegistryLimits::defaults());
    FDR_CHECK_EQ(registry.load(config_for(path)).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(registry.domain_count(), std::size_t{4});
    FDR_CHECK_EQ(registry.membership_count(), std::size_t{2});
  }

  std::vector<std::pair<std::string, std::string>> images;
  images.emplace_back("empty-file", std::string());
  images.emplace_back("one-byte", good.substr(0, 1));
  images.emplace_back("shorter-than-header", good.substr(0, kStateHeaderBytes - 1));
  images.emplace_back("header-only", good.substr(0, kStateHeaderBytes));
  images.emplace_back("header-and-trailer-only", good.substr(0, kStateHeaderBytes + kStateTrailerBytes));
  // A payload that lost its last bytes and its trailer: the declared length no
  // longer matches the file size, and the trailer is not where it must be.
  images.emplace_back("truncated-payload", good.substr(0, good.size() - 16));

  std::string bad_magic = good;
  bad_magic[kMagicOffset] = 'X';
  images.emplace_back("bad-magic", bad_magic);

  std::string bad_version = good;
  write_u32(bad_version, kVersionOffset, kStateFormatVersion + 1u);
  images.emplace_back("unsupported-version", bad_version);

  std::string bad_flags = good;
  write_u32(bad_flags, kFlagsOffset, 1u);
  images.emplace_back("reserved-flags", bad_flags);

  std::string truncated_header = good;
  truncated_header[kHeaderDigestOffset - 1] = static_cast<char>(0xFF);
  images.emplace_back("header-digest-corrupt", truncated_header);

  std::string bad_trailer = good;
  bad_trailer[good.size() - 1] = 'X';
  images.emplace_back("trailer-corrupt", bad_trailer);

  // A wrong payload digest: the payload digest field is covered by the header
  // digest, so the header digest has to be recomputed for the payload check to
  // be the one that fires.
  std::string wrong_payload_sha = good;
  wrong_payload_sha[kPayloadDigestOffset] =
      static_cast<char>(static_cast<unsigned char>(wrong_payload_sha[kPayloadDigestOffset]) ^ 0x01);
  refresh_header_digest(wrong_payload_sha);
  images.emplace_back("wrong-payload-digest", wrong_payload_sha);

  std::string wrong_length = good;
  write_u64(wrong_length, kDeclaredLengthOffset,
            static_cast<std::uint64_t>(payload.size()) + 1u);
  images.emplace_back("declared-length-plus-one", wrong_length);

  std::string short_length = good;
  write_u64(short_length, kDeclaredLengthOffset, 1u);
  images.emplace_back("declared-length-one", short_length);

  std::string absurd_length = good;
  write_u64(absurd_length, kDeclaredLengthOffset, 0x8000000000000000ull);
  images.emplace_back("declared-length-2^63", absurd_length);

  std::string max_length = good;
  write_u64(max_length, kDeclaredLengthOffset, UINT64_MAX);
  images.emplace_back("declared-length-max", max_length);

  // A valid header that declares a zero-length payload: the framing is intact,
  // so this has to be refused by the payload decoder itself.
  {
    std::string empty_payload = good.substr(0, kStateHeaderBytes);
    empty_payload.append(kTrailerText, kStateTrailerBytes);
    write_u64(empty_payload, kDeclaredLengthOffset, 0u);
    const auto digest = sha256(std::string_view());
    for (std::size_t index = 0; index < digest.size(); ++index) {
      empty_payload[kPayloadDigestOffset + index] = static_cast<char>(digest[index]);
    }
    refresh_header_digest(empty_payload);
    images.emplace_back("zero-length-payload", empty_payload);
  }

  std::vector<std::string> accepted;
  std::vector<std::string> internal;
  std::vector<std::string> silent;
  std::vector<std::string> inconsistent;
  for (const std::pair<std::string, std::string>& item : images) {
    check_rejected(directory, item.first, item.second, accepted, internal, silent, inconsistent);
  }
  FDR_CHECK_MSG(accepted.empty(), "a corrupt image was accepted: " + join(accepted));
  FDR_CHECK_MSG(internal.empty(), "a corrupt image was blamed on InternalFailure: " + join(internal));
  FDR_CHECK_MSG(silent.empty(), "a rejection carried no message: " + join(silent));
  FDR_CHECK_MSG(inconsistent.empty(),
                "a rejected load left the registry inconsistent: " + join(inconsistent));

  // The same images are rejected when they arrive at a registry that already
  // holds state, and that state is untouched by every rejection.
  Fixture victim;
  build_fixture(victim);
  const std::size_t domains = victim.registry.domain_count();
  const std::size_t memberships = victim.registry.membership_count();
  const auto digest = victim.registry.state_digest();
  std::vector<std::string> disturbed;
  for (const std::pair<std::string, std::string>& item : images) {
    FDR_CHECK_MSG(spit(path, item.second), item.first + ": the image could not be written");
    const Outcome outcome = victim.registry.load(config_for(path));
    if (outcome.committed()) {
      disturbed.push_back(item.first + " was accepted");
      continue;
    }
    if (victim.registry.domain_count() != domains ||
        victim.registry.membership_count() != memberships ||
        !(victim.registry.state_digest() == digest)) {
      disturbed.push_back(item.first + " changed the registry");
    }
    std::string why;
    if (!victim.registry.validate_state(&why)) {
      disturbed.push_back(item.first + " left it inconsistent: " + why);
    }
  }
  FDR_CHECK_MSG(disturbed.empty(), "a rejected load disturbed live state: " + join(disturbed));

  // Inspection refuses the same images, and never fills the report it was given.
  std::vector<std::string> inspected_ok;
  for (const std::pair<std::string, std::string>& item : images) {
    FDR_CHECK_MSG(spit(path, item.second), item.first + ": the image could not be written");
    failure_domain_registry::PersistenceReport report;
    report.bytes = 7;
    report.domains = 9;
    const Outcome outcome = inspect_persistence(config_for(path), &report);
    const bool refused = outcome.code == OutcomeCode::IntegrityFailure ||
                         outcome.code == OutcomeCode::PersistenceFailure;
    if (!refused) {
      inspected_ok.push_back(item.first + " -> " +
                             std::string(failure_domain_registry::to_string(outcome.code)));
    }
    if (report.bytes != 7 || report.domains != 9) {
      inspected_ok.push_back(item.first + " filled the report");
    }
  }
  FDR_CHECK_MSG(inspected_ok.empty(), "inspection trusted a corrupt image: " + join(inspected_ok));
}

// ---------------------------------------------------------------------------
// Record-level corruption
// ---------------------------------------------------------------------------

FDR_TEST_CASE(corruption, record_level_corruption_is_rejected) {
  const TempDirectory directory("records");
  const std::filesystem::path path = directory.file("valid");

  Fixture fixture;
  build_fixture(fixture);
  FDR_CHECK_EQ(fixture.registry.save(config_for(path)).code, OutcomeCode::Committed);
  const std::string payload(payload_of(slurp(path)));
  FDR_CHECK(!payload.empty());

  const DomainOffsets first_domain = domain_offsets(payload, 0);
  const DomainOffsets second_domain = domain_offsets(payload, 1);
  const MembershipOffsets first_membership = membership_offsets(payload, 0);
  const RelationOffsets first_relation = relation_offsets(payload, 0);
  const std::size_t domain_count = count_offset(payload, Container::Domains);
  const std::size_t membership_count = count_offset(payload, Container::Memberships);
  const std::size_t relation_count = count_offset(payload, Container::Relations);
  FDR_CHECK(first_domain.id != kNoOffset);
  FDR_CHECK(second_domain.id != kNoOffset);
  FDR_CHECK(first_membership.id != kNoOffset);
  FDR_CHECK(first_relation.id != kNoOffset);
  FDR_CHECK(domain_count != kNoOffset);
  FDR_CHECK(membership_count != kNoOffset);
  FDR_CHECK(relation_count != kNoOffset);

  std::vector<std::pair<std::string, std::string>> images;

  // Duplicate identities: the second copy keeps a distinct position but the same
  // id, which is exactly what decode_payload checks for.
  images.emplace_back("duplicate-domain",
                      duplicate_record(payload, first_domain.span, domain_count));
  images.emplace_back("duplicate-membership",
                      duplicate_record(payload, first_membership.span, membership_count));

  // Malformed identifiers: a non-hex rendering, and a length prefix one byte
  // short of the text it introduces.
  {
    std::string image = replace_text(payload, first_domain.id, hex_text(32, 'z'));
    images.emplace_back("domain-id-non-hex", image);
  }
  {
    std::string image = payload;
    write_u32(image, first_domain.id, 31u);
    images.emplace_back("domain-id-short-length", image);
  }
  {
    std::string image = replace_text(payload, first_membership.id, hex_text(32, 'z'));
    images.emplace_back("membership-id-non-hex", image);
  }
  {
    std::string image = replace_text(payload, first_membership.member, "nosuch:" + hex_text(32, '0') + "@1");
    images.emplace_back("member-entity-class-unknown", image);
  }
  {
    std::string image = replace_text(payload, first_domain.klass, "no-such-class");
    images.emplace_back("domain-class-unknown", image);
  }

  // Invalid enumerators: a lifecycle byte the enumeration does not define, and
  // the zero byte that is not a lifecycle at all.
  {
    std::string image = payload;
    image[first_domain.lifecycle] = static_cast<char>(0x7F);
    images.emplace_back("domain-lifecycle-0x7f", image);
  }
  {
    std::string image = payload;
    image[first_membership.lifecycle] = static_cast<char>(0x00);
    images.emplace_back("membership-lifecycle-unknown", image);
  }

  // Impossible generations: zero where the decoder requires a real generation.
  {
    std::string image = payload;
    write_u64(image, first_domain.generation, 0u);
    images.emplace_back("domain-generation-zero", image);
  }
  {
    std::string image = payload;
    write_u64(image, first_membership.generation, 0u);
    images.emplace_back("membership-generation-zero", image);
  }
  {
    std::string image = payload;
    write_u64(image, first_membership.domain_generation, 0u);
    images.emplace_back("membership-domain-generation-zero", image);
  }

  // Dangling references: an identifier that parses but names nothing in the
  // image, for a relation endpoint and for a membership's domain.
  {
    std::string image = replace_text(payload, first_relation.target, hex_text(32, 'a'));
    images.emplace_back("relation-endpoint-dangling", image);
  }
  {
    std::string image = replace_text(payload, first_membership.domain, hex_text(32, 'b'));
    images.emplace_back("membership-domain-dangling", image);
  }

  // Absurd container counts: one far larger than the remaining bytes can hold,
  // and one that would overflow a size computation if it were multiplied.
  {
    std::string image = payload;
    write_u32(image, domain_count, 0x7FFFFFFFu);
    images.emplace_back("domain-count-absurd", image);
  }
  {
    std::string image = payload;
    write_u32(image, membership_count, 0xFFFFFFFFu);
    images.emplace_back("membership-count-overflow", image);
  }
  {
    std::string image = payload;
    write_u32(image, first_domain.metadata_count, 0xFFFFFFFFu);
    images.emplace_back("metadata-count-overflow", image);
  }
  {
    std::string image = payload;
    write_u32(image, first_membership.derivation_source_count, 0xFFFFFFFFu);
    images.emplace_back("derivation-source-count-overflow", image);
  }

  std::vector<std::string> accepted;
  std::vector<std::string> internal;
  std::vector<std::string> silent;
  std::vector<std::string> inconsistent;
  for (const std::pair<std::string, std::string>& item : images) {
    check_rejected(directory, item.first, build_container(item.second), accepted, internal, silent,
                   inconsistent);
  }
  FDR_CHECK_MSG(accepted.empty(), "a corrupted record was accepted: " + join(accepted));
  FDR_CHECK_MSG(internal.empty(), "a corrupted record was blamed on InternalFailure: " + join(internal));
  FDR_CHECK_MSG(silent.empty(), "a rejection carried no message: " + join(silent));
  FDR_CHECK_MSG(inconsistent.empty(),
                "a rejected load left the registry inconsistent: " + join(inconsistent));

  // The same images aimed at a registry that already holds state: every
  // rejection leaves that state exactly as it was.
  Fixture victim;
  build_fixture(victim);
  const std::size_t domains = victim.registry.domain_count();
  const std::size_t memberships = victim.registry.membership_count();
  const auto digest = victim.registry.state_digest();
  std::vector<std::string> disturbed;
  for (const std::pair<std::string, std::string>& item : images) {
    FDR_CHECK_MSG(spit(path, build_container(item.second)),
                  item.first + ": the image could not be written");
    const Outcome outcome = victim.registry.load(config_for(path));
    if (outcome.committed()) {
      disturbed.push_back(item.first + " was accepted");
      continue;
    }
    if (victim.registry.domain_count() != domains ||
        victim.registry.membership_count() != memberships ||
        !(victim.registry.state_digest() == digest)) {
      disturbed.push_back(item.first + " changed the registry");
    }
    std::string why;
    if (!victim.registry.validate_state(&why)) {
      disturbed.push_back(item.first + " left it inconsistent: " + why);
    }
  }
  FDR_CHECK_MSG(disturbed.empty(), "a rejected record load disturbed live state: " + join(disturbed));
}

FDR_TEST_CASE(corruption, two_mutations_this_build_accepts_are_pinned) {
  const TempDirectory directory("accepted");
  const std::filesystem::path path = directory.file("valid");

  Fixture fixture;
  build_fixture(fixture);
  FDR_CHECK_EQ(fixture.registry.save(config_for(path)).code, OutcomeCode::Committed);
  const std::string payload(payload_of(slurp(path)));
  const MembershipOffsets membership = membership_offsets(payload, 0);
  const RelationOffsets relation = relation_offsets(payload, 0);
  const std::size_t relation_count = count_offset(payload, Container::Relations);
  FDR_CHECK(membership.domain_generation != kNoOffset);
  FDR_CHECK(relation.id != kNoOffset);
  FDR_CHECK(relation_count != kNoOffset);

  // The payload writes memberships ordered by id, so the first record is the
  // smallest membership id in the image.
  std::vector<MembershipId> membership_ids;
  for (const failure_domain_registry::Membership& record : fixture.registry.members_of(fixture.rack)) {
    membership_ids.push_back(record.id);
  }
  for (const failure_domain_registry::Membership& record : fixture.registry.members_of(fixture.pdu)) {
    membership_ids.push_back(record.id);
  }
  std::sort(membership_ids.begin(), membership_ids.end());
  FDR_CHECK_EQ(membership_ids.size(), std::size_t{2});
  const MembershipId first_id = membership_ids[0];

  // (1) A membership bound to a generation the domain never had. The loader now
  // rejects it: a generation above the domain's current one could never have been
  // produced by this runtime, so the image is not a state this registry could
  // have written.
  {
    std::string image = payload;
    write_u64(image, membership.domain_generation, 4242u);
    FDR_CHECK_MSG(spit(path, build_container(image)), "the image could not be written");
    Registry registry(RegistryLimits::defaults());
    const Outcome outcome = registry.load(config_for(path));
    FDR_CHECK_EQ(outcome.code, OutcomeCode::IntegrityFailure);
    FDR_CHECK(outcome.message.find("domain generation that never existed") != std::string::npos);
    FDR_CHECK_EQ(registry.membership_count(), std::size_t{0});
    std::string why;
    FDR_CHECK_MSG(registry.validate_state(&why),
                  "validate_state rejected the mis-bound membership: " + why);
  }

  // (2) A cycle over an acyclic relation type. The loader now re-checks
  // acyclicity per relation type exactly as the runtime applies it, so the image
  // is rejected instead of loading into a state the registry could never have
  // produced.
  {
    std::string image = duplicate_record(payload, relation.span, relation_count);
    const RelationOffsets duplicate = relation_offsets(image, 1);
    FDR_CHECK(duplicate.source != kNoOffset);
    FDR_CHECK(duplicate.target != kNoOffset);
    // A different relation id, so the record is not a duplicate.
    image[duplicate.id + 4] = static_cast<char>(image[duplicate.id + 4] == '0' ? '1' : '0');
    // Swap the two endpoints, which turns rack-contained-by-row into a cycle.
    for (std::size_t index = 0; index < 32; ++index) {
      std::swap(image[duplicate.source + 4 + index], image[duplicate.target + 4 + index]);
    }
    FDR_CHECK_MSG(spit(path, build_container(image)), "the image could not be written");
    Registry registry(RegistryLimits::defaults());
    const Outcome outcome = registry.load(config_for(path));
    FDR_CHECK_EQ(outcome.code, OutcomeCode::IntegrityFailure);
    FDR_CHECK(outcome.message.find("cycle over an acyclic relation type") != std::string::npos);
    FDR_CHECK_EQ(registry.domain_count(), std::size_t{0});
    FDR_CHECK_EQ(registry.relations_of(fixture.rack).size(), std::size_t{0});
  }
}

// ---------------------------------------------------------------------------
// Exhaustive truncation
// ---------------------------------------------------------------------------

FDR_TEST_CASE(corruption, every_truncation_of_a_representative_image_is_rejected) {
  const TempDirectory directory("truncate");
  const std::filesystem::path path = directory.file("image");

  Fixture fixture;
  build_fixture(fixture);
  FDR_CHECK_EQ(fixture.registry.save(config_for(path)).code, OutcomeCode::Committed);
  const std::string image = slurp(path);
  FDR_CHECK_EQ(image.size(), kStateHeaderBytes + payload_of(image).size() + kStateTrailerBytes);
  FDR_CHECK(image.size() > 300);

  // The intact image, as the control.
  {
    Registry registry(RegistryLimits::defaults());
    FDR_CHECK_EQ(registry.load(config_for(path)).code, OutcomeCode::Committed);
  }

  // A populated registry that every truncation is aimed at, so a rejected load
  // is proven not to disturb live state as well as not to be accepted.
  Fixture victim;
  build_fixture(victim);
  const std::size_t domains = victim.registry.domain_count();
  const std::size_t memberships = victim.registry.membership_count();
  const auto digest = victim.registry.state_digest();

  std::vector<std::string> accepted;
  std::vector<std::string> internal;
  std::vector<std::string> silent;
  std::vector<std::string> inconsistent;
  for (std::size_t length = 0; length < image.size(); ++length) {
    const std::string label = "truncated-" + std::to_string(length);
    FDR_CHECK_MSG(spit(path, std::string_view(image).substr(0, length)),
                  label + ": the image could not be written");
    const Outcome outcome = victim.registry.load(config_for(path));
    if (outcome.committed() || outcome.code == OutcomeCode::Idempotent) {
      accepted.push_back(label + " -> " + std::string(failure_domain_registry::to_string(outcome.code)));
    }
    if (outcome.code == OutcomeCode::InternalFailure) {
      internal.push_back(label);
    }
    if (outcome.message.empty()) {
      silent.push_back(label);
    }
    if (victim.registry.domain_count() != domains ||
        victim.registry.membership_count() != memberships ||
        !(victim.registry.state_digest() == digest)) {
      inconsistent.push_back(label + " changed live state");
    }
    std::string why;
    if (!victim.registry.validate_state(&why)) {
      inconsistent.push_back(label + " left it inconsistent: " + why);
    }
  }
  FDR_CHECK_MSG(accepted.empty(), "a truncated image was accepted: " + join(accepted));
  FDR_CHECK_MSG(internal.empty(), "a truncated image was blamed on InternalFailure: " + join(internal));
  FDR_CHECK_MSG(silent.empty(), "a truncation carried no message: " + join(silent));
  FDR_CHECK_MSG(inconsistent.empty(), "a truncation disturbed live state: " + join(inconsistent));

  // A fresh registry stays empty and consistent for the same sweep.
  std::vector<std::string> leaked;
  for (std::size_t length = 0; length < image.size(); length += 17) {
    FDR_CHECK_MSG(spit(path, std::string_view(image).substr(0, length)),
                  "the truncated image could not be written");
    Registry fresh(RegistryLimits::defaults());
    const Outcome outcome = fresh.load(config_for(path));
    if (outcome.committed() || fresh.domain_count() != 0 || fresh.membership_count() != 0) {
      leaked.push_back("length " + std::to_string(length));
      continue;
    }
    std::string why;
    if (!fresh.validate_state(&why)) {
      leaked.push_back("length " + std::to_string(length) + ": " + why);
    }
  }
  FDR_CHECK_MSG(leaked.empty(), "a truncated load left records behind: " + join(leaked));

  // Trailing bytes: one to sixty-four appended, and one inserted at every early
  // position. Both change the file size without changing the declared payload
  // length, so the container size check has to refuse them.
  std::vector<std::string> accepted_trailing;
  for (std::size_t extra = 1; extra <= 64; ++extra) {
    const std::string padded = image + std::string(extra, 'x');
    FDR_CHECK_MSG(spit(path, padded), "the padded image could not be written");
    Registry registry(RegistryLimits::defaults());
    const Outcome outcome = registry.load(config_for(path));
    if (outcome.committed()) {
      accepted_trailing.push_back("appended " + std::to_string(extra));
    }
  }
  const std::size_t insert_limit = image.size() < 64 ? image.size() : 64;
  for (std::size_t position = 0; position <= insert_limit; ++position) {
    std::string padded = image;
    padded.insert(position, 1, 'x');
    FDR_CHECK_MSG(spit(path, padded), "the padded image could not be written");
    Registry registry(RegistryLimits::defaults());
    const Outcome outcome = registry.load(config_for(path));
    if (outcome.committed()) {
      accepted_trailing.push_back("inserted at " + std::to_string(position));
    }
  }
  FDR_CHECK_MSG(accepted_trailing.empty(),
                "an image with trailing bytes was accepted: " + join(accepted_trailing));
}

FDR_TEST_CASE(corruption, every_truncation_of_a_minimal_image_is_rejected) {
  const TempDirectory directory("minimal");
  const std::filesystem::path path = directory.file("minimal");

  // A registry that was never granted anything: the payload is the header, four
  // counters, seven empty container counts and nothing else.
  Registry source(RegistryLimits::defaults());
  FDR_CHECK_EQ(source.save(config_for(path)).code, OutcomeCode::Committed);
  const std::string image = slurp(path);
  FDR_CHECK_EQ(image.size(), kStateHeaderBytes + payload_of(image).size() + kStateTrailerBytes);
  FDR_CHECK(image.size() < std::size_t{400});
  FDR_CHECK_EQ(source.domain_count(), std::size_t{0});

  // The intact minimal image loads and yields an empty, consistent registry.
  {
    Registry registry(RegistryLimits::defaults());
    const Outcome outcome = registry.load(config_for(path));
    FDR_CHECK_EQ(outcome.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(registry.domain_count(), std::size_t{0});
    FDR_CHECK_EQ(registry.membership_count(), std::size_t{0});
    std::string why;
    FDR_CHECK_MSG(registry.validate_state(&why), "empty image is inconsistent: " + why);
  }

  std::vector<std::string> accepted;
  std::vector<std::string> mishandled;
  for (std::size_t length = 0; length < image.size(); ++length) {
    const std::string label = "minimal-truncated-" + std::to_string(length);
    FDR_CHECK_MSG(spit(path, std::string_view(image).substr(0, length)),
                  label + ": the image could not be written");
    const Verdict verdict = try_load(path);
    if (verdict.accepted) {
      accepted.push_back(label + " -> " + std::string(failure_domain_registry::to_string(verdict.code)));
    }
    if (verdict.internal) {
      mishandled.push_back(label + " was blamed on InternalFailure");
    }
    if (verdict.silent) {
      mishandled.push_back(label + " carried no message");
    }
    if (verdict.inconsistent) {
      mishandled.push_back(label + " left an inconsistent registry");
    }
  }
  FDR_CHECK_MSG(accepted.empty(), "a truncated minimal image was accepted: " + join(accepted));
  FDR_CHECK_MSG(mishandled.empty(), "a truncated minimal image was mishandled: " + join(mishandled));

  // Truncating exactly at the header and at the trailer boundary is refused as
  // well, and both are distinct checks: one is too short to be a container, the
  // other declares a payload it does not carry.
  FDR_CHECK_MSG(spit(path, image.substr(0, kStateHeaderBytes)), "the image could not be written");
  FDR_CHECK(!try_load(path).accepted);
  FDR_CHECK_MSG(spit(path, image.substr(0, image.size() - 1)), "the image could not be written");
  FDR_CHECK(!try_load(path).accepted);
  FDR_CHECK_MSG(spit(path, image.substr(0, kStateHeaderBytes + kStateTrailerBytes)),
                "the image could not be written");
  FDR_CHECK(!try_load(path).accepted);
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
