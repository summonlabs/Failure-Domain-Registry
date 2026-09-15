// Failure Domain Registry - versioned, integrity-checked persistence.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Container layout (all integers little endian):
//
//   0   magic        8 bytes  "FDRSTATE"
//   8   version      u32      kStateFormatVersion
//   12  flags        u32      reserved, must be zero
//   16  payload      u64      payload length in bytes
//   24  payload sha  32 bytes SHA-256 over the payload
//   56  header sha   32 bytes SHA-256 over bytes [0, 56)
//   88  payload      N bytes
//   88+N trailer    6 bytes  "FDREND"
//
// The file size must equal 88 + N + 6 exactly and the trailer must be present
// at that offset, so a truncation at any byte position is rejected before a
// single record is decoded.

#include "registry_internal.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <system_error>

#include "byte_codec.hpp"
#include "failure_domain_registry/digest.hpp"
#include "failure_domain_registry/version.hpp"

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace failure_domain_registry {
namespace {

constexpr char kMagic[8] = {'F', 'D', 'R', 'S', 'T', 'A', 'T', 'E'};
constexpr char kTrailer[6] = {'F', 'D', 'R', 'E', 'N', 'D'};
constexpr std::size_t kDigestOffset = 24;
constexpr std::size_t kHeaderDigestOffset = 56;

constexpr std::size_t kMaxPersistedStringBytes = hard_limits::kMaxStringBytes;
constexpr std::size_t kMaxPersistedMetadataEntries = hard_limits::kMaxMetadataEntries;
constexpr std::size_t kMaxPersistedHistory = hard_limits::kMaxHistoryEntriesPerRecord;
constexpr std::size_t kMaxPersistedEvidence = hard_limits::kMaxEvidencePerMembership;
constexpr std::size_t kMaxPersistedFences = 1'000'000;
constexpr std::size_t kMaxPersistedRules = 4'096;
constexpr std::size_t kMaxPersistedCoverage = hard_limits::kMaxCoverageDeclarations;
constexpr std::size_t kMaxPersistedPublishers = hard_limits::kMaxPublishers;
constexpr std::size_t kMaxPersistedRelations = hard_limits::kMaxRelations;

bool write_all(const std::filesystem::path& path, std::string_view bytes, bool durable,
               std::string* error) {
#ifdef _WIN32
  std::FILE* file = nullptr;
  if (_wfopen_s(&file, path.wstring().c_str(), L"wb") != 0 || file == nullptr) {
    *error = "cannot open the destination for writing";
    return false;
  }
#else
  std::FILE* file = std::fopen(path.string().c_str(), "wb");
  if (file == nullptr) {
    *error = "cannot open the destination for writing";
    return false;
  }
#endif
  const std::size_t written =
      bytes.empty() ? 0 : std::fwrite(bytes.data(), 1, bytes.size(), file);
  if (written != bytes.size()) {
    std::fclose(file);
    *error = "short write";
    return false;
  }
  const bool flushed = std::fflush(file) == 0;
  bool synced = true;
  if (durable) {
#ifdef _WIN32
    synced = _commit(_fileno(file)) == 0;
#else
    synced = ::fsync(::fileno(file)) == 0;
#endif
  }
  std::fclose(file);
  if (!flushed || !synced) {
    *error = durable ? "flush or sync failed" : "flush failed";
    return false;
  }
  return true;
}

bool read_all(const std::filesystem::path& path, std::string* bytes, std::string* error) {
#ifdef _WIN32
  std::FILE* file = nullptr;
  if (_wfopen_s(&file, path.wstring().c_str(), L"rb") != 0 || file == nullptr) {
    *error = "cannot open the image for reading";
    return false;
  }
#else
  std::FILE* file = std::fopen(path.string().c_str(), "rb");
  if (file == nullptr) {
    *error = "cannot open the image for reading";
    return false;
  }
#endif
  std::vector<char> buffer(65536);
  bytes->clear();
  for (;;) {
    const std::size_t got = std::fread(buffer.data(), 1, buffer.size(), file);
    if (got > 0) {
      bytes->append(buffer.data(), got);
    }
    if (got < buffer.size()) {
      if (std::ferror(file) != 0) {
        std::fclose(file);
        *error = "read error";
        return false;
      }
      break;
    }
  }
  std::fclose(file);
  return true;
}

void encode_provenance(codec::Writer& writer, const Provenance& provenance) {
  writer.u8(static_cast<std::uint8_t>(provenance.source));
  writer.u8(static_cast<std::uint8_t>(provenance.evidence));
  writer.u8(static_cast<std::uint8_t>(provenance.truth));
  writer.bytes(provenance.publisher.to_string());
  writer.bytes(provenance.worker_boot.to_string());
  writer.u64(provenance.evidence_generation.value());
  writer.bytes(provenance.source_identity);
  writer.bytes(provenance.derivation_rule.to_string());
  writer.bytes(provenance.derivation_context);
}

bool decode_provenance(codec::Reader& reader, Provenance* provenance) {
  std::uint8_t source = 0;
  std::uint8_t evidence = 0;
  std::uint8_t truth = 0;
  std::uint64_t evidence_generation = 0;
  std::string publisher;
  std::string worker_boot;
  if (!reader.u8(&source) || !reader.u8(&evidence) || !reader.u8(&truth)) {
    return false;
  }
  if (!reader.bytes(&publisher, kOpaqueIdTextLength) ||
      !reader.bytes(&worker_boot, kOpaqueIdTextLength)) {
    return false;
  }
  if (!reader.u64(&evidence_generation)) {
    return false;
  }
  if (!reader.bytes(&provenance->source_identity, kMaxPersistedStringBytes)) {
    return false;
  }
  std::string derivation_rule;
  if (!reader.bytes(&derivation_rule, kOpaqueIdTextLength)) {
    return false;
  }
  if (!reader.bytes(&provenance->derivation_context, kMaxPersistedStringBytes)) {
    return false;
  }
  if (source != 0) {
    if (!is_valid_provenance_source(static_cast<ProvenanceSource>(source))) {
      return false;
    }
    provenance->source = static_cast<ProvenanceSource>(source);
  }
  if (evidence != 0) {
    if (!is_valid_evidence_class(static_cast<EvidenceClass>(evidence))) {
      return false;
    }
    provenance->evidence = static_cast<EvidenceClass>(evidence);
  }
  if (truth != 0) {
    if (!is_valid_truth_class(static_cast<TruthClass>(truth))) {
      return false;
    }
    provenance->truth = static_cast<TruthClass>(truth);
  }
  const std::optional<PublisherId> publisher_id = PublisherId::parse(publisher);
  if (!publisher_id.has_value()) {
    return false;
  }
  provenance->publisher = *publisher_id;
  const std::optional<WorkerBootId> worker_boot_id = WorkerBootId::parse(worker_boot);
  if (!worker_boot_id.has_value()) {
    return false;
  }
  provenance->worker_boot = *worker_boot_id;
  provenance->evidence_generation = EvidenceGeneration(evidence_generation);
  if (!derivation_rule.empty()) {
    const std::optional<DerivationRuleId> rule = DerivationRuleId::parse(derivation_rule);
    if (!rule.has_value()) {
      return false;
    }
    provenance->derivation_rule = *rule;
  }
  return true;
}

void encode_metadata(codec::Writer& writer, const std::vector<MetadataEntry>& metadata) {
  writer.u32(static_cast<std::uint32_t>(metadata.size()));
  for (const MetadataEntry& entry : metadata) {
    writer.bytes(entry.key);
    writer.bytes(entry.value);
  }
}

bool decode_metadata(codec::Reader& reader, std::vector<MetadataEntry>* metadata) {
  std::uint32_t count = 0;
  if (!reader.count(&count, 8, kMaxPersistedMetadataEntries)) {
    return false;
  }
  metadata->reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    MetadataEntry entry;
    if (!reader.bytes(&entry.key, kMaxPersistedStringBytes) ||
        !reader.bytes(&entry.value, kMaxPersistedStringBytes)) {
      return false;
    }
    metadata->push_back(std::move(entry));
  }
  return true;
}

void encode_domain(codec::Writer& writer, const FailureDomain& record) {
  writer.bytes(record.id.to_string());
  writer.bytes(record.domain_class.to_string());
  writer.u64(record.generation.value());
  writer.u8(static_cast<std::uint8_t>(record.lifecycle));
  writer.bytes(record.name);
  writer.bytes(record.administrative_scope);
  encode_provenance(writer, record.provenance);
  writer.u64(record.created_generation.value());
  writer.u64(record.created_at.value());
  writer.u64(record.created_epoch.value());
  writer.bytes(record.superseded_by.to_string());
  writer.bytes(record.supersedes.to_string());
  writer.bytes(record.merged_into.to_string());
  encode_metadata(writer, record.metadata);
  writer.u32(static_cast<std::uint32_t>(record.history.size()));
  for (const DomainHistoryEntry& entry : record.history) {
    writer.u64(entry.previous_generation.value());
    writer.u64(entry.generation.value());
    writer.u8(static_cast<std::uint8_t>(entry.lifecycle));
    writer.bytes(entry.cause);
    writer.u8(static_cast<std::uint8_t>(entry.evidence));
    writer.u64(entry.epoch.value());
    writer.u64(entry.at.value());
  }
}

bool decode_domain(codec::Reader& reader, FailureDomain* record) {
  std::string id;
  std::string klass;
  std::string name;
  std::string scope;
  std::string superseded_by;
  std::string supersedes;
  std::string merged_into;
  std::uint8_t lifecycle = 0;
  if (!reader.bytes(&id, kOpaqueIdTextLength) || !reader.bytes(&klass, 128)) {
    return false;
  }
  std::uint64_t generation = 0;
  if (!reader.u64(&generation) || !reader.u8(&lifecycle)) {
    return false;
  }
  if (!reader.bytes(&name, kMaxPersistedStringBytes) ||
      !reader.bytes(&scope, 256)) {
    return false;
  }
  if (!decode_provenance(reader, &record->provenance)) {
    return false;
  }
  std::uint64_t created_generation = 0;
  std::uint64_t created_at = 0;
  std::uint64_t created_epoch = 0;
  if (!reader.u64(&created_generation) || !reader.u64(&created_at) ||
      !reader.u64(&created_epoch)) {
    return false;
  }
  if (!reader.bytes(&superseded_by, kOpaqueIdTextLength) ||
      !reader.bytes(&supersedes, kOpaqueIdTextLength) ||
      !reader.bytes(&merged_into, kOpaqueIdTextLength)) {
    return false;
  }
  if (!decode_metadata(reader, &record->metadata)) {
    return false;
  }
  std::uint32_t history_count = 0;
  if (!reader.count(&history_count, 32, kMaxPersistedHistory)) {
    return false;
  }
  record->history.reserve(history_count);
  for (std::uint32_t i = 0; i < history_count; ++i) {
    DomainHistoryEntry entry;
    std::uint64_t previous = 0;
    std::uint64_t current = 0;
    std::uint8_t entry_lifecycle = 0;
    std::uint8_t evidence = 0;
    std::uint64_t epoch = 0;
    std::uint64_t at = 0;
    if (!reader.u64(&previous) || !reader.u64(&current) || !reader.u8(&entry_lifecycle) ||
        !reader.bytes(&entry.cause, kMaxPersistedStringBytes) || !reader.u8(&evidence) ||
        !reader.u64(&epoch) || !reader.u64(&at)) {
      return false;
    }
    if (entry_lifecycle != 0) {
      if (!is_valid_domain_lifecycle(static_cast<DomainLifecycle>(entry_lifecycle))) {
        return false;
      }
      entry.lifecycle = static_cast<DomainLifecycle>(entry_lifecycle);
    }
    if (evidence != 0) {
      if (!is_valid_evidence_class(static_cast<EvidenceClass>(evidence))) {
        return false;
      }
      entry.evidence = static_cast<EvidenceClass>(evidence);
    }
    entry.previous_generation = FailureDomainGeneration(previous);
    entry.generation = FailureDomainGeneration(current);
    entry.epoch = CoordinatorEpoch(epoch);
    entry.at = RegistryGeneration(at);
    record->history.push_back(std::move(entry));
  }

  const std::optional<FailureDomainId> domain_id = FailureDomainId::parse(id);
  if (!domain_id.has_value() || domain_id->is_null()) {
    return false;
  }
  const std::optional<DomainClassRef> class_ref = DomainClassRef::parse(klass);
  if (!class_ref.has_value()) {
    return false;
  }
  if (!is_valid_domain_lifecycle(static_cast<DomainLifecycle>(lifecycle))) {
    return false;
  }
  if (generation == 0) {
    return false;
  }
  if (scope.empty()) {
    return false;
  }
  record->id = *domain_id;
  record->domain_class = *class_ref;
  record->generation = FailureDomainGeneration(generation);
  record->lifecycle = static_cast<DomainLifecycle>(lifecycle);
  record->name = std::move(name);
  record->administrative_scope = std::move(scope);
  record->created_generation = FailureDomainGeneration(created_generation);
  record->created_at = RegistryGeneration(created_at);
  record->created_epoch = CoordinatorEpoch(created_epoch);
  if (!superseded_by.empty()) {
    const std::optional<FailureDomainId> parsed = FailureDomainId::parse(superseded_by);
    if (!parsed.has_value()) {
      return false;
    }
    record->superseded_by = *parsed;
  }
  if (!supersedes.empty()) {
    const std::optional<FailureDomainId> parsed = FailureDomainId::parse(supersedes);
    if (!parsed.has_value()) {
      return false;
    }
    record->supersedes = *parsed;
  }
  if (!merged_into.empty()) {
    const std::optional<FailureDomainId> parsed = FailureDomainId::parse(merged_into);
    if (!parsed.has_value()) {
      return false;
    }
    record->merged_into = *parsed;
  }
  return true;
}

void encode_membership(codec::Writer& writer, const Membership& record) {
  writer.bytes(record.id.to_string());
  writer.bytes(record.domain.to_string());
  writer.u64(record.domain_generation.value());
  writer.bytes(record.member.to_string());
  writer.u64(record.generation.value());
  writer.u8(static_cast<std::uint8_t>(record.lifecycle));
  writer.u8(static_cast<std::uint8_t>(record.kind));
  writer.u8(static_cast<std::uint8_t>(record.role));
  writer.u8(static_cast<std::uint8_t>(record.dependency));
  writer.u64(record.evidence_generation.value());
  writer.u64(record.created_at.value());
  writer.u64(record.created_epoch.value());
  writer.bytes(record.superseded_by.to_string());
  writer.bytes(record.supersedes.to_string());
  encode_provenance(writer, record.provenance);
  writer.bytes(record.derivation.rule.to_string());
  writer.u64(record.derivation.generation.value());
  writer.u32(static_cast<std::uint32_t>(record.derivation.sources.size()));
  for (const MembershipId& source : record.derivation.sources) {
    writer.bytes(source.to_string());
  }
  writer.u32(static_cast<std::uint32_t>(record.derivation.source_generations.size()));
  for (const MembershipGeneration& generation : record.derivation.source_generations) {
    writer.u64(generation.value());
  }
  writer.bytes(record.derivation.context);
  writer.u8(record.derivation.valid ? 1 : 0);
  writer.u32(static_cast<std::uint32_t>(record.evidence.size()));
  for (const MembershipEvidence& entry : record.evidence) {
    encode_provenance(writer, entry.provenance);
    writer.u8(entry.live ? 1 : 0);
  }
  encode_metadata(writer, record.metadata);
  writer.u32(static_cast<std::uint32_t>(record.history.size()));
  for (const MembershipHistoryEntry& entry : record.history) {
    writer.u64(entry.previous_generation.value());
    writer.u64(entry.generation.value());
    writer.u8(static_cast<std::uint8_t>(entry.lifecycle));
    writer.bytes(entry.cause);
    writer.u8(static_cast<std::uint8_t>(entry.evidence));
    writer.u64(entry.epoch.value());
    writer.u64(entry.at.value());
  }
}

bool decode_membership(codec::Reader& reader, Membership* record) {
  std::string id;
  std::string domain;
  std::string member;
  std::string superseded_by;
  std::string supersedes;
  std::uint8_t lifecycle = 0;
  std::uint8_t kind = 0;
  std::uint8_t role = 0;
  std::uint8_t dependency = 0;
  std::uint64_t domain_generation = 0;
  std::uint64_t generation = 0;
  std::uint64_t evidence_generation = 0;
  std::uint64_t created_at = 0;
  std::uint64_t created_epoch = 0;
  if (!reader.bytes(&id, kOpaqueIdTextLength) || !reader.bytes(&domain, kOpaqueIdTextLength) ||
      !reader.u64(&domain_generation) || !reader.bytes(&member, 96) ||
      !reader.u64(&generation) || !reader.u8(&lifecycle) || !reader.u8(&kind) ||
      !reader.u8(&role) || !reader.u8(&dependency) || !reader.u64(&evidence_generation) ||
      !reader.u64(&created_at) || !reader.u64(&created_epoch) ||
      !reader.bytes(&superseded_by, kOpaqueIdTextLength) ||
      !reader.bytes(&supersedes, kOpaqueIdTextLength)) {
    return false;
  }
  if (!decode_provenance(reader, &record->provenance)) {
    return false;
  }
  std::string rule;
  std::uint64_t derivation_generation = 0;
  std::uint32_t source_count = 0;
  if (!reader.bytes(&rule, kOpaqueIdTextLength) || !reader.u64(&derivation_generation) ||
      !reader.count(&source_count, kOpaqueIdTextLength + 4, kMaxPersistedEvidence * 8 + 64)) {
    return false;
  }
  for (std::uint32_t i = 0; i < source_count; ++i) {
    std::string source;
    if (!reader.bytes(&source, kOpaqueIdTextLength)) {
      return false;
    }
    const std::optional<MembershipId> parsed = MembershipId::parse(source);
    if (!parsed.has_value()) {
      return false;
    }
    record->derivation.sources.push_back(*parsed);
  }
  std::uint32_t generation_count = 0;
  if (!reader.count(&generation_count, 8, kMaxPersistedEvidence * 8 + 64)) {
    return false;
  }
  for (std::uint32_t i = 0; i < generation_count; ++i) {
    std::uint64_t value = 0;
    if (!reader.u64(&value)) {
      return false;
    }
    record->derivation.source_generations.push_back(MembershipGeneration(value));
  }
  if (!reader.bytes(&record->derivation.context, kMaxPersistedStringBytes)) {
    return false;
  }
  std::uint8_t valid = 0;
  if (!reader.u8(&valid)) {
    return false;
  }
  record->derivation.valid = valid != 0;
  std::uint32_t evidence_count = 0;
  if (!reader.count(&evidence_count, 40, kMaxPersistedEvidence)) {
    return false;
  }
  for (std::uint32_t i = 0; i < evidence_count; ++i) {
    MembershipEvidence entry;
    if (!decode_provenance(reader, &entry.provenance)) {
      return false;
    }
    std::uint8_t live = 0;
    if (!reader.u8(&live)) {
      return false;
    }
    entry.live = live != 0;
    record->evidence.push_back(std::move(entry));
  }
  if (!decode_metadata(reader, &record->metadata)) {
    return false;
  }
  std::uint32_t history_count = 0;
  if (!reader.count(&history_count, 32, kMaxPersistedHistory)) {
    return false;
  }
  for (std::uint32_t i = 0; i < history_count; ++i) {
    MembershipHistoryEntry entry;
    std::uint64_t previous = 0;
    std::uint64_t current = 0;
    std::uint8_t entry_lifecycle = 0;
    std::uint8_t evidence = 0;
    std::uint64_t epoch = 0;
    std::uint64_t at = 0;
    if (!reader.u64(&previous) || !reader.u64(&current) || !reader.u8(&entry_lifecycle) ||
        !reader.bytes(&entry.cause, kMaxPersistedStringBytes) || !reader.u8(&evidence) ||
        !reader.u64(&epoch) || !reader.u64(&at)) {
      return false;
    }
    if (entry_lifecycle != 0) {
      if (!is_valid_membership_lifecycle(static_cast<MembershipLifecycle>(entry_lifecycle))) {
        return false;
      }
      entry.lifecycle = static_cast<MembershipLifecycle>(entry_lifecycle);
    }
    if (evidence != 0 && !is_valid_evidence_class(static_cast<EvidenceClass>(evidence))) {
      return false;
    }
    entry.evidence = static_cast<EvidenceClass>(evidence);
    entry.previous_generation = MembershipGeneration(previous);
    entry.generation = MembershipGeneration(current);
    entry.epoch = CoordinatorEpoch(epoch);
    entry.at = RegistryGeneration(at);
    record->history.push_back(std::move(entry));
  }

  const std::optional<MembershipId> membership_id = MembershipId::parse(id);
  const std::optional<FailureDomainId> domain_id = FailureDomainId::parse(domain);
  const std::optional<EntityRef> member_ref = EntityRef::parse(member);
  if (!membership_id.has_value() || !domain_id.has_value() || !member_ref.has_value()) {
    return false;
  }
  if (generation == 0 || domain_generation == 0) {
    return false;
  }
  if (!is_valid_membership_lifecycle(static_cast<MembershipLifecycle>(lifecycle)) ||
      !is_valid_membership_kind(static_cast<MembershipKind>(kind)) ||
      !is_valid_membership_role(static_cast<MembershipRole>(role)) ||
      !is_valid_dependency_semantics(static_cast<DependencySemantics>(dependency))) {
    return false;
  }
  if (!rule.empty()) {
    const std::optional<DerivationRuleId> parsed = DerivationRuleId::parse(rule);
    if (!parsed.has_value()) {
      return false;
    }
    record->derivation.rule = *parsed;
  }
  record->id = *membership_id;
  record->domain = *domain_id;
  record->domain_generation = FailureDomainGeneration(domain_generation);
  record->member = *member_ref;
  record->generation = MembershipGeneration(generation);
  record->lifecycle = static_cast<MembershipLifecycle>(lifecycle);
  record->kind = static_cast<MembershipKind>(kind);
  record->role = static_cast<MembershipRole>(role);
  record->dependency = static_cast<DependencySemantics>(dependency);
  record->evidence_generation = EvidenceGeneration(evidence_generation);
  record->created_at = RegistryGeneration(created_at);
  record->created_epoch = CoordinatorEpoch(created_epoch);
  record->derivation.generation = DerivationGeneration(derivation_generation);
  if (!superseded_by.empty()) {
    const std::optional<MembershipId> parsed = MembershipId::parse(superseded_by);
    if (!parsed.has_value()) {
      return false;
    }
    record->superseded_by = *parsed;
  }
  if (!supersedes.empty()) {
    const std::optional<MembershipId> parsed = MembershipId::parse(supersedes);
    if (!parsed.has_value()) {
      return false;
    }
    record->supersedes = *parsed;
  }
  return true;
}

} // namespace

/// Byte width of a record in the persisted encoding. Used by the mutation paths
/// to enforce max_record_bytes against the real encoder rather than a proxy.
std::size_t encoded_domain_bytes(const FailureDomain& record) {
  codec::Writer writer;
  encode_domain(writer, record);
  return writer.size();
}

std::size_t encoded_membership_bytes(const Membership& record) {
  codec::Writer writer;
  encode_membership(writer, record);
  return writer.size();
}

std::size_t encoded_relation_bytes(const DomainRelation& record) {
  codec::Writer writer;
  writer.bytes(record.id.to_string());
  writer.bytes(record.source.to_string());
  writer.bytes(record.target.to_string());
  writer.u8(static_cast<std::uint8_t>(record.type));
  encode_provenance(writer, record.provenance);
  writer.u64(record.created_at.value());
  writer.u64(record.created_epoch.value());
  return writer.size();
}

namespace {

void rebuild_indexes(RegistryState& state) {
  state.by_entity.clear();
  state.by_domain.clear();
  state.by_publisher.clear();
  state.by_class.clear();
  state.by_scope.clear();
  state.relations_by_domain.clear();
  state.children.clear();
  state.parents.clear();
  for (auto& slot : state.domains_by_lifecycle) {
    slot.clear();
  }
  for (auto& slot : state.memberships_by_lifecycle) {
    slot.clear();
  }
  for (const auto& entry : state.domains) {
    const FailureDomain& record = *entry.second;
    state.by_class[record.domain_class.to_string()].push_back(record.id);
    state.by_scope[record.administrative_scope].push_back(record.id);
    const auto slot = static_cast<std::size_t>(record.lifecycle);
    if (slot < kLifecycleSlots) {
      state.domains_by_lifecycle[slot].push_back(record.id);
    }
  }
  for (const auto& entry : state.memberships) {
    const Membership& record = *entry.second;
    state.by_entity[record.member.id()].push_back(record.id);
    state.by_domain[record.domain].push_back(record.id);
    for (const PublisherId& publisher : membership_evidence_publishers(record)) {
      state.by_publisher[publisher].push_back(record.id);
    }
    const auto slot = static_cast<std::size_t>(record.lifecycle);
    if (slot < kLifecycleSlots) {
      state.memberships_by_lifecycle[slot].push_back(record.id);
    }
  }
  for (const auto& entry : state.relations) {
    const DomainRelation& record = *entry.second;
    state.relations_by_domain[record.source].push_back(record.id);
    state.relations_by_domain[record.target].push_back(record.id);
    if (record.type == DomainRelationType::ContainedBy) {
      state.children[record.target].push_back(record.source);
      state.parents[record.source].push_back(record.target);
    }
  }
}

} // namespace

namespace {

std::string encode_payload(const RegistryState& state) {
  codec::Writer writer;
  writer.bytes("fdr/payload/v1");
  writer.u64(state.generation.value());
  writer.u64(state.epoch.value());
  writer.u64(state.next_snapshot.value());
  writer.u64(state.next_evidence_generation);

  std::vector<FailureDomainId> domain_ids;
  domain_ids.reserve(state.domains.size());
  for (const auto& entry : state.domains) {
    domain_ids.push_back(entry.first);
  }
  std::sort(domain_ids.begin(), domain_ids.end(), domain_id_less);
  writer.u32(static_cast<std::uint32_t>(domain_ids.size()));
  for (const FailureDomainId& id : domain_ids) {
    encode_domain(writer, *state.domains.at(id));
  }

  std::vector<MembershipId> membership_ids;
  membership_ids.reserve(state.memberships.size());
  for (const auto& entry : state.memberships) {
    membership_ids.push_back(entry.first);
  }
  std::sort(membership_ids.begin(), membership_ids.end(), membership_id_less);
  writer.u32(static_cast<std::uint32_t>(membership_ids.size()));
  for (const MembershipId& id : membership_ids) {
    encode_membership(writer, *state.memberships.at(id));
  }

  std::vector<DomainRelationId> relation_ids;
  relation_ids.reserve(state.relations.size());
  for (const auto& entry : state.relations) {
    relation_ids.push_back(entry.first);
  }
  std::sort(relation_ids.begin(), relation_ids.end());
  writer.u32(static_cast<std::uint32_t>(relation_ids.size()));
  for (const DomainRelationId& id : relation_ids) {
    const DomainRelation& record = *state.relations.at(id);
    writer.bytes(record.id.to_string());
    writer.bytes(record.source.to_string());
    writer.bytes(record.target.to_string());
    writer.u8(static_cast<std::uint8_t>(record.type));
    encode_provenance(writer, record.provenance);
    writer.u64(record.created_at.value());
    writer.u64(record.created_epoch.value());
  }

  std::vector<CoverageDeclaration> coverage = state.coverage;
  std::sort(coverage.begin(), coverage.end(),
            [](const CoverageDeclaration& left, const CoverageDeclaration& right) {
              if (left.administrative_scope != right.administrative_scope) {
                return left.administrative_scope < right.administrative_scope;
              }
              return left.domain_class.to_string() < right.domain_class.to_string();
            });
  writer.u32(static_cast<std::uint32_t>(coverage.size()));
  for (const CoverageDeclaration& declaration : coverage) {
    writer.bytes(declaration.administrative_scope);
    writer.bytes(declaration.domain_class.to_string());
    writer.u8(static_cast<std::uint8_t>(declaration.state));
    encode_provenance(writer, declaration.provenance);
    writer.u64(declaration.declared_at.value());
    writer.u64(declaration.epoch.value());
  }

  std::vector<PublisherId> publisher_ids;
  publisher_ids.reserve(state.publishers.size());
  for (const auto& entry : state.publishers) {
    publisher_ids.push_back(entry.first);
  }
  std::sort(publisher_ids.begin(), publisher_ids.end());
  writer.u32(static_cast<std::uint32_t>(publisher_ids.size()));
  for (const PublisherId& id : publisher_ids) {
    const PublisherRegistration& registration = state.publishers.at(id);
    writer.bytes(registration.publisher.to_string());
    writer.bytes(registration.name);
    writer.u32(static_cast<std::uint32_t>(registration.scope.classes.size()));
    for (DomainClass klass : registration.scope.classes) {
      writer.u8(static_cast<std::uint8_t>(klass));
    }
    writer.bytes(registration.scope.administrative_scope);
    writer.u8(static_cast<std::uint8_t>(registration.scope.max_evidence));
    writer.u64(registration.generation.value());
  }

  std::vector<std::pair<PublisherId, WorkerBootId>> fence_keys;
  for (const auto& entry : state.fences) {
    for (const FenceRecord& fence : entry.second) {
      fence_keys.emplace_back(fence.publisher, fence.worker_boot);
    }
  }
  std::sort(fence_keys.begin(), fence_keys.end());
  writer.u32(static_cast<std::uint32_t>(fence_keys.size()));
  for (const auto& key : fence_keys) {
    const std::vector<FenceRecord>& fences = state.fences.at(key.first);
    for (const FenceRecord& fence : fences) {
      if (fence.worker_boot != key.second) {
        continue;
      }
      writer.bytes(fence.publisher.to_string());
      writer.bytes(fence.worker_boot.to_string());
      writer.u8(static_cast<std::uint8_t>(fence.reason));
      writer.u64(fence.epoch.value());
      writer.u64(fence.at_generation.value());
    }
  }

  std::vector<DerivationRuleId> rule_ids;
  rule_ids.reserve(state.rules.size());
  for (const auto& entry : state.rules) {
    rule_ids.push_back(entry.first);
  }
  std::sort(rule_ids.begin(), rule_ids.end());
  writer.u32(static_cast<std::uint32_t>(rule_ids.size()));
  for (const DerivationRuleId& id : rule_ids) {
    const DerivationRule& rule = state.rules.at(id);
    writer.bytes(rule.id.to_string());
    writer.bytes(rule.name);
    writer.u8(static_cast<std::uint8_t>(rule.op));
    writer.bytes(rule.source_class.to_string());
    writer.bytes(rule.target_class.to_string());
    writer.u8(static_cast<std::uint8_t>(rule.member_class));
    writer.u8(static_cast<std::uint8_t>(rule.derived_role));
    writer.u8(static_cast<std::uint8_t>(rule.dependency));
    writer.u32(rule.rule_version);
    writer.bytes(rule.publisher.to_string());
    writer.u64(rule.published_at.value());
    writer.u8(rule.enabled ? 1 : 0);
  }
  return writer.buffer();
}

bool decode_payload(std::string_view payload, RegistryState* state, std::string* error) {
  codec::Reader reader(payload);
  std::string header;
  if (!reader.bytes(&header, 32) || header != "fdr/payload/v1") {
    *error = "payload header is not recognized";
    return false;
  }
  std::uint64_t generation = 0;
  std::uint64_t epoch = 0;
  std::uint64_t next_snapshot = 0;
  std::uint64_t next_evidence_generation = 0;
  if (!reader.u64(&generation) || !reader.u64(&epoch) || !reader.u64(&next_snapshot) ||
      !reader.u64(&next_evidence_generation)) {
    *error = "payload counters are truncated";
    return false;
  }
  state->generation = RegistryGeneration(generation);
  state->epoch = CoordinatorEpoch(epoch);
  state->next_snapshot = SnapshotSequence(next_snapshot == 0 ? 1 : next_snapshot);
  state->next_evidence_generation = next_evidence_generation == 0 ? 1 : next_evidence_generation;

  std::uint32_t domain_count = 0;
  if (!reader.count(&domain_count, 24, hard_limits::kMaxDomains)) {
    *error = "domain count is absurd or truncated";
    return false;
  }
  for (std::uint32_t i = 0; i < domain_count; ++i) {
    FailureDomain record;
    if (!decode_domain(reader, &record)) {
      *error = "domain record " + std::to_string(i) + " is malformed or truncated";
      return false;
    }
    if (state->domains.find(record.id) != state->domains.end()) {
      *error = "duplicate domain id in the image";
      return false;
    }
    state->domains[record.id] = std::make_shared<const FailureDomain>(std::move(record));
  }

  std::uint32_t membership_count = 0;
  if (!reader.count(&membership_count, 32, hard_limits::kMaxMemberships)) {
    *error = "membership count is absurd or truncated";
    return false;
  }
  for (std::uint32_t i = 0; i < membership_count; ++i) {
    Membership record;
    if (!decode_membership(reader, &record)) {
      *error = "membership record " + std::to_string(i) + " is malformed or truncated";
      return false;
    }
    if (state->memberships.find(record.id) != state->memberships.end()) {
      *error = "duplicate membership id in the image";
      return false;
    }
    if (state->domains.find(record.domain) == state->domains.end()) {
      *error = "membership references a domain that is not in the image";
      return false;
    }
    state->memberships[record.id] = std::make_shared<const Membership>(std::move(record));
  }

  std::uint32_t relation_count = 0;
  if (!reader.count(&relation_count, 40, kMaxPersistedRelations)) {
    *error = "relation count is absurd or truncated";
    return false;
  }
  for (std::uint32_t i = 0; i < relation_count; ++i) {
    std::string id;
    std::string source;
    std::string target;
    std::uint8_t type = 0;
    DomainRelation record;
    if (!reader.bytes(&id, kOpaqueIdTextLength) || !reader.bytes(&source, kOpaqueIdTextLength) ||
        !reader.bytes(&target, kOpaqueIdTextLength) || !reader.u8(&type)) {
      *error = "relation record " + std::to_string(i) + " is truncated";
      return false;
    }
    if (!decode_provenance(reader, &record.provenance)) {
      *error = "relation provenance is malformed";
      return false;
    }
    std::uint64_t created_at = 0;
    std::uint64_t created_epoch = 0;
    if (!reader.u64(&created_at) || !reader.u64(&created_epoch)) {
      *error = "relation counters are truncated";
      return false;
    }
    if (!is_valid_domain_relation_type(static_cast<DomainRelationType>(type))) {
      *error = "relation carries an invalid relation type";
      return false;
    }
    const std::optional<DomainRelationId> relation_id = DomainRelationId::parse(id);
    const std::optional<FailureDomainId> source_id = FailureDomainId::parse(source);
    const std::optional<FailureDomainId> target_id = FailureDomainId::parse(target);
    if (!relation_id.has_value() || !source_id.has_value() || !target_id.has_value()) {
      *error = "relation carries a malformed identifier";
      return false;
    }
    if (state->domains.find(*source_id) == state->domains.end() ||
        state->domains.find(*target_id) == state->domains.end()) {
      *error = "relation is dangling: an endpoint is not in the image";
      return false;
    }
    record.id = *relation_id;
    record.source = *source_id;
    record.target = *target_id;
    record.type = static_cast<DomainRelationType>(type);
    record.created_at = RegistryGeneration(created_at);
    record.created_epoch = CoordinatorEpoch(created_epoch);
    if (state->relations.find(record.id) != state->relations.end()) {
      *error = "duplicate relation in the image";
      return false;
    }
    state->relations[record.id] = std::make_shared<const DomainRelation>(std::move(record));
  }

  std::uint32_t coverage_count = 0;
  if (!reader.count(&coverage_count, 32, kMaxPersistedCoverage)) {
    *error = "coverage count is absurd or truncated";
    return false;
  }
  for (std::uint32_t i = 0; i < coverage_count; ++i) {
    CoverageDeclaration declaration;
    std::string klass;
    std::uint8_t state_value = 0;
    if (!reader.bytes(&declaration.administrative_scope, 256) ||
        !reader.bytes(&klass, 128) || !reader.u8(&state_value)) {
      *error = "coverage declaration is truncated";
      return false;
    }
    if (!decode_provenance(reader, &declaration.provenance)) {
      *error = "coverage provenance is malformed";
      return false;
    }
    std::uint64_t declared_at = 0;
    std::uint64_t declaration_epoch = 0;
    if (!reader.u64(&declared_at) || !reader.u64(&declaration_epoch)) {
      *error = "coverage counters are truncated";
      return false;
    }
    const std::optional<DomainClassRef> class_ref = DomainClassRef::parse(klass);
    if (!class_ref.has_value()) {
      *error = "coverage carries an invalid domain class";
      return false;
    }
    if (!is_valid_coverage_state(static_cast<CoverageState>(state_value))) {
      *error = "coverage carries an invalid coverage state";
      return false;
    }
    declaration.domain_class = *class_ref;
    declaration.state = static_cast<CoverageState>(state_value);
    declaration.declared_at = RegistryGeneration(declared_at);
    declaration.epoch = CoordinatorEpoch(declaration_epoch);
    state->coverage.push_back(std::move(declaration));
  }

  std::uint32_t publisher_count = 0;
  if (!reader.count(&publisher_count, 24, kMaxPersistedPublishers)) {
    *error = "publisher count is absurd or truncated";
    return false;
  }
  for (std::uint32_t i = 0; i < publisher_count; ++i) {
    PublisherRegistration registration;
    std::string id;
    std::string name;
    std::uint32_t class_count = 0;
    std::string scope;
    std::uint8_t max_evidence = 0;
    std::uint64_t publisher_generation = 0;
    if (!reader.bytes(&id, kOpaqueIdTextLength) || !reader.bytes(&name, kMaxPersistedStringBytes) ||
        !reader.count(&class_count, 1, kDomainClassCount)) {
      *error = "publisher record is truncated";
      return false;
    }
    for (std::uint32_t c = 0; c < class_count; ++c) {
      std::uint8_t klass = 0;
      if (!reader.u8(&klass)) {
        *error = "publisher class list is truncated";
        return false;
      }
      if (!is_valid_domain_class(static_cast<DomainClass>(klass))) {
        *error = "publisher grant carries an invalid domain class";
        return false;
      }
      registration.scope.classes.push_back(static_cast<DomainClass>(klass));
    }
    if (!reader.bytes(&scope, 256) || !reader.u8(&max_evidence) ||
        !reader.u64(&publisher_generation)) {
      *error = "publisher grant is truncated";
      return false;
    }
    if (!is_valid_evidence_class(static_cast<EvidenceClass>(max_evidence))) {
      *error = "publisher grant carries an invalid evidence class";
      return false;
    }
    const std::optional<PublisherId> publisher_id = PublisherId::parse(id);
    if (!publisher_id.has_value()) {
      *error = "publisher grant carries a malformed publisher id";
      return false;
    }
    registration.publisher = *publisher_id;
    registration.name = std::move(name);
    registration.scope.administrative_scope = std::move(scope);
    registration.scope.max_evidence = static_cast<EvidenceClass>(max_evidence);
    registration.generation = PublisherGeneration(publisher_generation);
    state->publishers[registration.publisher] = std::move(registration);
  }

  std::uint32_t fence_count = 0;
  if (!reader.count(&fence_count, 40, kMaxPersistedFences)) {
    *error = "fence count is absurd or truncated";
    return false;
  }
  for (std::uint32_t i = 0; i < fence_count; ++i) {
    std::string publisher;
    std::string boot;
    std::uint8_t reason = 0;
    std::uint64_t fence_epoch = 0;
    std::uint64_t at_generation = 0;
    if (!reader.bytes(&publisher, kOpaqueIdTextLength) ||
        !reader.bytes(&boot, kOpaqueIdTextLength) || !reader.u8(&reason) ||
        !reader.u64(&fence_epoch) || !reader.u64(&at_generation)) {
      *error = "fence record is truncated";
      return false;
    }
    const std::optional<PublisherId> publisher_id = PublisherId::parse(publisher);
    const std::optional<WorkerBootId> boot_id = WorkerBootId::parse(boot);
    if (!publisher_id.has_value() || !boot_id.has_value()) {
      *error = "fence record carries a malformed identifier";
      return false;
    }
    FenceRecord fence;
    fence.publisher = *publisher_id;
    fence.worker_boot = *boot_id;
    fence.reason = static_cast<FenceReason>(reason);
    fence.epoch = CoordinatorEpoch(fence_epoch);
    fence.at_generation = RegistryGeneration(at_generation);
    state->fences[fence.publisher].push_back(fence);
  }

  std::uint32_t rule_count = 0;
  if (!reader.count(&rule_count, 24, kMaxPersistedRules)) {
    *error = "derivation rule count is absurd or truncated";
    return false;
  }
  for (std::uint32_t i = 0; i < rule_count; ++i) {
    DerivationRule rule;
    std::string id;
    std::string source_class;
    std::string target_class;
    std::string publisher;
    std::uint8_t op = 0;
    std::uint8_t member_class = 0;
    std::uint8_t derived_role = 0;
    std::uint8_t dependency = 0;
    std::uint8_t enabled = 0;
    std::uint64_t published_at = 0;
    if (!reader.bytes(&id, kOpaqueIdTextLength) ||
        !reader.bytes(&rule.name, kMaxPersistedStringBytes) || !reader.u8(&op) ||
        !reader.bytes(&source_class, 128) || !reader.bytes(&target_class, 128) ||
        !reader.u8(&member_class) || !reader.u8(&derived_role) || !reader.u8(&dependency) ||
        !reader.u32(&rule.rule_version) || !reader.bytes(&publisher, kOpaqueIdTextLength) ||
        !reader.u64(&published_at) || !reader.u8(&enabled)) {
      *error = "derivation rule record is truncated";
      return false;
    }
    rule.published_at = RegistryGeneration(published_at);
    const std::optional<DerivationRuleId> rule_id = DerivationRuleId::parse(id);
    const std::optional<DomainClassRef> source_ref = DomainClassRef::parse(source_class);
    const std::optional<DomainClassRef> target_ref = DomainClassRef::parse(target_class);
    const std::optional<PublisherId> publisher_id = PublisherId::parse(publisher);
    if (!rule_id.has_value() || !source_ref.has_value() || !target_ref.has_value() ||
        !publisher_id.has_value()) {
      *error = "derivation rule carries a malformed identifier or class";
      return false;
    }
    if (!is_valid_derivation_operator(static_cast<DerivationOperator>(op))) {
      *error = "derivation rule carries an unsupported operator";
      return false;
    }
    if (!is_valid_membership_role(static_cast<MembershipRole>(derived_role)) ||
        !is_valid_dependency_semantics(static_cast<DependencySemantics>(dependency))) {
      *error = "derivation rule carries an invalid role or dependency";
      return false;
    }
    rule.id = *rule_id;
    rule.op = static_cast<DerivationOperator>(op);
    rule.source_class = *source_ref;
    rule.target_class = *target_ref;
    rule.member_class = member_class == 0 ? EntityClass::Unknown
                                          : static_cast<EntityClass>(member_class);
    if (rule.member_class != EntityClass::Unknown && !is_valid_entity_class(rule.member_class)) {
      *error = "derivation rule carries an invalid member class";
      return false;
    }
    rule.derived_role = static_cast<MembershipRole>(derived_role);
    rule.dependency = static_cast<DependencySemantics>(dependency);
    rule.publisher = *publisher_id;
    rule.enabled = enabled != 0;
    state->rules[rule.id] = std::move(rule);
  }

  // Generation invariants: a membership must name a domain generation that
  // actually existed. A generation above the domain's current one could never
  // have been produced by this runtime.
  for (const auto& entry : state->memberships) {
    const Membership& record = *entry.second;
    const auto domain_it = state->domains.find(record.domain);
    if (domain_it == state->domains.end()) {
      *error = "membership references a domain that is not in the image";
      return false;
    }
    if (record.domain_generation.is_zero() ||
        record.domain_generation.value() > domain_it->second->generation.value()) {
      *error = "membership names a domain generation that never existed";
      return false;
    }
  }

  // Relation invariants: the image must not hold a cycle over a relation type
  // that is acyclic by definition. Cycles are detected per relation type,
  // exactly as the runtime applies them.
  for (std::uint8_t raw = 1; raw <= kDomainRelationTypeCount; ++raw) {
    const auto relation_type = static_cast<DomainRelationType>(raw);
    if (!is_acyclic_relation(relation_type)) {
      continue;
    }
    std::unordered_map<FailureDomainId, std::vector<FailureDomainId>> edges;
    for (const auto& entry : state->relations) {
      const DomainRelation& record = *entry.second;
      if (record.type != relation_type) {
        continue;
      }
      edges[record.source].push_back(record.target);
    }
    std::unordered_map<FailureDomainId, int> colour;
    std::vector<std::pair<FailureDomainId, std::size_t>> stack;
    for (const auto& start : edges) {
      if (colour[start.first] != 0) {
        continue;
      }
      stack.clear();
      stack.emplace_back(start.first, 0);
      colour[start.first] = 1;
      while (!stack.empty()) {
        std::pair<FailureDomainId, std::size_t>& frame = stack.back();
        const auto it = edges.find(frame.first);
        if (it == edges.end() || frame.second >= it->second.size()) {
          colour[frame.first] = 2;
          stack.pop_back();
          continue;
        }
        const FailureDomainId next = it->second[frame.second++];
        if (colour[next] == 1) {
          *error = "the image holds a cycle over an acyclic relation type";
          return false;
        }
        if (colour[next] == 0) {
          colour[next] = 1;
          stack.emplace_back(next, 0);
        }
      }
    }
  }

  if (!reader.exhausted()) {
    *error = "payload carries trailing bytes that no record accounts for";
    return false;
  }
  return true;
}

/// Assembles the complete container and checks that it reads back before it is
/// allowed to replace anything on disk.
std::string build_container(std::string_view payload) {
  std::string container;
  container.reserve(kStateHeaderBytes + payload.size() + kStateTrailerBytes);
  container.append(kMagic, sizeof(kMagic));
  std::string counters;
  append_u32(counters, kStateFormatVersion);
  append_u32(counters, 0);
  append_u64(counters, static_cast<std::uint64_t>(payload.size()));
  container.append(counters);
  const DigestBytes payload_digest = sha256(payload);
  container.append(reinterpret_cast<const char*>(payload_digest.data()), payload_digest.size());
  const DigestBytes header_digest =
      sha256(container.data(), kHeaderDigestOffset);
  container.append(reinterpret_cast<const char*>(header_digest.data()), header_digest.size());
  container.append(payload);
  container.append(kTrailer, sizeof(kTrailer));
  return container;
}

bool verify_container(std::string_view container, std::string* error, std::uint32_t* version,
                      std::string_view* payload) {
  if (container.size() < kStateHeaderBytes + kStateTrailerBytes) {
    *error = "the image is shorter than the smallest valid container";
    return false;
  }
  if (std::memcmp(container.data(), kMagic, sizeof(kMagic)) != 0) {
    *error = "bad magic: this is not a Failure Domain Registry image";
    return false;
  }
  codec::Reader reader(container.substr(8));
  std::uint32_t format_version = 0;
  std::uint32_t flags = 0;
  std::uint64_t payload_bytes = 0;
  if (!reader.u32(&format_version) || !reader.u32(&flags) || !reader.u64(&payload_bytes)) {
    *error = "the container header is truncated";
    return false;
  }
  if (format_version != kStateFormatVersion) {
    *error = "unsupported state format version " + std::to_string(format_version);
    return false;
  }
  if (flags != 0) {
    *error = "the container declares reserved flags that this build does not understand";
    return false;
  }
  const std::uint64_t expected =
      static_cast<std::uint64_t>(kStateHeaderBytes) + payload_bytes + kStateTrailerBytes;
  if (expected != static_cast<std::uint64_t>(container.size())) {
    *error = "declared size does not match the file size: the image is truncated or padded";
    return false;
  }
  if (std::memcmp(container.data() + kStateHeaderBytes + payload_bytes, kTrailer,
                  sizeof(kTrailer)) != 0) {
    *error = "the trailer is missing or corrupt";
    return false;
  }
  const DigestBytes header_digest =
      sha256(container.data(), kHeaderDigestOffset);
  if (std::memcmp(header_digest.data(), container.data() + kHeaderDigestOffset,
                  kDigestBytes) != 0) {
    *error = "the container header digest does not match";
    return false;
  }
  const std::string_view body = container.substr(kStateHeaderBytes,
                                                  static_cast<std::size_t>(payload_bytes));
  const DigestBytes payload_digest = sha256(body.data(), body.size());
  if (std::memcmp(payload_digest.data(), container.data() + kDigestOffset, kDigestBytes) != 0) {
    *error = "the payload digest does not match: the image is corrupt";
    return false;
  }
  *version = format_version;
  *payload = body;
  return true;
}

std::uint64_t process_id() {
#ifdef _WIN32
  return static_cast<std::uint64_t>(::_getpid());
#else
  return static_cast<std::uint64_t>(::getpid());
#endif
}

} // namespace

Outcome Registry::save(const PersistenceConfig& config) const {
  if (config.path.empty()) {
    return Outcome::make(OutcomeCode::PersistenceFailure, "no persistence path was configured");
  }
  std::string payload;
  StateDigest digest;
  RegistryGeneration generation;
  CoordinatorEpoch epoch;
  std::size_t domains = 0;
  std::size_t memberships = 0;
  std::size_t relations = 0;
  std::size_t coverage = 0;
  std::size_t publishers = 0;
  std::size_t fences = 0;
  std::size_t rules = 0;
  {
    const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
    payload = encode_payload(impl_->state);
    digest = impl_->compute_state_digest();
    generation = impl_->state.generation;
    epoch = impl_->state.epoch;
    domains = impl_->state.domains.size();
    memberships = impl_->state.memberships.size();
    relations = impl_->state.relations.size();
    coverage = impl_->state.coverage.size();
    publishers = impl_->state.publishers.size();
    rules = impl_->state.rules.size();
    for (const auto& entry : impl_->state.fences) {
      fences += entry.second.size();
    }
  }
  const std::string container = build_container(payload);
  std::uint32_t container_version = 0;
  {
    std::string_view body;
    std::string verify_error;
    if (!verify_container(container, &verify_error, &container_version, &body)) {
      return Outcome::make(OutcomeCode::IntegrityFailure,
                           "the freshly built image does not verify: " + verify_error);
    }
  }

  const std::filesystem::path target(config.path);
  std::filesystem::path temporary = target;
  temporary += ".tmp-" + std::to_string(process_id());
  std::string error;
  if (!write_all(temporary, container, config.durable, &error)) {
    std::error_code ignored;
    std::filesystem::remove(temporary, ignored);
    return Outcome::make(OutcomeCode::PersistenceFailure, "cannot write the image: " + error);
  }
  if (config.atomic) {
    std::error_code rename_error;
    std::filesystem::rename(temporary, target, rename_error);
    if (rename_error) {
      std::error_code ignored;
      std::filesystem::remove(temporary, ignored);
      return Outcome::make(OutcomeCode::PersistenceFailure,
                           "cannot replace the destination atomically: " +
                               rename_error.message());
    }
  } else {
    std::error_code ignored;
    std::filesystem::remove(target, ignored);
    std::error_code rename_error;
    std::filesystem::rename(temporary, target, rename_error);
    if (rename_error) {
      std::filesystem::remove(temporary, ignored);
      return Outcome::make(OutcomeCode::PersistenceFailure,
                           "cannot move the image into place: " + rename_error.message());
    }
  }
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "state saved");
  outcome.steps.push_back(ExplanationStep{
      "persist", "bytes", std::to_string(container.size()),
      std::to_string(domains) + " domains, " + std::to_string(memberships) + " memberships, " +
          std::to_string(relations) + " relations, " + std::to_string(coverage) +
          " coverage declarations, " + std::to_string(publishers) + " publishers, " +
          std::to_string(fences) + " fences, " + std::to_string(rules) + " rules, format " +
          std::to_string(container_version)});
  outcome.state_generation = generation;
  outcome.epoch = epoch;
  return outcome;
}

Outcome Registry::load(const PersistenceConfig& config) {
  if (config.path.empty()) {
    return Outcome::make(OutcomeCode::PersistenceFailure, "no persistence path was configured");
  }
  const std::filesystem::path target(config.path);
  std::error_code exists_error;
  if (!std::filesystem::exists(target, exists_error)) {
    return Outcome::make(OutcomeCode::NotFound, "no persisted image exists at the path");
  }
  std::string container;
  std::string error;
  if (!read_all(target, &container, &error)) {
    return Outcome::make(OutcomeCode::PersistenceFailure, "cannot read the image: " + error);
  }
  std::uint32_t version = 0;
  std::string_view body;
  if (!verify_container(container, &error, &version, &body)) {
    return Outcome::make(OutcomeCode::IntegrityFailure, error);
  }
  RegistryState loaded;
  if (!decode_payload(body, &loaded, &error)) {
    return Outcome::make(OutcomeCode::IntegrityFailure, error);
  }
  rebuild_indexes(loaded);

  const std::size_t domains = loaded.domains.size();
  const std::size_t memberships = loaded.memberships.size();
  const std::size_t relations = loaded.relations.size();
  const RegistryGeneration generation = loaded.generation;
  RegistryGeneration live_generation;
  CoordinatorEpoch live_epoch;
  {
    const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
    // Only durable classification crosses the boundary. Live sessions are
    // never restored: durability does not imply current process authority.
    impl_->state = std::move(loaded);
    impl_->idempotency.clear();
    impl_->idempotency_entries = 0;
    impl_->bump_generation();
    live_generation = impl_->state.generation;
    live_epoch = impl_->state.epoch;
  }
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "state loaded");
  outcome.state_generation = live_generation;
  outcome.epoch = live_epoch;
  outcome.steps.push_back(ExplanationStep{
      "recover", "records",
      std::to_string(domains) + " domains, " + std::to_string(memberships) +
          " memberships, " + std::to_string(relations) + " relations",
      "persisted generation was " + generation.to_string() +
          "; no live session was restored"});
  return impl_->record(std::move(outcome));
}

Outcome inspect_persistence(const PersistenceConfig& config, PersistenceReport* report) {
  if (config.path.empty()) {
    return Outcome::make(OutcomeCode::PersistenceFailure, "no persistence path was configured");
  }
  std::string container;
  std::string error;
  if (!read_all(std::filesystem::path(config.path), &container, &error)) {
    return Outcome::make(OutcomeCode::PersistenceFailure, "cannot read the image: " + error);
  }
  std::uint32_t version = 0;
  std::string_view body;
  if (!verify_container(container, &error, &version, &body)) {
    return Outcome::make(OutcomeCode::IntegrityFailure, error);
  }
  RegistryState loaded;
  if (!decode_payload(body, &loaded, &error)) {
    return Outcome::make(OutcomeCode::IntegrityFailure, error);
  }
  if (report != nullptr) {
    report->bytes = container.size();
    report->domains = loaded.domains.size();
    report->memberships = loaded.memberships.size();
    report->relations = loaded.relations.size();
    report->coverage_declarations = loaded.coverage.size();
    report->publishers = loaded.publishers.size();
    report->derivation_rules = loaded.rules.size();
    for (const auto& entry : loaded.fences) {
      report->fences += entry.second.size();
    }
    report->generation = loaded.generation;
    report->epoch = loaded.epoch;
    report->format_version = version;
    // The semantic state digest, not the container's payload hash: this is the
    // value a consumer compares against Registry::state_digest().
    report->digest = compute_state_digest_of(loaded);
  }
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "image is readable and verified");
  outcome.steps.push_back(ExplanationStep{"inspect", "bytes", std::to_string(container.size()),
                                          "container verified"});
  return outcome;
}

} // namespace failure_domain_registry
