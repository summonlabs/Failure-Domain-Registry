// Failure Domain Registry — configured resource bounds.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A bound that is documented but not enforced is worse than no bound at all, so
// this file does two things for every field of RegistryLimits and FrameLimits:
// it pins the validation rule (the ceiling is inclusive, the floor is not, the
// failure names the field) and it drives the public API until the bound is the
// reason a call is refused. Every refusal is also checked for the property that
// matters most: the registry did not change, and validate_state still agrees
// with the record tables.
//
// The oversized-input cases exist because the cost of saying "no" must not grow
// with the size of the thing being refused: a publication, a metadata set and a
// query set are all offered far past their bound, and the registry answers with
// a ResourceLimit naming the bound rather than with work proportional to it.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "failure_domain_registry/digest.hpp"
#include "failure_domain_registry/failure_domain_registry.hpp"
#include "failure_domain_registry/version.hpp"
#include "support/test_harness.hpp"

namespace {

using failure_domain_registry::AddRelationRequest;
using failure_domain_registry::AttachMemberRequest;
using failure_domain_registry::AuthorityContext;
using failure_domain_registry::AuthorityScope;
using failure_domain_registry::CoordinatorEpoch;
using failure_domain_registry::CreateDomainRequest;
using failure_domain_registry::DeclareCoverageRequest;
using failure_domain_registry::DependencySemantics;
using failure_domain_registry::DigestBytes;
using failure_domain_registry::DomainClass;
using failure_domain_registry::DomainClassRef;
using failure_domain_registry::DomainLifecycle;
using failure_domain_registry::DomainRelationType;
using failure_domain_registry::EntityClass;
using failure_domain_registry::EntityGeneration;
using failure_domain_registry::EntityId;
using failure_domain_registry::EntityRef;
using failure_domain_registry::EvidenceClass;
using failure_domain_registry::FailureDomainGeneration;
using failure_domain_registry::FailureDomainId;
using failure_domain_registry::FrameLimits;
namespace hard_limits = failure_domain_registry::hard_limits;
using failure_domain_registry::IdBytes;
using failure_domain_registry::Membership;
using failure_domain_registry::MembershipGeneration;
using failure_domain_registry::MembershipKind;
using failure_domain_registry::MembershipLifecycle;
using failure_domain_registry::MembershipRole;
using failure_domain_registry::MetadataEntry;
using failure_domain_registry::MutationAttempt;
using failure_domain_registry::MutationAttemptId;
using failure_domain_registry::Outcome;
using failure_domain_registry::OutcomeCode;
using failure_domain_registry::PersistenceConfig;
using failure_domain_registry::Provenance;
using failure_domain_registry::ProvenanceSource;
using failure_domain_registry::PublicationMode;
using failure_domain_registry::PublisherId;
using failure_domain_registry::PublisherRegistration;
using failure_domain_registry::Registry;
using failure_domain_registry::RegistryGeneration;
using failure_domain_registry::RegistryLimits;
using failure_domain_registry::ReplaceMembershipRequest;
using failure_domain_registry::RequestDigest;
using failure_domain_registry::TopologyChangeRequest;
using failure_domain_registry::TruthClass;
using failure_domain_registry::UpdateDomainRequest;
using failure_domain_registry::ValidationResult;
using failure_domain_registry::WorkerBootId;
using failure_domain_registry::MembershipBatchEntry;
using failure_domain_registry::MembershipBatchRequest;

// ---------------------------------------------------------------------------
// Deterministic identities
// ---------------------------------------------------------------------------

/// A deterministic, non-null 128-bit value derived from a label. Nothing here
/// depends on time, on the process or on the order the cases run in.
IdBytes bytes_from(std::string_view label) {
  const std::string framed = std::string("fdr/test-limits/identity/v1/") + std::string(label);
  const DigestBytes digest = failure_domain_registry::sha256(framed);
  IdBytes bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    bytes[index] = digest[index];
  }
  bytes[0] = static_cast<std::uint8_t>(bytes[0] | 0x80u);
  return bytes;
}

template <class Id>
Id id_from(std::string_view label) {
  return Id::from_bytes(bytes_from(label));
}

PublisherId publisher_from(std::string_view label) {
  return id_from<PublisherId>(std::string("publisher/") + std::string(label));
}

WorkerBootId boot_from(std::string_view label) {
  return id_from<WorkerBootId>(std::string("boot/") + std::string(label));
}

MutationAttemptId attempt_from(std::string_view label) {
  return id_from<MutationAttemptId>(std::string("attempt/") + std::string(label));
}

EntityRef entity_ref(EntityClass entity_class, std::string_view label, std::uint64_t generation) {
  return EntityRef(entity_class, bytes_from(std::string("entity/") + std::string(label)),
                   EntityGeneration(generation));
}

std::string text_of(std::size_t length, char value) { return std::string(length, value); }

Provenance provenance_of(ProvenanceSource source, EvidenceClass evidence, std::string_view identity) {
  Provenance provenance;
  provenance.source = source;
  provenance.evidence = evidence;
  provenance.truth = TruthClass::Real;
  provenance.source_identity = std::string(identity);
  return provenance;
}

/// Operator-owned evidence: durable, and the strongest class the matrix has.
Provenance durable_provenance(std::string_view identity) {
  return provenance_of(ProvenanceSource::OperatorInventory,
                       EvidenceClass::DirectAuthoritativeInfrastructure, identity);
}

MetadataEntry metadata(std::string key, std::string value) {
  MetadataEntry entry;
  entry.key = std::move(key);
  entry.value = std::move(value);
  return entry;
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

/// Everything a refused request must leave untouched. The registry generation
/// alone would miss an index updated without a commit, so every count the
/// public API publishes is compared, and validate_state is asked to reconcile
/// the record tables with the indexes.
struct Fingerprint {
  RegistryGeneration generation;
  CoordinatorEpoch epoch;
  std::size_t domains{0};
  std::size_t memberships{0};
  std::size_t sessions{0};
  std::size_t publishers{0};
  std::size_t current_memberships{0};
  std::size_t revalidation_memberships{0};
  std::size_t superseded_memberships{0};
  std::size_t retired_memberships{0};
  std::size_t conflicted_memberships{0};

  static Fingerprint capture(const Registry& registry) {
    Fingerprint out;
    out.generation = registry.generation();
    out.epoch = registry.epoch();
    out.domains = registry.domain_count();
    out.memberships = registry.membership_count();
    out.sessions = registry.live_sessions().size();
    out.publishers = registry.publishers().size();
    out.current_memberships =
        registry.memberships_in_lifecycle(MembershipLifecycle::Current).size();
    out.revalidation_memberships =
        registry.memberships_in_lifecycle(MembershipLifecycle::RevalidationRequired).size();
    out.superseded_memberships =
        registry.memberships_in_lifecycle(MembershipLifecycle::Superseded).size();
    out.retired_memberships =
        registry.memberships_in_lifecycle(MembershipLifecycle::Retired).size();
    out.conflicted_memberships =
        registry.memberships_in_lifecycle(MembershipLifecycle::Conflicted).size();
    return out;
  }

  /// Empty when the registry still matches, otherwise the first difference.
  std::string drift(const Registry& registry) const {
    std::string why;
    if (!registry.validate_state(&why)) {
      return "validate_state failed: " + why;
    }
    if (!(registry.generation() == generation)) {
      return "generation moved from " + generation.to_string() + " to " +
             registry.generation().to_string();
    }
    if (!(registry.epoch() == epoch)) {
      return "epoch moved from " + epoch.to_string() + " to " + registry.epoch().to_string();
    }
    if (registry.domain_count() != domains) {
      return "domain count moved from " + std::to_string(domains) + " to " +
             std::to_string(registry.domain_count());
    }
    if (registry.membership_count() != memberships) {
      return "membership count moved from " + std::to_string(memberships) + " to " +
             std::to_string(registry.membership_count());
    }
    if (registry.live_sessions().size() != sessions) {
      return "the live session set moved";
    }
    if (registry.publishers().size() != publishers) {
      return "the publisher set moved";
    }
    if (registry.memberships_in_lifecycle(MembershipLifecycle::Current).size() !=
            current_memberships ||
        registry.memberships_in_lifecycle(MembershipLifecycle::RevalidationRequired).size() !=
            revalidation_memberships ||
        registry.memberships_in_lifecycle(MembershipLifecycle::Superseded).size() !=
            superseded_memberships ||
        registry.memberships_in_lifecycle(MembershipLifecycle::Retired).size() !=
            retired_memberships ||
        registry.memberships_in_lifecycle(MembershipLifecycle::Conflicted).size() !=
            conflicted_memberships) {
      return "a membership lifecycle count moved";
    }
    return std::string();
  }
};

// ---------------------------------------------------------------------------
// The bootstrap fixture
// ---------------------------------------------------------------------------

/// A registry plus the authority handshake every mutation needs: an epoch, a
/// durable grant and one live incarnation.
struct Fixture {
  std::unique_ptr<Registry> registry;
  Outcome advanced;
  Outcome granted;
  Outcome attached;
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  CoordinatorEpoch epoch{};

  AuthorityContext authority(
      EvidenceClass evidence = EvidenceClass::DirectAuthoritativeInfrastructure) const {
    AuthorityContext context;
    context.publisher = publisher;
    context.worker_boot = worker_boot;
    context.epoch = epoch;
    context.evidence = evidence;
    return context;
  }

  /// Empty when every bootstrap step committed.
  std::string problem() const {
    if (!advanced.committed()) {
      return "advance_epoch: " + advanced.message;
    }
    if (!granted.committed()) {
      return "grant_publisher: " + granted.message;
    }
    if (!attached.committed()) {
      return "attach_worker: " + attached.message;
    }
    return std::string();
  }
};

Fixture open(RegistryLimits limits) {
  Fixture fixture;
  fixture.registry = std::make_unique<Registry>(limits);
  fixture.publisher = publisher_from("limits");
  fixture.worker_boot = boot_from("limits");
  fixture.advanced = fixture.registry->advance_epoch(CoordinatorEpoch(0), &fixture.epoch);
  PublisherRegistration registration;
  registration.publisher = fixture.publisher;
  registration.name = "limits";
  registration.scope = AuthorityScope::unrestricted();
  fixture.granted = fixture.registry->grant_publisher(registration, AuthorityContext{});
  fixture.attached = fixture.registry->attach_worker(
      fixture.publisher, fixture.worker_boot, fixture.epoch, "limits",
      EvidenceClass::DirectAuthoritativeInfrastructure);
  return fixture;
}

/// One durable domain declaration. The caller asserts the outcome so a fixture
/// failure can never be mistaken for the behaviour under test.
Outcome declare_domain(Registry& registry, const AuthorityContext& authority,
                       const DomainClassRef& domain_class, std::string_view scope,
                       std::string_view identity_key, std::string_view name,
                       std::string_view attempt_label, const Provenance& provenance) {
  CreateDomainRequest request;
  request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
  request.authority = authority;
  request.domain_class = domain_class;
  request.administrative_scope = std::string(scope);
  request.identity_key = std::string(identity_key);
  request.name = std::string(name);
  request.provenance = provenance;
  return registry.create_domain(request);
}

Outcome attach_member(Registry& registry, const AuthorityContext& authority,
                      const FailureDomainId& domain, const EntityRef& member,
                      std::string_view attempt_label, const Provenance& provenance,
                      MembershipRole role = MembershipRole::SharedRisk,
                      MembershipKind kind = MembershipKind::Direct) {
  AttachMemberRequest request;
  request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
  request.authority = authority;
  request.domain = domain;
  request.member = member;
  request.kind = kind;
  request.role = role;
  request.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
  request.provenance = provenance;
  return registry.attach_member(request);
}

Outcome add_relation(Registry& registry, const AuthorityContext& authority,
                     const FailureDomainId& source, const FailureDomainId& target,
                     DomainRelationType type, std::string_view attempt_label,
                     const Provenance& provenance) {
  AddRelationRequest request;
  request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
  request.authority = authority;
  request.source = source;
  request.target = target;
  request.type = type;
  request.provenance = provenance;
  return registry.add_relation(request);
}

Outcome update_transition(Registry& registry, const AuthorityContext& authority,
                          const FailureDomainId& domain, DomainLifecycle target,
                          std::string_view attempt_label) {
  UpdateDomainRequest request;
  request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
  request.authority = authority;
  request.domain = domain;
  request.transition = target;
  return registry.update_domain(request);
}

Outcome declare(Registry& registry, const AuthorityContext& authority, std::string_view scope,
                const DomainClassRef& domain_class,
                failure_domain_registry::CoverageState state, std::string_view attempt_label,
                const Provenance& provenance) {
  DeclareCoverageRequest request;
  request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
  request.authority = authority;
  request.administrative_scope = std::string(scope);
  request.domain_class = domain_class;
  request.state = state;
  request.provenance = provenance;
  return registry.declare_coverage(request);
}

FailureDomainId domain_of(std::string_view scope, const DomainClassRef& domain_class,
                          std::string_view identity_key) {
  return failure_domain_registry::domain_id_for(scope, domain_class, identity_key);
}

/// The public walk results are ordered by identity, so an expectation written in
/// dependency order has to be sorted before it can be compared.
std::vector<FailureDomainId> sorted_ids(std::vector<FailureDomainId> ids) {
  std::sort(ids.begin(), ids.end());
  return ids;
}

std::string describe(const Outcome& outcome) {
  return std::string(failure_domain_registry::to_string(outcome.code)) + ": " + outcome.message;
}

/// True when the outcome carries a step that names the bound and the value the
/// bound had. Registry refusals report the offending field in a step rather
/// than in the message.
bool names_bound(const Outcome& outcome, std::string_view field, std::string_view value) {
  for (const failure_domain_registry::ExplanationStep& step : outcome.steps) {
    if (step.field == field && (value.empty() || step.value == value)) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

struct RegistryLimitField {
  const char* name;
  std::size_t RegistryLimits::*member;
  std::size_t hard_max;
  std::size_t minimum;
};

const RegistryLimitField kRegistryLimitFields[] = {
    {"max_domains", &RegistryLimits::max_domains, hard_limits::kMaxDomains, 1},
    {"max_memberships", &RegistryLimits::max_memberships, hard_limits::kMaxMemberships, 1},
    {"max_relations", &RegistryLimits::max_relations, hard_limits::kMaxRelations, 1},
    {"max_string_bytes", &RegistryLimits::max_string_bytes, hard_limits::kMaxStringBytes, 16},
    {"max_metadata_entries", &RegistryLimits::max_metadata_entries, hard_limits::kMaxMetadataEntries, 1},
    {"max_metadata_value_bytes", &RegistryLimits::max_metadata_value_bytes,
     hard_limits::kMaxMetadataValueBytes, 1},
    {"max_metadata_bytes_per_record", &RegistryLimits::max_metadata_bytes_per_record,
     hard_limits::kMaxMetadataBytesPerRecord, 1},
    {"max_record_bytes", &RegistryLimits::max_record_bytes, hard_limits::kMaxRecordBytes, 256},
    {"max_evidence_per_membership", &RegistryLimits::max_evidence_per_membership,
     hard_limits::kMaxEvidencePerMembership, 1},
    {"max_members_per_batch", &RegistryLimits::max_members_per_batch, hard_limits::kMaxMembersPerBatch, 1},
    {"max_query_set_cardinality", &RegistryLimits::max_query_set_cardinality,
     hard_limits::kMaxQuerySetCardinality, 1},
    {"max_hierarchy_depth", &RegistryLimits::max_hierarchy_depth, hard_limits::kMaxHierarchyDepth, 1},
    {"max_ancestor_walk", &RegistryLimits::max_ancestor_walk, hard_limits::kMaxAncestorWalk, 1},
    {"max_history_entries_per_record", &RegistryLimits::max_history_entries_per_record,
     hard_limits::kMaxHistoryEntriesPerRecord, 1},
    {"max_history_query", &RegistryLimits::max_history_query, hard_limits::kMaxHistoryQuery, 1},
    {"max_idempotency_entries_per_publisher", &RegistryLimits::max_idempotency_entries_per_publisher,
     hard_limits::kMaxIdempotencyEntriesPerPublisher, 1},
    {"max_fenced_boots_per_publisher", &RegistryLimits::max_fenced_boots_per_publisher,
     hard_limits::kMaxFencedBootsPerPublisher, 1},
    {"max_publishers", &RegistryLimits::max_publishers, hard_limits::kMaxPublishers, 1},
    {"max_coverage_declarations", &RegistryLimits::max_coverage_declarations,
     hard_limits::kMaxCoverageDeclarations, 1},
};

struct FrameLimitField {
  const char* name;
  std::size_t FrameLimits::*member;
  std::size_t hard_max;
  std::size_t minimum;
};

const FrameLimitField kFrameLimitFields[] = {
    {"max_payload_bytes", &FrameLimits::max_payload_bytes, hard_limits::kMaxFramePayloadBytes, 64},
    {"max_pending_frames", &FrameLimits::max_pending_frames, 65536, 1},
    {"max_sessions", &FrameLimits::max_sessions, hard_limits::kMaxSessions, 1},
    {"worker_threads", &FrameLimits::worker_threads, hard_limits::kMaxWorkerThreads, 1},
};

bool throws_invalid_argument(const RegistryLimits& limits, std::string* what) {
  try {
    const Registry registry(limits);
    (void)registry;
  } catch (const std::invalid_argument& error) {
    if (what != nullptr) {
      *what = error.what();
    }
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// A crafted persistence image
// ---------------------------------------------------------------------------

std::string payload_prefix() {
  std::string out;
  failure_domain_registry::append_bytes(out, "fdr/payload/v1");
  failure_domain_registry::append_u64(out, 1);
  failure_domain_registry::append_u64(out, 1);
  failure_domain_registry::append_u64(out, 1);
  failure_domain_registry::append_u64(out, 1);
  return out;
}

/// The container the library writes: magic, version, flags, declared payload
/// length, payload digest, header digest, payload, trailer. Both digests are
/// correct, so a rejection can only come from the declared length or from the
/// payload records themselves.
std::string container_of(std::string_view payload, std::uint64_t declared_payload_length) {
  std::string out;
  out.append("FDRSTATE", 8);
  failure_domain_registry::append_u32(out, failure_domain_registry::kStateFormatVersion);
  failure_domain_registry::append_u32(out, 0);
  failure_domain_registry::append_u64(out, declared_payload_length);
  const DigestBytes payload_digest = failure_domain_registry::sha256(payload);
  out.append(reinterpret_cast<const char*>(payload_digest.data()), payload_digest.size());
  const DigestBytes header_digest = failure_domain_registry::sha256(out);
  out.append(reinterpret_cast<const char*>(header_digest.data()), header_digest.size());
  out.append(payload);
  out.append("FDREND", 6);
  return out;
}

std::string payload_with_counts(const std::vector<std::uint32_t>& counts) {
  std::string out = payload_prefix();
  for (const std::uint32_t count : counts) {
    failure_domain_registry::append_u32(out, count);
  }
  return out;
}

std::filesystem::path scratch_path(std::string_view label) {
  return std::filesystem::temp_directory_path() /
         ("fdr-agent5-limits-" + std::string(label) + ".img");
}

void write_image(const std::filesystem::path& path, std::string_view bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

} // namespace

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

FDR_TEST_CASE(limits, defaults_validate_and_every_field_has_the_same_floor_and_ceiling_rule) {
  const RegistryLimits defaults = RegistryLimits::defaults();
  const ValidationResult valid = defaults.validate();
  FDR_CHECK_MSG(valid.ok, "the default RegistryLimits do not validate: " + valid.message);
  FDR_CHECK(valid.message.empty());
  FDR_CHECK(static_cast<bool>(valid));
  FDR_CHECK(!ValidationResult::failure("x").ok);
  FDR_CHECK(ValidationResult::success().ok);

  static_assert(sizeof(kRegistryLimitFields) / sizeof(kRegistryLimitFields[0]) == 19,
                "the table must carry one row per RegistryLimits field");

  for (const RegistryLimitField& field : kRegistryLimitFields) {
    const std::string name(field.name);

    // The compiled-in ceiling is what the table above claims it is.
    {
      RegistryLimits limits = defaults;
      limits.*field.member = field.hard_max;
      const ValidationResult at_ceiling = limits.validate();
      FDR_CHECK_MSG(at_ceiling.ok,
                   name + ": the hard ceiling itself is rejected: " + at_ceiling.message);
    }
    // One byte above the ceiling is rejected, and the message names the field.
    {
      RegistryLimits limits = defaults;
      limits.*field.member = field.hard_max + 1;
      const ValidationResult above = limits.validate();
      FDR_CHECK_MSG(!above.ok, name + ": a value above the hard ceiling validated");
      FDR_CHECK_MSG(above.message.find(name) != std::string::npos,
                   name + ": the failure message does not name the field: " + above.message);
      FDR_CHECK_MSG(above.message.find("hard ceiling") != std::string::npos,
                   name + ": the failure message does not say why: " + above.message);
      FDR_CHECK_MSG(above.message.find(std::to_string(field.hard_max)) != std::string::npos,
                   name + ": the failure message does not report the ceiling: " + above.message);
    }
    // Lowering the field to its floor stays valid: configuration may always be
    // made stricter. max_ancestor_walk is coupled to max_hierarchy_depth, so
    // lowering the walk bound lowers the depth ceiling with it.
    {
      RegistryLimits limits = defaults;
      limits.*field.member = field.minimum;
      if (name == "max_ancestor_walk") {
        limits.max_hierarchy_depth = field.minimum;
      }
      const ValidationResult lowered = limits.validate();
      FDR_CHECK_MSG(lowered.ok, name + ": the documented floor is rejected: " + lowered.message);
    }
    // The floor is exclusive at zero, and the message states the minimum.
    {
      RegistryLimits limits = defaults;
      limits.*field.member = 0;
      const ValidationResult zero = limits.validate();
      FDR_CHECK_MSG(!zero.ok, name + ": zero validated as a bound");
      FDR_CHECK_MSG(zero.message.find(name) != std::string::npos,
                   name + ": the failure message does not name the field: " + zero.message);
      FDR_CHECK_MSG(zero.message.find("at least") != std::string::npos,
                   name + ": the failure message does not state the minimum: " + zero.message);
      FDR_CHECK_MSG(zero.message.find(std::to_string(field.minimum)) != std::string::npos,
                   name + ": the failure message does not report the minimum: " + zero.message);
    }
    // A field below its floor but above zero is still rejected, so the floor is
    // a real bound and not just a zero check.
    if (field.minimum > 1) {
      RegistryLimits limits = defaults;
      limits.*field.member = field.minimum - 1;
      const ValidationResult below = limits.validate();
      FDR_CHECK_MSG(!below.ok, name + ": a value below the floor validated");
      FDR_CHECK_MSG(below.message.find(name) != std::string::npos,
                   name + ": the failure message does not name the field: " + below.message);
    }
  }

  // The published defaults are inside their own ceilings, which the loop above
  // cannot see because it overwrites one field at a time.
  FDR_CHECK_EQ(defaults.max_domains, std::size_t{1'000'000});
  FDR_CHECK_EQ(defaults.max_memberships, std::size_t{2'000'000});
  FDR_CHECK_EQ(defaults.max_string_bytes, std::size_t{1024});
  FDR_CHECK_EQ(defaults.max_metadata_entries, std::size_t{32});
  FDR_CHECK_EQ(defaults.max_evidence_per_membership, std::size_t{8});
  FDR_CHECK_EQ(defaults.max_members_per_batch, std::size_t{16'384});
  FDR_CHECK_EQ(defaults.max_query_set_cardinality, std::size_t{1024});
  FDR_CHECK_EQ(defaults.max_hierarchy_depth, std::size_t{64});
  FDR_CHECK_EQ(defaults.max_ancestor_walk, std::size_t{1024});
  FDR_CHECK_EQ(defaults.max_history_entries_per_record, std::size_t{64});
  FDR_CHECK_EQ(defaults.max_idempotency_entries_per_publisher, std::size_t{4096});
  FDR_CHECK_EQ(defaults.max_fenced_boots_per_publisher, std::size_t{64});
  FDR_CHECK_EQ(defaults.max_publishers, std::size_t{4096});
  FDR_CHECK_EQ(defaults.max_coverage_declarations, std::size_t{4096});
}

FDR_TEST_CASE(limits, an_invalid_configuration_is_refused_at_construction) {
  std::string what;
  RegistryLimits above = RegistryLimits::defaults();
  above.max_domains = hard_limits::kMaxDomains + 1;
  FDR_CHECK_MSG(throws_invalid_argument(above, &what),
               "a registry accepted max_domains above the hard ceiling");
  FDR_CHECK_MSG(what.find("invalid RegistryLimits") != std::string::npos,
               "the constructor message does not identify the configuration: " + what);
  FDR_CHECK_MSG(what.find("max_domains") != std::string::npos,
               "the constructor message does not name the field: " + what);

  what.clear();
  RegistryLimits zero = RegistryLimits::defaults();
  zero.max_memberships = 0;
  FDR_CHECK_MSG(throws_invalid_argument(zero, &what), "a registry accepted a zero membership bound");
  FDR_CHECK_MSG(what.find("max_memberships") != std::string::npos,
               "the constructor message does not name the field: " + what);

  // A configuration that only lowers a bound is accepted, and the registry
  // reports back exactly what it was given.
  RegistryLimits custom = RegistryLimits::defaults();
  custom.max_domains = 7;
  custom.max_string_bytes = 16;
  custom.max_metadata_entries = 1;
  const Registry registry(custom);
  FDR_CHECK_EQ(registry.limits().max_domains, std::size_t{7});
  FDR_CHECK_EQ(registry.limits().max_string_bytes, std::size_t{16});
  FDR_CHECK_EQ(registry.limits().max_metadata_entries, std::size_t{1});
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{0});
  FDR_CHECK_EQ(registry.epoch(), CoordinatorEpoch(0));
}

FDR_TEST_CASE(limits, the_default_frame_limits_validate_and_the_payload_ceiling_is_the_hard_one) {
  const FrameLimits defaults = FrameLimits::defaults();
  const ValidationResult valid = defaults.validate();
  FDR_CHECK_MSG(valid.ok, "the default FrameLimits do not validate: " + valid.message);
  FDR_CHECK_EQ(defaults.max_payload_bytes, std::size_t{1024 * 1024});
  FDR_CHECK_EQ(defaults.max_pending_frames, std::size_t{64});
  FDR_CHECK_EQ(defaults.max_sessions, std::size_t{256});
  FDR_CHECK_EQ(defaults.worker_threads, std::size_t{4});
  FDR_CHECK_EQ(defaults.idle_timeout_ms, std::uint32_t{0});
  static_assert(hard_limits::kMaxFramePayloadBytes == 4u * 1024u * 1024u,
                "the compiled-in frame payload ceiling is four mebibytes");

  static_assert(sizeof(kFrameLimitFields) / sizeof(kFrameLimitFields[0]) == 4,
                "the table must carry one row per bounded FrameLimits field");
  for (const FrameLimitField& field : kFrameLimitFields) {
    const std::string name(field.name);
    FrameLimits limits = defaults;
    limits.*field.member = field.hard_max;
    FDR_CHECK_MSG(limits.validate().ok, name + ": the hard ceiling itself is rejected");
    limits.*field.member = field.hard_max + 1;
    const ValidationResult above = limits.validate();
    FDR_CHECK_MSG(!above.ok, name + ": a value above the ceiling validated");
    FDR_CHECK_MSG(above.message.find(name) != std::string::npos,
                 name + ": the failure does not name the field: " + above.message);
    limits.*field.member = field.minimum;
    FDR_CHECK_MSG(limits.validate().ok, name + ": the floor is rejected");
    limits.*field.member = field.minimum - 1;
    const ValidationResult below = limits.validate();
    FDR_CHECK_MSG(!below.ok, name + ": a value below the floor validated");
    FDR_CHECK_MSG(below.message.find(name) != std::string::npos,
                 name + ": the failure does not name the field: " + below.message);
  }

  // Zero disables idle closure; the field carries no ceiling of its own, and
  // validate() does not inspect it at all, so even the largest value is
  // accepted. Both facts are asserted rather than assumed.
  FrameLimits idle_disabled = defaults;
  idle_disabled.idle_timeout_ms = 0;
  FDR_CHECK(idle_disabled.validate().ok);
  FrameLimits idle_forever = defaults;
  idle_forever.idle_timeout_ms = UINT32_MAX;
  FDR_CHECK_MSG(idle_forever.validate().ok,
               "validate() invented a ceiling for idle_timeout_ms that the header never declared");
}

// ---------------------------------------------------------------------------
// RegistryLimits enforced through the public API
// ---------------------------------------------------------------------------

FDR_TEST_CASE(limits, max_domains_refuses_the_next_domain_and_names_the_bound) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_domains = 2;
  Fixture fixture = open(limits);
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const Provenance provenance = durable_provenance("inv");
  const DomainClassRef klass(DomainClass::Rack);

  FDR_CHECK_EQ(
      declare_domain(registry, fixture.authority(), klass, "dc1", "rack-1", "r1", "d1", provenance).code,
      OutcomeCode::Committed);
  FDR_CHECK_EQ(
      declare_domain(registry, fixture.authority(), klass, "dc1", "rack-2", "r2", "d2", provenance).code,
      OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{2});

  const Fingerprint before = Fingerprint::capture(registry);
  const Outcome refused =
      declare_domain(registry, fixture.authority(), klass, "dc1", "rack-3", "r3", "d3", provenance);
  FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
  FDR_CHECK_MSG(names_bound(refused, "max_domains", "2"),
               "the refusal does not report max_domains = 2: " + describe(refused));
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{2});
  FDR_CHECK(!registry.domain(domain_of("dc1", klass, "rack-3")).has_value());
  const std::string drift = before.drift(registry);
  FDR_CHECK_MSG(drift.empty(), "a refused domain creation changed state: " + drift);

  // The bound is on records, not on requests: re-declaring an existing domain
  // is still an idempotent read of the same identity.
  FDR_CHECK_EQ(
      declare_domain(registry, fixture.authority(), klass, "dc1", "rack-1", "r1", "d4", provenance).code,
      OutcomeCode::Idempotent);
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{2});
}

FDR_TEST_CASE(limits, max_memberships_refuses_the_next_membership) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_memberships = 1;
  Fixture fixture = open(limits);
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const Provenance provenance = durable_provenance("inv");
  const DomainClassRef klass(DomainClass::Conduit);
  const FailureDomainId domain = domain_of("dc1", klass, "conduit-1");
  FDR_CHECK_EQ(
      declare_domain(registry, fixture.authority(), klass, "dc1", "conduit-1", "c1", "d1", provenance).code,
      OutcomeCode::Committed);

  const EntityRef first_member = entity_ref(EntityClass::Switch, "member-1", 1);
  const EntityRef second_member = entity_ref(EntityClass::Switch, "member-2", 1);
  FDR_CHECK_EQ(attach_member(registry, fixture.authority(), domain, first_member, "a1", provenance).code,
              OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{1});

  const Fingerprint before = Fingerprint::capture(registry);
  const Outcome refused =
      attach_member(registry, fixture.authority(), domain, second_member, "a2", provenance);
  FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
  FDR_CHECK_MSG(names_bound(refused, "max_memberships", "1"),
               "the refusal does not report max_memberships = 1: " + describe(refused));
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{1});
  FDR_CHECK(registry.memberships_of(second_member.id()).empty());
  const std::string drift = before.drift(registry);
  FDR_CHECK_MSG(drift.empty(), "a refused attach changed state: " + drift);
}

FDR_TEST_CASE(limits, max_relations_refuses_the_next_edge) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_relations = 1;
  Fixture fixture = open(limits);
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const Provenance provenance = durable_provenance("inv");
  const DomainClassRef rack(DomainClass::Rack);
  const DomainClassRef row(DomainClass::Row);
  const FailureDomainId rack_id = domain_of("dc1", rack, "rack-1");
  const FailureDomainId row_id = domain_of("dc1", row, "row-1");
  FDR_CHECK_EQ(
      declare_domain(registry, fixture.authority(), rack, "dc1", "rack-1", "r1", "d1", provenance).code,
      OutcomeCode::Committed);
  FDR_CHECK_EQ(
      declare_domain(registry, fixture.authority(), row, "dc1", "row-1", "w1", "d2", provenance).code,
      OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(registry, fixture.authority(), rack_id, row_id,
                           DomainRelationType::ContainedBy, "r1", provenance).code,
              OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.relations_of(rack_id).size(), std::size_t{1});

  const Fingerprint before = Fingerprint::capture(registry);
  const Outcome refused = add_relation(registry, fixture.authority(), rack_id, row_id,
                                       DomainRelationType::CorrelatedWith, "r2", provenance);
  FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
  FDR_CHECK_MSG(refused.message.find("relation limit") != std::string::npos,
               "the refusal does not name the relation limit: " + describe(refused));
  FDR_CHECK_EQ(registry.relations_of(rack_id).size(), std::size_t{1});
  const std::string drift = before.drift(registry);
  FDR_CHECK_MSG(drift.empty(), "a refused relation changed state: " + drift);
}

FDR_TEST_CASE(limits, the_three_metadata_bounds_are_enforced_before_the_domain_exists) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_metadata_entries = 2;
  limits.max_metadata_value_bytes = 8;
  limits.max_metadata_bytes_per_record = 12;
  Fixture fixture = open(limits);
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const Provenance provenance = durable_provenance("inv");
  const DomainClassRef klass(DomainClass::Pdu);

  const auto create_with = [&registry, &fixture, &klass, &provenance](
                               std::string_view key, std::vector<MetadataEntry> entries,
                               std::string_view attempt_label) {
    CreateDomainRequest request;
    request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
    request.authority = fixture.authority();
    request.domain_class = klass;
    request.administrative_scope = "dc1";
    request.identity_key = std::string(key);
    request.name = std::string(key);
    request.provenance = provenance;
    request.metadata = std::move(entries);
    return registry.create_domain(request);
  };

  const Fingerprint before = Fingerprint::capture(registry);

  // One entry past the count bound.
  {
    const Outcome refused = create_with(
        "pdu-a", {metadata("a", "1"), metadata("b", "2"), metadata("c", "3")}, "m1");
    FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
    FDR_CHECK_MSG(refused.message.find("too many metadata entries") != std::string::npos,
                 "the count bound was not the reported reason: " + describe(refused));
  }
  // One byte past the per-value bound.
  {
    const Outcome refused =
        create_with("pdu-b", {metadata("a", text_of(9, 'v')), metadata("b", "2")}, "m2");
    FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
    FDR_CHECK_MSG(refused.message.find("value too long") != std::string::npos,
                 "the value bound was not the reported reason: " + describe(refused));
  }
  // Under both of those, but past the per-record budget: two entries of a
  // one-byte key and a seven-byte value cost sixteen bytes together.
  {
    const Outcome refused =
        create_with("pdu-c", {metadata("a", text_of(7, 'v')), metadata("b", text_of(7, 'v'))}, "m3");
    FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
    FDR_CHECK_MSG(refused.message.find("per-record budget") != std::string::npos,
                 "the record budget was not the reported reason: " + describe(refused));
  }
  // An empty key is malformed rather than oversized: the two are different
  // faults and must not be collapsed.
  {
    const Outcome refused = create_with("pdu-d", {metadata(std::string(), "v")}, "m4");
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
  }
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{0});
  const std::string drift = before.drift(registry);
  FDR_CHECK_MSG(drift.empty(), "a refused metadata set changed state: " + drift);

  // The control: the same shape inside every bound commits.
  {
    const Outcome committed =
        create_with("pdu-e", {metadata("a", text_of(7, 'v'))}, "m5");
    FDR_CHECK_EQ(committed.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(registry.domain_count(), std::size_t{1});
    const std::optional<failure_domain_registry::FailureDomain> record =
        registry.domain(domain_of("dc1", klass, "pdu-e"));
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->metadata.size(), std::size_t{1});
    FDR_CHECK_EQ(record->metadata[0].value, text_of(7, 'v'));
  }
}

FDR_TEST_CASE(limits, max_string_bytes_bounds_names_and_source_identities) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_string_bytes = 16;
  Fixture fixture = open(limits);
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::Generator);

  const Fingerprint before = Fingerprint::capture(registry);

  // A name one byte past the bound, checked before anything is created.
  {
    const Outcome refused = declare_domain(registry, fixture.authority(), klass, "dc1", "gen-1",
                                           text_of(17, 'n'), "s1", durable_provenance("inv"));
    FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
    FDR_CHECK_MSG(refused.message.find("name is too long") != std::string::npos,
                 "the name bound was not the reported reason: " + describe(refused));
  }
  // A source identity one byte past the same bound.
  {
    const Outcome refused = declare_domain(registry, fixture.authority(), klass, "dc1", "gen-2",
                                           "gen-2", "s2", durable_provenance(text_of(17, 'i')));
    FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
    FDR_CHECK_MSG(refused.message.find("source identity is too long") != std::string::npos,
                 "the source-identity bound was not the reported reason: " + describe(refused));
  }
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{0});
  const std::string drift = before.drift(registry);
  FDR_CHECK_MSG(drift.empty(), "a refused over-long string changed state: " + drift);

  // Exactly at the bound is inside it, for both the name and the identity.
  FDR_CHECK_EQ(declare_domain(registry, fixture.authority(), klass, "dc1", "gen-3", text_of(16, 'n'),
                             "s3", durable_provenance(text_of(16, 'i'))).code,
              OutcomeCode::Committed);
  const FailureDomainId id = domain_of("dc1", klass, "gen-3");
  const std::optional<failure_domain_registry::FailureDomain> record = registry.domain(id);
  FDR_CHECK(record.has_value());
  FDR_CHECK_EQ(record->name.size(), std::size_t{16});
  FDR_CHECK_EQ(record->provenance.source_identity.size(), std::size_t{16});

  // update_domain applies the same bound to a replacement name.
  {
    UpdateDomainRequest request;
    request.attempt = MutationAttempt{attempt_from("s4"), RequestDigest{}};
    request.authority = fixture.authority();
    request.domain = id;
    request.name = text_of(17, 'n');
    const Outcome refused = registry.update_domain(request);
    FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
    FDR_CHECK_MSG(refused.message.find("name is too long") != std::string::npos,
                 "the update path does not apply the name bound: " + describe(refused));
    FDR_CHECK_EQ(registry.domain(id)->generation, FailureDomainGeneration(1));
  }
}

FDR_TEST_CASE(limits, max_evidence_per_membership_bounds_corroboration) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_evidence_per_membership = 1;
  Fixture fixture = open(limits);
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::CoolingZone);
  const FailureDomainId domain = domain_of("dc1", klass, "cooling-1");
  FDR_CHECK_EQ(declare_domain(registry, fixture.authority(), klass, "dc1", "cooling-1", "c1", "d1",
                             durable_provenance("inv")).code,
              OutcomeCode::Committed);

  const EntityRef member = entity_ref(EntityClass::Host, "host-1", 3);
  const Provenance first = durable_provenance("inv");
  FDR_CHECK_EQ(attach_member(registry, fixture.authority(), domain, member, "a1", first).code,
              OutcomeCode::Committed);
  const failure_domain_registry::MembershipId membership_id =
      failure_domain_registry::membership_id_for(
          failure_domain_registry::MembershipKey{domain, member.id(), member.generation(),
                                                 MembershipKind::Direct});
  const std::optional<Membership> created = registry.membership(membership_id);
  FDR_CHECK(created.has_value());
  FDR_CHECK_EQ(created->evidence.size(), std::size_t{1});

  // A second corroboration from the same source is a different role, so the
  // request is not idempotent and has to add evidence - which the bound forbids.
  const Fingerprint before = Fingerprint::capture(registry);
  {
    const Outcome refused = attach_member(registry, fixture.authority(), domain, member, "a2", first,
                                          MembershipRole::Primary);
    FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
    FDR_CHECK_MSG(refused.message.find("maximum evidence") != std::string::npos,
                 "the evidence bound was not the reported reason: " + describe(refused));
  }
  // replace_membership walks the same bound on the same record.
  {
    ReplaceMembershipRequest request;
    request.attempt = MutationAttempt{attempt_from("a3"), RequestDigest{}};
    request.authority = fixture.authority();
    request.membership = membership_id;
    request.role = MembershipRole::Backup;
    request.provenance = first;
    const Outcome refused = registry.replace_membership(request);
    FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
    FDR_CHECK_MSG(refused.message.find("maximum evidence") != std::string::npos,
                 "the replace path does not apply the evidence bound: " + describe(refused));
  }
  const std::optional<Membership> after = registry.membership(membership_id);
  FDR_CHECK(after.has_value());
  FDR_CHECK_EQ(after->evidence.size(), std::size_t{1});
  FDR_CHECK_EQ(after->generation, created->generation);
  FDR_CHECK_EQ(after->role, MembershipRole::SharedRisk);
  const std::string drift = before.drift(registry);
  FDR_CHECK_MSG(drift.empty(), "a refused corroboration changed state: " + drift);
}

FDR_TEST_CASE(limits, max_members_per_batch_refuses_an_oversized_publication_whole) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_members_per_batch = 2;
  Fixture fixture = open(limits);
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::Conduit);
  const FailureDomainId domain = domain_of("dc1", klass, "conduit-1");
  FDR_CHECK_EQ(declare_domain(registry, fixture.authority(), klass, "dc1", "conduit-1", "c1", "d1",
                             durable_provenance("inv")).code,
              OutcomeCode::Committed);

  const auto publication = [&fixture, &domain](std::size_t count, std::string_view attempt_label) {
    MembershipBatchRequest request;
    request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
    request.authority = fixture.authority();
    request.mode = PublicationMode::Incremental;
    request.administrative_scope = "dc1";
    for (std::size_t index = 0; index < count; ++index) {
      MembershipBatchEntry entry;
      entry.domain = domain;
      entry.member = entity_ref(EntityClass::Switch, "batch-member-" + std::to_string(index), 1);
      entry.kind = MembershipKind::Direct;
      entry.role = MembershipRole::SharedRisk;
      entry.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
      entry.provenance = durable_provenance("inv");
      request.entries.push_back(std::move(entry));
    }
    return request;
  };

  const Fingerprint before = Fingerprint::capture(registry);
  {
    const Outcome refused = registry.publish_memberships(publication(3, "p1"));
    FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
    FDR_CHECK_MSG(names_bound(refused, "entries", "3"),
                 "the refusal does not report the offered entry count: " + describe(refused));
    FDR_CHECK_MSG(refused.steps.size() == 1 &&
                     refused.steps[0].detail.find("limit is 2") != std::string::npos,
                 "the refusal does not report the bound in force: " + describe(refused));
  }
  // A publication far past the bound costs the same answer, and commits
  // nothing at all: the count is read, compared and reported.
  {
    const Outcome refused = registry.publish_memberships(publication(50000, "p2"));
    FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
    FDR_CHECK_MSG(names_bound(refused, "entries", "50000"),
                 "an absurd publication was not reported with its size: " + describe(refused));
  }
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{0});
  const std::string drift = before.drift(registry);
  FDR_CHECK_MSG(drift.empty(), "a refused publication changed state: " + drift);

  // Exactly at the bound commits, and commits both entries.
  const Outcome committed = registry.publish_memberships(publication(2, "p3"));
  FDR_CHECK_EQ(committed.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{2});
}

FDR_TEST_CASE(limits, max_query_set_cardinality_truncates_and_says_so) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_query_set_cardinality = 2;
  Fixture fixture = open(limits);
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::Row);
  const FailureDomainId domain = domain_of("dc1", klass, "row-1");
  FDR_CHECK_EQ(declare_domain(registry, fixture.authority(), klass, "dc1", "row-1", "w1", "d1",
                             durable_provenance("inv")).code,
              OutcomeCode::Committed);
  const EntityRef first = entity_ref(EntityClass::Switch, "set-1", 1);
  const EntityRef second = entity_ref(EntityClass::Switch, "set-2", 1);
  const EntityRef third = entity_ref(EntityClass::Switch, "set-3", 1);
  FDR_CHECK_EQ(attach_member(registry, fixture.authority(), domain, first, "a1",
                            durable_provenance("inv")).code,
              OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_member(registry, fixture.authority(), domain, second, "a2",
                            durable_provenance("inv")).code,
              OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_member(registry, fixture.authority(), domain, third, "a3",
                            durable_provenance("inv")).code,
              OutcomeCode::Committed);

  const std::vector<EntityId> three{first.id(), second.id(), third.id()};
  const failure_domain_registry::OverlapResult overlap = registry.overlap(three);
  FDR_CHECK_MSG(overlap.truncated, "a query set past the cardinality bound was not marked truncated");
  FDR_CHECK_EQ(overlap.state, failure_domain_registry::IndependenceState::SharedDomain);
  FDR_CHECK_EQ(overlap.shared.size(), std::size_t{1});
  FDR_CHECK_EQ(overlap.shared[0].members.size(), std::size_t{2});
  bool saw_limit_step = false;
  for (const failure_domain_registry::ExplanationStep& step : overlap.steps) {
    if (step.stage == "limit" && step.field == "entities" && step.value == "3") {
      saw_limit_step = true;
    }
  }
  FDR_CHECK_MSG(saw_limit_step, "the truncated answer does not report the size it was given");

  const failure_domain_registry::IndependenceResult independence =
      registry.independence(three, {klass});
  FDR_CHECK_MSG(independence.truncated, "independence did not report the truncation");
  FDR_CHECK_EQ(independence.state, failure_domain_registry::IndependenceState::SharedDomain);

  // Inside the bound nothing is truncated, so the flag is a real observation
  // rather than a constant.
  const std::vector<EntityId> two{first.id(), second.id()};
  FDR_CHECK(!registry.overlap(two).truncated);
  FDR_CHECK(!registry.independence(two, {klass}).truncated);

  // A topology notification is a mutation, so an oversized entity list is
  // refused outright instead of being truncated.
  {
    TopologyChangeRequest request;
    request.attempt = MutationAttempt{attempt_from("t1"), RequestDigest{}};
    request.authority = fixture.authority();
    request.topology_generation = failure_domain_registry::TopologyGeneration(2);
    request.affected_entities = three;
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = registry.notify_topology_change(request);
    FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
    FDR_CHECK_MSG(refused.message.find("too many affected entities") != std::string::npos,
                 "the topology bound was not the reported reason: " + describe(refused));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a refused topology notification changed state: " + drift);
  }
}

FDR_TEST_CASE(limits, max_publishers_refuses_a_further_grant) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_publishers = 1;
  Fixture fixture = open(limits);
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  FDR_CHECK_EQ(registry.publishers().size(), std::size_t{1});

  PublisherRegistration second;
  second.publisher = publisher_from("limits-second");
  second.name = "second";
  second.scope = AuthorityScope::unrestricted();

  const Fingerprint before = Fingerprint::capture(registry);
  const Outcome refused = registry.grant_publisher(second, fixture.authority());
  FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
  FDR_CHECK_MSG(refused.message.find("publisher limit") != std::string::npos,
               "the publisher bound was not the reported reason: " + describe(refused));
  FDR_CHECK_EQ(registry.publishers().size(), std::size_t{1});
  FDR_CHECK(!registry.publisher(second.publisher).has_value());
  const std::string drift = before.drift(registry);
  FDR_CHECK_MSG(drift.empty(), "a refused grant changed state: " + drift);
}

FDR_TEST_CASE(limits, max_coverage_declarations_refuses_a_further_declaration) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_coverage_declarations = 1;
  Fixture fixture = open(limits);
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef rack(DomainClass::Rack);
  const DomainClassRef pdu(DomainClass::Pdu);
  const Provenance provenance = durable_provenance("inv");

  FDR_CHECK_EQ(declare(registry, fixture.authority(), "dc1", rack,
                      failure_domain_registry::CoverageState::Complete, "c1", provenance).code,
              OutcomeCode::Committed);

  const Fingerprint before = Fingerprint::capture(registry);
  const Outcome refused = declare(registry, fixture.authority(), "dc1", pdu,
                                  failure_domain_registry::CoverageState::Complete, "c2", provenance);
  FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
  FDR_CHECK_MSG(refused.message.find("coverage declaration limit") != std::string::npos,
               "the coverage bound was not the reported reason: " + describe(refused));
  const std::string drift = before.drift(registry);
  FDR_CHECK_MSG(drift.empty(), "a refused coverage declaration changed state: " + drift);

  // The declaration that did commit is the one that is visible, and the one
  // that did not is absent: the bound is on records, not on attempts.
  const failure_domain_registry::CoverageReport report = registry.coverage("dc1", {rack, pdu});
  FDR_CHECK_EQ(report.entries.size(), std::size_t{2});
  FDR_CHECK(report.entries[0].declared);
  FDR_CHECK(!report.entries[1].declared);
  FDR_CHECK_EQ(report.entries[0].domain_class, rack);
  FDR_CHECK_EQ(report.entries[1].domain_class, pdu);
  // The declared class reports exactly what was declared, with the evidence and
  // truth behind it; the class nothing was declared for reports the default
  // "nothing is known here" state, which is what stops an absent record from
  // being read as proven independence.
  FDR_CHECK_EQ(report.entries[0].state, failure_domain_registry::CoverageState::Complete);
  FDR_CHECK_EQ(report.entries[1].state, failure_domain_registry::CoverageState::UnknownCoverage);
  FDR_CHECK_EQ(report.entries[1].evidence, EvidenceClass::Unknown);
  FDR_CHECK_EQ(report.entries[0].evidence, EvidenceClass::DirectAuthoritativeInfrastructure);
  FDR_CHECK_EQ(report.entries[0].truth, TruthClass::Real);
  FDR_CHECK(!report.complete_for_all);
  FDR_CHECK(!report.has_partial);
  FDR_CHECK(report.has_unknown);
}

FDR_TEST_CASE(limits, max_history_entries_per_record_keeps_the_newest_entries) {
  RegistryLimits bounded_limits = RegistryLimits::defaults();
  bounded_limits.max_history_entries_per_record = 3;
  Fixture bounded = open(bounded_limits);
  FDR_CHECK_MSG(bounded.problem().empty(), "the fixture did not open: " + bounded.problem());
  Fixture reference = open(RegistryLimits::defaults());
  FDR_CHECK_MSG(reference.problem().empty(), "the reference fixture did not open: " + reference.problem());

  const DomainClassRef klass(DomainClass::Pod);
  const FailureDomainId bounded_id = domain_of("dc1", klass, "pod-1");
  const FailureDomainId reference_id = domain_of("dc1", klass, "pod-1");
  FDR_CHECK_EQ(declare_domain(*bounded.registry, bounded.authority(), klass, "dc1", "pod-1", "p1",
                             "d1", durable_provenance("inv")).code,
              OutcomeCode::Committed);
  FDR_CHECK_EQ(declare_domain(*reference.registry, reference.authority(), klass, "dc1", "pod-1", "p1",
                             "d1", durable_provenance("inv")).code,
              OutcomeCode::Committed);
  FDR_CHECK(bounded.registry->domain(bounded_id)->history.empty());

  // Six legal transitions, alternating between the two states a domain may
  // legitimately move between.
  for (int step = 0; step < 6; ++step) {
    const DomainLifecycle target = step % 2 == 0 ? DomainLifecycle::RevalidationRequired
                                                 : DomainLifecycle::Current;
    const std::string label = "t" + std::to_string(step);
    FDR_CHECK_EQ(update_transition(*bounded.registry, bounded.authority(), bounded_id, target, label).code,
                OutcomeCode::Committed);
    FDR_CHECK_EQ(
        update_transition(*reference.registry, reference.authority(), reference_id, target, label).code,
        OutcomeCode::Committed);
  }

  const std::optional<failure_domain_registry::FailureDomain> limited =
      bounded.registry->domain(bounded_id);
  const std::optional<failure_domain_registry::FailureDomain> full =
      reference.registry->domain(reference_id);
  FDR_CHECK(limited.has_value());
  FDR_CHECK(full.has_value());
  FDR_CHECK_EQ(full->history.size(), std::size_t{6});
  FDR_CHECK_EQ(limited->history.size(), std::size_t{3});
  FDR_CHECK_EQ(limited->generation, full->generation);
  FDR_CHECK_EQ(limited->lifecycle, DomainLifecycle::Current);
  FDR_CHECK_EQ(full->lifecycle, limited->lifecycle);

  // Every retained step describes the state the change produced: the last of
  // the six transitions moved the record to CURRENT, so that is what the last
  // step records, and the step before it records the demotion that preceded it.
  FDR_CHECK_EQ(limited->history[0].lifecycle, DomainLifecycle::Current);
  FDR_CHECK_EQ(limited->history[1].lifecycle, DomainLifecycle::RevalidationRequired);
  FDR_CHECK_EQ(limited->history[2].lifecycle, DomainLifecycle::Current);

  // The retained window is the last three entries of the unbounded history:
  // eviction drops the oldest, never the newest.
  for (std::size_t index = 0; index < limited->history.size(); ++index) {
    const failure_domain_registry::DomainHistoryEntry& kept = limited->history[index];
    const failure_domain_registry::DomainHistoryEntry& expected =
        full->history[full->history.size() - limited->history.size() + index];
    FDR_CHECK_EQ(kept.generation, expected.generation);
    FDR_CHECK_EQ(kept.previous_generation, expected.previous_generation);
    FDR_CHECK_EQ(kept.lifecycle, expected.lifecycle);
    FDR_CHECK_EQ(kept.cause, expected.cause);
    FDR_CHECK_EQ(kept.evidence, expected.evidence);
    FDR_CHECK_EQ(kept.epoch, expected.epoch);
  }

  // The domain was created at generation 1 and each transition advanced it by
  // one, so the three retained steps describe generations 5, 6 and 7 and the
  // previous_generation of each is the generation it replaced.
  FDR_CHECK_EQ(limited->history.front().generation, FailureDomainGeneration(5));
  FDR_CHECK_EQ(limited->history.front().previous_generation, FailureDomainGeneration(4));
  FDR_CHECK_EQ(limited->history.back().generation, FailureDomainGeneration(7));
  FDR_CHECK_EQ(limited->history.back().previous_generation, FailureDomainGeneration(6));
  FDR_CHECK(limited->history.front().generation < limited->history.back().generation);

  // "at" is the registry generation the change happened in, so the three steps
  // are ordered by the registry generation they were recorded at.
  FDR_CHECK(limited->history.front().at < limited->history.back().at);
}

FDR_TEST_CASE(limits, max_fenced_boots_per_publisher_evicts_the_oldest_fence) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_fenced_boots_per_publisher = 2;
  Fixture fixture = open(limits);
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;

  const WorkerBootId boots[] = {fixture.worker_boot, boot_from("limits-b2"), boot_from("limits-b3"),
                                boot_from("limits-b4")};
  FDR_CHECK_EQ(registry.fences().size(), std::size_t{0});
  for (std::size_t index = 1; index < 4; ++index) {
    FDR_CHECK_EQ(registry
                    .attach_worker(fixture.publisher, boots[index], fixture.epoch,
                                   "reincarnation-" + std::to_string(index),
                                   EvidenceClass::DirectAuthoritativeInfrastructure)
                    .code,
                OutcomeCode::Committed);
  }

  const std::vector<failure_domain_registry::FenceRecord> fences = registry.fences();
  FDR_CHECK_EQ(fences.size(), std::size_t{2});
  bool has_first = false;
  bool has_second = false;
  bool has_third = false;
  for (const failure_domain_registry::FenceRecord& fence : fences) {
    FDR_CHECK_EQ(fence.publisher, fixture.publisher);
    FDR_CHECK_EQ(fence.reason, failure_domain_registry::FenceReason::Reincarnated);
    has_first = has_first || fence.worker_boot == boots[0];
    has_second = has_second || fence.worker_boot == boots[1];
    has_third = has_third || fence.worker_boot == boots[2];
  }
  FDR_CHECK_MSG(!has_first, "the oldest fence survived a bound of two");
  FDR_CHECK(has_second);
  FDR_CHECK(has_third);
  // The incarnation that is live is not fenced, so the retained pair really is
  // the two most recent.
  FDR_CHECK(registry.is_worker_live(fixture.publisher, boots[3]));
  FDR_CHECK_EQ(registry.live_sessions().size(), std::size_t{1});
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the fence eviction left the state inconsistent: " + why);
}

FDR_TEST_CASE(limits, max_idempotency_entries_per_publisher_evicts_the_smallest_attempt_id) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_idempotency_entries_per_publisher = 2;
  Fixture fixture = open(limits);
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::Link);
  const Provenance provenance = durable_provenance("inv");

  // Three attempt ids whose order is fixed by their last byte, so "the smallest
  // was evicted" is a statement about the ids and not about hash order.
  const auto attempt_with_last_byte = [](std::uint8_t last) {
    IdBytes bytes{};
    bytes[0] = 0xC1u;
    bytes[15] = last;
    return MutationAttemptId::from_bytes(bytes);
  };
  const MutationAttemptId smallest = attempt_with_last_byte(0x01u);
  const MutationAttemptId middle = attempt_with_last_byte(0x02u);
  const MutationAttemptId largest = attempt_with_last_byte(0x03u);
  FDR_CHECK(smallest < middle);
  FDR_CHECK(middle < largest);

  const auto create = [&registry, &fixture, &klass, &provenance](const MutationAttemptId& attempt,
                                                                 std::string_view key) {
    CreateDomainRequest request;
    request.attempt = MutationAttempt{attempt, RequestDigest{}};
    request.authority = fixture.authority();
    request.domain_class = klass;
    request.administrative_scope = "dc1";
    request.identity_key = std::string(key);
    request.name = std::string(key);
    request.provenance = provenance;
    return registry.create_domain(request);
  };

  FDR_CHECK_EQ(create(smallest, "link-1").code, OutcomeCode::Committed);
  FDR_CHECK_EQ(create(middle, "link-2").code, OutcomeCode::Committed);
  // The third insert pushes the table to three entries; the smallest id goes.
  FDR_CHECK_EQ(create(largest, "link-3").code, OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{3});

  // The evicted attempt is genuinely forgotten: reusing its id with different
  // content is a new mutation, not a conflict.
  FDR_CHECK_EQ(create(smallest, "link-4").code, OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{4});
  // The two retained attempts are still recognized: a different content under
  // the same id is a conflicting replay, and the identical content is an
  // idempotent one.
  FDR_CHECK_EQ(create(middle, "link-5").code, OutcomeCode::ConflictingReplay);
  const Outcome replay = create(largest, "link-3");
  FDR_CHECK_EQ(replay.code, OutcomeCode::Idempotent);
  FDR_CHECK_MSG(replay.message.find("exact replay") != std::string::npos,
               "an exact replay was not reported as one: " + describe(replay));
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{4});

  // Determinism: the same sequence against a second registry with the same
  // limits evicts the same attempt, so which replays are recognized is a
  // property of the attempt ids and their order, never of hash iteration order.
  {
    Fixture twin = open(limits);
    FDR_CHECK_MSG(twin.problem().empty(), "the twin fixture did not open: " + twin.problem());
    Registry& other = *twin.registry;
    const auto create_other = [&other, &twin, &klass, &provenance](const MutationAttemptId& attempt,
                                                                   std::string_view key) {
      CreateDomainRequest request;
      request.attempt = MutationAttempt{attempt, RequestDigest{}};
      request.authority = twin.authority();
      request.domain_class = klass;
      request.administrative_scope = "dc1";
      request.identity_key = std::string(key);
      request.name = std::string(key);
      request.provenance = provenance;
      return other.create_domain(request);
    };
    FDR_CHECK_EQ(create_other(smallest, "link-1").code, OutcomeCode::Committed);
    FDR_CHECK_EQ(create_other(middle, "link-2").code, OutcomeCode::Committed);
    FDR_CHECK_EQ(create_other(largest, "link-3").code, OutcomeCode::Committed);
    FDR_CHECK_EQ(create_other(smallest, "link-4").code, OutcomeCode::Committed);
    FDR_CHECK_EQ(create_other(middle, "link-5").code, OutcomeCode::ConflictingReplay);
    FDR_CHECK_EQ(create_other(largest, "link-3").code, OutcomeCode::Idempotent);
    FDR_CHECK_EQ(other.domain_count(), std::size_t{4});
  }

  // The table bound counts entries, not publishers: each mutation above counted
  // against the same publisher and the registry stayed consistent.
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "idempotency eviction left the state inconsistent: " + why);
}

FDR_TEST_CASE(limits, max_ancestor_walk_bounds_the_cycle_walk_and_reports_it) {
  // A chain of four containment domains. Building it never walks more than one
  // node, because every new edge points at a domain with no outgoing edge yet.
  const auto build_chain = [](Registry& registry, const AuthorityContext& authority,
                              std::size_t length) {
    std::vector<FailureDomainId> chain;
    const DomainClassRef klass(DomainClass::Rack);
    for (std::size_t index = 0; index < length; ++index) {
      const std::string key = "chain-" + std::to_string(index);
      const Outcome created =
          declare_domain(registry, authority, klass, "dc-chain", key, key,
                         "chain-d" + std::to_string(index), durable_provenance("inv"));
      if (!created.committed()) {
        return std::vector<FailureDomainId>{};
      }
      chain.push_back(domain_of("dc-chain", klass, key));
    }
    for (std::size_t index = 0; index + 1 < chain.size(); ++index) {
      const Outcome linked = add_relation(registry, authority, chain[index], chain[index + 1],
                                          DomainRelationType::ContainedBy,
                                          "chain-r" + std::to_string(index),
                                          durable_provenance("inv"));
      if (!linked.committed()) {
        return std::vector<FailureDomainId>{};
      }
    }
    return chain;
  };

  // A hierarchy exactly as deep as the configured ceiling is fully walkable: the
  // depth ceiling admits three domains in a chain, the closure of that chain is
  // evaluated rather than refused, and the read walks return every ancestor and
  // every descendant because the walk bound is not below the ceiling.
  {
    RegistryLimits limits = RegistryLimits::defaults();
    limits.max_hierarchy_depth = 2;
    limits.max_ancestor_walk = 2;
    FDR_CHECK_MSG(limits.validate().ok, limits.validate().message);
    Fixture fixture = open(limits);
    FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
    const std::vector<FailureDomainId> chain = build_chain(*fixture.registry, fixture.authority(), 3);
    FDR_CHECK_EQ(chain.size(), std::size_t{3});
    // A CONTAINED_BY edge points from the contained domain to its container, so
    // the innermost domain has the ancestors and the outermost the descendants.
    // The public results come back in identity order.
    FDR_CHECK_EQ(fixture.registry->ancestors(chain[0]), sorted_ids({chain[1], chain[2]}));
    FDR_CHECK_EQ(fixture.registry->descendants(chain[2]), sorted_ids({chain[1], chain[0]}));

    // Closing the chain would be a real cycle, and it would also be deeper than
    // the ceiling. The depth rule is evaluated first, so the answer is the
    // ceiling rather than the probe - either way the edge is refused and leaves
    // no trace. (A cycle over a chain that fits inside the ceiling is rejected as
    // a cycle by the adversarial suite.)
    const Fingerprint before = Fingerprint::capture(*fixture.registry);
    const Outcome refused = add_relation(*fixture.registry, fixture.authority(), chain[2], chain[0],
                                         DomainRelationType::ContainedBy, "close",
                                         durable_provenance("inv"));
    FDR_CHECK_EQ(refused.code, OutcomeCode::InvalidHierarchy);
    FDR_CHECK_MSG(refused.message.find("max_hierarchy_depth") != std::string::npos,
                  "the depth ceiling was not the reported reason: " + describe(refused));
    const std::string drift = before.drift(*fixture.registry);
    FDR_CHECK_MSG(drift.empty(), "a refused closing edge changed state: " + drift);

    // One containment level deeper than the configured ceiling is refused by
    // the ceiling itself, before any probe runs.
    const DomainClassRef klass(DomainClass::Rack);
    FDR_CHECK_EQ(declare_domain(*fixture.registry, fixture.authority(), klass, "dc-chain", "chain-3",
                                "chain-3", "chain-d3", durable_provenance("inv"))
                     .code,
                 OutcomeCode::Committed);
    const FailureDomainId beyond = domain_of("dc-chain", klass, "chain-3");
    const Fingerprint before_deep = Fingerprint::capture(*fixture.registry);
    const Outcome refused_deep =
        add_relation(*fixture.registry, fixture.authority(), chain[2], beyond,
                     DomainRelationType::ContainedBy, "deep", durable_provenance("inv"));
    FDR_CHECK_EQ(refused_deep.code, OutcomeCode::InvalidHierarchy);
    FDR_CHECK_MSG(refused_deep.message.find("max_hierarchy_depth") != std::string::npos,
                 "the depth ceiling was not the reported reason: " + describe(refused_deep));
    FDR_CHECK_MSG(names_bound(refused_deep, "max_hierarchy_depth", "2"),
                 "the refusal does not report max_hierarchy_depth = 2: " + describe(refused_deep));
    const std::string deep_drift = before_deep.drift(*fixture.registry);
    FDR_CHECK_MSG(deep_drift.empty(), "a refused containment edge changed state: " + deep_drift);
  }

  // The probe's node budget is still a real bound. The acyclicity probe counts
  // the nodes it visits rather than the depth it reaches, so a domain with five
  // containers exhausts a bound of two even though every edge is one level
  // deep, and the registry says so instead of answering "no cycle".
  {
    RegistryLimits limits = RegistryLimits::defaults();
    limits.max_hierarchy_depth = 2;
    limits.max_ancestor_walk = 2;
    FDR_CHECK_MSG(limits.validate().ok, limits.validate().message);
    Fixture fixture = open(limits);
    FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
    Registry& registry = *fixture.registry;
    const DomainClassRef klass(DomainClass::Rack);
    const FailureDomainId child = domain_of("dc-bushy", klass, "bushy-child");
    FDR_CHECK_EQ(declare_domain(registry, fixture.authority(), klass, "dc-bushy", "bushy-child",
                                "bushy-child", "bushy-d0", durable_provenance("inv"))
                     .code,
                 OutcomeCode::Committed);
    const std::size_t kContainers = 5;
    for (std::size_t index = 0; index < kContainers; ++index) {
      const std::string key = "bushy-parent-" + std::to_string(index);
      FDR_CHECK_EQ(declare_domain(registry, fixture.authority(), klass, "dc-bushy", key, key,
                                  "bushy-d" + std::to_string(index + 1), durable_provenance("inv"))
                       .code,
                   OutcomeCode::Committed);
      // Every edge is one level deep, so the depth ceiling admits all five.
      FDR_CHECK_EQ(add_relation(registry, fixture.authority(), child,
                                domain_of("dc-bushy", klass, key), DomainRelationType::ContainedBy,
                                "bushy-r" + std::to_string(index), durable_provenance("inv"))
                       .code,
                   OutcomeCode::Committed);
    }
    // ancestors() finishes the breadth-first level it is on, so it reports all
    // five containers even though the bound is two: the bound is a probe budget
    // and not a promise about a bushy graph.
    FDR_CHECK_EQ(registry.ancestors(child).size(), kContainers);

    const FailureDomainId fresh = domain_of("dc-bushy", klass, "bushy-fresh");
    FDR_CHECK_EQ(declare_domain(registry, fixture.authority(), klass, "dc-bushy", "bushy-fresh",
                                "bushy-fresh", "bushy-d6", durable_provenance("inv"))
                     .code,
                 OutcomeCode::Committed);
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome bounded = add_relation(registry, fixture.authority(), fresh, child,
                                         DomainRelationType::ContainedBy, "bushy-close",
                                         durable_provenance("inv"));
    FDR_CHECK_EQ(bounded.code, OutcomeCode::InvalidHierarchy);
    FDR_CHECK_MSG(bounded.message.find("max_ancestor_walk") != std::string::npos,
                 "a bounded hierarchy walk was not reported as bounded: " + describe(bounded));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a bounded hierarchy walk changed state: " + drift);
    FDR_CHECK(registry.ancestors(fresh).empty());
    FDR_CHECK_EQ(registry.relations_of(child).size(), kContainers);

    std::string why;
    FDR_CHECK_MSG(registry.validate_state(&why), "the bushy hierarchy broke the state: " + why);
  }
}

FDR_TEST_CASE(limits, the_bounds_that_used_to_be_unenforced_are_enforced) {
  // max_hierarchy_depth, max_record_bytes and max_history_query are consulted by
  // the paths they name, so a configuration below the defaults actually bites
  // instead of being accepted and then ignored.
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_hierarchy_depth = 1;
  // A plain domain record encodes to a few hundred bytes, so a one-kilobyte
  // budget is below the default and still admits a normal record.
  limits.max_record_bytes = 1024;
  limits.max_history_query = 1;
  limits.max_metadata_value_bytes = 4096;
  limits.max_metadata_bytes_per_record = 4096;
  FDR_CHECK(limits.validate().ok);
  Fixture fixture = open(limits);
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::Rack);
  const Provenance provenance = durable_provenance("inv");

  // A containment chain exactly as deep as the configured ceiling commits: one
  // edge between two domains.
  FailureDomainId previous;
  for (std::size_t index = 0; index < 2; ++index) {
    const std::string key = "deep-" + std::to_string(index);
    FDR_CHECK_EQ(declare_domain(registry, fixture.authority(), klass, "dc-deep", key, key,
                               "deep-d" + std::to_string(index), provenance).code,
                OutcomeCode::Committed);
    const FailureDomainId current = domain_of("dc-deep", klass, key);
    if (index > 0) {
      FDR_CHECK_EQ(add_relation(registry, fixture.authority(), previous, current,
                               DomainRelationType::ContainedBy,
                               "deep-r" + std::to_string(index), provenance).code,
                  OutcomeCode::Committed);
    }
    previous = current;
  }
  const FailureDomainId outermost = previous;
  const FailureDomainId innermost = domain_of("dc-deep", klass, "deep-0");
  FDR_CHECK_EQ(registry.descendants(outermost).size(), std::size_t{1});
  FDR_CHECK_EQ(registry.ancestors(innermost).size(), std::size_t{1});

  // One level deeper is refused by the ceiling itself, and the refusal leaves
  // nothing behind.
  {
    FDR_CHECK_EQ(declare_domain(registry, fixture.authority(), klass, "dc-deep", "deep-2", "deep-2",
                               "deep-d2", provenance).code,
                OutcomeCode::Committed);
    const FailureDomainId beyond = domain_of("dc-deep", klass, "deep-2");
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = add_relation(registry, fixture.authority(), outermost, beyond,
                                        DomainRelationType::ContainedBy, "deep-r2", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::InvalidHierarchy);
    FDR_CHECK_MSG(refused.message.find("max_hierarchy_depth") != std::string::npos,
                 "the depth ceiling was not the reported reason: " + describe(refused));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a refused depth-ceiling edge changed state: " + drift);
    FDR_CHECK(registry.ancestors(beyond).empty());
  }

  // A record whose real persisted encoding exceeds max_record_bytes is refused
  // before it exists, and the refusal names the measured size.
  {
    const Fingerprint before = Fingerprint::capture(registry);
    CreateDomainRequest request;
    request.attempt = MutationAttempt{attempt_from("big"), RequestDigest{}};
    request.authority = fixture.authority();
    request.domain_class = klass;
    request.administrative_scope = "dc-deep";
    request.identity_key = "big-record";
    request.name = "big-record";
    request.provenance = provenance;
    request.metadata = {metadata("blob", text_of(1000, 'v'))};
    const Outcome refused = registry.create_domain(request);
    FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
    FDR_CHECK_MSG(refused.message.find("max_record_bytes") != std::string::npos,
                 "the record-size bound was not the reported reason: " + describe(refused));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a refused oversized record changed state: " + drift);
    FDR_CHECK_EQ(registry.domain_count(), std::size_t{3});
  }

  // A record inside the budget still commits: the bound is a ceiling, not a
  // blanket refusal.
  {
    CreateDomainRequest request;
    request.attempt = MutationAttempt{attempt_from("fits"), RequestDigest{}};
    request.authority = fixture.authority();
    request.domain_class = klass;
    request.administrative_scope = "dc-deep";
    request.identity_key = "small-record";
    request.name = "small-record";
    request.provenance = provenance;
    request.metadata = {metadata("blob", text_of(32, 'v'))};
    FDR_CHECK_EQ(registry.create_domain(request).code, OutcomeCode::Committed);
  }

  // History rendering is bounded by max_history_query: the newest entries are
  // rendered and the rest are reported as truncated, never dropped silently.
  {
    FDR_CHECK_EQ(declare_domain(registry, fixture.authority(), klass, "dc-deep", "history-0",
                               "history-0", "history-d0", provenance).code,
                OutcomeCode::Committed);
    const FailureDomainId history_target = domain_of("dc-deep", klass, "history-0");
    FDR_CHECK_EQ(update_transition(registry, fixture.authority(), history_target,
                                   DomainLifecycle::RevalidationRequired, "hist-t1").code,
                OutcomeCode::Committed);
    FDR_CHECK_EQ(update_transition(registry, fixture.authority(), history_target,
                                   DomainLifecycle::Current, "hist-t2").code,
                OutcomeCode::Committed);
    const failure_domain_registry::Explanation explanation = registry.explain_domain(history_target);
    std::size_t rendered = 0;
    bool truncated = false;
    for (const failure_domain_registry::ExplanationStep& step : explanation.steps) {
      if (step.stage != "history") {
        continue;
      }
      if (step.field == "truncated") {
        truncated = true;
        continue;
      }
      ++rendered;
    }
    FDR_CHECK_EQ(rendered, limits.max_history_query);
    FDR_CHECK_MSG(truncated, "a bounded history read was not reported as truncated");
  }

  // Snapshots are not retained at all, so the retention bound has nothing to
  // bound: three snapshots in a row all succeed with distinct sequences.
  {
    const failure_domain_registry::Snapshot first = registry.snapshot("dc-deep");
    const failure_domain_registry::Snapshot second = registry.snapshot("dc-deep");
    const failure_domain_registry::Snapshot third = registry.snapshot("dc-deep");
    FDR_CHECK_EQ(first.sequence, failure_domain_registry::SnapshotSequence(1));
    FDR_CHECK_EQ(second.sequence, failure_domain_registry::SnapshotSequence(2));
    FDR_CHECK_EQ(third.sequence, failure_domain_registry::SnapshotSequence(3));
    FDR_CHECK(registry.snapshot_is_current(third));
  }

  // History reads are bounded by the caller's own max_records, not by
  // max_history_query: asking for three outcomes after more than three exists
  // returns three.
  {
    const std::vector<Outcome> recent = registry.recent_outcomes(3);
    FDR_CHECK_EQ(recent.size(), std::size_t{3});
    FDR_CHECK_EQ(registry.recent_outcomes(1).size(), std::size_t{1});
  }

  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the enforced bounds broke the state: " + why);
}

// ---------------------------------------------------------------------------
// Checked arithmetic on a persisted image
// ---------------------------------------------------------------------------

FDR_TEST_CASE(limits, an_absurd_persisted_count_or_length_is_refused_without_allocating) {
  static_assert(failure_domain_registry::kStateHeaderBytes == 88,
                "the persistence container header is eighty-eight bytes");
  static_assert(failure_domain_registry::kStateTrailerBytes == 6,
                "the persistence container trailer is six bytes");

  const std::filesystem::path control_path = scratch_path("control");
  const std::filesystem::path absurd_count_path = scratch_path("count");
  const std::filesystem::path overflowing_count_path = scratch_path("overflow");
  const std::filesystem::path absurd_membership_path = scratch_path("membership");
  const std::filesystem::path absurd_length_path = scratch_path("length");
  const std::filesystem::path truncated_path = scratch_path("truncated");
  // The control proves the crafted container is exactly the real format: an
  // empty payload with all seven counts zero loads.
  {
    const std::string payload = payload_with_counts({0, 0, 0, 0, 0, 0, 0});
    write_image(control_path, container_of(payload, payload.size()));
    Registry registry;
    PersistenceConfig config;
    config.path = control_path.string();
    const Outcome loaded = registry.load(config);
    FDR_CHECK_MSG(loaded.code == OutcomeCode::Committed,
                 "the crafted control image did not load: " + describe(loaded));
    FDR_CHECK_EQ(registry.domain_count(), std::size_t{0});
    FDR_CHECK_EQ(registry.membership_count(), std::size_t{0});
    FDR_CHECK_EQ(registry.epoch(), CoordinatorEpoch(1));
  }

  // A declared domain count far above the hard ceiling. The reader compares it
  // against the ceiling and against the bytes that remain before it allocates
  // anything for the records.
  {
    const std::string payload = payload_with_counts({0xFFFFFFFFu});
    write_image(absurd_count_path, container_of(payload, payload.size()));
    Registry registry;
    PersistenceConfig config;
    config.path = absurd_count_path.string();
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome loaded = registry.load(config);
    FDR_CHECK_EQ(loaded.code, OutcomeCode::IntegrityFailure);
    FDR_CHECK_MSG(loaded.message.find("domain count is absurd") != std::string::npos,
                 "the absurd count was not the reported reason: " + describe(loaded));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a refused image changed state: " + drift);
  }

  // A plausible count that the remaining bytes cannot possibly satisfy: three
  // million domain records in a payload with no records at all. This is the
  // checked size computation, and it is a division rather than a
  // multiplication, so it cannot overflow on the way.
  {
    std::string payload = payload_prefix();
    failure_domain_registry::append_u32(payload, 3'000'000u);
    write_image(overflowing_count_path, container_of(payload, payload.size()));
    Registry registry;
    PersistenceConfig config;
    config.path = overflowing_count_path.string();
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome loaded = registry.load(config);
    FDR_CHECK_EQ(loaded.code, OutcomeCode::IntegrityFailure);
    FDR_CHECK_MSG(loaded.message.find("domain count is absurd") != std::string::npos,
                 "an unsatisfiable count was not the reported reason: " + describe(loaded));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a refused image changed state: " + drift);
  }

  // The same rule for the second counted container.
  {
    const std::string payload = payload_with_counts({0, 0xFFFFFFFFu});
    write_image(absurd_membership_path, container_of(payload, payload.size()));
    Registry registry;
    PersistenceConfig config;
    config.path = absurd_membership_path.string();
    const Outcome loaded = registry.load(config);
    FDR_CHECK_EQ(loaded.code, OutcomeCode::IntegrityFailure);
    FDR_CHECK_MSG(loaded.message.find("membership count is absurd") != std::string::npos,
                 "the absurd membership count was not the reported reason: " + describe(loaded));
  }

  // An absurd declared payload length is refused by the size equation before
  // the payload is even looked at.
  {
    const std::string payload = payload_with_counts({0, 0, 0, 0, 0, 0, 0});
    write_image(absurd_length_path,
                container_of(payload, static_cast<std::uint64_t>(1) << 40));
    Registry registry;
    PersistenceConfig config;
    config.path = absurd_length_path.string();
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome loaded = registry.load(config);
    FDR_CHECK_EQ(loaded.code, OutcomeCode::IntegrityFailure);
    FDR_CHECK_MSG(loaded.message.find("declared size does not match") != std::string::npos,
                 "an absurd declared length was not the reported reason: " + describe(loaded));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a refused image changed state: " + drift);
  }

  // A truncated container is refused by the same equation, so a partial write
  // can never be recovered as a smaller valid state.
  {
    const std::string payload = payload_with_counts({0, 0, 0, 0, 0, 0, 0});
    const std::string container = container_of(payload, payload.size());
    write_image(truncated_path, std::string_view(container).substr(0, container.size() - 1));
    Registry registry;
    PersistenceConfig config;
    config.path = truncated_path.string();
    const Outcome loaded = registry.load(config);
    FDR_CHECK_EQ(loaded.code, OutcomeCode::IntegrityFailure);
    FDR_CHECK(!loaded.message.empty());
  }

  // A path with no image at all is a different answer from a corrupt image.
  {
    Registry registry;
    PersistenceConfig config;
    config.path = scratch_path("absent").string();
    FDR_CHECK_EQ(registry.load(config).code, OutcomeCode::NotFound);
  }

  std::error_code ignored;
  std::filesystem::remove(control_path, ignored);
  std::filesystem::remove(absurd_count_path, ignored);
  std::filesystem::remove(overflowing_count_path, ignored);
  std::filesystem::remove(absurd_membership_path, ignored);
  std::filesystem::remove(absurd_length_path, ignored);
  std::filesystem::remove(truncated_path, ignored);
}

FDR_TEST_CASE(limits, coverage_declarations_are_reported_and_drive_the_independence_answer) {
  Fixture fixture = open(RegistryLimits::defaults());
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef conduit(DomainClass::Conduit);
  const DomainClassRef site(DomainClass::Site);
  const Provenance provenance = durable_provenance("inv");

  // Two domains in one administrative scope with one member each: the two
  // entities share no domain, so the answer is decided entirely by coverage.
  const FailureDomainId left_domain = domain_of("dc1", conduit, "conduit-left");
  const FailureDomainId right_domain = domain_of("dc1", conduit, "conduit-right");
  FDR_CHECK_EQ(declare_domain(registry, fixture.authority(), conduit, "dc1", "conduit-left",
                              "conduit-left", "cv1", provenance).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(declare_domain(registry, fixture.authority(), conduit, "dc1", "conduit-right",
                              "conduit-right", "cv2", provenance).code,
               OutcomeCode::Committed);
  const EntityRef left = entity_ref(EntityClass::Switch, "coverage-left", 1);
  const EntityRef right = entity_ref(EntityClass::Switch, "coverage-right", 1);
  FDR_CHECK_EQ(attach_member(registry, fixture.authority(), left_domain, left, "cv3", provenance).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_member(registry, fixture.authority(), right_domain, right, "cv4", provenance).code,
               OutcomeCode::Committed);

  // With nothing declared, the class is unknown and independence proves
  // nothing.
  {
    const failure_domain_registry::CoverageReport report = registry.coverage("dc1", {site, conduit});
    FDR_CHECK_EQ(report.entries.size(), std::size_t{2});
    // The entries come back in the order the caller asked for them.
    FDR_CHECK_EQ(report.entries[0].domain_class, site);
    FDR_CHECK_EQ(report.entries[1].domain_class, conduit);
    FDR_CHECK_EQ(report.entries[0].state, failure_domain_registry::CoverageState::UnknownCoverage);
    FDR_CHECK_EQ(report.entries[1].state, failure_domain_registry::CoverageState::UnknownCoverage);
    FDR_CHECK(!report.entries[0].declared);
    FDR_CHECK(!report.entries[1].declared);
    FDR_CHECK(report.has_unknown);
    FDR_CHECK(!report.has_partial);
    FDR_CHECK(!report.complete_for_all);
    const failure_domain_registry::IndependenceResult answer =
        registry.independence({left.id(), right.id()}, {conduit});
    FDR_CHECK_EQ(answer.state, failure_domain_registry::IndependenceState::NoKnowledge);
    FDR_CHECK_EQ(registry.correlate_member_sets({left.id()}, {right.id()}, {conduit}).state,
                 failure_domain_registry::IndependenceState::NoKnowledge);
  }

  // One Complete declaration and one Partial declaration, for different
  // classes, so each branch of the report is observable on its own.
  FDR_CHECK_EQ(declare(registry, fixture.authority(), "dc1", conduit,
                       failure_domain_registry::CoverageState::Complete, "cv5", provenance).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(declare(registry, fixture.authority(), "dc1", site,
                       failure_domain_registry::CoverageState::Partial, "cv6", provenance).code,
               OutcomeCode::Committed);

  const failure_domain_registry::CoverageReport report = registry.coverage("dc1", {site, conduit});
  FDR_CHECK_EQ(report.entries.size(), std::size_t{2});
  FDR_CHECK_EQ(report.entries[0].domain_class, site);
  FDR_CHECK_EQ(report.entries[1].domain_class, conduit);
  FDR_CHECK_EQ(report.entries[0].state, failure_domain_registry::CoverageState::Partial);
  FDR_CHECK_EQ(report.entries[1].state, failure_domain_registry::CoverageState::Complete);
  FDR_CHECK(report.entries[0].declared);
  FDR_CHECK(report.entries[1].declared);
  FDR_CHECK_EQ(report.entries[1].evidence, EvidenceClass::DirectAuthoritativeInfrastructure);
  FDR_CHECK_EQ(report.entries[1].truth, TruthClass::Real);
  FDR_CHECK(report.entries[1].administrative_scope == std::string("dc1"));
  FDR_CHECK(report.has_partial);
  FDR_CHECK(!report.has_unknown);
  FDR_CHECK_MSG(!report.complete_for_all,
                "a Partial declaration must forbid a complete answer for the scope");

  // Complete coverage plus no shared domain is a proof of independence.
  {
    const failure_domain_registry::IndependenceResult answer =
        registry.independence({left.id(), right.id()}, {conduit});
    FDR_CHECK_EQ(answer.state, failure_domain_registry::IndependenceState::ProvenIndependent);
    FDR_CHECK(answer.coverage.complete_for_all);
    FDR_CHECK(!answer.coverage.has_unknown);
    FDR_CHECK_EQ(registry.correlate_member_sets({left.id()}, {right.id()}, {conduit}).state,
                 failure_domain_registry::IndependenceState::ProvenIndependent);
  }
  // Partial coverage proves nothing, and names the class that blocked the
  // answer.
  {
    const failure_domain_registry::IndependenceResult answer =
        registry.independence({left.id(), right.id()}, {site});
    FDR_CHECK_EQ(answer.state, failure_domain_registry::IndependenceState::UnknownCoverage);
    FDR_CHECK(answer.coverage.has_partial);
    const failure_domain_registry::SetCorrelation correlation =
        registry.correlate_member_sets({left.id()}, {right.id()}, {site});
    FDR_CHECK_EQ(correlation.state, failure_domain_registry::IndependenceState::UnknownCoverage);
    FDR_CHECK_EQ(correlation.unknown_classes.size(), std::size_t{1});
    FDR_CHECK_EQ(correlation.unknown_classes[0], site);
  }
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the coverage declarations broke the state: " + why);
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
