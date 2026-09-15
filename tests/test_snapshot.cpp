// Failure Domain Registry — snapshot immutability, currentness and stable diffs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A snapshot is a value, not a view: these checks take a snapshot, drive the
// registry through every mutation that could possibly change it, and then
// compare the frozen canonical form, every entry and the digest. The diff cases
// run one session that exercises every reachable DiffKind and compare the
// reported kinds, their ordering and which side of each entry carries the value.
// The two kinds that no public operation can produce are named in comments
// instead of being faked.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "failure_domain_registry/failure_domain_registry.hpp"
#include "support/test_harness.hpp"

namespace {

using failure_domain_registry::append_bytes;
using failure_domain_registry::sha256;
using failure_domain_registry::to_hex;
using failure_domain_registry::AttachMemberRequest;
using failure_domain_registry::AuthorityContext;
using failure_domain_registry::AuthorityScope;
using failure_domain_registry::CoordinatorEpoch;
using failure_domain_registry::CreateDomainRequest;
using failure_domain_registry::DependencySemantics;
using failure_domain_registry::DerivationOperator;
using failure_domain_registry::DerivationReport;
using failure_domain_registry::DerivationRule;
using failure_domain_registry::DerivationRunRequest;
using failure_domain_registry::DetachMemberRequest;
using failure_domain_registry::DiffEntry;
using failure_domain_registry::DiffKind;
using failure_domain_registry::DomainClass;
using failure_domain_registry::DomainClassRef;
using failure_domain_registry::DomainLifecycle;
using failure_domain_registry::EntityClass;
using failure_domain_registry::EntityGeneration;
using failure_domain_registry::EntityRef;
using failure_domain_registry::EvidenceClass;
using failure_domain_registry::FailureDomainGeneration;
using failure_domain_registry::FailureDomainId;
using failure_domain_registry::IdBytes;
using failure_domain_registry::MarkRevalidationRequest;
using failure_domain_registry::MembershipId;
using failure_domain_registry::MembershipRole;
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
using failure_domain_registry::RegistryGeneration;
using failure_domain_registry::RegistryLimits;
using failure_domain_registry::ReplaceMembershipRequest;
using failure_domain_registry::RequestDigest;
using failure_domain_registry::RetireDomainRequest;
using failure_domain_registry::Snapshot;
using failure_domain_registry::SnapshotDiff;
using failure_domain_registry::SnapshotDomainEntry;
using failure_domain_registry::SnapshotId;
using failure_domain_registry::SnapshotMembershipEntry;
using failure_domain_registry::StateDigest;
using failure_domain_registry::SupersedeDomainRequest;
using failure_domain_registry::TruthClass;
using failure_domain_registry::UpdateDomainRequest;
using failure_domain_registry::WorkerBootId;

// ---------------------------------------------------------------------------
// Deterministic identity helpers and one bootstrap fixture
// ---------------------------------------------------------------------------

IdBytes pattern_bytes(std::uint8_t seed) {
  IdBytes out{};
  for (std::size_t index = 0; index < out.size(); ++index) {
    out[index] = static_cast<std::uint8_t>((index * 53u + seed * 7u + 1u) & 0xFFu);
  }
  return out;
}

PublisherId publisher_from(std::uint8_t seed) { return PublisherId::from_bytes(pattern_bytes(seed)); }
WorkerBootId boot_from(std::uint8_t seed) { return WorkerBootId::from_bytes(pattern_bytes(seed)); }

MutationAttemptId attempt_from(std::uint8_t seed) {
  return MutationAttemptId::from_bytes(pattern_bytes(static_cast<std::uint8_t>(seed + 0x30u)));
}

EntityRef entity_ref(EntityClass klass, std::uint8_t seed, EntityGeneration generation) {
  return EntityRef(klass, pattern_bytes(seed), generation);
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

/// The durable administrative provenance every fixture record starts with.
Provenance administrative() {
  return provenance_of(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration,
                       TruthClass::Real, "cmdb-1");
}

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

void bootstrap(Registry& registry, Session& session) {
  session.publisher = publisher_from(0x21);
  session.worker_boot = boot_from(0x21);

  PublisherRegistration registration;
  registration.publisher = session.publisher;
  registration.name = "snapshot-publisher";
  registration.scope = AuthorityScope::unrestricted();
  FDR_CHECK_EQ(registry.grant_publisher(registration, AuthorityContext{}).code,
               OutcomeCode::Committed);

  CoordinatorEpoch epoch;
  FDR_CHECK_EQ(registry.advance_epoch(CoordinatorEpoch{}, &epoch).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(epoch.value(), std::uint64_t{1});

  FDR_CHECK_EQ(registry
                   .attach_worker(session.publisher, session.worker_boot, epoch, "snapshot-worker",
                                  EvidenceClass::DirectAuthoritativeInfrastructure)
                   .code,
               OutcomeCode::Committed);
  session.epoch = epoch;
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

CreateDomainRequest create_request(const Session& session, DomainClass klass, std::string scope,
                                   std::string identity_key, std::string name,
                                   Provenance provenance, std::uint8_t attempt_seed) {
  CreateDomainRequest request;
  request.attempt = MutationAttempt(attempt_from(attempt_seed), RequestDigest{});
  request.authority = authority_of(session, provenance.evidence);
  request.domain_class = DomainClassRef(klass);
  request.administrative_scope = std::move(scope);
  request.identity_key = std::move(identity_key);
  request.name = std::move(name);
  request.provenance = std::move(provenance);
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
  request.role = role;
  request.provenance = std::move(provenance);
  return request;
}

/// Creates a domain and returns its deterministic id. A rejection aborts the
/// case through the harness, so it can never masquerade as a fixture.
FailureDomainId require_domain(Registry& registry, const CreateDomainRequest& request) {
  const Outcome outcome = registry.create_domain(request);
  if (outcome.code != OutcomeCode::Committed || !outcome.domain.has_value()) {
    ::fdrtest::fail(__FILE__, __LINE__, "domain create was rejected: " + outcome.message);
    return FailureDomainId{};
  }
  return *outcome.domain;
}

/// Attaches a member and returns its deterministic membership id, under the
/// same rule as require_domain.
MembershipId require_membership(Registry& registry, const AttachMemberRequest& request) {
  const Outcome outcome = registry.attach_member(request);
  if (outcome.code != OutcomeCode::Committed || !outcome.membership.has_value()) {
    ::fdrtest::fail(__FILE__, __LINE__, "attach was rejected: " + outcome.message);
    return MembershipId{};
  }
  return *outcome.membership;
}

// ---------------------------------------------------------------------------
// The shared starting world
// ---------------------------------------------------------------------------

struct World {
  FailureDomainId rack{};
  FailureDomainId pdu{};
  FailureDomainId conduit{};
  FailureDomainId row{};
  FailureDomainId row_successor{};
  EntityRef host_aa{};
  EntityRef host_bb{};
  EntityRef link_cc{};
  MembershipId aa_rack{};
  MembershipId aa_pdu{};
  MembershipId bb_pdu{};
  MembershipId cc_conduit{};
};

/// Four domains and four memberships: two of the memberships share the PDU
/// domain and one of those also belongs to the rack, which is the shape the
/// derivation case needs.
void build_world(Registry& registry, const Session& session, World& world) {
  const Provenance provenance = administrative();
  world.rack = require_domain(registry, create_request(session, DomainClass::Rack, "dc1",
                                                       "rack-r1", "rack one", provenance, 0x10));
  world.pdu = require_domain(registry, create_request(session, DomainClass::Pdu, "dc1",
                                                      "pdu-p1", "pdu one", provenance, 0x11));
  world.conduit = require_domain(registry, create_request(session, DomainClass::Conduit, "dc2",
                                                          "conduit-c1", "conduit one", provenance, 0x12));
  world.row = require_domain(registry, create_request(session, DomainClass::Row, "dc1", "row-1",
                                                      "row one", provenance, 0x13));
  world.row_successor = require_domain(registry, create_request(session, DomainClass::Row, "dc1",
                                                                "row-2", "row two", provenance, 0x14));

  world.host_aa = entity_ref(EntityClass::Host, 0x41, EntityGeneration(1));
  world.host_bb = entity_ref(EntityClass::Host, 0x42, EntityGeneration(1));
  world.link_cc = entity_ref(EntityClass::Link, 0x43, EntityGeneration(1));

  world.aa_rack = require_membership(
      registry,
      attach_request(session, world.rack, world.host_aa, MembershipRole::Primary, provenance, 0x21));
  world.aa_pdu = require_membership(
      registry,
      attach_request(session, world.pdu, world.host_aa, MembershipRole::SharedRisk, provenance, 0x22));
  world.bb_pdu = require_membership(
      registry,
      attach_request(session, world.pdu, world.host_bb, MembershipRole::SharedRisk, provenance, 0x23));
  world.cc_conduit = require_membership(
      registry,
      attach_request(session, world.conduit, world.link_cc, MembershipRole::Primary, provenance, 0x24));

  FDR_CHECK_EQ(registry.domain_count(), std::size_t{5});
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{4});
}

DerivationRule pdu_members_share_rack() {
  DerivationRule rule;
  rule.name = "pdu-members-share-rack";
  rule.op = DerivationOperator::MembersShareContainingClass;
  rule.source_class = DomainClassRef(DomainClass::Pdu);
  rule.target_class = DomainClassRef(DomainClass::Rack);
  rule.member_class = EntityClass::Host;
  rule.derived_role = MembershipRole::Derived;
  rule.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
  rule.rule_version = 1;
  return rule;
}

DerivationRunRequest derivation_request(const Session& session, std::uint8_t attempt_seed) {
  DerivationRunRequest request;
  request.attempt = MutationAttempt(attempt_from(attempt_seed), RequestDigest{});
  request.authority = authority_of(session, EvidenceClass::DirectAuthoritativeInfrastructure);
  return request;
}

// ---------------------------------------------------------------------------
// Snapshot and diff readers
// ---------------------------------------------------------------------------

std::string hex_of(std::string_view text) {
  const failure_domain_registry::DigestBytes bytes = sha256(text);
  return to_hex(bytes.data(), bytes.size());
}

const SnapshotDomainEntry* domain_entry(const Snapshot& snapshot, const FailureDomainId& id) {
  for (const SnapshotDomainEntry& entry : snapshot.domains) {
    if (entry.id == id) {
      return &entry;
    }
  }
  return nullptr;
}

const SnapshotMembershipEntry* membership_entry(const Snapshot& snapshot, const MembershipId& id) {
  for (const SnapshotMembershipEntry& entry : snapshot.memberships) {
    if (entry.id == id) {
      return &entry;
    }
  }
  return nullptr;
}

std::vector<DiffEntry> entries_of(const SnapshotDiff& diff, DiffKind kind) {
  std::vector<DiffEntry> out;
  for (const DiffEntry& entry : diff.entries) {
    if (entry.kind == kind) {
      out.push_back(entry);
    }
  }
  return out;
}

std::set<DiffKind> kinds_of(const SnapshotDiff& diff) {
  std::set<DiffKind> kinds;
  for (const DiffEntry& entry : diff.entries) {
    kinds.insert(entry.kind);
  }
  return kinds;
}

/// True when the entry is ordered before the other by the documented key.
bool diff_less(const DiffEntry& left, const DiffEntry& right) {
  if (left.kind != right.kind) {
    return static_cast<std::uint8_t>(left.kind) < static_cast<std::uint8_t>(right.kind);
  }
  if (left.domain != right.domain) {
    return left.domain < right.domain;
  }
  if (left.membership != right.membership) {
    return left.membership < right.membership;
  }
  return left.member < right.member;
}

bool ids_ascending(const std::vector<FailureDomainId>& ids) {
  for (std::size_t index = 1; index < ids.size(); ++index) {
    if (ids[index] < ids[index - 1]) {
      return false;
    }
  }
  return true;
}

/// Removes the directory it owns, including when a case aborts.
struct TempDirectory {
  std::filesystem::path path;

  explicit TempDirectory(const std::string& label) {
    path = std::filesystem::temp_directory_path() / ("fdr-snapshot-" + label);
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

  std::string image() const { return (path / "state.fdr").string(); }
};

} // namespace

// ---------------------------------------------------------------------------
// What a snapshot records
// ---------------------------------------------------------------------------

FDR_TEST_CASE(snapshot, records_identity_level_state_and_increments_its_sequence) {
  Registry registry(RegistryLimits::defaults());
  Session session;
  bootstrap(registry, session);
  World world;
  build_world(registry, session, world);

  const Snapshot first = registry.snapshot("scope-a");
  FDR_CHECK_EQ(first.sequence.value(), std::uint64_t{1});
  FDR_CHECK_EQ(first.state_generation, registry.generation());
  FDR_CHECK_EQ(first.epoch, registry.epoch());
  FDR_CHECK_EQ(first.scope, std::string("scope-a"));
  FDR_CHECK_EQ(first.domains.size(), registry.domain_count());
  FDR_CHECK_EQ(first.memberships.size(), registry.membership_count());
  FDR_CHECK_EQ(first.domains.size(), std::size_t{5});
  FDR_CHECK_EQ(first.memberships.size(), std::size_t{4});
  FDR_CHECK_EQ(first.is_empty(), false);
  FDR_CHECK(!first.digest.is_null());
  FDR_CHECK(!first.id.is_null());

  // The digest is the digest of the snapshot's own canonical form.
  FDR_CHECK_EQ(first.digest.to_string(), hex_of(first.canonical_form()));

  // Every domain entry carries the identity-level fields of the live record.
  for (const SnapshotDomainEntry& entry : first.domains) {
    const auto record = registry.domain(entry.id);
    FDR_CHECK_MSG(record.has_value(), "snapshot names a domain the registry does not hold");
    FDR_CHECK_EQ(entry.domain_class, record->domain_class);
    FDR_CHECK_EQ(entry.generation, record->generation);
    FDR_CHECK_EQ(entry.lifecycle, record->lifecycle);
    FDR_CHECK_EQ(entry.evidence, record->provenance.evidence);
    FDR_CHECK_EQ(entry.truth, record->provenance.truth);
    FDR_CHECK_EQ(entry.source, record->provenance.source);
    FDR_CHECK_EQ(entry.created_at, record->created_at);
  }
  for (const SnapshotMembershipEntry& entry : first.memberships) {
    const auto record = registry.membership(entry.id);
    FDR_CHECK_MSG(record.has_value(), "snapshot names a membership the registry does not hold");
    FDR_CHECK_EQ(entry.domain, record->domain);
    FDR_CHECK_EQ(entry.domain_generation, record->domain_generation);
    FDR_CHECK_EQ(entry.member, record->member);
    FDR_CHECK_EQ(entry.generation, record->generation);
    FDR_CHECK_EQ(entry.lifecycle, record->lifecycle);
    FDR_CHECK_EQ(entry.kind, record->kind);
    FDR_CHECK_EQ(entry.role, record->role);
    FDR_CHECK_EQ(entry.evidence, record->provenance.evidence);
    FDR_CHECK_EQ(entry.truth, record->provenance.truth);
    FDR_CHECK_EQ(entry.source, record->provenance.source);
    FDR_CHECK_EQ(entry.derivation_rule, record->derivation.rule);
    FDR_CHECK_EQ(entry.derivation_generation, record->derivation.generation);
  }

  // The entries are ordered by identity, not by insertion order.
  std::vector<FailureDomainId> domain_ids;
  for (const SnapshotDomainEntry& entry : first.domains) {
    domain_ids.push_back(entry.id);
  }
  FDR_CHECK(ids_ascending(domain_ids));
  std::vector<MembershipId> membership_ids;
  for (const SnapshotMembershipEntry& entry : first.memberships) {
    membership_ids.push_back(entry.id);
  }
  for (std::size_t index = 1; index < membership_ids.size(); ++index) {
    FDR_CHECK(!(membership_ids[index] < membership_ids[index - 1]));
  }

  // The sequence increments per snapshot; nothing else moved, so a second
  // snapshot has the same generation, digest and canonical form but a new
  // identity.
  const Snapshot second = registry.snapshot("scope-a");
  FDR_CHECK_EQ(second.sequence.value(), std::uint64_t{2});
  FDR_CHECK_EQ(second.state_generation, first.state_generation);
  FDR_CHECK_EQ(second.digest, first.digest);
  FDR_CHECK_EQ(second.canonical_form(), first.canonical_form());
  FDR_CHECK(!(second.id == first.id));

  // The scope is part of the snapshot: it is recorded and it is digested.
  const Snapshot third = registry.snapshot("scope-b");
  FDR_CHECK_EQ(third.sequence.value(), std::uint64_t{3});
  FDR_CHECK_EQ(third.scope, std::string("scope-b"));
  FDR_CHECK_EQ(third.domains.size(), first.domains.size());
  FDR_CHECK(!(third.canonical_form() == first.canonical_form()));
  FDR_CHECK(!(third.digest == first.digest));
  FDR_CHECK_EQ(third.digest.to_string(), hex_of(third.canonical_form()));
}

// ---------------------------------------------------------------------------
// Immutability
// ---------------------------------------------------------------------------

FDR_TEST_CASE(snapshot, entries_do_not_move_when_the_registry_moves_on) {
  Registry registry(RegistryLimits::defaults());
  Session session;
  bootstrap(registry, session);
  World world;
  build_world(registry, session, world);

  const Snapshot frozen = registry.snapshot("frozen");
  const std::string frozen_form = frozen.canonical_form();
  const std::vector<SnapshotDomainEntry> frozen_domains = frozen.domains;
  const std::vector<SnapshotMembershipEntry> frozen_memberships = frozen.memberships;
  const StateDigest frozen_digest = frozen.digest;
  const RegistryGeneration frozen_generation = frozen.state_generation;
  const CoordinatorEpoch frozen_epoch = frozen.epoch;
  const SnapshotId frozen_id = frozen.id;

  // Mutate in every way a snapshot could plausibly be affected by: add a
  // domain, change a lifecycle, add and remove a membership, change a role.
  const Provenance provenance = administrative();
  const FailureDomainId added = require_domain(registry, create_request(
      session, DomainClass::Link, "dc1", "link-l1", "link one", provenance, 0x15));

  UpdateDomainRequest lifecycle;
  lifecycle.attempt = MutationAttempt(attempt_from(0x51), RequestDigest{});
  lifecycle.authority = authority_of(session, EvidenceClass::AdministrativeDeclaration);
  lifecycle.domain = world.conduit;
  lifecycle.transition = DomainLifecycle::RevalidationRequired;
  FDR_CHECK_EQ(registry.update_domain(lifecycle).code, OutcomeCode::Committed);

  const EntityRef extra = entity_ref(EntityClass::Host, 0x44, EntityGeneration(1));
  const MembershipId attached = require_membership(
      registry, attach_request(session, added, extra, MembershipRole::Backup, provenance, 0x25));
  DetachMemberRequest detach;
  detach.attempt = MutationAttempt(attempt_from(0x52), RequestDigest{});
  detach.authority = authority_of(session, EvidenceClass::AdministrativeDeclaration);
  detach.domain = added;
  detach.member = extra;
  detach.reason = "snapshot immutability";
  FDR_CHECK_EQ(registry.detach_member(detach).code, OutcomeCode::Committed);

  ReplaceMembershipRequest replace;
  replace.attempt = MutationAttempt(attempt_from(0x53), RequestDigest{});
  replace.authority = authority_of(session, EvidenceClass::AdministrativeDeclaration);
  replace.membership = world.aa_rack;
  replace.role = MembershipRole::SharedRisk;
  FDR_CHECK_EQ(registry.replace_membership(replace).code, OutcomeCode::Committed);

  FDR_CHECK(registry.domain(world.row).has_value());
  RetireDomainRequest retire;
  retire.attempt = MutationAttempt(attempt_from(0x54), RequestDigest{});
  retire.authority = authority_of(session, EvidenceClass::AdministrativeDeclaration);
  retire.domain = world.row;
  retire.expected_generation = registry.domain(world.row)->generation;
  retire.reason = "snapshot immutability";
  FDR_CHECK_EQ(registry.retire_domain(retire).code, OutcomeCode::Committed);

  // The snapshot is a value: full canonical-form comparison, not a spot check.
  FDR_CHECK_EQ(frozen.canonical_form(), frozen_form);
  FDR_CHECK_EQ(frozen.domains, frozen_domains);
  FDR_CHECK_EQ(frozen.memberships, frozen_memberships);
  FDR_CHECK_EQ(frozen.digest, frozen_digest);
  FDR_CHECK_EQ(frozen.state_generation, frozen_generation);
  FDR_CHECK_EQ(frozen.epoch, frozen_epoch);
  FDR_CHECK_EQ(frozen.id, frozen_id);
  FDR_CHECK_EQ(frozen.scope, std::string("frozen"));
  FDR_CHECK_EQ(frozen.domains.size(), std::size_t{5});
  FDR_CHECK_EQ(frozen.memberships.size(), std::size_t{4});

  const SnapshotDomainEntry* conduit = domain_entry(frozen, world.conduit);
  FDR_CHECK(conduit != nullptr);
  FDR_CHECK_EQ(conduit->lifecycle, DomainLifecycle::Current);
  const SnapshotMembershipEntry* aa_rack = membership_entry(frozen, world.aa_rack);
  FDR_CHECK(aa_rack != nullptr);
  FDR_CHECK_EQ(aa_rack->role, MembershipRole::Primary);
  FDR_CHECK(membership_entry(frozen, attached) == nullptr);

  // The live registry really did move on.
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{6});
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{5});
  FDR_CHECK(registry.domain(world.conduit).has_value());
  FDR_CHECK_EQ(registry.domain(world.conduit)->lifecycle, DomainLifecycle::RevalidationRequired);
  FDR_CHECK(registry.membership(world.aa_rack).has_value());
  FDR_CHECK_EQ(registry.membership(world.aa_rack)->role, MembershipRole::SharedRisk);
  FDR_CHECK(!registry.snapshot_is_current(frozen));
  FDR_CHECK(!(registry.snapshot("frozen").canonical_form() == frozen_form));
}

// ---------------------------------------------------------------------------
// Currentness
// ---------------------------------------------------------------------------

FDR_TEST_CASE(snapshot, currentness_follows_the_registry_generation) {
  Registry registry(RegistryLimits::defaults());
  Session session;
  bootstrap(registry, session);
  World world;
  build_world(registry, session, world);

  const CreateDomainRequest replayable =
      create_request(session, DomainClass::Pdu, "dc3", "pdu-p9", "pdu nine", administrative(), 0x16);
  FDR_CHECK_EQ(registry.create_domain(replayable).code, OutcomeCode::Committed);

  const Snapshot snapshot_now = registry.snapshot("current");
  FDR_CHECK(registry.snapshot_is_current(snapshot_now));
  FDR_CHECK_EQ(snapshot_now.state_generation, registry.generation());

  // An exact replay is Idempotent: no new generation, so the snapshot stays
  // current.
  const Outcome replay = registry.create_domain(replayable);
  FDR_CHECK_EQ(replay.code, OutcomeCode::Idempotent);
  FDR_CHECK_EQ(registry.generation(), snapshot_now.state_generation);
  FDR_CHECK(registry.snapshot_is_current(snapshot_now));

  // A rejected mutation does not make it stale either.
  UpdateDomainRequest stale;
  stale.attempt = MutationAttempt(attempt_from(0x55), RequestDigest{});
  stale.authority = authority_of(session, EvidenceClass::AdministrativeDeclaration);
  stale.domain = world.rack;
  stale.expected_generation = FailureDomainGeneration(1234);
  FDR_CHECK_EQ(registry.update_domain(stale).code, OutcomeCode::StaleGeneration);
  FDR_CHECK(registry.snapshot_is_current(snapshot_now));

  // A committed mutation does, and the difference is exactly the generation.
  const MembershipId extra = require_membership(
      registry, attach_request(session, world.conduit,
                               entity_ref(EntityClass::Link, 0x45, EntityGeneration(1)),
                               MembershipRole::Redundant, administrative(), 0x26));
  FDR_CHECK(!extra.is_null());
  FDR_CHECK(!registry.snapshot_is_current(snapshot_now));
  FDR_CHECK(!(registry.generation() == snapshot_now.state_generation));

  // A fresh snapshot is current again and is a different value.
  const Snapshot following = registry.snapshot("current");
  FDR_CHECK(registry.snapshot_is_current(following));
  FDR_CHECK_EQ(following.state_generation, registry.generation());
  FDR_CHECK(!(following.id == snapshot_now.id));
  FDR_CHECK_EQ(following.sequence.value(), snapshot_now.sequence.value() + 1u);
  FDR_CHECK(!(following.canonical_form() == snapshot_now.canonical_form()));

  // A mutation that only advances the sequence (taking the snapshot) must not
  // make the newest snapshot stale.
  FDR_CHECK(registry.snapshot_is_current(following));
  FDR_CHECK(!registry.snapshot_is_current(snapshot_now));
}

// ---------------------------------------------------------------------------
// Canonical form across calls and across a round trip
// ---------------------------------------------------------------------------

FDR_TEST_CASE(snapshot, canonical_form_is_stable_across_calls_and_a_round_trip) {
  const TempDirectory directory("round-trip");
  Registry registry(RegistryLimits::defaults());
  Session session;
  bootstrap(registry, session);
  World world;
  build_world(registry, session, world);

  const Snapshot before = registry.snapshot("round-trip");
  FDR_CHECK_EQ(before.canonical_form(), before.canonical_form());
  FDR_CHECK_EQ(before.canonical_form(), before.canonical_form());
  // Two snapshots taken at the same generation and scope are the same value.
  FDR_CHECK_EQ(registry.snapshot("round-trip").canonical_form(), before.canonical_form());

  PersistenceConfig config;
  config.path = directory.image();
  config.durable = true;
  config.atomic = true;
  FDR_CHECK_EQ(registry.save(config).code, OutcomeCode::Committed);

  Registry restored(RegistryLimits::defaults());
  FDR_CHECK_EQ(restored.load(config).code, OutcomeCode::Committed);
  const Snapshot after = restored.snapshot("round-trip");

  // Everything the snapshot records about the classification survives exactly.
  FDR_CHECK_EQ(after.domains, before.domains);
  FDR_CHECK_EQ(after.memberships, before.memberships);
  FDR_CHECK_EQ(after.epoch, before.epoch);
  FDR_CHECK_EQ(after.scope, before.scope);
  FDR_CHECK_EQ(after.state_generation.value(), before.state_generation.value() + 1u);
  FDR_CHECK_EQ(after.digest.to_string(), hex_of(after.canonical_form()));

  // The canonical form differs only in the registry generation load deliberately
  // advanced, so the form is not byte-identical - and the difference is exactly
  // those eight bytes.
  const std::string tag = [] {
    std::string out;
    append_bytes(out, "fdr/snapshot/v1");
    return out;
  }();
  const std::size_t generation_offset = tag.size();
  const std::string before_form = before.canonical_form();
  const std::string after_form = after.canonical_form();
  FDR_CHECK_EQ(before_form.rfind(tag, 0), std::size_t{0});
  FDR_CHECK_EQ(after_form.rfind(tag, 0), std::size_t{0});
  FDR_CHECK_EQ(after_form.size(), before_form.size());
  FDR_CHECK(!(after_form == before_form));
  for (std::size_t index = 0; index < before_form.size(); ++index) {
    if (before_form[index] == after_form[index]) {
      continue;
    }
    FDR_CHECK_MSG(index >= generation_offset && index < generation_offset + 8,
                  "byte " + std::to_string(index) +
                      " differs outside the registry generation the load advanced");
  }
  // The epoch follows the generation, and every identity-level byte follows the
  // epoch, so the whole tail is shared.
  const std::size_t tail_offset = generation_offset + 16;
  FDR_CHECK_EQ(after_form.substr(tail_offset), before_form.substr(tail_offset));
}

// ---------------------------------------------------------------------------
// Diffs
// ---------------------------------------------------------------------------

FDR_TEST_CASE(snapshot, diff_of_identical_snapshots_is_empty) {
  Registry registry(RegistryLimits::defaults());
  Session session;
  bootstrap(registry, session);
  World world;
  build_world(registry, session, world);

  const Snapshot first = registry.snapshot("same");
  const Snapshot second = registry.snapshot("same");
  FDR_CHECK(!(first.id == second.id));
  FDR_CHECK_EQ(first.digest, second.digest);

  const SnapshotDiff diff = registry.diff(first, second);
  FDR_CHECK(diff.empty());
  FDR_CHECK_EQ(diff.entries.size(), std::size_t{0});
  FDR_CHECK_EQ(diff.before, first.id);
  FDR_CHECK_EQ(diff.after, second.id);
  FDR_CHECK_EQ(diff.before_generation, first.state_generation);
  FDR_CHECK_EQ(diff.after_generation, second.state_generation);
  FDR_CHECK(diff.render().find("no semantic change") != std::string::npos);

  // A snapshot diffed against itself is empty as well, and a registry with no
  // records at all produces two empty snapshots that differ only in sequence.
  const SnapshotDiff self = registry.diff(first, first);
  FDR_CHECK(self.empty());
  FDR_CHECK_EQ(self.before, self.after);

  Registry empty(RegistryLimits::defaults());
  Session empty_session;
  bootstrap(empty, empty_session);
  const Snapshot left = empty.snapshot("empty");
  const Snapshot right = empty.snapshot("empty");
  FDR_CHECK(left.is_empty());
  FDR_CHECK_EQ(left.domains.size(), std::size_t{0});
  FDR_CHECK_EQ(left.memberships.size(), std::size_t{0});
  FDR_CHECK(empty.diff(left, right).empty());
  FDR_CHECK_EQ(left.state_generation, right.state_generation);
}

FDR_TEST_CASE(snapshot, diff_reports_every_reachable_kind) {
  Registry registry(RegistryLimits::defaults());
  Session session;
  bootstrap(registry, session);
  World world;
  build_world(registry, session, world);
  FDR_CHECK_EQ(registry.publish_derivation_rule(
                   pdu_members_share_rack(),
                   authority_of(session, EvidenceClass::DirectAuthoritativeInfrastructure))
                   .code,
               OutcomeCode::Committed);

  // Created before the baseline so that a later lifecycle change on it is a
  // change between two snapshots rather than an addition.
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{5});
  const FailureDomainId link_domain = require_domain(registry, create_request(
      session, DomainClass::Link, "dc1", "link-l1", "link one", administrative(), 0x17));
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{6});

  const Snapshot baseline = registry.snapshot("diff");

  // Stage one: the derivation creates derived memberships, which can only be
  // reported as additions.
  DerivationReport report;
  const Outcome derived = registry.run_derivation(derivation_request(session, 0x31), &report);
  FDR_CHECK_EQ(derived.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(report.memberships_created, std::size_t{2});
  FDR_CHECK_EQ(report.memberships_updated, std::size_t{0});
  const Snapshot after_derivation = registry.snapshot("diff");
  const SnapshotDiff first_stage = registry.diff(baseline, after_derivation);
  FDR_CHECK_EQ(kinds_of(first_stage), std::set<DiffKind>{DiffKind::MembershipAdded});
  const std::vector<DiffEntry> derived_additions = entries_of(first_stage, DiffKind::MembershipAdded);
  FDR_CHECK_EQ(derived_additions.size(), std::size_t{2});
  for (const DiffEntry& entry : derived_additions) {
    FDR_CHECK(entry.before.empty());
    FDR_CHECK(!entry.after.empty());
    FDR_CHECK(!entry.membership.is_null());
    FDR_CHECK(!entry.member.is_null());
  }

  // Stage two reaches every remaining kind the public API can produce.
  const Provenance provenance = administrative();
  const FailureDomainId added = require_domain(registry, create_request(
      session, DomainClass::Cable, "dc1", "cable-c1", "cable one", provenance, 0x18));

  UpdateDomainRequest lifecycle;
  lifecycle.attempt = MutationAttempt(attempt_from(0x61), RequestDigest{});
  lifecycle.authority = authority_of(session, EvidenceClass::AdministrativeDeclaration);
  lifecycle.domain = link_domain;
  lifecycle.transition = DomainLifecycle::RevalidationRequired;
  FDR_CHECK_EQ(registry.update_domain(lifecycle).code, OutcomeCode::Committed);

  UpdateDomainRequest provenance_change;
  provenance_change.attempt = MutationAttempt(attempt_from(0x62), RequestDigest{});
  provenance_change.authority = authority_of(session, EvidenceClass::AdministrativeDeclaration);
  provenance_change.domain = world.conduit;
  // Only a stronger evidence class replaces a committed classification: an equal
  // class from a different source, or with a different truth label, is a conflict.
  provenance_change.provenance =
      provenance_of(ProvenanceSource::Cmdb, EvidenceClass::DirectAuthoritativeInfrastructure,
                    TruthClass::Real, "cmdb-1");
  FDR_CHECK_EQ(registry.update_domain(provenance_change).code, OutcomeCode::Committed);

  FDR_CHECK(registry.domain(world.row).has_value());
  SupersedeDomainRequest supersede;
  supersede.attempt = MutationAttempt(attempt_from(0x63), RequestDigest{});
  supersede.authority = authority_of(session, EvidenceClass::AdministrativeDeclaration);
  supersede.domain = world.row;
  supersede.expected_generation = registry.domain(world.row)->generation;
  supersede.successor = world.row_successor;
  supersede.demote_memberships = false;
  FDR_CHECK_EQ(registry.supersede_domain(supersede).code, OutcomeCode::Committed);

  const EntityRef extra_link = entity_ref(EntityClass::Link, 0x46, EntityGeneration(1));
  const MembershipId extra = require_membership(
      registry, attach_request(session, world.conduit, extra_link, MembershipRole::Redundant,
                               provenance, 0x27));

  ReplaceMembershipRequest stronger;
  stronger.attempt = MutationAttempt(attempt_from(0x64), RequestDigest{});
  stronger.authority = authority_of(session, EvidenceClass::DirectAuthoritativeInfrastructure);
  stronger.membership = world.aa_rack;
  stronger.provenance = provenance_of(ProvenanceSource::Cmdb,
                                      EvidenceClass::DirectAuthoritativeInfrastructure,
                                      TruthClass::Real, "cmdb-1");
  FDR_CHECK_EQ(registry.replace_membership(stronger).code, OutcomeCode::Committed);

  MarkRevalidationRequest mark;
  mark.attempt = MutationAttempt(attempt_from(0x65), RequestDigest{});
  mark.authority = authority_of(session, EvidenceClass::AdministrativeDeclaration);
  mark.membership = world.cc_conduit;
  mark.reason = "diff coverage";
  FDR_CHECK_EQ(registry.mark_revalidation_required(mark).code, OutcomeCode::Committed);

  // Reasserting a source membership moves its generation, so the next
  // derivation pass recomputes the memberships derived from it.
  const Provenance strongest = provenance_of(ProvenanceSource::Cmdb,
                                             EvidenceClass::DirectAuthoritativeInfrastructure,
                                             TruthClass::Real, "cmdb-1");
  AttachMemberRequest reassert = attach_request(session, world.pdu, world.host_aa,
                                                MembershipRole::SharedRisk, strongest, 0x28);
  FDR_CHECK_EQ(registry.attach_member(reassert).code, OutcomeCode::Committed);

  const EntityRef extra_host = entity_ref(EntityClass::Host, 0x47, EntityGeneration(1));
  FDR_CHECK_EQ(registry
                   .attach_member(attach_request(session, world.pdu, extra_host,
                                                 MembershipRole::SharedRisk, provenance, 0x29))
                   .code,
               OutcomeCode::Committed);

  DerivationReport recomputed;
  FDR_CHECK_EQ(registry.run_derivation(derivation_request(session, 0x32), &recomputed).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(recomputed.memberships_created, std::size_t{1});
  FDR_CHECK_EQ(recomputed.memberships_updated, std::size_t{2});

  const Snapshot after_session = registry.snapshot("diff");
  const SnapshotDiff session_diff = registry.diff(after_derivation, after_session);

  // Ten of the twelve kinds are reachable through the public API. This session
  // produces eight of them; the two removal kinds need a reset (below), and the
  // remaining two are unreachable and named in the comment after the checks.
  const std::set<DiffKind> expected{
      DiffKind::DomainAdded,        DiffKind::DomainSuperseded,
      DiffKind::DomainLifecycleChanged, DiffKind::DomainProvenanceChanged,
      DiffKind::MembershipAdded,    DiffKind::MembershipLifecycleChanged,
      DiffKind::MembershipProvenanceChanged, DiffKind::MembershipDerivationChanged};
  FDR_CHECK_EQ(kinds_of(session_diff).size(), expected.size());
  FDR_CHECK(kinds_of(session_diff) == expected);

  // The newly created domain is an addition, with the value on the after side.
  const std::vector<DiffEntry> domain_added = entries_of(session_diff, DiffKind::DomainAdded);
  FDR_CHECK_EQ(domain_added.size(), std::size_t{1});
  FDR_CHECK_EQ(domain_added[0].domain, added);
  FDR_CHECK(domain_added[0].before.empty());
  FDR_CHECK_EQ(domain_added[0].after, std::string("cable"));
  FDR_CHECK(domain_added[0].membership.is_null());
  FDR_CHECK(domain_added[0].member.is_null());

  // The lifecycle change carries both lifecycle names, before then after.
  const std::vector<DiffEntry> lifecycle_change =
      entries_of(session_diff, DiffKind::DomainLifecycleChanged);
  FDR_CHECK_EQ(lifecycle_change.size(), std::size_t{2});
  bool saw_link_lifecycle = false;
  bool saw_superseded_lifecycle = false;
  for (const DiffEntry& entry : lifecycle_change) {
    FDR_CHECK(!entry.before.empty());
    FDR_CHECK(!entry.after.empty());
    FDR_CHECK(!(entry.before == entry.after));
    if (entry.domain == link_domain) {
      FDR_CHECK_EQ(entry.before, std::string("CURRENT"));
      FDR_CHECK_EQ(entry.after, std::string("REVALIDATION_REQUIRED"));
      saw_link_lifecycle = true;
    }
    if (entry.domain == world.row) {
      FDR_CHECK_EQ(entry.before, std::string("CURRENT"));
      FDR_CHECK_EQ(entry.after, std::string("SUPERSEDED"));
      saw_superseded_lifecycle = true;
    }
  }
  FDR_CHECK(saw_link_lifecycle);
  FDR_CHECK(saw_superseded_lifecycle);

  // The supersession names the generations it moved between.
  const std::vector<DiffEntry> superseded = entries_of(session_diff, DiffKind::DomainSuperseded);
  FDR_CHECK_EQ(superseded.size(), std::size_t{1});
  FDR_CHECK_EQ(superseded[0].domain, world.row);
  FDR_CHECK(registry.domain(world.row).has_value());
  FDR_CHECK_EQ(superseded[0].before,
               std::to_string(registry.domain(world.row)->generation.value() - 1u));
  FDR_CHECK_EQ(superseded[0].after, registry.domain(world.row)->generation.to_string());
  FDR_CHECK(!(superseded[0].before == superseded[0].after));

  // The provenance change carries the evidence/truth pair on both sides.
  const std::vector<DiffEntry> domain_provenance =
      entries_of(session_diff, DiffKind::DomainProvenanceChanged);
  FDR_CHECK_EQ(domain_provenance.size(), std::size_t{1});
  FDR_CHECK_EQ(domain_provenance[0].domain, world.conduit);
  FDR_CHECK_EQ(domain_provenance[0].before, std::string("administrative-declaration/REAL"));
  FDR_CHECK_EQ(domain_provenance[0].after,
               std::string("direct-authoritative-infrastructure/REAL"));

  // Membership additions have the member on the after side, and the derived
  // memberships added in this stage are among them.
  const std::vector<DiffEntry> membership_added = entries_of(session_diff, DiffKind::MembershipAdded);
  FDR_CHECK(membership_added.size() >= std::size_t{2});
  for (const DiffEntry& entry : membership_added) {
    FDR_CHECK(entry.before.empty());
    FDR_CHECK_EQ(entry.after, entry.member.to_string());
    FDR_CHECK(!entry.membership.is_null());
  }

  const std::vector<DiffEntry> membership_lifecycle =
      entries_of(session_diff, DiffKind::MembershipLifecycleChanged);
  FDR_CHECK(membership_lifecycle.size() >= std::size_t{1});
  bool saw_cc = false;
  for (const DiffEntry& entry : membership_lifecycle) {
    FDR_CHECK(!entry.before.empty());
    FDR_CHECK(!entry.after.empty());
    if (entry.membership == world.cc_conduit) {
      FDR_CHECK_EQ(entry.domain, world.conduit);
      FDR_CHECK_EQ(entry.member, world.link_cc);
      FDR_CHECK_EQ(entry.before, std::string("CURRENT"));
      FDR_CHECK_EQ(entry.after, std::string("REVALIDATION_REQUIRED"));
      saw_cc = true;
    }
  }
  FDR_CHECK(saw_cc);

  const std::vector<DiffEntry> membership_provenance =
      entries_of(session_diff, DiffKind::MembershipProvenanceChanged);
  bool saw_aa_rack = false;
  bool saw_extra = false;
  for (const DiffEntry& entry : membership_provenance) {
    FDR_CHECK(!entry.before.empty());
    FDR_CHECK(!entry.after.empty());
    FDR_CHECK(!(entry.before == entry.after));
    if (entry.membership == world.aa_rack) {
      FDR_CHECK_EQ(entry.before, std::string("administrative-declaration/REAL"));
      FDR_CHECK_EQ(entry.after, std::string("direct-authoritative-infrastructure/REAL"));
      saw_aa_rack = true;
    }
    if (entry.membership == extra) {
      saw_extra = true;
    }
  }
  FDR_CHECK(saw_aa_rack);
  FDR_CHECK(!saw_extra);

  const std::vector<DiffEntry> derivation_changes =
      entries_of(session_diff, DiffKind::MembershipDerivationChanged);
  FDR_CHECK_EQ(derivation_changes.size(), std::size_t{2});
  for (const DiffEntry& entry : derivation_changes) {
    FDR_CHECK(!entry.before.empty());
    FDR_CHECK_EQ(entry.before, entry.after);
    FDR_CHECK_EQ(entry.domain, world.rack);
  }

  // No diff entry ever reports a kind this session could not have produced:
  // DomainClassChanged has no public operation that changes a committed
  // domain's class, and MembershipMoved has none that re-binds a membership to
  // another domain while keeping its identity - merge_domains creates a new
  // membership id for the survivor and supersedes the absorbed record. Both are
  // therefore unreachable and are asserted as absent here.
  FDR_CHECK_EQ(entries_of(session_diff, DiffKind::DomainClassChanged).size(), std::size_t{0});
  FDR_CHECK_EQ(entries_of(session_diff, DiffKind::MembershipMoved).size(), std::size_t{0});
  FDR_CHECK_EQ(entries_of(session_diff, DiffKind::DomainRemoved).size(), std::size_t{0});
  FDR_CHECK_EQ(entries_of(session_diff, DiffKind::MembershipRemoved).size(), std::size_t{0});
  FDR_CHECK_EQ(entries_of(first_stage, DiffKind::DomainClassChanged).size(), std::size_t{0});
  FDR_CHECK_EQ(entries_of(first_stage, DiffKind::MembershipMoved).size(), std::size_t{0});

  // A reset drops every record, which is the one public operation that produces
  // the two removal kinds.
  const std::size_t domains_before_reset = registry.domain_count();
  const std::size_t memberships_before_reset = registry.membership_count();
  FDR_CHECK_EQ(registry.reset().code, OutcomeCode::Committed);
  const Snapshot after_reset = registry.snapshot("diff");
  FDR_CHECK(after_reset.is_empty());
  const SnapshotDiff removed = registry.diff(after_session, after_reset);
  FDR_CHECK_EQ(kinds_of(removed),
               (std::set<DiffKind>{DiffKind::DomainRemoved, DiffKind::MembershipRemoved}));
  const std::vector<DiffEntry> domain_removed = entries_of(removed, DiffKind::DomainRemoved);
  const std::vector<DiffEntry> membership_removed = entries_of(removed, DiffKind::MembershipRemoved);
  FDR_CHECK_EQ(domain_removed.size(), domains_before_reset);
  FDR_CHECK_EQ(membership_removed.size(), memberships_before_reset);
  for (const DiffEntry& entry : domain_removed) {
    FDR_CHECK(!entry.before.empty());
    FDR_CHECK(entry.after.empty());
    FDR_CHECK(entry.membership.is_null());
  }
  for (const DiffEntry& entry : membership_removed) {
    FDR_CHECK_EQ(entry.before, entry.member.to_string());
    FDR_CHECK(entry.after.empty());
    FDR_CHECK(!entry.domain.is_null());
    FDR_CHECK(!entry.membership.is_null());
  }
  // Every domain and membership kind that can appear in this session does.
  const std::set<DiffKind> first_stage_kinds = kinds_of(first_stage);
  const std::set<DiffKind> session_kinds = kinds_of(session_diff);
  const std::set<DiffKind> removed_kinds = kinds_of(removed);
  std::set<DiffKind> reachable = first_stage_kinds;
  reachable.insert(session_kinds.begin(), session_kinds.end());
  reachable.insert(removed_kinds.begin(), removed_kinds.end());
  FDR_CHECK_EQ(reachable.size(), std::size_t{10});
}

FDR_TEST_CASE(snapshot, diff_entries_are_ordered_by_kind_then_identity) {
  Registry registry(RegistryLimits::defaults());
  Session session;
  bootstrap(registry, session);
  World world;
  build_world(registry, session, world);

  const Snapshot before = registry.snapshot("order");
  const Provenance provenance = administrative();

  // Several domains and memberships of the same kinds, so the ordering has to
  // compare identities inside one kind rather than just the kinds.
  const DomainClass classes[] = {DomainClass::Link, DomainClass::Cable, DomainClass::Pod};
  FailureDomainId added[3] = {};
  for (std::size_t index = 0; index < 3; ++index) {
    added[index] = require_domain(
        registry, create_request(session, classes[index], "dc3",
                                 std::string("order-") + std::to_string(index),
                                 std::string("order ") + std::to_string(index), provenance,
                                 static_cast<std::uint8_t>(0x70u + index)));
  }
  // All three memberships land in the same non-exclusive domain, so their
  // entries differ only in the membership identity the ordering must compare.
  MembershipId memberships[3] = {};
  for (std::size_t index = 0; index < 3; ++index) {
    memberships[index] = require_membership(
        registry,
        attach_request(session, added[1],
                       entity_ref(EntityClass::Host, static_cast<std::uint8_t>(0x50u + index),
                                  EntityGeneration(1)),
                       MembershipRole::Backup, provenance, static_cast<std::uint8_t>(0x74u + index)));
  }
  FDR_CHECK(!memberships[0].is_null());
  FDR_CHECK(!memberships[1].is_null());
  FDR_CHECK(!memberships[2].is_null());

  const Snapshot after = registry.snapshot("order");
  const SnapshotDiff diff = registry.diff(before, after);
  FDR_CHECK(diff.entries.size() >= std::size_t{6});
  for (std::size_t index = 1; index < diff.entries.size(); ++index) {
    FDR_CHECK_MSG(diff_less(diff.entries[index - 1], diff.entries[index]),
                  "diff entries are not ordered at index " + std::to_string(index));
  }
  // The kind ordering is the enumerator ordering, so DomainAdded entries all
  // precede MembershipAdded entries.
  const std::vector<DiffEntry> domain_added = entries_of(diff, DiffKind::DomainAdded);
  const std::vector<DiffEntry> membership_added = entries_of(diff, DiffKind::MembershipAdded);
  FDR_CHECK_EQ(domain_added.size(), std::size_t{3});
  FDR_CHECK_EQ(membership_added.size(), std::size_t{3});
  for (std::size_t index = 1; index < domain_added.size(); ++index) {
    FDR_CHECK(domain_added[index - 1].domain < domain_added[index].domain);
  }
  for (std::size_t index = 1; index < membership_added.size(); ++index) {
    const DiffEntry& left = membership_added[index - 1];
    const DiffEntry& right = membership_added[index];
    FDR_CHECK(left.domain < right.domain ||
              (left.domain == right.domain && left.membership < right.membership));
    FDR_CHECK_EQ(left.domain, added[1]);
    FDR_CHECK_EQ(right.domain, added[1]);
  }
  FDR_CHECK(diff.entries.front().kind == DiffKind::DomainAdded);
  FDR_CHECK(diff.entries.back().kind == DiffKind::MembershipAdded);
}

FDR_TEST_CASE(snapshot, diff_kind_names_cover_every_enumerator) {
  constexpr std::size_t kKindCount = 13;
  const std::string_view names[kKindCount] = {
      "unknown",           "domain-added",        "domain-removed",
      "domain-superseded", "domain-lifecycle-changed", "domain-class-changed",
      "domain-provenance-changed", "membership-added", "membership-removed",
      "membership-moved",  "membership-lifecycle-changed", "membership-provenance-changed",
      "membership-derivation-changed"};

  std::set<std::string_view> unique;
  for (std::size_t index = 0; index < kKindCount; ++index) {
    const DiffKind kind = static_cast<DiffKind>(index);
    const std::string_view name = failure_domain_registry::to_string(kind);
    FDR_CHECK_MSG(!name.empty(), "diff kind " + std::to_string(index) + " has no name");
    FDR_CHECK_EQ(name, names[index]);
    FDR_CHECK_MSG(unique.insert(name).second, "duplicate diff kind name: " + std::string(name));
  }
  FDR_CHECK_EQ(unique.size(), kKindCount);
  FDR_CHECK_EQ(failure_domain_registry::to_string(DiffKind::Unknown), std::string_view("unknown"));
  FDR_CHECK_EQ(failure_domain_registry::to_string(static_cast<DiffKind>(200)),
               std::string_view("unknown"));
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
