// Failure Domain Registry — durable state, reports and conservative recovery.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Everything here touches the real file system through the public persistence
// surface: a registry with domains of several classes, memberships, a relation,
// coverage declarations, two publisher grants, a derivation rule and a fence is
// saved, the file is inspected and read back into a fresh registry, and every
// index is compared against the answer the source registry gave before the
// save. Nothing is simulated and no failure is faked.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
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
using failure_domain_registry::inspect_persistence;
using failure_domain_registry::kStateFormatVersion;
using failure_domain_registry::sha256;
using failure_domain_registry::to_hex;
using failure_domain_registry::AttachMemberRequest;
using failure_domain_registry::AuthorityContext;
using failure_domain_registry::AuthorityScope;
using failure_domain_registry::BlastRadius;
using failure_domain_registry::CoordinatorEpoch;
using failure_domain_registry::CoverageEntry;
using failure_domain_registry::CoverageReport;
using failure_domain_registry::CoverageState;
using failure_domain_registry::CreateDomainRequest;
using failure_domain_registry::DeclareCoverageRequest;
using failure_domain_registry::DependencySemantics;
using failure_domain_registry::DerivationOperator;
using failure_domain_registry::DerivationReport;
using failure_domain_registry::DerivationRule;
using failure_domain_registry::DerivationRunRequest;
using failure_domain_registry::DomainClass;
using failure_domain_registry::DomainClassRef;
using failure_domain_registry::DomainLifecycle;
using failure_domain_registry::DomainRelation;
using failure_domain_registry::DomainRelationType;
using failure_domain_registry::EntityClass;
using failure_domain_registry::EntityGeneration;
using failure_domain_registry::EntityId;
using failure_domain_registry::EntityRef;
using failure_domain_registry::EvidenceClass;
using failure_domain_registry::FailureDomain;
using failure_domain_registry::FailureDomainGeneration;
using failure_domain_registry::FailureDomainId;
using failure_domain_registry::FenceReason;
using failure_domain_registry::IdBytes;
using failure_domain_registry::IndependenceState;
using failure_domain_registry::Membership;
using failure_domain_registry::MembershipId;
using failure_domain_registry::MembershipLifecycle;
using failure_domain_registry::MembershipRole;
using failure_domain_registry::MutationAttempt;
using failure_domain_registry::MutationAttemptId;
using failure_domain_registry::Outcome;
using failure_domain_registry::OutcomeCode;
using failure_domain_registry::OverlapResult;
using failure_domain_registry::PersistenceConfig;
using failure_domain_registry::PersistenceReport;
using failure_domain_registry::Provenance;
using failure_domain_registry::ProvenanceSource;
using failure_domain_registry::PublisherId;
using failure_domain_registry::PublisherRegistration;
using failure_domain_registry::Registry;
using failure_domain_registry::RegistryGeneration;
using failure_domain_registry::RegistryLimits;
using failure_domain_registry::RequestDigest;
using failure_domain_registry::StateDigest;
using failure_domain_registry::TruthClass;
using failure_domain_registry::WorkerBootId;

// ---------------------------------------------------------------------------
// File helpers
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

void spit(const std::filesystem::path& path, std::string_view bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!bytes.empty()) {
    stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }
}

std::size_t count_files(const std::filesystem::path& directory) {
  std::size_t count = 0;
  std::error_code error;
  std::filesystem::directory_iterator iterator(directory, error);
  const std::filesystem::directory_iterator end;
  while (!error && iterator != end) {
    if (iterator->is_regular_file()) {
      ++count;
    }
    iterator.increment(error);
  }
  return count;
}

std::size_t file_bytes(const std::filesystem::path& path) {
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(path, error);
  if (error) {
    return 0;
  }
  return static_cast<std::size_t>(size);
}

/// Removes the directory it owns, including when a case aborts.
struct TempDirectory {
  std::filesystem::path path;

  explicit TempDirectory(const std::string& label) {
    path = std::filesystem::temp_directory_path() / ("fdr-persistence-" + label);
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

  std::filesystem::path image() const { return path / "state.fdr"; }
};

// ---------------------------------------------------------------------------
// Deterministic fixture
// ---------------------------------------------------------------------------

IdBytes pattern_bytes(std::uint8_t seed) {
  IdBytes out{};
  for (std::size_t index = 0; index < out.size(); ++index) {
    out[index] = static_cast<std::uint8_t>((index * 29u + seed * 13u + 1u) & 0xFFu);
  }
  return out;
}

PublisherId publisher_from(std::uint8_t seed) { return PublisherId::from_bytes(pattern_bytes(seed)); }
WorkerBootId boot_from(std::uint8_t seed) { return WorkerBootId::from_bytes(pattern_bytes(seed)); }

MutationAttemptId attempt_from(std::uint8_t seed) {
  return MutationAttemptId::from_bytes(pattern_bytes(static_cast<std::uint8_t>(seed + 0x20u)));
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
  session.publisher = publisher_from(0x31);
  session.worker_boot = boot_from(0x31);

  PublisherRegistration registration;
  registration.publisher = session.publisher;
  registration.name = "persistence-publisher";
  registration.scope = AuthorityScope::unrestricted();
  FDR_CHECK_EQ(registry.grant_publisher(registration, AuthorityContext{}).code,
               OutcomeCode::Committed);

  CoordinatorEpoch epoch;
  FDR_CHECK_EQ(registry.advance_epoch(CoordinatorEpoch{}, &epoch).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(epoch.value(), std::uint64_t{1});

  FDR_CHECK_EQ(registry
                   .attach_worker(session.publisher, session.worker_boot, epoch,
                                  "persistence-worker",
                                  EvidenceClass::DirectAuthoritativeInfrastructure)
                   .code,
               OutcomeCode::Committed);
  session.epoch = epoch;
}

/// Grants a second publisher through the first one and attaches an incarnation.
void grant_second(Registry& registry, const Session& granter, Session& second) {
  second.publisher = publisher_from(0x32);
  second.worker_boot = boot_from(0x32);
  second.epoch = granter.epoch;
  PublisherRegistration registration;
  registration.publisher = second.publisher;
  registration.name = "second-publisher";
  registration.scope = AuthorityScope::unrestricted();
  FDR_CHECK_EQ(registry
                   .grant_publisher(registration,
                                    authority_of(granter,
                                                 EvidenceClass::DirectAuthoritativeInfrastructure))
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(registry
                   .attach_worker(second.publisher, second.worker_boot, granter.epoch,
                                  "second-worker", EvidenceClass::DirectAuthoritativeInfrastructure)
                   .code,
               OutcomeCode::Committed);
}

FailureDomainId require_domain(Registry& registry, const CreateDomainRequest& request) {
  const Outcome outcome = registry.create_domain(request);
  if (outcome.code != OutcomeCode::Committed || !outcome.domain.has_value()) {
    ::fdrtest::fail(__FILE__, __LINE__, "domain create was rejected: " + outcome.message);
    return FailureDomainId{};
  }
  return *outcome.domain;
}

MembershipId require_membership(Registry& registry, const AttachMemberRequest& request) {
  const Outcome outcome = registry.attach_member(request);
  if (outcome.code != OutcomeCode::Committed || !outcome.membership.has_value()) {
    ::fdrtest::fail(__FILE__, __LINE__, "attach was rejected: " + outcome.message);
    return MembershipId{};
  }
  return *outcome.membership;
}

CreateDomainRequest create_request(const Session& session, DomainClass klass, std::string scope,
                                   std::string identity_key, std::string name,
                                   Provenance provenance, std::uint8_t attempt_seed,
                                   std::vector<failure_domain_registry::MetadataEntry> metadata = {}) {
  CreateDomainRequest request;
  request.attempt = MutationAttempt(attempt_from(attempt_seed), RequestDigest{});
  request.authority = authority_of(session, provenance.evidence);
  request.domain_class = DomainClassRef(klass);
  request.administrative_scope = std::move(scope);
  request.identity_key = std::move(identity_key);
  request.name = std::move(name);
  request.provenance = std::move(provenance);
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

// ---------------------------------------------------------------------------
// The rich classification every round-trip case saves
// ---------------------------------------------------------------------------

struct World {
  FailureDomainId rack{};
  FailureDomainId pdu{};
  FailureDomainId conduit{};
  FailureDomainId cable{};
  FailureDomainId row{};
  EntityRef host_aa{};
  EntityRef host_bb{};
  EntityRef link_cc{};
  MembershipId aa_rack{};
  MembershipId aa_pdu{};
  MembershipId bb_pdu{};
  MembershipId cc_conduit{};
  MembershipId cc_cable{};
  std::size_t relations{0};
  std::size_t coverage_declarations{0};
};

/// Domains of several classes, five memberships, two typed relations, two
/// coverage declarations, a second publisher grant, a derivation rule that
/// produces derived memberships and one fence.
void build_world(Registry& registry, const Session& session, World& world) {
  const Provenance durable = provenance_of(ProvenanceSource::OperatorInventory,
                                           EvidenceClass::DirectAuthoritativeInfrastructure,
                                           TruthClass::Real, "inv-1");
  world.rack = require_domain(registry, create_request(session, DomainClass::Rack, "dc1",
                                                       "rack-r1", "rack one", durable, 0x40,
                                                       {{"aisle", "a"}, {"floor", "2"}}));
  world.pdu = require_domain(registry, create_request(session, DomainClass::Pdu, "dc1", "pdu-p1",
                                                      "pdu one", durable, 0x41));
  world.conduit = require_domain(registry, create_request(session, DomainClass::Conduit, "dc2",
                                                          "conduit-c1", "conduit one", durable, 0x42));
  world.cable = require_domain(registry, create_request(session, DomainClass::Cable, "dc2",
                                                        "cable-c1", "cable one", durable, 0x43));
  world.row = require_domain(registry, create_request(session, DomainClass::Row, "dc1", "row-1",
                                                      "row one", durable, 0x44));

  world.host_aa = entity_ref(EntityClass::Host, 0x51, EntityGeneration(1));
  world.host_bb = entity_ref(EntityClass::Host, 0x52, EntityGeneration(1));
  world.link_cc = entity_ref(EntityClass::Link, 0x53, EntityGeneration(1));

  world.aa_rack = require_membership(
      registry,
      attach_request(session, world.rack, world.host_aa, MembershipRole::Primary, durable, 0x45));
  world.aa_pdu = require_membership(
      registry,
      attach_request(session, world.pdu, world.host_aa, MembershipRole::SharedRisk, durable, 0x46));
  world.bb_pdu = require_membership(
      registry,
      attach_request(session, world.pdu, world.host_bb, MembershipRole::SharedRisk, durable, 0x47));
  world.cc_conduit = require_membership(
      registry,
      attach_request(session, world.conduit, world.link_cc, MembershipRole::Primary, durable, 0x48));
  world.cc_cable = require_membership(
      registry,
      attach_request(session, world.cable, world.link_cc, MembershipRole::Redundant, durable, 0x49));

  failure_domain_registry::AddRelationRequest contained;
  contained.attempt = MutationAttempt(attempt_from(0x4A), RequestDigest{});
  contained.authority = authority_of(session, EvidenceClass::DirectAuthoritativeInfrastructure);
  contained.source = world.rack;
  contained.target = world.row;
  contained.type = DomainRelationType::ContainedBy;
  contained.provenance = provenance_of(ProvenanceSource::TopologyDerivation,
                                       EvidenceClass::DerivedTopology, TruthClass::Real, "");
  FDR_CHECK_EQ(registry.add_relation(contained).code, OutcomeCode::Committed);
  world.relations += 1;

  failure_domain_registry::AddRelationRequest powered;
  powered.attempt = MutationAttempt(attempt_from(0x4B), RequestDigest{});
  powered.authority = authority_of(session, EvidenceClass::DirectAuthoritativeInfrastructure);
  powered.source = world.rack;
  powered.target = world.pdu;
  powered.type = DomainRelationType::PoweredBy;
  powered.provenance = provenance_of(ProvenanceSource::TopologyDerivation,
                                     EvidenceClass::DerivedTopology, TruthClass::Real, "");
  FDR_CHECK_EQ(registry.add_relation(powered).code, OutcomeCode::Committed);
  world.relations += 1;

  FDR_CHECK_EQ(registry
                   .declare_coverage(coverage_request(session, "dc1", DomainClass::Rack,
                                                      CoverageState::Complete, durable, 0x4C))
                   .code,
               OutcomeCode::Committed);
  world.coverage_declarations += 1;
  FDR_CHECK_EQ(registry
                   .declare_coverage(coverage_request(session, "dc1", DomainClass::Pdu,
                                                      CoverageState::Partial, durable, 0x4D))
                   .code,
               OutcomeCode::Committed);
  world.coverage_declarations += 1;

  Session second;
  grant_second(registry, session, second);
  FDR_CHECK_EQ(registry
                   .publish_derivation_rule(
                       pdu_members_share_rack(),
                       authority_of(session, EvidenceClass::DirectAuthoritativeInfrastructure))
                   .code,
               OutcomeCode::Committed);

  DerivationReport report;
  DerivationRunRequest run;
  run.attempt = MutationAttempt(attempt_from(0x4E), RequestDigest{});
  run.authority = authority_of(session, EvidenceClass::DirectAuthoritativeInfrastructure);
  FDR_CHECK_EQ(registry.run_derivation(run, &report).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(report.memberships_created, std::size_t{2});

  // One fenced incarnation, so the image carries a fence record as well.
  FDR_CHECK_EQ(registry
                   .fence_worker(second.publisher, second.worker_boot,
                                 FenceReason::Administrative, session.epoch)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.fences().size(), std::size_t{1});
  FDR_CHECK_EQ(registry.publishers().size(), std::size_t{2});
  FDR_CHECK_EQ(registry.derivation_rules().size(), std::size_t{1});
}

PersistenceConfig config_for(const std::filesystem::path& path) {
  PersistenceConfig config;
  config.path = path.string();
  config.durable = true;
  config.atomic = true;
  return config;
}

// ---------------------------------------------------------------------------
// Report helpers
// ---------------------------------------------------------------------------

/// The first unsigned number of every comma-separated segment of a rendered
/// persistence step, e.g. "3 domains, 7 memberships, ... format 1" ->
/// {3, 7, ..., 1}, so the counters save() reports can be compared with the
/// report inspect_persistence() builds.
std::vector<std::uint64_t> leading_numbers(std::string_view text) {
  std::vector<std::uint64_t> out;
  std::size_t index = 0;
  while (index < text.size()) {
    std::size_t end = text.find(',', index);
    if (end == std::string_view::npos) {
      end = text.size();
    }
    const std::string_view segment = text.substr(index, end - index);
    std::size_t cursor = 0;
    while (cursor < segment.size() && !(segment[cursor] >= '0' && segment[cursor] <= '9')) {
      ++cursor;
    }
    if (cursor < segment.size()) {
      std::uint64_t value = 0;
      while (cursor < segment.size() && segment[cursor] >= '0' && segment[cursor] <= '9') {
        value = value * 10u + static_cast<std::uint64_t>(segment[cursor] - '0');
        ++cursor;
      }
      out.push_back(value);
    }
    index = end + 1;
  }
  return out;
}

const failure_domain_registry::ExplanationStep* step_with_field(const Outcome& outcome,
                                                               std::string_view field) {
  for (const failure_domain_registry::ExplanationStep& step : outcome.steps) {
    if (step.field == field) {
      return &step;
    }
  }
  return nullptr;
}

std::vector<FailureDomainId> domain_ids(const std::vector<FailureDomain>& records) {
  std::vector<FailureDomainId> out;
  for (const FailureDomain& record : records) {
    out.push_back(record.id);
  }
  return out;
}

std::vector<MembershipId> membership_ids(const std::vector<Membership>& records) {
  std::vector<MembershipId> out;
  for (const Membership& record : records) {
    out.push_back(record.id);
  }
  return out;
}

std::vector<std::string> relation_forms(const std::vector<DomainRelation>& records) {
  std::vector<std::string> out;
  for (const DomainRelation& record : records) {
    out.push_back(record.canonical_form());
  }
  return out;
}

std::vector<FailureDomainId> sorted(std::vector<FailureDomainId> ids) {
  std::sort(ids.begin(), ids.end());
  return ids;
}

} // namespace

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

FDR_TEST_CASE(persistence, round_trip_restores_the_whole_classification) {
  const TempDirectory directory("round-trip");
  const PersistenceConfig config = config_for(directory.image());

  Registry source(RegistryLimits::defaults());
  Session session;
  bootstrap(source, session);
  World world;
  build_world(source, session, world);

  const std::size_t domains = source.domain_count();
  const std::size_t memberships = source.membership_count();
  const StateDigest digest = source.state_digest();
  const RegistryGeneration generation = source.generation();
  const CoordinatorEpoch epoch = source.epoch();
  FDR_CHECK_EQ(domains, std::size_t{5});
  FDR_CHECK_EQ(memberships, std::size_t{7});

  const auto rack = source.domain(world.rack);
  const auto aa_rack = source.membership(world.aa_rack);
  const auto aa_pdu = source.membership(world.aa_pdu);
  FDR_CHECK(rack.has_value());
  FDR_CHECK(aa_rack.has_value());
  FDR_CHECK(aa_pdu.has_value());
  const std::string rack_form = rack->canonical_form();
  const std::string aa_rack_form = aa_rack->canonical_form();
  const std::string aa_pdu_form = aa_pdu->canonical_form();
  const std::vector<std::string> relation_before = relation_forms(source.relations_of(world.rack));
  FDR_CHECK_EQ(relation_before.size(), std::size_t{2});

  std::string why;
  FDR_CHECK_MSG(source.validate_state(&why), "source registry is inconsistent: " + why);
  FDR_CHECK_EQ(source.save(config).code, OutcomeCode::Committed);
  FDR_CHECK(std::filesystem::exists(directory.image()));

  Registry restored(RegistryLimits::defaults());
  const Outcome loaded = restored.load(config);
  FDR_CHECK_MSG(loaded.code == OutcomeCode::Committed, "load failed: " + loaded.message);

  // Counts, digest, generation and epoch.
  FDR_CHECK_EQ(restored.domain_count(), domains);
  FDR_CHECK_EQ(restored.membership_count(), memberships);
  FDR_CHECK_EQ(restored.state_digest(), digest);
  FDR_CHECK_EQ(restored.epoch(), epoch);
  FDR_CHECK_EQ(restored.generation().value(), generation.value() + 1u);
  why.clear();
  FDR_CHECK_MSG(restored.validate_state(&why), "restored registry is inconsistent: " + why);

  // Records are restored byte for byte, not merely counted.
  FDR_CHECK(restored.domain(world.rack).has_value());
  FDR_CHECK_EQ(restored.domain(world.rack)->canonical_form(), rack_form);
  FDR_CHECK(restored.membership(world.aa_rack).has_value());
  FDR_CHECK_EQ(restored.membership(world.aa_rack)->canonical_form(), aa_rack_form);
  FDR_CHECK(restored.membership(world.aa_pdu).has_value());
  FDR_CHECK_EQ(restored.membership(world.aa_pdu)->canonical_form(), aa_pdu_form);
  FDR_CHECK_EQ(relation_forms(restored.relations_of(world.rack)), relation_before);

  // Grants, fences, rules and coverage crossed the boundary too.
  FDR_CHECK_EQ(restored.publishers().size(), source.publishers().size());
  FDR_CHECK_EQ(restored.fences().size(), std::size_t{1});
  FDR_CHECK_EQ(restored.fences()[0].reason, FenceReason::Administrative);
  FDR_CHECK_EQ(restored.derivation_rules(), source.derivation_rules());
  FDR_CHECK_EQ(restored.derivation_rules().size(), std::size_t{1});
  FDR_CHECK_EQ(restored
                   .coverage("dc1", {DomainClassRef(DomainClass::Rack),
                                     DomainClassRef(DomainClass::Pdu)})
                   .entries,
               source.coverage("dc1", {DomainClassRef(DomainClass::Rack),
                                       DomainClassRef(DomainClass::Pdu)})
                   .entries);

  // Derived memberships keep their derivation identity.
  const std::vector<Membership> derived = restored.members_of(world.rack);
  std::size_t derived_count = 0;
  for (const Membership& record : derived) {
    if (record.kind == failure_domain_registry::MembershipKind::Derived) {
      ++derived_count;
      FDR_CHECK(record.derivation.valid);
      FDR_CHECK(!record.derivation.rule.is_null());
      FDR_CHECK_EQ(record.derivation.sources.size(), record.derivation.source_generations.size());
    }
  }
  FDR_CHECK_EQ(derived_count, std::size_t{2});

  // No live session is ever restored.
  FDR_CHECK_EQ(restored.live_sessions().size(), std::size_t{0});
  FDR_CHECK(!restored.is_worker_live(session.publisher, session.worker_boot));
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

FDR_TEST_CASE(persistence, save_and_inspect_reports_agree_on_the_image) {
  const TempDirectory directory("report");
  const PersistenceConfig config = config_for(directory.image());

  Registry source(RegistryLimits::defaults());
  Session session;
  bootstrap(source, session);
  World world;
  build_world(source, session, world);

  const Outcome saved = source.save(config);
  FDR_CHECK_EQ(saved.code, OutcomeCode::Committed);
  const failure_domain_registry::ExplanationStep* step = step_with_field(saved, "bytes");
  FDR_CHECK(step != nullptr);
  FDR_CHECK_EQ(step->stage, std::string("persist"));

  PersistenceReport report;
  const Outcome inspected = inspect_persistence(config, &report);
  FDR_CHECK_EQ(inspected.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(report.bytes, file_bytes(directory.image()));
  FDR_CHECK_EQ(std::to_string(report.bytes), step->value);
  FDR_CHECK_EQ(report.format_version, kStateFormatVersion);
  FDR_CHECK_EQ(report.generation, source.generation());
  FDR_CHECK_EQ(report.epoch, source.epoch());
  FDR_CHECK_EQ(report.domains, source.domain_count());
  FDR_CHECK_EQ(report.memberships, source.membership_count());
  FDR_CHECK_EQ(report.coverage_declarations, world.coverage_declarations);
  FDR_CHECK_EQ(report.publishers, source.publishers().size());
  FDR_CHECK_EQ(report.fences, source.fences().size());
  FDR_CHECK_EQ(report.derivation_rules, source.derivation_rules().size());

  // The relation count: every edge is returned for both of its endpoints.
  std::size_t relation_endpoints = 0;
  for (const FailureDomain& record : source.domains(64)) {
    relation_endpoints += source.relations_of(record.id).size();
  }
  FDR_CHECK_EQ(relation_endpoints, world.relations * 2);
  FDR_CHECK_EQ(report.relations, world.relations);

  // The save step's rendered counts are the inspected counts.
  const std::vector<std::uint64_t> rendered = leading_numbers(step->detail);
  FDR_CHECK_EQ(rendered.size(), std::size_t{8});
  FDR_CHECK_EQ(rendered[0], static_cast<std::uint64_t>(report.domains));
  FDR_CHECK_EQ(rendered[1], static_cast<std::uint64_t>(report.memberships));
  FDR_CHECK_EQ(rendered[2], static_cast<std::uint64_t>(report.relations));
  FDR_CHECK_EQ(rendered[3], static_cast<std::uint64_t>(report.coverage_declarations));
  FDR_CHECK_EQ(rendered[4], static_cast<std::uint64_t>(report.publishers));
  FDR_CHECK_EQ(rendered[5], static_cast<std::uint64_t>(report.fences));
  FDR_CHECK_EQ(rendered[6], static_cast<std::uint64_t>(report.derivation_rules));
  FDR_CHECK_EQ(rendered[7], static_cast<std::uint64_t>(kStateFormatVersion));

  // The report's digest is the semantic state digest - the value a consumer
  // compares against Registry::state_digest() - while the container's own
  // integrity check stays the payload hash the header carries: recomputable from
  // the file alone, and independent of the canonical forms.
  const std::string image = slurp(directory.image());
  FDR_CHECK_EQ(image.size(), report.bytes);
  const std::string_view payload(image.data() + failure_domain_registry::kStateHeaderBytes,
                                 image.size() - failure_domain_registry::kStateHeaderBytes -
                                     failure_domain_registry::kStateTrailerBytes);
  // magic 8 + version 4 + flags 4 + payload length 8, then the payload hash.
  constexpr std::size_t kPayloadHashOffset = 8u + 4u + 4u + 8u;
  const std::string_view stored_payload_hash(image.data() + kPayloadHashOffset, 32u);
  const auto payload_digest = sha256(payload);
  FDR_CHECK_EQ(
      to_hex(reinterpret_cast<const std::uint8_t*>(stored_payload_hash.data()),
             stored_payload_hash.size()),
      to_hex(payload_digest.data(), payload_digest.size()));
  FDR_CHECK_EQ(report.digest, source.state_digest());

  // A second inspection is byte-for-byte the same, so nothing is cached.
  PersistenceReport again;
  FDR_CHECK_EQ(inspect_persistence(config, &again).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(again.bytes, report.bytes);
  FDR_CHECK_EQ(again.digest, report.digest);
  FDR_CHECK_EQ(again.domains, report.domains);
  FDR_CHECK_EQ(again.memberships, report.memberships);
}

FDR_TEST_CASE(persistence, inspect_rejects_a_corrupted_image_without_trusting_it) {
  const TempDirectory directory("inspect-corrupt");
  const PersistenceConfig config = config_for(directory.image());

  Registry source(RegistryLimits::defaults());
  Session session;
  bootstrap(source, session);
  World world;
  build_world(source, session, world);
  FDR_CHECK_EQ(source.save(config).code, OutcomeCode::Committed);

  PersistenceReport sentinel;
  sentinel.bytes = 12345;
  sentinel.domains = 42;
  sentinel.memberships = 43;
  sentinel.relations = 44;
  sentinel.coverage_declarations = 45;
  sentinel.publishers = 46;
  sentinel.fences = 47;
  sentinel.derivation_rules = 48;
  sentinel.format_version = 999;

  const std::string good = slurp(directory.image());
  FDR_CHECK(good.size() > failure_domain_registry::kStateHeaderBytes +
                             failure_domain_registry::kStateTrailerBytes);
  std::string corrupt = good;
  corrupt[failure_domain_registry::kStateHeaderBytes + 4] =
      static_cast<char>(corrupt[failure_domain_registry::kStateHeaderBytes + 4] ^ 0x5A);
  FDR_CHECK(!(corrupt == good));
  spit(directory.image(), corrupt);

  const Outcome inspected = inspect_persistence(config, &sentinel);
  FDR_CHECK_EQ(inspected.code, OutcomeCode::IntegrityFailure);
  FDR_CHECK(!inspected.message.empty());
  FDR_CHECK_EQ(sentinel.bytes, std::size_t{12345});
  FDR_CHECK_EQ(sentinel.domains, std::size_t{42});
  FDR_CHECK_EQ(sentinel.memberships, std::size_t{43});
  FDR_CHECK_EQ(sentinel.relations, std::size_t{44});
  FDR_CHECK_EQ(sentinel.coverage_declarations, std::size_t{45});
  FDR_CHECK_EQ(sentinel.publishers, std::size_t{46});
  FDR_CHECK_EQ(sentinel.fences, std::size_t{47});
  FDR_CHECK_EQ(sentinel.derivation_rules, std::size_t{48});
  FDR_CHECK_EQ(sentinel.format_version, std::uint32_t{999});

  // load() rejects the same image and leaves the target registry empty.
  Registry target(RegistryLimits::defaults());
  const Outcome loaded = target.load(config);
  FDR_CHECK_EQ(loaded.code, OutcomeCode::IntegrityFailure);
  FDR_CHECK(!loaded.message.empty());
  FDR_CHECK_EQ(target.domain_count(), std::size_t{0});
  FDR_CHECK_EQ(target.membership_count(), std::size_t{0});
  FDR_CHECK_EQ(target.generation().value(), std::uint64_t{0});
  std::string why;
  FDR_CHECK_MSG(target.validate_state(&why), "rejected load left an inconsistent registry: " + why);

  // A truncated image is rejected the same way.
  spit(directory.image(), std::string_view(good).substr(0, good.size() - 7));
  FDR_CHECK_EQ(inspect_persistence(config, &sentinel).code, OutcomeCode::IntegrityFailure);
  FDR_CHECK_EQ(sentinel.bytes, std::size_t{12345});

  // A missing image is not-found-shaped, and an empty path is a configuration
  // failure rather than an integrity failure.
  std::error_code ignored;
  std::filesystem::remove(directory.image(), ignored);
  FDR_CHECK_EQ(inspect_persistence(config, &sentinel).code, OutcomeCode::PersistenceFailure);
  FDR_CHECK_EQ(inspect_persistence(PersistenceConfig{}, &sentinel).code,
               OutcomeCode::PersistenceFailure);
  FDR_CHECK_EQ(sentinel.domains, std::size_t{42});

  Registry absent(RegistryLimits::defaults());
  FDR_CHECK_EQ(absent.load(config).code, OutcomeCode::NotFound);

  // The restored image still inspects cleanly: nothing was remembered from the
  // rejected ones.
  spit(directory.image(), good);
  PersistenceReport fresh;
  FDR_CHECK_EQ(inspect_persistence(config, &fresh).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(fresh.domains, source.domain_count());
  FDR_CHECK_EQ(fresh.memberships, source.membership_count());
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

FDR_TEST_CASE(persistence, configuration_is_honoured_and_leaves_no_temporary_file) {
  const TempDirectory directory("config");

  Registry registry(RegistryLimits::defaults());
  Session session;
  bootstrap(registry, session);
  World world;
  build_world(registry, session, world);
  const RegistryGeneration generation = registry.generation();
  const std::size_t domains = registry.domain_count();
  const StateDigest digest = registry.state_digest();

  // A path in a directory that does not exist is a PersistenceFailure and
  // changes nothing.
  PersistenceConfig missing;
  missing.path = (directory.path / "no-such-directory" / "state.fdr").string();
  missing.durable = true;
  missing.atomic = true;
  const Outcome failed = registry.save(missing);
  FDR_CHECK_EQ(failed.code, OutcomeCode::PersistenceFailure);
  FDR_CHECK(!failed.message.empty());
  FDR_CHECK_EQ(registry.generation(), generation);
  FDR_CHECK_EQ(registry.domain_count(), domains);
  FDR_CHECK_EQ(registry.state_digest(), digest);
  FDR_CHECK(!std::filesystem::exists(missing.path));
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "failed save changed the registry: " + why);

  // An empty path is refused by both directions and by inspection.
  FDR_CHECK_EQ(registry.save(PersistenceConfig{}).code, OutcomeCode::PersistenceFailure);
  FDR_CHECK_EQ(registry.load(PersistenceConfig{}).code, OutcomeCode::PersistenceFailure);
  FDR_CHECK_EQ(inspect_persistence(PersistenceConfig{}, nullptr).code,
               OutcomeCode::PersistenceFailure);
  FDR_CHECK_EQ(registry.state_digest(), digest);
  FDR_CHECK_EQ(count_files(directory.path), std::size_t{0});

  // Every flag combination writes one file, leaves no sibling temporary file,
  // inspects cleanly and reads back into a fresh registry.
  const bool flags[4][2] = {{true, true}, {true, false}, {false, true}, {false, false}};
  for (const auto& flag_pair : flags) {
    PersistenceConfig config;
    config.path = directory.image().string();
    config.durable = flag_pair[0];
    config.atomic = flag_pair[1];
    const Outcome saved = registry.save(config);
    FDR_CHECK_MSG(saved.code == OutcomeCode::Committed,
                  "save with durable=" + std::string(flag_pair[0] ? "true" : "false") +
                      " atomic=" + std::string(flag_pair[1] ? "true" : "false") +
                      " failed: " + saved.message);
    FDR_CHECK(std::filesystem::exists(directory.image()));
    FDR_CHECK_EQ(count_files(directory.path), std::size_t{1});

    PersistenceReport report;
    FDR_CHECK_EQ(inspect_persistence(config, &report).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(report.bytes, file_bytes(directory.image()));

    Registry restored(RegistryLimits::defaults());
    FDR_CHECK_EQ(restored.load(config).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(restored.state_digest(), digest);
    FDR_CHECK_EQ(restored.domain_count(), domains);
    FDR_CHECK_EQ(count_files(directory.path), std::size_t{1});

    std::error_code ignored;
    std::filesystem::remove(directory.image(), ignored);
    FDR_CHECK_EQ(count_files(directory.path), std::size_t{0});
  }

  // Saving twice to the same path is fine and the second image is complete.
  PersistenceConfig config = config_for(directory.image());
  FDR_CHECK_EQ(registry.save(config).code, OutcomeCode::Committed);
  const std::size_t first_bytes = file_bytes(directory.image());
  FDR_CHECK_EQ(registry.save(config).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(file_bytes(directory.image()), first_bytes);
  FDR_CHECK_EQ(count_files(directory.path), std::size_t{1});
  PersistenceReport report;
  FDR_CHECK_EQ(inspect_persistence(config, &report).code, OutcomeCode::Committed);
  // The report's digest is the semantic state digest of the image, so it agrees
  // with the registry it was written from and with the registry that reads it
  // back, not merely with the container's payload hash.
  FDR_CHECK_EQ(report.digest, registry.state_digest());
  Registry reloaded(RegistryLimits::defaults());
  FDR_CHECK_EQ(reloaded.load(config).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(report.digest, reloaded.state_digest());
  const std::string image = slurp(directory.image());
  const std::string_view payload(image.data() + failure_domain_registry::kStateHeaderBytes,
                                 image.size() - failure_domain_registry::kStateHeaderBytes -
                                     failure_domain_registry::kStateTrailerBytes);
  constexpr std::size_t kPayloadHashOffset = 8u + 4u + 4u + 8u;
  const std::string_view stored_payload_hash(image.data() + kPayloadHashOffset, 32u);
  const auto payload_digest = sha256(payload);
  FDR_CHECK_EQ(
      to_hex(reinterpret_cast<const std::uint8_t*>(stored_payload_hash.data()),
             stored_payload_hash.size()),
      to_hex(payload_digest.data(), payload_digest.size()));
}

// ---------------------------------------------------------------------------
// Conservative recovery
// ---------------------------------------------------------------------------

FDR_TEST_CASE(persistence, recovery_demotes_process_bound_evidence_and_keeps_durable_truth) {
  const TempDirectory directory("recovery");
  const PersistenceConfig config = config_for(directory.image());

  Registry source(RegistryLimits::defaults());
  Session first;
  bootstrap(source, first);
  Session second;
  grant_second(source, first, second);

  const Provenance durable = provenance_of(ProvenanceSource::OperatorInventory,
                                           EvidenceClass::DirectAuthoritativeInfrastructure,
                                           TruthClass::Real, "inv-durable");
  const Provenance process_bound = provenance_of(ProvenanceSource::DiscoveryAgent,
                                                 EvidenceClass::DirectHardwareController,
                                                 TruthClass::Real, "probe-1");

  const FailureDomainId durable_domain =
      require_domain(source, create_request(second, DomainClass::Rack, "dc1", "rack-r1",
                                            "durable rack", durable, 0x60));
  const FailureDomainId volatile_domain =
      require_domain(source, create_request(first, DomainClass::Rack, "dc2", "rack-r2",
                                            "volatile rack", process_bound, 0x61,
                                            {{"probed", "yes"}}));
  const EntityRef member = entity_ref(EntityClass::Host, 0x61, EntityGeneration(1));
  const MembershipId durable_membership = require_membership(
      source, attach_request(second, durable_domain, member, MembershipRole::Primary, durable, 0x62));
  const EntityRef other = entity_ref(EntityClass::Host, 0x62, EntityGeneration(1));
  const MembershipId volatile_membership = require_membership(
      source, attach_request(first, volatile_domain, other, MembershipRole::Primary, process_bound,
                             0x63));

  FDR_CHECK_EQ(source
                   .process_bound_incarnations()
                   .size(),
               std::size_t{1});
  FDR_CHECK_EQ(source.save(config).code, OutcomeCode::Committed);

  Registry restored(RegistryLimits::defaults());
  FDR_CHECK_EQ(restored.load(config).code, OutcomeCode::Committed);

  // load() restores durable classification only: no live session comes back and
  // the durable records are untouched.
  FDR_CHECK_EQ(restored.live_sessions().size(), std::size_t{0});
  FDR_CHECK(!restored.is_worker_live(first.publisher, first.worker_boot));
  FDR_CHECK(!restored.is_worker_live(second.publisher, second.worker_boot));
  const auto durable_domain_before = restored.domain(durable_domain);
  const auto durable_membership_before = restored.membership(durable_membership);
  FDR_CHECK(durable_domain_before.has_value());
  FDR_CHECK(durable_membership_before.has_value());
  const std::string durable_domain_form = durable_domain_before->canonical_form();
  const std::string durable_membership_form = durable_membership_before->canonical_form();
  FDR_CHECK_EQ(durable_domain_before->lifecycle, DomainLifecycle::Current);
  FDR_CHECK_EQ(durable_membership_before->lifecycle, MembershipLifecycle::Current);

  // Conservative recovery is exactly what the coordinator performs on startup:
  // every incarnation that published process-bound evidence is fenced.
  const std::vector<std::pair<PublisherId, WorkerBootId>> incarnations =
      restored.process_bound_incarnations();
  FDR_CHECK_EQ(incarnations.size(), std::size_t{1});
  FDR_CHECK_EQ(incarnations[0].first, first.publisher);
  FDR_CHECK_EQ(incarnations[0].second, first.worker_boot);
  for (const std::pair<PublisherId, WorkerBootId>& incarnation : incarnations) {
    const Outcome fenced = restored.fence_worker(incarnation.first, incarnation.second,
                                                 FenceReason::CoordinatorRestart, restored.epoch());
    FDR_CHECK_MSG(fenced.code == OutcomeCode::Committed, "fence failed: " + fenced.message);
  }

  // The process-bound domain and membership are demoted; their durable
  // neighbours are byte-for-byte unchanged.
  const auto volatile_domain_after = restored.domain(volatile_domain);
  const auto volatile_membership_after = restored.membership(volatile_membership);
  FDR_CHECK(volatile_domain_after.has_value());
  FDR_CHECK(volatile_membership_after.has_value());
  FDR_CHECK_EQ(volatile_domain_after->lifecycle, DomainLifecycle::RevalidationRequired);
  FDR_CHECK_EQ(volatile_membership_after->lifecycle, MembershipLifecycle::RevalidationRequired);
  FDR_CHECK_EQ(volatile_membership_after->live_evidence_count(), std::size_t{0});
  // The evidence class is preserved even though the process that published it is
  // gone: the record says what it was, and the lifecycle says it is no longer
  // trustworthy.
  FDR_CHECK_EQ(volatile_membership_after->provenance.evidence,
               EvidenceClass::DirectHardwareController);
  FDR_CHECK(!(volatile_membership_after->canonical_form() == durable_membership_form));

  FDR_CHECK(restored.domain(durable_domain).has_value());
  FDR_CHECK_EQ(restored.domain(durable_domain)->canonical_form(), durable_domain_form);
  FDR_CHECK_EQ(restored.domain(durable_domain)->lifecycle, DomainLifecycle::Current);
  FDR_CHECK_EQ(restored.domain(durable_domain)->generation,
               durable_domain_before->generation);
  FDR_CHECK(restored.membership(durable_membership).has_value());
  FDR_CHECK_EQ(restored.membership(durable_membership)->canonical_form(),
               durable_membership_form);
  FDR_CHECK_EQ(restored.membership(durable_membership)->lifecycle, MembershipLifecycle::Current);
  FDR_CHECK_EQ(restored.membership(durable_membership)->live_evidence_count(), std::size_t{1});
  FDR_CHECK_EQ(restored.membership(durable_membership)->provenance.evidence,
               EvidenceClass::DirectAuthoritativeInfrastructure);

  std::string why;
  FDR_CHECK_MSG(restored.validate_state(&why), "recovered registry is inconsistent: " + why);

  // The old boot ids can never mutate again.
  CreateDomainRequest stale = create_request(first, DomainClass::Pdu, "dc3", "pdu-p3", "pdu three",
                                             durable, 0x64);
  FDR_CHECK_EQ(restored.create_domain(stale).code, OutcomeCode::StaleWorkerBoot);
  FDR_CHECK_EQ(restored
                   .attach_worker(first.publisher, first.worker_boot, restored.epoch(), "again",
                                  EvidenceClass::DirectAuthoritativeInfrastructure)
                   .code,
               OutcomeCode::StaleWorkerBoot);
  FDR_CHECK_EQ(restored.domain_count(), std::size_t{2});

  // A new incarnation of the same publisher is accepted and can mutate, and the
  // durable classification still survives it.
  const WorkerBootId successor = boot_from(0x33);
  FDR_CHECK_EQ(restored
                   .attach_worker(first.publisher, successor, restored.epoch(), "successor",
                                  EvidenceClass::DirectAuthoritativeInfrastructure)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK(restored.is_worker_live(first.publisher, successor));
  CreateDomainRequest fresh = create_request(first, DomainClass::Pdu, "dc3", "pdu-p3", "pdu three",
                                             durable, 0x65);
  fresh.authority.worker_boot = successor;
  FDR_CHECK_EQ(restored.create_domain(fresh).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(restored.domain_count(), std::size_t{3});
  FDR_CHECK_EQ(restored.domain(durable_domain)->canonical_form(), durable_domain_form);
  FDR_CHECK_EQ(restored.membership(durable_membership)->canonical_form(), durable_membership_form);
}

// ---------------------------------------------------------------------------
// Every index after a round trip
// ---------------------------------------------------------------------------

FDR_TEST_CASE(persistence, every_index_agrees_with_the_pre_save_answer) {
  const TempDirectory directory("indexes");
  const PersistenceConfig config = config_for(directory.image());

  Registry source(RegistryLimits::defaults());
  Session session;
  bootstrap(source, session);
  World world;
  build_world(source, session, world);

  const std::vector<FailureDomainId> class_rack =
      domain_ids(source.domains_of_class(DomainClassRef(DomainClass::Rack)));
  const std::vector<FailureDomainId> class_pdu =
      domain_ids(source.domains_of_class(DomainClassRef(DomainClass::Pdu)));
  const std::vector<FailureDomainId> scope_dc1 = domain_ids(source.domains_in_scope("dc1"));
  const std::vector<FailureDomainId> scope_dc2 = domain_ids(source.domains_in_scope("dc2"));
  const std::vector<FailureDomainId> current =
      domain_ids(source.domains_in_lifecycle(DomainLifecycle::Current));
  const std::vector<MembershipId> by_entity =
      membership_ids(source.memberships_of(entity_id(EntityClass::Host, 0x51)));
  const std::vector<MembershipId> by_entity_ref =
      membership_ids(source.memberships_of(world.host_aa));
  const std::vector<MembershipId> by_domain = membership_ids(source.members_of(world.rack));
  const std::vector<MembershipId> by_publisher =
      membership_ids(source.memberships_of_publisher(session.publisher));
  const std::vector<MembershipId> current_memberships =
      membership_ids(source.memberships_in_lifecycle(MembershipLifecycle::Current));
  const auto membership_record = source.membership(world.aa_rack);
  FDR_CHECK(membership_record.has_value());
  const std::string membership_form = membership_record->canonical_form();
  const std::vector<std::string> relations_before = relation_forms(source.relations_of(world.rack));
  const std::vector<FailureDomainId> ancestors_before = source.ancestors(world.rack);
  const std::vector<FailureDomainId> descendants_before = source.descendants(world.row);
  const BlastRadius radius_before = source.blast_radius(world.rack);
  const CoverageReport coverage_before =
      source.coverage("dc1", {DomainClassRef(DomainClass::Rack), DomainClassRef(DomainClass::Pdu)});
  const OverlapResult overlap_before =
      source.overlap(entity_id(EntityClass::Host, 0x51), entity_id(EntityClass::Host, 0x52));

  FDR_CHECK_EQ(class_rack.size(), std::size_t{1});
  FDR_CHECK_EQ(class_pdu.size(), std::size_t{1});
  FDR_CHECK_EQ(scope_dc1.size(), std::size_t{3});
  FDR_CHECK_EQ(scope_dc2.size(), std::size_t{2});
  FDR_CHECK_EQ(current.size(), std::size_t{5});
  // The entity index is by entity id, so it also holds the derived membership
  // the derivation created for that host; the entity-ref query filters by the
  // exact bound generation, which is the same generation here.
  FDR_CHECK_EQ(by_entity.size(), std::size_t{3});
  FDR_CHECK_EQ(by_entity_ref.size(), std::size_t{3});
  FDR_CHECK_EQ(by_domain.size(), std::size_t{3});
  FDR_CHECK_EQ(by_publisher.size(), std::size_t{5});
  FDR_CHECK_EQ(current_memberships.size(), std::size_t{7});
  FDR_CHECK(!ancestors_before.empty());
  FDR_CHECK(!descendants_before.empty());
  // Two distinct members: the host that is both a direct rack member and the
  // subject of a derived membership, and the host the derivation pulled in.
  FDR_CHECK_EQ(radius_before.members.size(), std::size_t{2});
  FDR_CHECK_EQ(coverage_before.entries.size(), std::size_t{2});
  FDR_CHECK_EQ(coverage_before.entries[0].state, CoverageState::Complete);
  FDR_CHECK_EQ(coverage_before.entries[1].state, CoverageState::Partial);
  FDR_CHECK_EQ(overlap_before.state, IndependenceState::SharedDomain);

  FDR_CHECK_EQ(source.save(config).code, OutcomeCode::Committed);
  Registry restored(RegistryLimits::defaults());
  FDR_CHECK_EQ(restored.load(config).code, OutcomeCode::Committed);

  FDR_CHECK_EQ(domain_ids(restored.domains_of_class(DomainClassRef(DomainClass::Rack))), class_rack);
  FDR_CHECK_EQ(domain_ids(restored.domains_of_class(DomainClassRef(DomainClass::Pdu))), class_pdu);
  FDR_CHECK_EQ(domain_ids(restored.domains_in_scope("dc1")), scope_dc1);
  FDR_CHECK_EQ(domain_ids(restored.domains_in_scope("dc2")), scope_dc2);
  FDR_CHECK_EQ(domain_ids(restored.domains_in_lifecycle(DomainLifecycle::Current)), current);
  FDR_CHECK_EQ(membership_ids(restored.memberships_of(entity_id(EntityClass::Host, 0x51))), by_entity);
  FDR_CHECK_EQ(membership_ids(restored.memberships_of(world.host_aa)), by_entity_ref);
  FDR_CHECK_EQ(membership_ids(restored.members_of(world.rack)), by_domain);
  FDR_CHECK_EQ(membership_ids(restored.memberships_of_publisher(session.publisher)), by_publisher);
  FDR_CHECK_EQ(membership_ids(restored.memberships_in_lifecycle(MembershipLifecycle::Current)),
               current_memberships);
  FDR_CHECK(restored.membership(world.aa_rack).has_value());
  FDR_CHECK_EQ(restored.membership(world.aa_rack)->canonical_form(), membership_form);
  FDR_CHECK_EQ(relation_forms(restored.relations_of(world.rack)), relations_before);
  FDR_CHECK_EQ(restored.ancestors(world.rack), ancestors_before);
  FDR_CHECK_EQ(restored.descendants(world.row), descendants_before);

  const BlastRadius radius_after = restored.blast_radius(world.rack);
  FDR_CHECK_EQ(radius_after.domain, radius_before.domain);
  FDR_CHECK_EQ(radius_after.domain_class, radius_before.domain_class);
  FDR_CHECK_EQ(radius_after.generation, radius_before.generation);
  FDR_CHECK_EQ(radius_after.lifecycle, radius_before.lifecycle);
  FDR_CHECK_EQ(radius_after.members, radius_before.members);
  FDR_CHECK_EQ(sorted(radius_after.child_domains), sorted(radius_before.child_domains));
  FDR_CHECK_EQ(sorted(radius_after.related_domains), sorted(radius_before.related_domains));
  FDR_CHECK_EQ(radius_after.truncated, radius_before.truncated);

  FDR_CHECK_EQ(restored.coverage("dc1", {DomainClassRef(DomainClass::Rack),
                                         DomainClassRef(DomainClass::Pdu)})
                   .entries,
               coverage_before.entries);
  const OverlapResult overlap_after =
      restored.overlap(entity_id(EntityClass::Host, 0x51), entity_id(EntityClass::Host, 0x52));
  FDR_CHECK_EQ(overlap_after.state, overlap_before.state);
  FDR_CHECK_EQ(overlap_after.shared.size(), overlap_before.shared.size());
  for (std::size_t index = 0; index < overlap_after.shared.size(); ++index) {
    FDR_CHECK_EQ(overlap_after.shared[index].domain, overlap_before.shared[index].domain);
    FDR_CHECK_EQ(overlap_after.shared[index].domain_class, overlap_before.shared[index].domain_class);
    FDR_CHECK_EQ(overlap_after.shared[index].generation, overlap_before.shared[index].generation);
    FDR_CHECK_EQ(overlap_after.shared[index].members, overlap_before.shared[index].members);
  }
  FDR_CHECK_EQ(overlap_after.uncovered_classes, overlap_before.uncovered_classes);
  FDR_CHECK_EQ(overlap_after.indeterminate_classes, overlap_before.indeterminate_classes);
  FDR_CHECK_EQ(overlap_after.truncated, overlap_before.truncated);
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
