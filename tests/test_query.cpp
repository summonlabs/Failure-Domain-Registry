// Failure Domain Registry — query, overlap, independence and blast-radius proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every answer is driven through the public Registry surface and compared with
// the exact value the runtime produces, including the ordering of the
// shared-domain list and the order of the members inside one shared domain.
// Queries are pure, so the cases that can prove it also assert the state
// generation, the state digest and validate_state after the call.
//
// Two behaviours are asserted as the implementation actually produces them
// rather than as the header comments describe them, because the caller receives
// the implementation:
//
//   * SetCorrelation::shared_domains entries carry no members: correlation
//     reports which domains intersect, never which entities intersect.
//   * overlap reports every domain held by at least two of the addressed
//     entities, so a domain held by a pair is reported even when a third entity
//     was addressed as well; and the indeterminate answers are decided by the
//     lifecycle of the memberships involved, not by the lifecycle of the domain.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "failure_domain_registry/authority.hpp"
#include "failure_domain_registry/coverage.hpp"
#include "failure_domain_registry/domain.hpp"
#include "failure_domain_registry/domain_class.hpp"
#include "failure_domain_registry/entity.hpp"
#include "failure_domain_registry/errors.hpp"
#include "failure_domain_registry/ids.hpp"
#include "failure_domain_registry/lifecycle.hpp"
#include "failure_domain_registry/membership.hpp"
#include "failure_domain_registry/provenance.hpp"
#include "failure_domain_registry/query.hpp"
#include "failure_domain_registry/registry.hpp"
#include "failure_domain_registry/requests.hpp"
#include "support/test_harness.hpp"

namespace {

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
using failure_domain_registry::DetachMemberRequest;
using failure_domain_registry::DomainClass;
using failure_domain_registry::DomainClassRef;
using failure_domain_registry::DomainLifecycle;
using failure_domain_registry::EntityClass;
using failure_domain_registry::EntityGeneration;
using failure_domain_registry::EntityId;
using failure_domain_registry::EntityRef;
using failure_domain_registry::EvidenceClass;
using failure_domain_registry::ExplanationStep;
using failure_domain_registry::FailureDomain;
using failure_domain_registry::FailureDomainGeneration;
using failure_domain_registry::FailureDomainId;
using failure_domain_registry::IdBytes;
using failure_domain_registry::IndependenceResult;
using failure_domain_registry::IndependenceState;
using failure_domain_registry::MarkRevalidationRequest;
using failure_domain_registry::Membership;
using failure_domain_registry::MembershipId;
using failure_domain_registry::MembershipKind;
using failure_domain_registry::MembershipLifecycle;
using failure_domain_registry::MembershipRole;
using failure_domain_registry::MutationAttempt;
using failure_domain_registry::MutationAttemptId;
using failure_domain_registry::Outcome;
using failure_domain_registry::OutcomeCode;
using failure_domain_registry::OverlapResult;
using failure_domain_registry::Provenance;
using failure_domain_registry::ProvenanceSource;
using failure_domain_registry::PublisherId;
using failure_domain_registry::PublisherRegistration;
using failure_domain_registry::Registry;
using failure_domain_registry::RegistryGeneration;
using failure_domain_registry::RegistryLimits;
using failure_domain_registry::RequestDigest;
using failure_domain_registry::SetCorrelation;
using failure_domain_registry::SharedDomain;
using failure_domain_registry::StateDigest;
using failure_domain_registry::TruthClass;
using failure_domain_registry::UpdateDomainRequest;
using failure_domain_registry::WorkerBootId;
using failure_domain_registry::domain_id_for;
using failure_domain_registry::kDomainClassCount;
using failure_domain_registry::to_string;

/// A non-null publisher identity. The first byte distinguishes publishers; the
/// last keeps the rendering from looking like a counter.
PublisherId publisher_from(std::uint8_t seed) {
  IdBytes bytes{};
  bytes[0] = seed;
  bytes[15] = 0xE1u;
  return PublisherId::from_bytes(bytes);
}

WorkerBootId boot_from(std::uint8_t seed) {
  IdBytes bytes{};
  bytes[0] = seed;
  bytes[15] = 0xB1u;
  return WorkerBootId::from_bytes(bytes);
}

/// A canonical entity identity: the class is carried in the bytes too, so two
/// entities of different classes never accidentally share an id.
EntityRef entity_ref(EntityClass entity_class, std::uint8_t seed, std::uint64_t generation) {
  IdBytes bytes{};
  bytes[0] = seed;
  bytes[1] = 0x11u;
  bytes[2] = static_cast<std::uint8_t>(entity_class);
  return EntityRef(EntityId(entity_class, bytes), EntityGeneration(generation));
}

/// Attempts must be unique per mutation: the same id with different content is a
/// conflicting replay, so every helper takes an explicit counter value.
MutationAttempt attempt_from(std::uint64_t counter) {
  IdBytes bytes{};
  bytes[0] = 0x5Du;
  bytes[7] = static_cast<std::uint8_t>((counter >> 8) & 0xFFu);
  bytes[15] = static_cast<std::uint8_t>(counter & 0xFFu);
  return MutationAttempt(MutationAttemptId::from_bytes(bytes), RequestDigest{});
}

Provenance provenance_of(ProvenanceSource source, EvidenceClass evidence, TruthClass truth,
                         std::string_view source_identity) {
  Provenance provenance;
  provenance.source = source;
  provenance.evidence = evidence;
  provenance.truth = truth;
  provenance.source_identity = std::string(source_identity);
  return provenance;
}

/// A registry with one bootstrap publisher attached and the epoch established.
/// The helper never asserts: every case calls require_fixture() first, so a
/// broken fixture is reported as a fixture failure rather than as a query
/// defect.
struct Fixture {
  std::unique_ptr<Registry> registry;
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  CoordinatorEpoch epoch{};
  AuthorityContext authority{};
  Provenance provenance{};
};

Fixture make_fixture(RegistryLimits limits) {
  Fixture fixture;
  fixture.registry = std::make_unique<Registry>(limits);
  fixture.publisher = publisher_from(0x01u);
  fixture.worker_boot = boot_from(0x02u);
  PublisherRegistration registration;
  registration.publisher = fixture.publisher;
  registration.name = "query-publisher";
  registration.scope = AuthorityScope::unrestricted();
  fixture.registry->grant_publisher(registration, AuthorityContext{});
  CoordinatorEpoch epoch;
  if (fixture.registry->advance_epoch(CoordinatorEpoch{}, &epoch).committed()) {
    fixture.epoch = epoch;
  }
  fixture.registry->attach_worker(fixture.publisher, fixture.worker_boot, fixture.epoch,
                                  "query-suite", EvidenceClass::DirectAuthoritativeInfrastructure);
  fixture.authority.publisher = fixture.publisher;
  fixture.authority.worker_boot = fixture.worker_boot;
  fixture.authority.epoch = fixture.epoch;
  fixture.authority.evidence = EvidenceClass::DirectAuthoritativeInfrastructure;
  fixture.provenance = provenance_of(ProvenanceSource::PhysicalInfrastructure,
                                     EvidenceClass::DirectAuthoritativeInfrastructure, TruthClass::Real,
                                     "query-inventory");
  return fixture;
}

/// Fails the case unless the bootstrap fixture is fully live. Without the epoch
/// every mutation below would come back STALE_EPOCH, which is easy to misread.
void require_fixture(Registry& registry, const Fixture& fixture) {
  FDR_CHECK_EQ(fixture.epoch.value(), std::uint64_t{1});
  FDR_CHECK(registry.is_worker_live(fixture.publisher, fixture.worker_boot));
  FDR_CHECK(registry.publisher(fixture.publisher).has_value());
  FDR_CHECK_EQ(registry.generation().is_zero(), false);
}

/// A committed domain creation and the identity it addressed.
struct DomainHandle {
  Outcome outcome;
  FailureDomainId id{};
};

DomainHandle create_domain(Registry& registry, const Fixture& fixture, DomainClass domain_class,
                           const std::string& scope, const std::string& identity_key,
                           std::uint64_t attempt_number) {
  CreateDomainRequest request;
  request.attempt = attempt_from(attempt_number);
  request.authority = fixture.authority;
  request.domain_class = DomainClassRef(domain_class);
  request.administrative_scope = scope;
  request.identity_key = identity_key;
  request.name = identity_key;
  request.provenance = fixture.provenance;
  DomainHandle handle;
  handle.outcome = registry.create_domain(request);
  handle.id = domain_id_for(scope, DomainClassRef(domain_class), identity_key);
  return handle;
}

Outcome attach_entity(Registry& registry, const Fixture& fixture, const FailureDomainId& domain,
                      const EntityRef& member, std::uint64_t attempt_number,
                      MembershipKind kind = MembershipKind::Direct,
                      const Provenance& provenance = Provenance{}) {
  AttachMemberRequest request;
  request.attempt = attempt_from(attempt_number);
  request.authority = fixture.authority;
  request.domain = domain;
  request.member = member;
  request.kind = kind;
  request.role = MembershipRole::Primary;
  request.provenance =
      provenance.source == ProvenanceSource::Unknown ? fixture.provenance : provenance;
  return registry.attach_member(request);
}

using failure_domain_registry::AddRelationRequest;
using failure_domain_registry::DomainRelationType;

Outcome add_relation(Registry& registry, const Fixture& fixture, const FailureDomainId& source,
                     const FailureDomainId& target, std::uint64_t attempt_number,
                     DomainRelationType type = DomainRelationType::ContainedBy) {
  AddRelationRequest request;
  request.attempt = attempt_from(attempt_number);
  request.authority = fixture.authority;
  request.source = source;
  request.target = target;
  request.type = type;
  request.provenance = fixture.provenance;
  return registry.add_relation(request);
}

Outcome declare_coverage(Registry& registry, const Fixture& fixture, const std::string& scope,
                         DomainClass domain_class, CoverageState state,
                         std::uint64_t attempt_number,
                         ProvenanceSource source = ProvenanceSource::PhysicalInfrastructure) {
  DeclareCoverageRequest request;
  request.attempt = attempt_from(attempt_number);
  request.authority = fixture.authority;
  request.administrative_scope = scope;
  request.domain_class = DomainClassRef(domain_class);
  request.state = state;
  request.provenance = provenance_of(source, EvidenceClass::DirectAuthoritativeInfrastructure,
                                     TruthClass::Real, "query-coverage");
  return registry.declare_coverage(request);
}

/// Declares one state for every canonical class in one scope. The overlap form
/// of the query addresses every class, so only a complete scope can prove
/// anything to it.
Outcome declare_every_class(Registry& registry, const Fixture& fixture, const std::string& scope,
                            CoverageState state, std::uint64_t first_attempt) {
  Outcome outcome = Outcome::make(OutcomeCode::NotFound, "no class was declared");
  for (std::uint8_t raw = 1; raw <= kDomainClassCount; ++raw) {
    outcome = declare_coverage(registry, fixture, scope, static_cast<DomainClass>(raw), state,
                               first_attempt + raw);
  }
  return outcome;
}

/// The current membership of one entity in one domain, or the null id.
MembershipId membership_of(Registry& registry, const FailureDomainId& domain,
                           const EntityRef& member) {
  for (const Membership& membership : registry.memberships_of(member.id())) {
    if (membership.domain == domain) {
      return membership.id;
    }
  }
  return MembershipId{};
}

bool has_step(const std::vector<ExplanationStep>& steps, std::string_view stage) {
  for (const ExplanationStep& step : steps) {
    if (step.stage == stage) {
      return true;
    }
  }
  return false;
}

/// The named field of a step, whatever stage produced it.
bool has_field(const std::vector<ExplanationStep>& steps, std::string_view field) {
  for (const ExplanationStep& step : steps) {
    if (step.field == field) {
      return true;
    }
  }
  return false;
}

/// True when the report addresses the class and a declaration exists for it.
bool is_declared(const CoverageReport& report, const DomainClassRef& domain_class) {
  for (const CoverageEntry& entry : report.entries) {
    if (entry.domain_class == domain_class) {
      return entry.declared;
    }
  }
  return false;
}

/// Ascending domain-id order: the canonical order every ordered query result is
/// returned in.
std::vector<FailureDomainId> sorted_ids(std::vector<FailureDomainId> ids) {
  std::sort(ids.begin(), ids.end());
  return ids;
}

} // namespace

// ---------------------------------------------------------------------------
// Overlap
// ---------------------------------------------------------------------------

FDR_TEST_CASE(query, overlap_two_entities_in_one_current_domain_is_shared) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 1);
  const DomainHandle other_rack = create_domain(*fixture.registry, fixture, DomainClass::Rack,
                                                "dc1", "rack-2", 2);
  FDR_CHECK_EQ(rack.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(other_rack.outcome.code, OutcomeCode::Committed);

  const EntityRef left = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef right = entity_ref(EntityClass::Switch, 0x02u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, left, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, right, 11).code,
               OutcomeCode::Committed);

  const OverlapResult result = fixture.registry->overlap(left.id(), right.id());
  FDR_CHECK_EQ(result.state, IndependenceState::SharedDomain);
  FDR_CHECK(result.shares_any_domain());
  FDR_CHECK(!result.truncated);
  FDR_CHECK_EQ(result.shared.size(), std::size_t{1});
  FDR_CHECK(result.uncovered_classes.empty());
  FDR_CHECK(result.indeterminate_classes.empty());

  const SharedDomain& shared = result.shared.front();
  FDR_CHECK_EQ(shared.domain, rack.id);
  FDR_CHECK(!(shared.domain == other_rack.id));
  FDR_CHECK_EQ(shared.domain_class, DomainClassRef(DomainClass::Rack));
  FDR_CHECK(shared.generation == FailureDomainGeneration(1));
  FDR_CHECK(shared.most_specific);
  FDR_CHECK_EQ(shared.members.size(), std::size_t{2});
  FDR_CHECK(shared.members[0] == left);
  FDR_CHECK(shared.members[1] == right);

  // A positive answer names the stage that produced it.
  FDR_CHECK(has_step(result.steps, "overlap"));
  FDR_CHECK(has_step(result.steps, "membership"));
}

FDR_TEST_CASE(query, overlap_reports_shared_members_in_caller_order) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 1);
  FDR_CHECK_EQ(rack.outcome.code, OutcomeCode::Committed);
  const EntityRef left = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef right = entity_ref(EntityClass::Switch, 0x02u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, left, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, right, 11).code,
               OutcomeCode::Committed);

  const OverlapResult forward = fixture.registry->overlap(left.id(), right.id());
  const OverlapResult backward = fixture.registry->overlap(right.id(), left.id());
  FDR_CHECK_EQ(forward.shared.size(), std::size_t{1});
  FDR_CHECK_EQ(backward.shared.size(), std::size_t{1});
  FDR_CHECK_EQ(forward.shared.front().members.size(), std::size_t{2});
  FDR_CHECK(forward.shared.front().members[0] == left);
  FDR_CHECK(forward.shared.front().members[1] == right);
  FDR_CHECK(backward.shared.front().members[0] == right);
  FDR_CHECK(backward.shared.front().members[1] == left);

  // The two-entity overload is the vector overload with the two ids in order.
  const std::vector<EntityId> addressed{right.id(), left.id()};
  const OverlapResult vector_form = fixture.registry->overlap(addressed);
  FDR_CHECK_EQ(vector_form.state, IndependenceState::SharedDomain);
  FDR_CHECK_EQ(vector_form.shared.size(), std::size_t{1});
  FDR_CHECK(vector_form.shared.front() == backward.shared.front());
  FDR_CHECK(!(vector_form.shared.front() == forward.shared.front()));
}

FDR_TEST_CASE(query, overlap_without_a_shared_domain_needs_complete_coverage) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle first = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                           "rack-1", 1);
  const DomainHandle second = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                            "rack-2", 2);
  const EntityRef left = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef right = entity_ref(EntityClass::Switch, 0x02u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, first.id, left, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, second.id, right, 11).code,
               OutcomeCode::Committed);

  // Nothing was declared, so the absence of a shared domain proves nothing and
  // the answer says so instead of claiming independence.
  const OverlapResult unknown = fixture.registry->overlap(left.id(), right.id());
  FDR_CHECK_EQ(unknown.state, IndependenceState::NoKnowledge);
  FDR_CHECK(unknown.shared.empty());
  FDR_CHECK(!unknown.shares_any_domain());
  FDR_CHECK_EQ(unknown.uncovered_classes.size(), static_cast<std::size_t>(kDomainClassCount));

  // One declared class is not enough for a query that addresses all of them.
  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Rack,
                                CoverageState::Complete, 20)
                   .code,
               OutcomeCode::Committed);
  const OverlapResult partial = fixture.registry->overlap(left.id(), right.id());
  FDR_CHECK_EQ(partial.state, IndependenceState::UnknownCoverage);
  FDR_CHECK(partial.shared.empty());
  FDR_CHECK_EQ(partial.uncovered_classes.size(),
               static_cast<std::size_t>(kDomainClassCount) - 1u);

  FDR_CHECK_EQ(declare_every_class(*fixture.registry, fixture, "dc1", CoverageState::Complete, 100)
                   .code,
               OutcomeCode::Committed);
  const OverlapResult complete = fixture.registry->overlap(left.id(), right.id());
  FDR_CHECK_EQ(complete.state, IndependenceState::ProvenIndependent);
  FDR_CHECK(complete.shared.empty());
  FDR_CHECK(complete.uncovered_classes.empty());
  FDR_CHECK(has_step(complete.steps, "overlap"));
  FDR_CHECK(has_field(complete.steps, "coverage"));
}

FDR_TEST_CASE(query, overlap_reports_every_shared_domain_with_the_most_specific_flagged) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle pod = create_domain(*fixture.registry, fixture, DomainClass::Pod, "dc1",
                                         "pod-1", 1);
  const DomainHandle row = create_domain(*fixture.registry, fixture, DomainClass::Row, "dc1",
                                         "row-1", 2);
  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 3);
  const DomainHandle conduit_a = create_domain(*fixture.registry, fixture, DomainClass::Conduit,
                                               "dc1", "conduit-a", 4);
  const DomainHandle conduit_b = create_domain(*fixture.registry, fixture, DomainClass::Conduit,
                                               "dc1", "conduit-b", 5);
  FDR_CHECK_EQ(pod.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(row.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(rack.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(conduit_a.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(conduit_b.outcome.code, OutcomeCode::Committed);

  // Rack is contained by Row, Row is contained by Pod: the containment chain the
  // most-specific flag is computed from.
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, rack.id, row.id, 30).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, row.id, pod.id, 31).code,
               OutcomeCode::Committed);

  const EntityRef left = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef right = entity_ref(EntityClass::Switch, 0x02u, 1);
  const FailureDomainId shared_domains[] = {pod.id, row.id, rack.id, conduit_a.id, conduit_b.id};
  std::uint64_t attempt = 40;
  for (const FailureDomainId& domain : shared_domains) {
    FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, domain, left, attempt++).code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, domain, right, attempt++).code,
                 OutcomeCode::Committed);
  }

  const OverlapResult result = fixture.registry->overlap(left.id(), right.id());
  FDR_CHECK_EQ(result.state, IndependenceState::SharedDomain);
  FDR_CHECK_EQ(result.shared.size(), std::size_t{5});

  // Ordered by class name, then by domain id inside one class.
  const FailureDomainId first_conduit =
      conduit_a.id < conduit_b.id ? conduit_a.id : conduit_b.id;
  const FailureDomainId second_conduit =
      conduit_a.id < conduit_b.id ? conduit_b.id : conduit_a.id;
  FDR_CHECK_EQ(result.shared[0].domain_class, DomainClassRef(DomainClass::Conduit));
  FDR_CHECK_EQ(result.shared[0].domain, first_conduit);
  FDR_CHECK_EQ(result.shared[1].domain_class, DomainClassRef(DomainClass::Conduit));
  FDR_CHECK_EQ(result.shared[1].domain, second_conduit);
  FDR_CHECK_EQ(result.shared[2].domain, pod.id);
  FDR_CHECK_EQ(result.shared[3].domain, rack.id);
  FDR_CHECK_EQ(result.shared[4].domain, row.id);

  // A shared domain is most specific when no other shared domain is contained by
  // it. Pod contains Row which contains Rack, and all three are shared, so only
  // the rack qualifies; the two conduits contain nothing at all, so each of them
  // is most specific inside its own disconnected subgraph.
  FDR_CHECK(result.shared[0].most_specific);
  FDR_CHECK(result.shared[1].most_specific);
  FDR_CHECK(!result.shared[2].most_specific);
  FDR_CHECK(result.shared[3].most_specific);
  FDR_CHECK(!result.shared[4].most_specific);

  for (const SharedDomain& shared : result.shared) {
    FDR_CHECK_EQ(shared.members.size(), std::size_t{2});
    FDR_CHECK(shared.members[0] == left);
    FDR_CHECK(shared.members[1] == right);
  }
}

FDR_TEST_CASE(query, overlap_is_shared_by_a_pair_even_when_a_larger_set_is_addressed) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 1);
  const DomainHandle conduit = create_domain(*fixture.registry, fixture, DomainClass::Conduit,
                                             "dc1", "conduit-1", 2);
  const DomainHandle private_conduit = create_domain(*fixture.registry, fixture,
                                                     DomainClass::Conduit, "dc1", "conduit-2", 3);
  FDR_CHECK_EQ(rack.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(conduit.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(private_conduit.outcome.code, OutcomeCode::Committed);

  const EntityRef first = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef second = entity_ref(EntityClass::Switch, 0x02u, 1);
  const EntityRef third = entity_ref(EntityClass::Switch, 0x03u, 1);
  const EntityRef unaddressed = entity_ref(EntityClass::Switch, 0x04u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, first, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, second, 11).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, unaddressed, 12).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, conduit.id, first, 13).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, conduit.id, second, 14).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, conduit.id, third, 15).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, private_conduit.id, third, 16).code,
               OutcomeCode::Committed);

  const std::vector<EntityId> addressed{first.id(), second.id(), third.id()};
  const OverlapResult result = fixture.registry->overlap(addressed);
  FDR_CHECK_EQ(result.state, IndependenceState::SharedDomain);
  FDR_CHECK_EQ(result.shared.size(), std::size_t{2});
  FDR_CHECK_EQ(result.shared[0].domain, conduit.id);
  FDR_CHECK_EQ(result.shared[1].domain, rack.id);

  // The conduit is held by all three addressed entities.
  FDR_CHECK_EQ(result.shared[0].members.size(), std::size_t{3});
  FDR_CHECK(result.shared[0].members[0] == first);
  FDR_CHECK(result.shared[0].members[1] == second);
  FDR_CHECK(result.shared[0].members[2] == third);

  // The rack is held by two of the three, and that is enough to be reported; the
  // unaddressed member is never listed.
  FDR_CHECK_EQ(result.shared[1].members.size(), std::size_t{2});
  FDR_CHECK(result.shared[1].members[0] == first);
  FDR_CHECK(result.shared[1].members[1] == second);
  for (const SharedDomain& shared : result.shared) {
    for (const EntityRef& member : shared.members) {
      FDR_CHECK(!(member == unaddressed));
    }
  }

  // A domain held by a single addressed entity is not an overlap.
  FDR_CHECK(!(result.shared[0].domain == private_conduit.id));
}

FDR_TEST_CASE(query, overlap_beyond_the_query_cardinality_is_truncated) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_query_set_cardinality = 3;
  Fixture fixture = make_fixture(limits);
  require_fixture(*fixture.registry, fixture);
  FDR_CHECK_EQ(fixture.registry->limits().max_query_set_cardinality, std::size_t{3});

  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 1);
  FDR_CHECK_EQ(rack.outcome.code, OutcomeCode::Committed);
  const EntityRef members[5] = {entity_ref(EntityClass::Switch, 0x01u, 1),
                                entity_ref(EntityClass::Switch, 0x02u, 1),
                                entity_ref(EntityClass::Switch, 0x03u, 1),
                                entity_ref(EntityClass::Switch, 0x04u, 1),
                                entity_ref(EntityClass::Switch, 0x05u, 1)};
  std::uint64_t attempt = 10;
  std::vector<EntityId> addressed;
  for (const EntityRef& member : members) {
    FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, member, attempt++).code,
                 OutcomeCode::Committed);
    addressed.push_back(member.id());
  }

  const OverlapResult truncated = fixture.registry->overlap(addressed);
  FDR_CHECK(truncated.truncated);
  FDR_CHECK_EQ(truncated.state, IndependenceState::SharedDomain);
  FDR_CHECK_EQ(truncated.shared.size(), std::size_t{1});
  FDR_CHECK_EQ(truncated.shared.front().members.size(), std::size_t{3});
  FDR_CHECK(truncated.shared.front().members[0] == members[0]);
  FDR_CHECK(truncated.shared.front().members[1] == members[1]);
  FDR_CHECK(truncated.shared.front().members[2] == members[2]);
  FDR_CHECK(has_step(truncated.steps, "limit"));

  // The independence form reports the same truncation.
  const IndependenceResult independence = fixture.registry->independence(
      addressed, std::vector<DomainClassRef>{DomainClassRef(DomainClass::Rack)});
  FDR_CHECK(independence.truncated);
  FDR_CHECK_EQ(independence.state, IndependenceState::SharedDomain);
  FDR_CHECK_EQ(independence.shared.size(), std::size_t{1});
  FDR_CHECK_EQ(independence.shared.front().members.size(), std::size_t{3});

  // The same five entities under the default bound are all addressed.
  Fixture roomy = make_fixture(RegistryLimits::defaults());
  require_fixture(*roomy.registry, roomy);
  const DomainHandle roomy_rack = create_domain(*roomy.registry, roomy, DomainClass::Rack, "dc1",
                                                "rack-1", 1);
  FDR_CHECK_EQ(roomy_rack.outcome.code, OutcomeCode::Committed);
  attempt = 10;
  for (const EntityRef& member : members) {
    FDR_CHECK_EQ(attach_entity(*roomy.registry, roomy, roomy_rack.id, member, attempt++).code,
                 OutcomeCode::Committed);
  }
  const OverlapResult complete = roomy.registry->overlap(addressed);
  FDR_CHECK(!complete.truncated);
  FDR_CHECK_EQ(complete.shared.size(), std::size_t{1});
  FDR_CHECK_EQ(complete.shared.front().members.size(), std::size_t{5});
}

FDR_TEST_CASE(query, overlap_is_revalidation_required_when_a_membership_needs_revalidation) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 1);
  FDR_CHECK_EQ(rack.outcome.code, OutcomeCode::Committed);
  const EntityRef left = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef right = entity_ref(EntityClass::Switch, 0x02u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, left, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, right, 11).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(fixture.registry->overlap(left.id(), right.id()).state,
               IndependenceState::SharedDomain);

  const MembershipId membership = membership_of(*fixture.registry, rack.id, left);
  FDR_CHECK(!membership.is_null());
  MarkRevalidationRequest mark;
  mark.attempt = attempt_from(20);
  mark.authority = fixture.authority;
  mark.membership = membership;
  mark.reason = "query-suite";
  FDR_CHECK_EQ(fixture.registry->mark_revalidation_required(mark).code, OutcomeCode::Committed);
  const std::optional<Membership> demoted = fixture.registry->membership(membership);
  FDR_CHECK(demoted.has_value());
  FDR_CHECK_EQ(demoted->lifecycle, MembershipLifecycle::RevalidationRequired);

  const OverlapResult result = fixture.registry->overlap(left.id(), right.id());
  FDR_CHECK_EQ(result.state, IndependenceState::RevalidationRequired);
  FDR_CHECK(result.shared.empty());
  FDR_CHECK_EQ(result.indeterminate_classes.size(), std::size_t{1});
  FDR_CHECK(has_step(result.steps, "overlap"));
}

FDR_TEST_CASE(query, overlap_is_conflicted_when_a_membership_is_conflicted) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 1);
  FDR_CHECK_EQ(rack.outcome.code, OutcomeCode::Committed);
  const EntityRef left = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef right = entity_ref(EntityClass::Switch, 0x02u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, left, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, right, 11).code,
               OutcomeCode::Committed);

  // Equally strong evidence from a different source is a conflict, not a win.
  const Provenance other = provenance_of(ProvenanceSource::Cmdb,
                                         EvidenceClass::DirectAuthoritativeInfrastructure,
                                         TruthClass::Real, "query-cmdb");
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, right, 12, MembershipKind::Direct,
                             other)
                   .code,
               OutcomeCode::MembershipConflict);
  const MembershipId membership = membership_of(*fixture.registry, rack.id, right);
  const std::optional<Membership> conflicted = fixture.registry->membership(membership);
  FDR_CHECK(conflicted.has_value());
  FDR_CHECK_EQ(conflicted->lifecycle, MembershipLifecycle::Conflicted);

  const OverlapResult result = fixture.registry->overlap(left.id(), right.id());
  FDR_CHECK_EQ(result.state, IndependenceState::Conflicted);
  FDR_CHECK(result.shared.empty());
  FDR_CHECK(!result.indeterminate_classes.empty());
}

FDR_TEST_CASE(query, overlap_keys_indeterminacy_on_memberships_not_on_the_domain) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle first = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                           "rack-1", 1);
  const DomainHandle second = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                            "rack-2", 2);
  FDR_CHECK_EQ(first.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(second.outcome.code, OutcomeCode::Committed);
  const EntityRef left = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef right = entity_ref(EntityClass::Switch, 0x02u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, first.id, left, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, second.id, right, 11).code,
               OutcomeCode::Committed);

  // The domain needs revalidation, but its memberships are still current. The
  // answer is decided by the memberships, so this is an ordinary negative answer
  // in an unclassified scope - never REVALIDATION_REQUIRED on the domain alone.
  UpdateDomainRequest update;
  update.attempt = attempt_from(20);
  update.authority = fixture.authority;
  update.domain = first.id;
  update.expected_generation = FailureDomainGeneration(1);
  update.transition = DomainLifecycle::RevalidationRequired;
  FDR_CHECK_EQ(fixture.registry->update_domain(update).code, OutcomeCode::Committed);
  const std::optional<FailureDomain> record = fixture.registry->domain(first.id);
  FDR_CHECK(record.has_value());
  FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::RevalidationRequired);

  const OverlapResult result = fixture.registry->overlap(left.id(), right.id());
  FDR_CHECK_EQ(result.state, IndependenceState::NoKnowledge);
  FDR_CHECK(result.indeterminate_classes.empty());
  FDR_CHECK(result.shared.empty());

  const BlastRadius radius = fixture.registry->blast_radius(first.id);
  FDR_CHECK_EQ(radius.lifecycle, DomainLifecycle::RevalidationRequired);
  FDR_CHECK_EQ(radius.members.size(), std::size_t{1});
  FDR_CHECK(radius.members.front() == left);
}

// ---------------------------------------------------------------------------
// Independence
// ---------------------------------------------------------------------------

FDR_TEST_CASE(query, independence_requires_complete_coverage_of_every_addressed_class) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle first = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                           "rack-1", 1);
  const DomainHandle second = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                            "rack-2", 2);
  const EntityRef left = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef right = entity_ref(EntityClass::Switch, 0x02u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, first.id, left, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, second.id, right, 11).code,
               OutcomeCode::Committed);

  const std::vector<EntityId> addressed{left.id(), right.id()};
  const std::vector<DomainClassRef> classes{DomainClassRef(DomainClass::Rack),
                                            DomainClassRef(DomainClass::Pod)};

  const IndependenceResult unknown = fixture.registry->independence(addressed, classes);
  FDR_CHECK_EQ(unknown.state, IndependenceState::NoKnowledge);
  FDR_CHECK(!unknown.proven_independent());
  FDR_CHECK_EQ(unknown.coverage.entries.size(), std::size_t{2});
  FDR_CHECK_EQ(unknown.coverage.entries[0].domain_class, DomainClassRef(DomainClass::Rack));
  FDR_CHECK_EQ(unknown.coverage.entries[1].domain_class, DomainClassRef(DomainClass::Pod));

  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Rack,
                                CoverageState::Complete, 20)
                   .code,
               OutcomeCode::Committed);
  const IndependenceResult partial = fixture.registry->independence(addressed, classes);
  FDR_CHECK_EQ(partial.state, IndependenceState::UnknownCoverage);
  FDR_CHECK(!partial.proven_independent());

  // The report preserves the caller's class order and marks which classes were
  // declared, and a declared COMPLETE really is reported as complete.
  const CoverageReport report = partial.coverage;
  FDR_CHECK_EQ(report.entries.size(), std::size_t{2});
  FDR_CHECK_EQ(report.entries[0].domain_class, DomainClassRef(DomainClass::Rack));
  FDR_CHECK(report.entries[0].declared);
  FDR_CHECK_EQ(report.entries[0].state, CoverageState::Complete);
  FDR_CHECK_EQ(report.entries[1].domain_class, DomainClassRef(DomainClass::Pod));
  FDR_CHECK(!report.entries[1].declared);
  FDR_CHECK_EQ(report.entries[1].state, CoverageState::UnknownCoverage);
  FDR_CHECK_EQ(report.entries[0].administrative_scope, std::string("dc1"));
  FDR_CHECK(report.has_unknown);
  FDR_CHECK(!report.complete_for_all);

  // A class that is only PARTIAL cannot prove independence either.
  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Pod,
                                CoverageState::Partial, 21)
                   .code,
               OutcomeCode::Committed);
  const IndependenceResult partly = fixture.registry->independence(addressed, classes);
  FDR_CHECK_EQ(partly.state, IndependenceState::UnknownCoverage);
  FDR_CHECK(!partly.proven_independent());
  FDR_CHECK_EQ(partly.coverage.entries[1].state, CoverageState::Partial);
  FDR_CHECK(partly.coverage.has_partial);
  FDR_CHECK(!partly.coverage.complete_for_all);

  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Pod,
                                CoverageState::Complete, 22)
                   .code,
               OutcomeCode::Committed);
  const IndependenceResult complete = fixture.registry->independence(addressed, classes);
  FDR_CHECK_EQ(complete.state, IndependenceState::ProvenIndependent);
  FDR_CHECK(complete.proven_independent());
  FDR_CHECK(complete.shared.empty());
  FDR_CHECK(complete.coverage.complete_for_all);
  FDR_CHECK(!complete.coverage.has_partial);
  FDR_CHECK(!complete.coverage.has_unknown);
  FDR_CHECK(has_step(complete.steps, "independence"));
}

FDR_TEST_CASE(query, independence_reports_the_shared_domain_of_the_addressed_entities) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 1);
  FDR_CHECK_EQ(rack.outcome.code, OutcomeCode::Committed);
  const EntityRef left = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef right = entity_ref(EntityClass::Switch, 0x02u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, left, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, right, 11).code,
               OutcomeCode::Committed);

  const IndependenceResult result = fixture.registry->independence(
      std::vector<EntityId>{left.id(), right.id()},
      std::vector<DomainClassRef>{DomainClassRef(DomainClass::Rack)});
  FDR_CHECK_EQ(result.state, IndependenceState::SharedDomain);
  FDR_CHECK_EQ(result.shared.size(), std::size_t{1});
  FDR_CHECK_EQ(result.shared.front().domain, rack.id);
  FDR_CHECK_EQ(result.shared.front().members.size(), std::size_t{2});
  FDR_CHECK(result.shared.front().members[0] == left);
  FDR_CHECK(result.shared.front().members[1] == right);
  FDR_CHECK_EQ(result.coverage.entries.size(), std::size_t{1});

  // A class the entities do not share is addressed without changing the answer.
  const IndependenceResult narrowed = fixture.registry->independence(
      std::vector<EntityId>{left.id(), right.id()},
      std::vector<DomainClassRef>{DomainClassRef(DomainClass::Pod)});
  FDR_CHECK(!(narrowed.state == IndependenceState::SharedDomain));
}

FDR_TEST_CASE(query, independence_uses_the_explicit_scope_and_derives_it_when_empty) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle first = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                           "rack-1", 1);
  const DomainHandle second = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc2",
                                            "rack-2", 2);
  FDR_CHECK_EQ(first.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(second.outcome.code, OutcomeCode::Committed);
  const EntityRef left = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef right = entity_ref(EntityClass::Switch, 0x02u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, first.id, left, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, second.id, right, 11).code,
               OutcomeCode::Committed);

  // Coverage is declared for dc1 only.
  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Rack,
                                CoverageState::Complete, 20)
                   .code,
               OutcomeCode::Committed);
  const std::vector<EntityId> addressed{left.id(), right.id()};
  const std::vector<DomainClassRef> classes{DomainClassRef(DomainClass::Rack)};

  // The explicit scope is used verbatim, so a scope with no declaration cannot
  // prove anything.
  FDR_CHECK_EQ(fixture.registry->independence(addressed, classes, "dc1").state,
               IndependenceState::ProvenIndependent);
  FDR_CHECK_EQ(fixture.registry->independence(addressed, classes, "dc2").state,
               IndependenceState::NoKnowledge);
  FDR_CHECK_EQ(fixture.registry->independence(addressed, classes, "dc9").state,
               IndependenceState::NoKnowledge);

  // An empty scope is derived from the addressed entities' current memberships:
  // the entities live in dc1 and dc2, and dc2 is undeclared, so the derived
  // answer covers both scopes, is unknown, and is not the dc1-only answer. A
  // single declared scope anywhere in the derived set is enough to make the
  // answer UNKNOWN rather than NO_KNOWLEDGE.
  const IndependenceResult derived = fixture.registry->independence(addressed, classes);
  FDR_CHECK_EQ(derived.state, IndependenceState::UnknownCoverage);
  FDR_CHECK_EQ(fixture.registry->independence(addressed, classes, std::string_view()).state,
               derived.state);
  FDR_CHECK_EQ(fixture.registry->independence(addressed, classes, "dc1").state,
               IndependenceState::ProvenIndependent);

  // With both scopes fully covered the derived answer becomes proven.
  FDR_CHECK_EQ(declare_every_class(*fixture.registry, fixture, "dc2", CoverageState::Complete, 100)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(fixture.registry->independence(addressed, classes).state,
               IndependenceState::ProvenIndependent);
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

FDR_TEST_CASE(query, coverage_reports_entries_in_the_order_the_caller_asked) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  // Two entities in two dc1 racks, so the scope the engine derives for them is
  // the scope the declarations below address, and they share no domain.
  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 1);
  const DomainHandle other = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                           "rack-2", 2);
  FDR_CHECK_EQ(rack.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(other.outcome.code, OutcomeCode::Committed);
  const EntityRef left = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef right = entity_ref(EntityClass::Switch, 0x02u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, left, 3).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, other.id, right, 4).code,
               OutcomeCode::Committed);

  // Deliberately not canonical order: the report follows the caller.
  const std::vector<DomainClassRef> classes{DomainClassRef(DomainClass::Pod),
                                            DomainClassRef(DomainClass::Rack),
                                            DomainClassRef(DomainClass::Conduit)};
  const CoverageReport undeclared = fixture.registry->coverage("dc1", classes);
  FDR_CHECK_EQ(undeclared.entries.size(), std::size_t{3});
  FDR_CHECK_EQ(undeclared.entries[0].domain_class, DomainClassRef(DomainClass::Pod));
  FDR_CHECK_EQ(undeclared.entries[1].domain_class, DomainClassRef(DomainClass::Rack));
  FDR_CHECK_EQ(undeclared.entries[2].domain_class, DomainClassRef(DomainClass::Conduit));
  for (const CoverageEntry& entry : undeclared.entries) {
    FDR_CHECK(!entry.declared);
    FDR_CHECK_EQ(entry.administrative_scope, std::string("dc1"));
    FDR_CHECK_EQ(entry.evidence, EvidenceClass::Unknown);
    FDR_CHECK_EQ(entry.truth, TruthClass::Unknown);
    // Nothing was declared, so the entry really is unknown.
    FDR_CHECK_EQ(entry.state, CoverageState::UnknownCoverage);
  }
  FDR_CHECK(!undeclared.complete_for_all);
  FDR_CHECK(undeclared.has_unknown);
  FDR_CHECK(!undeclared.has_partial);

  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Rack,
                                CoverageState::Complete, 20)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Pod,
                                CoverageState::Partial, 21, ProvenanceSource::Cmdb)
                   .code,
               OutcomeCode::Committed);

  const CoverageReport declared = fixture.registry->coverage("dc1", classes);
  FDR_CHECK_EQ(declared.entries.size(), std::size_t{3});
  FDR_CHECK_EQ(declared.entries[0].domain_class, DomainClassRef(DomainClass::Pod));
  FDR_CHECK_EQ(declared.entries[1].domain_class, DomainClassRef(DomainClass::Rack));
  FDR_CHECK_EQ(declared.entries[2].domain_class, DomainClassRef(DomainClass::Conduit));

  // A declaration is reported with its provenance: that part is exact.
  FDR_CHECK(declared.entries[0].declared);
  FDR_CHECK_EQ(declared.entries[0].evidence, EvidenceClass::DirectAuthoritativeInfrastructure);
  FDR_CHECK_EQ(declared.entries[0].truth, TruthClass::Real);
  FDR_CHECK(declared.entries[1].declared);
  FDR_CHECK(!declared.entries[2].declared);

  // The state of each entry is the declaration that was made for that class,
  // and the report's summary flags follow from the entries.
  FDR_CHECK_EQ(declared.entries[0].state, CoverageState::Partial);
  FDR_CHECK_EQ(declared.entries[1].state, CoverageState::Complete);
  FDR_CHECK_EQ(declared.entries[2].state, CoverageState::UnknownCoverage);
  FDR_CHECK(declared.has_partial);
  FDR_CHECK(declared.has_unknown);
  // One unknown class is enough to stop the report from claiming completeness.
  FDR_CHECK(!declared.complete_for_all);

  // When every addressed class is complete the report says so, and the partial
  // and unknown flags are clear. Re-declaring a class replaces its declaration.
  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Conduit,
                                CoverageState::Complete, 22)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Pod,
                                CoverageState::Complete, 23)
                   .code,
               OutcomeCode::Committed);
  const CoverageReport every_class = fixture.registry->coverage("dc1", classes);
  FDR_CHECK(every_class.complete_for_all);
  FDR_CHECK(!every_class.has_partial);
  FDR_CHECK(!every_class.has_unknown);
  for (const CoverageEntry& entry : every_class.entries) {
    FDR_CHECK_EQ(entry.state, CoverageState::Complete);
    FDR_CHECK(entry.declared);
  }
  const std::vector<DomainClassRef> rack_only{DomainClassRef(DomainClass::Rack)};
  FDR_CHECK_EQ(fixture.registry->independence(std::vector<EntityId>{left.id(), right.id()},
                                              rack_only)
                   .state,
               IndependenceState::ProvenIndependent);
}

FDR_TEST_CASE(query, coverage_is_scoped_and_the_empty_scope_aggregates) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Rack,
                                CoverageState::Complete, 20)
                   .code,
               OutcomeCode::Committed);

  const std::vector<DomainClassRef> classes{DomainClassRef(DomainClass::Rack)};
  FDR_CHECK(fixture.registry->coverage("dc1", classes).entries.front().declared);
  // Another scope is a different question with a different answer.
  FDR_CHECK(!fixture.registry->coverage("dc2", classes).entries.front().declared);
  FDR_CHECK(!fixture.registry->coverage(std::string_view(), classes).entries.empty());
  // An empty scope does not filter by scope, so the dc1 declaration is visible.
  FDR_CHECK(fixture.registry->coverage(std::string_view(), classes).entries.front().declared);

  // An empty class list addresses every canonical class, in enumerator order.
  const CoverageReport all = fixture.registry->coverage("dc1", std::vector<DomainClassRef>());
  FDR_CHECK_EQ(all.entries.size(), static_cast<std::size_t>(kDomainClassCount));
  for (std::uint8_t raw = 1; raw <= kDomainClassCount; ++raw) {
    const std::size_t index = static_cast<std::size_t>(raw) - 1u;
    FDR_CHECK_EQ(all.entries[index].domain_class,
                 DomainClassRef(static_cast<DomainClass>(raw)));
  }
  // The last entry is the last canonical class, so the list covers them all.
  FDR_CHECK_EQ(all.entries.back().domain_class, DomainClassRef(DomainClass::Custom));
  FDR_CHECK(is_declared(all, DomainClassRef(DomainClass::Rack)));
  FDR_CHECK(!is_declared(all, DomainClassRef(DomainClass::Device)));
  FDR_CHECK(!is_declared(all, DomainClassRef(DomainClass::Fabric)));
}

FDR_TEST_CASE(query, coverage_declarations_are_idempotent_and_replace_deterministically) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Rack,
                                CoverageState::Partial, 20)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Rack,
                                CoverageState::Partial, 21)
                   .code,
               OutcomeCode::Idempotent);
  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Rack,
                                CoverageState::Complete, 22)
                   .code,
               OutcomeCode::Committed);
  // Declaring "nothing is known" explicitly is a legal declaration.
  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Rack,
                                CoverageState::UnknownCoverage, 23)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Rack,
                                CoverageState::Complete, 24)
                   .code,
               OutcomeCode::Committed);

  // The zero enumerator is not one of the three states and is refused before
  // anything is stored.
  DeclareCoverageRequest invalid;
  invalid.attempt = attempt_from(24);
  invalid.authority = fixture.authority;
  invalid.administrative_scope = "dc1";
  invalid.domain_class = DomainClassRef(DomainClass::Rack);
  invalid.state = CoverageState::Unknown;
  invalid.provenance = fixture.provenance;
  FDR_CHECK_EQ(fixture.registry->declare_coverage(invalid).code, OutcomeCode::MalformedRequest);
  const std::vector<DomainClassRef> rack_only{DomainClassRef(DomainClass::Rack)};
  FDR_CHECK_EQ(fixture.registry->coverage("dc1", rack_only).entries.size(), std::size_t{1});

  // An empty scope name is refused, so a declaration can never be global by
  // accident.
  DeclareCoverageRequest unscoped;
  unscoped.attempt = attempt_from(25);
  unscoped.authority = fixture.authority;
  unscoped.domain_class = DomainClassRef(DomainClass::Pod);
  unscoped.state = CoverageState::Complete;
  unscoped.provenance = fixture.provenance;
  FDR_CHECK_EQ(fixture.registry->declare_coverage(unscoped).code, OutcomeCode::MalformedRequest);
  const std::vector<DomainClassRef> pod_only{DomainClassRef(DomainClass::Pod)};
  FDR_CHECK(!fixture.registry->coverage("dc1", pod_only).entries.front().declared);

  std::string why;
  FDR_CHECK_MSG(fixture.registry->validate_state(&why), "the registry did not validate: " + why);
}

// ---------------------------------------------------------------------------
// Correlation of two caller-supplied member sets
// ---------------------------------------------------------------------------

FDR_TEST_CASE(query, correlate_member_sets_reports_the_shared_domains_and_classes) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 1);
  const DomainHandle conduit = create_domain(*fixture.registry, fixture, DomainClass::Conduit,
                                             "dc1", "conduit-1", 2);
  const EntityRef left = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef right = entity_ref(EntityClass::Switch, 0x02u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, left, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, conduit.id, left, 11).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, right, 12).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Rack,
                                CoverageState::Complete, 20)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Conduit,
                                CoverageState::Complete, 21)
                   .code,
               OutcomeCode::Committed);

  const SetCorrelation correlation = fixture.registry->correlate_member_sets(
      std::vector<EntityId>{left.id()}, std::vector<EntityId>{right.id()},
      std::vector<DomainClassRef>{DomainClassRef(DomainClass::Rack)});
  FDR_CHECK_EQ(correlation.state, IndependenceState::SharedDomain);
  FDR_CHECK_EQ(correlation.shared_domains.size(), std::size_t{1});
  FDR_CHECK_EQ(correlation.shared_domains.front().domain, rack.id);
  FDR_CHECK_EQ(correlation.shared_domains.front().domain_class, DomainClassRef(DomainClass::Rack));
  FDR_CHECK_EQ(correlation.shared_classes.size(), std::size_t{1});
  FDR_CHECK_EQ(correlation.shared_classes.front(), DomainClassRef(DomainClass::Rack));
  FDR_CHECK(correlation.unknown_classes.empty());
  // Asserted as produced: correlation names the domains, never the entities, so
  // the members vector of a correlated shared domain is empty.
  FDR_CHECK(correlation.shared_domains.front().members.empty());

  // The conduit is shared by nobody here, and it is filtered out by class
  // anyway: addressing only the conduit finds no correlation.
  const SetCorrelation narrowed = fixture.registry->correlate_member_sets(
      std::vector<EntityId>{left.id()}, std::vector<EntityId>{right.id()},
      std::vector<DomainClassRef>{DomainClassRef(DomainClass::Conduit)});
  FDR_CHECK(!(narrowed.state == IndependenceState::SharedDomain));
  FDR_CHECK(narrowed.shared_domains.empty());
  FDR_CHECK(narrowed.shared_classes.empty());

  // Both classes addressed at once reports both the domain and its class.
  const SetCorrelation both = fixture.registry->correlate_member_sets(
      std::vector<EntityId>{left.id()}, std::vector<EntityId>{right.id()},
      std::vector<DomainClassRef>{DomainClassRef(DomainClass::Rack),
                                  DomainClassRef(DomainClass::Conduit)});
  FDR_CHECK_EQ(both.state, IndependenceState::SharedDomain);
  FDR_CHECK_EQ(both.shared_domains.size(), std::size_t{1});
  FDR_CHECK_EQ(both.shared_classes.size(), std::size_t{1});

  // Empty sets are not a correlation question.
  const SetCorrelation empty = fixture.registry->correlate_member_sets(
      std::vector<EntityId>(), std::vector<EntityId>{right.id()},
      std::vector<DomainClassRef>{DomainClassRef(DomainClass::Rack)});
  FDR_CHECK_EQ(empty.state, IndependenceState::Unknown);
  FDR_CHECK(has_step(empty.steps, "validate"));
}

FDR_TEST_CASE(query, correlate_member_sets_needs_coverage_for_a_negative_answer) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle first = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                           "rack-1", 1);
  const DomainHandle second = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                            "rack-2", 2);
  const EntityRef left = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef right = entity_ref(EntityClass::Switch, 0x02u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, first.id, left, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, second.id, right, 11).code,
               OutcomeCode::Committed);

  const std::vector<EntityId> left_set{left.id()};
  const std::vector<EntityId> right_set{right.id()};
  const std::vector<DomainClassRef> classes{DomainClassRef(DomainClass::Rack),
                                            DomainClassRef(DomainClass::Pod)};

  // Disjoint sets with nothing declared: the absence of a shared domain is not a
  // proof.
  const SetCorrelation unknown = fixture.registry->correlate_member_sets(left_set, right_set, classes);
  FDR_CHECK_EQ(unknown.state, IndependenceState::NoKnowledge);
  FDR_CHECK(unknown.shared_domains.empty());
  FDR_CHECK_EQ(unknown.unknown_classes.size(), std::size_t{2});
  FDR_CHECK_EQ(unknown.unknown_classes[0], DomainClassRef(DomainClass::Rack));
  FDR_CHECK_EQ(unknown.unknown_classes[1], DomainClassRef(DomainClass::Pod));

  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Rack,
                                CoverageState::Complete, 20)
                   .code,
               OutcomeCode::Committed);
  const SetCorrelation partial = fixture.registry->correlate_member_sets(left_set, right_set, classes);
  FDR_CHECK_EQ(partial.state, IndependenceState::UnknownCoverage);
  FDR_CHECK_EQ(partial.unknown_classes.size(), std::size_t{1});
  FDR_CHECK_EQ(partial.unknown_classes.front(), DomainClassRef(DomainClass::Pod));

  // PARTIAL is not COMPLETE: the class stays in unknown_classes and the answer
  // stays unknown.
  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Pod,
                                CoverageState::Partial, 22)
                   .code,
               OutcomeCode::Committed);
  const SetCorrelation partly = fixture.registry->correlate_member_sets(left_set, right_set, classes);
  FDR_CHECK_EQ(partly.state, IndependenceState::UnknownCoverage);
  FDR_CHECK_EQ(partly.unknown_classes.size(), std::size_t{1});
  FDR_CHECK_EQ(partly.unknown_classes.front(), DomainClassRef(DomainClass::Pod));

  FDR_CHECK_EQ(declare_coverage(*fixture.registry, fixture, "dc1", DomainClass::Pod,
                                CoverageState::Complete, 21)
                   .code,
               OutcomeCode::Committed);
  const SetCorrelation independent = fixture.registry->correlate_member_sets(left_set, right_set, classes);
  FDR_CHECK_EQ(independent.state, IndependenceState::ProvenIndependent);
  FDR_CHECK(independent.shared_domains.empty());
  FDR_CHECK(independent.unknown_classes.empty());
  FDR_CHECK(independent.shared_classes.empty());

  // An explicit scope overrides the scope derived from the addressed entities.
  FDR_CHECK_EQ(fixture.registry->correlate_member_sets(left_set, right_set, classes, "dc1").state,
               IndependenceState::ProvenIndependent);
  FDR_CHECK_EQ(fixture.registry->correlate_member_sets(left_set, right_set, classes, "dc9").state,
               IndependenceState::NoKnowledge);
}

// ---------------------------------------------------------------------------
// Blast radius
// ---------------------------------------------------------------------------

FDR_TEST_CASE(query, blast_radius_lists_only_current_members_in_canonical_order) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 1);
  FDR_CHECK_EQ(rack.outcome.code, OutcomeCode::Committed);
  // Deliberately attached out of canonical order, with two generations of one
  // identity, so the ordering is exercised rather than assumed.
  const EntityRef newer_switch = entity_ref(EntityClass::Switch, 0x01u, 2);
  const EntityRef older_switch = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef second_switch = entity_ref(EntityClass::Switch, 0x02u, 1);
  const EntityRef host = entity_ref(EntityClass::Host, 0x03u, 1);
  const EntityRef detached = entity_ref(EntityClass::Switch, 0x04u, 1);
  const EntityRef demoted = entity_ref(EntityClass::Switch, 0x05u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, newer_switch, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, older_switch, 11).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, second_switch, 12).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, host, 13).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, detached, 14).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, demoted, 15).code,
               OutcomeCode::Committed);

  // A retired membership and a revalidation-required membership are both still
  // records, and neither is a current member.
  DetachMemberRequest detach;
  detach.attempt = attempt_from(20);
  detach.authority = fixture.authority;
  detach.domain = rack.id;
  detach.member = detached;
  detach.kind = MembershipKind::Direct;
  detach.reason = "query-suite";
  FDR_CHECK_EQ(fixture.registry->detach_member(detach).code, OutcomeCode::Committed);

  const MembershipId demoted_membership = membership_of(*fixture.registry, rack.id, demoted);
  FDR_CHECK(!demoted_membership.is_null());
  MarkRevalidationRequest mark;
  mark.attempt = attempt_from(21);
  mark.authority = fixture.authority;
  mark.membership = demoted_membership;
  mark.reason = "query-suite";
  FDR_CHECK_EQ(fixture.registry->mark_revalidation_required(mark).code, OutcomeCode::Committed);

  const BlastRadius radius = fixture.registry->blast_radius(rack.id);
  FDR_CHECK_EQ(radius.domain, rack.id);
  FDR_CHECK_EQ(radius.domain_class, DomainClassRef(DomainClass::Rack));
  FDR_CHECK_EQ(radius.lifecycle, DomainLifecycle::Current);
  FDR_CHECK(radius.generation == FailureDomainGeneration(1));
  FDR_CHECK(!radius.truncated);
  FDR_CHECK_EQ(radius.members.size(), std::size_t{4});
  // Ordered by entity class, then entity id, then generation.
  FDR_CHECK(radius.members[0] == older_switch);
  FDR_CHECK(radius.members[1] == newer_switch);
  FDR_CHECK(radius.members[2] == second_switch);
  FDR_CHECK(radius.members[3] == host);
  for (const EntityRef& member : radius.members) {
    FDR_CHECK(!(member == detached));
    FDR_CHECK(!(member == demoted));
  }

  // The classes reported are the classes of the domains the members belong to,
  // in canonical class-name order - not the class of the domain asked about.
  FDR_CHECK_EQ(radius.member_domain_classes.size(), std::size_t{1});
  FDR_CHECK_EQ(radius.member_domain_classes.front(), DomainClassRef(DomainClass::Rack));
  const DomainHandle conduit = create_domain(*fixture.registry, fixture, DomainClass::Conduit, "dc1",
                                             "conduit-2", 31);
  FDR_CHECK_EQ(conduit.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, conduit.id, host, 32).code,
               OutcomeCode::Committed);
  const BlastRadius widened = fixture.registry->blast_radius(rack.id);
  FDR_CHECK_EQ(widened.members.size(), std::size_t{4});
  FDR_CHECK_EQ(widened.member_domain_classes.size(), std::size_t{2});
  FDR_CHECK_EQ(widened.member_domain_classes[0], DomainClassRef(DomainClass::Conduit));
  FDR_CHECK_EQ(widened.member_domain_classes[1], DomainClassRef(DomainClass::Rack));

  // A Conduit domain whose Link members also belong to Cable domains reports the
  // classes of those member domains - never just the class that was queried.
  const DomainHandle cable = create_domain(*fixture.registry, fixture, DomainClass::Cable, "dc1",
                                           "cable-1", 33);
  const DomainHandle conduit_domain = create_domain(*fixture.registry, fixture, DomainClass::Conduit,
                                                    "dc1", "conduit-3", 34);
  FDR_CHECK_EQ(cable.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(conduit_domain.outcome.code, OutcomeCode::Committed);
  const EntityRef link_one = entity_ref(EntityClass::Link, 0x11u, 1);
  const EntityRef link_two = entity_ref(EntityClass::Link, 0x12u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, conduit_domain.id, link_one, 35).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, conduit_domain.id, link_two, 36).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, cable.id, link_one, 37).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, cable.id, link_two, 38).code,
               OutcomeCode::Committed);
  const BlastRadius links = fixture.registry->blast_radius(conduit_domain.id);
  FDR_CHECK_EQ(links.domain_class, DomainClassRef(DomainClass::Conduit));
  FDR_CHECK_EQ(links.members.size(), std::size_t{2});
  FDR_CHECK_EQ(links.member_domain_classes.size(), std::size_t{2});
  FDR_CHECK_EQ(links.member_domain_classes[0], DomainClassRef(DomainClass::Cable));
  FDR_CHECK_EQ(links.member_domain_classes[1], DomainClassRef(DomainClass::Conduit));
  FDR_CHECK(!(links.member_domain_classes.size() == std::size_t{1}));
  std::vector<DomainClassRef> unique_classes = links.member_domain_classes;
  std::sort(unique_classes.begin(), unique_classes.end(),
            [](const DomainClassRef& left, const DomainClassRef& right) {
              return left.to_string() < right.to_string();
            });
  FDR_CHECK_EQ(std::unique(unique_classes.begin(), unique_classes.end()), unique_classes.end());

  // A domain with no current member reports no member class at all.
  const DomainHandle empty = create_domain(*fixture.registry, fixture, DomainClass::Conduit, "dc1",
                                           "conduit-1", 30);
  FDR_CHECK_EQ(empty.outcome.code, OutcomeCode::Committed);
  const BlastRadius empty_radius = fixture.registry->blast_radius(empty.id);
  FDR_CHECK(empty_radius.members.empty());
  FDR_CHECK(empty_radius.member_domain_classes.empty());
  FDR_CHECK(empty_radius.child_domains.empty());
  FDR_CHECK(empty_radius.related_domains.empty());

  // An unknown domain yields a named but empty answer.
  const BlastRadius absent = fixture.registry->blast_radius(FailureDomainId::from_bytes(IdBytes{0xABu}));
  FDR_CHECK_EQ(absent.domain_class, DomainClassRef());
  FDR_CHECK(absent.members.empty());
}

FDR_TEST_CASE(query, blast_radius_walks_containment_and_reports_other_relations) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle outer = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                           "rack-outer", 1);
  const DomainHandle middle = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                            "rack-middle", 2);
  const DomainHandle inner = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                           "rack-inner", 3);
  const DomainHandle pdu = create_domain(*fixture.registry, fixture, DomainClass::Pdu, "dc1",
                                         "pdu-1", 4);
  const DomainHandle conduit = create_domain(*fixture.registry, fixture, DomainClass::Conduit,
                                             "dc1", "conduit-1", 5);
  FDR_CHECK_EQ(outer.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(middle.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(inner.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(pdu.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(conduit.outcome.code, OutcomeCode::Committed);

  // middle is contained by outer, inner is contained by middle.
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, middle.id, outer.id, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, inner.id, middle.id, 11).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, outer.id, pdu.id, 12,
                            DomainRelationType::DependsOn)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, outer.id, conduit.id, 13,
                            DomainRelationType::CorrelatedWith)
                   .code,
               OutcomeCode::Committed);
  // A relation between two descendants is not a relation of the ancestor.
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, inner.id, conduit.id, 14,
                            DomainRelationType::CorrelatedWith)
                   .code,
               OutcomeCode::Committed);

  const BlastRadius radius = fixture.registry->blast_radius(outer.id);
  // The containment walk is breadth-first, so the nearest descendant is listed
  // first; it is not re-sorted by identity.
  FDR_CHECK_EQ(radius.child_domains.size(), std::size_t{2});
  FDR_CHECK(radius.child_domains[0] == middle.id);
  FDR_CHECK(radius.child_domains[1] == inner.id);
  // Related domains, by contrast, are ordered by identity.
  FDR_CHECK_EQ(radius.related_domains, sorted_ids({pdu.id, conduit.id}));
  FDR_CHECK_EQ(radius.related_domains.size(), std::size_t{2});
  for (const FailureDomainId& id : radius.related_domains) {
    // CONTAINED_BY is structure, not a related domain.
    FDR_CHECK(!(id == middle.id));
    FDR_CHECK(!(id == inner.id));
  }
  FDR_CHECK(!radius.truncated);

  // The walk is directional: an ancestor has no child domains.
  const BlastRadius leaf = fixture.registry->blast_radius(inner.id);
  FDR_CHECK(leaf.child_domains.empty());
  FDR_CHECK_EQ(leaf.related_domains.size(), std::size_t{1});
  FDR_CHECK(leaf.related_domains.front() == conduit.id);
  FDR_CHECK(!leaf.truncated);
}

// ---------------------------------------------------------------------------
// Ancestors and descendants
// ---------------------------------------------------------------------------

FDR_TEST_CASE(query, ancestors_and_descendants_are_exact_transitive_sets) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle first = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                           "rack-1", 1);
  const DomainHandle second = create_domain(*fixture.registry, fixture, DomainClass::Row, "dc1",
                                            "row-1", 2);
  const DomainHandle third = create_domain(*fixture.registry, fixture, DomainClass::Pod, "dc1",
                                           "pod-1", 3);
  const DomainHandle fourth = create_domain(*fixture.registry, fixture, DomainClass::Site, "dc1",
                                            "site-1", 4);
  FDR_CHECK_EQ(first.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(second.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(third.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(fourth.outcome.code, OutcomeCode::Committed);

  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, first.id, second.id, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, second.id, third.id, 11).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, third.id, fourth.id, 12).code,
               OutcomeCode::Committed);

  const std::vector<FailureDomainId> ancestors = fixture.registry->ancestors(first.id);
  FDR_CHECK_EQ(ancestors, sorted_ids({second.id, third.id, fourth.id}));
  FDR_CHECK_EQ(ancestors.size(), std::size_t{3});
  for (const FailureDomainId& id : ancestors) {
    FDR_CHECK(!(id == first.id));
  }

  const std::vector<FailureDomainId> descendants = fixture.registry->descendants(fourth.id);
  FDR_CHECK_EQ(descendants, sorted_ids({first.id, second.id, third.id}));
  for (const FailureDomainId& id : descendants) {
    FDR_CHECK(!(id == fourth.id));
  }

  // The two directions are complementary, and the ends of the chain are exact.
  FDR_CHECK_EQ(fixture.registry->ancestors(fourth.id).size(), std::size_t{0});
  FDR_CHECK_EQ(fixture.registry->descendants(first.id).size(), std::size_t{0});
  FDR_CHECK_EQ(fixture.registry->ancestors(second.id), sorted_ids({third.id, fourth.id}));
  FDR_CHECK_EQ(fixture.registry->descendants(second.id), sorted_ids({first.id}));
  // An unknown domain has neither.
  FDR_CHECK(fixture.registry->ancestors(FailureDomainId::from_bytes(IdBytes{0xACu})).empty());
  FDR_CHECK(fixture.registry->descendants(FailureDomainId::from_bytes(IdBytes{0xACu})).empty());
}

// ---------------------------------------------------------------------------
// Purity
// ---------------------------------------------------------------------------

FDR_TEST_CASE(query, queries_do_not_mutate_the_registry) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 1);
  const DomainHandle row = create_domain(*fixture.registry, fixture, DomainClass::Row, "dc1",
                                         "row-1", 2);
  FDR_CHECK_EQ(rack.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(row.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, rack.id, row.id, 10).code,
               OutcomeCode::Committed);
  const EntityRef left = entity_ref(EntityClass::Switch, 0x01u, 1);
  const EntityRef right = entity_ref(EntityClass::Switch, 0x02u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, left, 11).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id, right, 12).code,
               OutcomeCode::Committed);

  const RegistryGeneration generation = fixture.registry->generation();
  const StateDigest digest = fixture.registry->state_digest();
  const std::size_t domains = fixture.registry->domain_count();
  const std::size_t memberships = fixture.registry->membership_count();
  const std::vector<DomainClassRef> classes{DomainClassRef(DomainClass::Rack)};

  (void)fixture.registry->overlap(left.id(), right.id());
  (void)fixture.registry->independence(std::vector<EntityId>{left.id(), right.id()}, classes);
  (void)fixture.registry->coverage("dc1", classes);
  (void)fixture.registry->blast_radius(rack.id);
  (void)fixture.registry->correlate_member_sets(std::vector<EntityId>{left.id()},
                                                std::vector<EntityId>{right.id()}, classes);
  (void)fixture.registry->ancestors(rack.id);
  (void)fixture.registry->descendants(row.id);
  (void)fixture.registry->relations_of(rack.id);
  (void)fixture.registry->members_of(rack.id);
  (void)fixture.registry->domains_in_scope("dc1");

  FDR_CHECK(fixture.registry->generation() == generation);
  FDR_CHECK(fixture.registry->state_digest() == digest);
  FDR_CHECK_EQ(fixture.registry->domain_count(), domains);
  FDR_CHECK_EQ(fixture.registry->membership_count(), memberships);
  std::string why;
  FDR_CHECK_MSG(fixture.registry->validate_state(&why), "the registry did not validate: " + why);

  // The check is sensitive: one committed mutation moves both the generation and
  // the digest, so the assertions above are not vacuous.
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, rack.id,
                             entity_ref(EntityClass::Host, 0x03u, 1), 20)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK(!(fixture.registry->generation() == generation));
  FDR_CHECK(!(fixture.registry->state_digest() == digest));
  FDR_CHECK_EQ(fixture.registry->membership_count(), memberships + 1u);
  FDR_CHECK_MSG(fixture.registry->validate_state(&why), "the registry did not validate: " + why);
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
