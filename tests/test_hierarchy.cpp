// Failure Domain Registry — relation and hierarchy proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Acyclicity is a property of the relation type, not of the graph: the six
// directed types may never close a cycle while SHARES_RISK_WITH and
// CORRELATED_WITH may form arbitrary graphs. Every one of the eight types is
// compared against an expectation table written out in full below, and then
// exercised, so a change to either property cannot pass unnoticed.
//
// A rejected relation is checked twice: the OutcomeCode says why it was refused,
// and the relation count, the state generation and validate_state together prove
// that nothing was committed behind the refusal. Two bounds are asserted
// separately: max_hierarchy_depth is the true longest containment chain a
// CONTAINED_BY edge may create, measured when that edge is added, and
// max_ancestor_walk is the separate budget of the acyclicity probe and of the
// read walks.
//
// The last case pins the replay window every mutation shares: an attempt id that
// fell out of the per-publisher idempotency table is re-evaluated and answered
// from the state, while an attempt id still inside it is recognised as an exact
// replay - and the eviction order is the attempt id, smallest first.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "failure_domain_registry/authority.hpp"
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
#include "failure_domain_registry/relation.hpp"
#include "failure_domain_registry/requests.hpp"
#include "support/containment_probe.hpp"
#include "support/test_harness.hpp"

namespace {

using failure_domain_registry::AddRelationRequest;
using failure_domain_registry::AuthorityContext;
using failure_domain_registry::AuthorityScope;
using failure_domain_registry::BlastRadius;
using failure_domain_registry::CoordinatorEpoch;
using failure_domain_registry::CreateDomainRequest;
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
using failure_domain_registry::FailureDomainGeneration;
using failure_domain_registry::FailureDomainId;
using failure_domain_registry::IdBytes;
using failure_domain_registry::MembershipKind;
using failure_domain_registry::MembershipRole;
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
using failure_domain_registry::RequestDigest;
using failure_domain_registry::RetireDomainRequest;
using failure_domain_registry::TruthClass;
using failure_domain_registry::WorkerBootId;
using failure_domain_registry::domain_id_for;
using failure_domain_registry::domain_relation_type_from_string;
using failure_domain_registry::inverse_text;
using failure_domain_registry::is_acyclic_relation;
using failure_domain_registry::is_containment_class;
using failure_domain_registry::is_symmetric_relation;
using failure_domain_registry::is_valid_domain_relation_type;
using failure_domain_registry::kDomainRelationTypeCount;
using failure_domain_registry::relation_id_for;
using failure_domain_registry::to_string;

/// The exact per-type semantics of src/relation.cpp, in enumerator order:
/// 0 Unknown, 1 CONTAINED_BY, 2 DEPENDS_ON, 3 SHARES_RISK_WITH, 4 POWERED_BY,
/// 5 COOLED_BY, 6 CONTROLLED_BY, 7 BACKED_BY, 8 CORRELATED_WITH.
///
/// Only containment and dependency-shaped relations must stay acyclic;
/// shared-risk and correlation are the two symmetric types.
constexpr bool kAcyclic[kDomainRelationTypeCount + 1] = {
    false, true, true, false, true, true, true, true, false};
constexpr bool kSymmetric[kDomainRelationTypeCount + 1] = {
    false, false, false, true, false, false, false, false, true};
constexpr std::string_view kTypeNames[kDomainRelationTypeCount + 1] = {
    "UNKNOWN",     "CONTAINED_BY", "DEPENDS_ON",   "SHARES_RISK_WITH", "POWERED_BY",
    "COOLED_BY",   "CONTROLLED_BY", "BACKED_BY",   "CORRELATED_WITH"};

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
  registration.name = "hierarchy-publisher";
  registration.scope = AuthorityScope::unrestricted();
  fixture.registry->grant_publisher(registration, AuthorityContext{});
  CoordinatorEpoch epoch;
  if (fixture.registry->advance_epoch(CoordinatorEpoch{}, &epoch).committed()) {
    fixture.epoch = epoch;
  }
  fixture.registry->attach_worker(fixture.publisher, fixture.worker_boot, fixture.epoch,
                                  "hierarchy-suite", EvidenceClass::DirectAuthoritativeInfrastructure);
  fixture.authority.publisher = fixture.publisher;
  fixture.authority.worker_boot = fixture.worker_boot;
  fixture.authority.epoch = fixture.epoch;
  fixture.authority.evidence = EvidenceClass::DirectAuthoritativeInfrastructure;
  fixture.provenance = provenance_of(ProvenanceSource::PhysicalInfrastructure,
                                     EvidenceClass::DirectAuthoritativeInfrastructure, TruthClass::Real,
                                     "hierarchy-inventory");
  return fixture;
}

void require_fixture(Registry& registry, const Fixture& fixture) {
  FDR_CHECK_EQ(fixture.epoch.value(), std::uint64_t{1});
  FDR_CHECK(registry.is_worker_live(fixture.publisher, fixture.worker_boot));
  FDR_CHECK(registry.publisher(fixture.publisher).has_value());
}

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

std::vector<FailureDomainId> sorted_ids(std::vector<FailureDomainId> ids) {
  std::sort(ids.begin(), ids.end());
  return ids;
}

std::size_t relation_count(Registry& registry, const FailureDomainId& id) {
  return registry.relations_of(id).size();
}

/// The walk results are ordered, so a repeated domain can only be adjacent. A
/// transitive walk over an acyclic relation must never repeat one.
bool reports_each_domain_once(std::vector<FailureDomainId> ids) {
  return std::unique(ids.begin(), ids.end()) == ids.end();
}

/// True when the exact edge exists, addressed from either endpoint.
bool has_edge(Registry& registry, const FailureDomainId& first, const FailureDomainId& second,
              DomainRelationType type) {
  const DomainRelationId expected = relation_id_for(first, second, type);
  for (const DomainRelation& relation : registry.relations_of(first)) {
    if (relation.id == expected) {
      return true;
    }
  }
  return false;
}

/// Creates `count` rack domains named "<prefix><index>" and returns their ids in
/// creation order.
std::vector<FailureDomainId> create_domains(Registry& registry, const Fixture& fixture,
                                            const std::string& prefix, std::size_t count,
                                            std::uint64_t first_attempt) {
  std::vector<FailureDomainId> ids;
  for (std::size_t index = 0; index < count; ++index) {
    const std::string key = prefix + std::to_string(index);
    const DomainHandle handle =
        create_domain(registry, fixture, DomainClass::Rack, "dc1", key, first_attempt + index);
    if (handle.outcome.code != OutcomeCode::Committed) {
      ::fdrtest::fail(__FILE__, __LINE__,
                      "creating " + key + " was refused: " + handle.outcome.message);
    }
    ids.push_back(handle.id);
  }
  return ids;
}

/// True when a refusal names the hierarchy ceiling and the depth it measured.
bool reports_ceiling(const Outcome& outcome, std::size_t ceiling, std::size_t measured) {
  for (const failure_domain_registry::ExplanationStep& step : outcome.steps) {
    if (step.stage != "hierarchy" || step.field != "max_hierarchy_depth") {
      continue;
    }
    if (step.value == std::to_string(ceiling) &&
        step.detail.find("depth is " + std::to_string(measured)) != std::string::npos) {
      return true;
    }
  }
  return false;
}

/// Fails the case unless a refusal left the relation graph, the generation and
/// the indexes exactly as they were.
void require_refusal_left_no_trace(Registry& registry, const FailureDomainId& first,
                                   const FailureDomainId& second,
                                   RegistryGeneration generation) {
  FDR_CHECK(registry.generation() == generation);
  FDR_CHECK_EQ(relation_count(registry, first), std::size_t{1});
  FDR_CHECK_EQ(relation_count(registry, second), std::size_t{1});
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the registry did not validate: " + why);
}

} // namespace

// ---------------------------------------------------------------------------
// Relation type semantics
// ---------------------------------------------------------------------------

FDR_TEST_CASE(hierarchy, relation_type_semantics_are_exact) {
  for (std::uint8_t raw = 0; raw <= kDomainRelationTypeCount; ++raw) {
    const auto type = static_cast<DomainRelationType>(raw);
    const std::size_t index = static_cast<std::size_t>(raw);
    FDR_CHECK_EQ(std::string(to_string(type)), std::string(kTypeNames[index]));
    FDR_CHECK_EQ(is_acyclic_relation(type), kAcyclic[index]);
    FDR_CHECK_EQ(is_symmetric_relation(type), kSymmetric[index]);
    FDR_CHECK_EQ(is_valid_domain_relation_type(type), raw != 0u);
    // Every name round-trips through the wire form, and the two symmetric types
    // render as their own inverse.
    if (raw != 0u) {
      const std::optional<DomainRelationType> parsed =
          domain_relation_type_from_string(to_string(type));
      FDR_CHECK(parsed.has_value());
      FDR_CHECK_EQ(*parsed, type);
      if (kSymmetric[index]) {
        FDR_CHECK_EQ(inverse_text(type), to_string(type));
      }
    }
  }
  FDR_CHECK_EQ(inverse_text(DomainRelationType::ContainedBy), std::string_view("CONTAINS"));
  FDR_CHECK_EQ(inverse_text(DomainRelationType::BackedBy), std::string_view("BACKS"));
  FDR_CHECK(!domain_relation_type_from_string("contained_by").has_value());
  FDR_CHECK(!domain_relation_type_from_string("").has_value());
  FDR_CHECK(!domain_relation_type_from_string("UNKNOWN").has_value());

  // A value outside the enumeration is never a relation type.
  FDR_CHECK(!is_valid_domain_relation_type(static_cast<DomainRelationType>(9)));
  FDR_CHECK(!is_valid_domain_relation_type(static_cast<DomainRelationType>(255)));
}

// ---------------------------------------------------------------------------
// Committed containment
// ---------------------------------------------------------------------------

FDR_TEST_CASE(hierarchy, add_relation_commits_a_containment_edge) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 1);
  const DomainHandle row = create_domain(*fixture.registry, fixture, DomainClass::Row, "dc1",
                                         "row-1", 2);
  const DomainHandle pod = create_domain(*fixture.registry, fixture, DomainClass::Pod, "dc1",
                                         "pod-1", 3);
  FDR_CHECK_EQ(rack.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(row.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(pod.outcome.code, OutcomeCode::Committed);

  const RegistryGeneration before = fixture.registry->generation();
  const Outcome committed = add_relation(*fixture.registry, fixture, rack.id, row.id, 10);
  FDR_CHECK_EQ(committed.code, OutcomeCode::Committed);
  FDR_CHECK(committed.domain.has_value());
  FDR_CHECK_EQ(*committed.domain, rack.id);
  FDR_CHECK_EQ(committed.related_domains.size(), std::size_t{1});
  FDR_CHECK(committed.related_domains.front() == row.id);
  FDR_CHECK_EQ(fixture.registry->generation().value(), before.value() + 1u);

  // The edge is visible from both endpoints, exactly once each time.
  const std::vector<DomainRelation> from_source = fixture.registry->relations_of(rack.id);
  const std::vector<DomainRelation> from_target = fixture.registry->relations_of(row.id);
  FDR_CHECK_EQ(from_source.size(), std::size_t{1});
  FDR_CHECK_EQ(from_target.size(), std::size_t{1});
  FDR_CHECK(from_source.front() == from_target.front());
  const DomainRelation& relation = from_source.front();
  FDR_CHECK(relation.source == rack.id);
  FDR_CHECK(relation.target == row.id);
  FDR_CHECK_EQ(relation.type, DomainRelationType::ContainedBy);
  FDR_CHECK_EQ(relation.id, relation_id_for(rack.id, row.id, DomainRelationType::ContainedBy));
  FDR_CHECK_EQ(relation.provenance.source, ProvenanceSource::PhysicalInfrastructure);
  FDR_CHECK_EQ(relation.provenance.publisher, fixture.publisher);
  FDR_CHECK(relation.created_epoch == fixture.epoch);
  FDR_CHECK(!relation.render().empty());
  FDR_CHECK(!relation.canonical_form().empty());

  FDR_CHECK_EQ(fixture.registry->ancestors(rack.id), sorted_ids({row.id}));
  FDR_CHECK_EQ(fixture.registry->descendants(row.id), sorted_ids({rack.id}));

  // The chain extends transitively in both directions.
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, row.id, pod.id, 11).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(fixture.registry->ancestors(rack.id), sorted_ids({row.id, pod.id}));
  FDR_CHECK_EQ(fixture.registry->ancestors(row.id), sorted_ids({pod.id}));
  FDR_CHECK_EQ(fixture.registry->descendants(pod.id), sorted_ids({rack.id, row.id}));
  FDR_CHECK_EQ(fixture.registry->ancestors(pod.id).size(), std::size_t{0});
  FDR_CHECK_EQ(fixture.registry->descendants(rack.id).size(), std::size_t{0});
  FDR_CHECK_EQ(relation_count(*fixture.registry, row.id), std::size_t{2});

  std::string why;
  FDR_CHECK_MSG(fixture.registry->validate_state(&why), "the registry did not validate: " + why);
}

// ---------------------------------------------------------------------------
// Cycle rejection
// ---------------------------------------------------------------------------

FDR_TEST_CASE(hierarchy, containment_cycles_are_rejected_for_every_acyclic_type) {
  for (std::uint8_t raw = 1; raw <= kDomainRelationTypeCount; ++raw) {
    const auto type = static_cast<DomainRelationType>(raw);
    if (!is_acyclic_relation(type)) {
      continue;
    }
    Fixture fixture = make_fixture(RegistryLimits::defaults());
    require_fixture(*fixture.registry, fixture);
    const DomainHandle first = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                             "rack-a", 1);
    const DomainHandle second = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                              "rack-b", 2);
    const DomainHandle third = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                             "rack-c", 3);
    FDR_CHECK_EQ(first.outcome.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(second.outcome.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(third.outcome.code, OutcomeCode::Committed);

    FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, first.id, second.id, 10, type).code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, second.id, third.id, 11, type).code,
                 OutcomeCode::Committed);
    const RegistryGeneration generation = fixture.registry->generation();
    const Outcome cycle = add_relation(*fixture.registry, fixture, third.id, first.id, 12, type);
    FDR_CHECK_MSG(cycle.code == OutcomeCode::CycleRejected,
                  std::string("type ") + std::string(to_string(type)) +
                      " accepted a cycle: " + cycle.message);
    // The refusal is explained at the stage that produced it.
    FDR_CHECK(!cycle.steps.empty());
    FDR_CHECK_EQ(cycle.steps.front().stage, std::string("hierarchy"));
    // Nothing was committed: the same generation, the same two edges, valid state.
    FDR_CHECK(fixture.registry->generation() == generation);
    FDR_CHECK_EQ(relation_count(*fixture.registry, first.id), std::size_t{1});
    FDR_CHECK_EQ(relation_count(*fixture.registry, second.id), std::size_t{2});
    FDR_CHECK_EQ(relation_count(*fixture.registry, third.id), std::size_t{1});
    FDR_CHECK(fixture.registry->relations_of(first.id).front().type == type);
    std::string why;
    FDR_CHECK_MSG(fixture.registry->validate_state(&why),
                  std::string("the registry did not validate after a cycle rejection: ") + why);
  }
}

FDR_TEST_CASE(hierarchy, two_cycles_and_self_relations_are_rejected_without_a_trace) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle first = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                           "rack-a", 1);
  const DomainHandle second = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                            "rack-b", 2);
  FDR_CHECK_EQ(first.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(second.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, first.id, second.id, 10).code,
               OutcomeCode::Committed);

  const RegistryGeneration generation = fixture.registry->generation();
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, second.id, first.id, 11).code,
               OutcomeCode::CycleRejected);
  require_refusal_left_no_trace(*fixture.registry, first.id, second.id, generation);

  // A domain is never related to itself, whatever the type.
  const Outcome self = add_relation(*fixture.registry, fixture, first.id, first.id, 12);
  FDR_CHECK_EQ(self.code, OutcomeCode::MalformedRequest);
  FDR_CHECK(fixture.registry->generation() == generation);
  FDR_CHECK_EQ(relation_count(*fixture.registry, first.id), std::size_t{1});
  const Outcome symmetric_self = add_relation(*fixture.registry, fixture, second.id, second.id, 13,
                                               DomainRelationType::CorrelatedWith);
  FDR_CHECK_EQ(symmetric_self.code, OutcomeCode::MalformedRequest);
  FDR_CHECK(fixture.registry->generation() == generation);
  FDR_CHECK_EQ(relation_count(*fixture.registry, second.id), std::size_t{1});

  // The refused edge was never stored: only the committed one exists.
  for (const DomainRelation& relation : fixture.registry->relations_of(second.id)) {
    FDR_CHECK(relation.source == first.id);
    FDR_CHECK(relation.target == second.id);
  }
}

FDR_TEST_CASE(hierarchy, symmetric_relations_may_cycle_and_canonicalise_their_endpoints) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle first = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                           "rack-a", 1);
  const DomainHandle second = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                            "rack-b", 2);
  const DomainHandle third = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                           "rack-c", 3);
  FDR_CHECK_EQ(first.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(second.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(third.outcome.code, OutcomeCode::Committed);

  // A symmetric edge has one identity whichever way it is written; a directed
  // edge does not.
  FDR_CHECK_EQ(relation_id_for(first.id, second.id, DomainRelationType::CorrelatedWith),
               relation_id_for(second.id, first.id, DomainRelationType::CorrelatedWith));
  FDR_CHECK_EQ(relation_id_for(first.id, second.id, DomainRelationType::SharesRiskWith),
               relation_id_for(second.id, first.id, DomainRelationType::SharesRiskWith));
  FDR_CHECK(!(relation_id_for(first.id, second.id, DomainRelationType::DependsOn) ==
              relation_id_for(second.id, first.id, DomainRelationType::DependsOn)));

  // Three correlations around a triangle: legal, because correlation is not
  // containment.
  const DomainRelationType correlated = DomainRelationType::CorrelatedWith;
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, first.id, second.id, 10, correlated).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, second.id, third.id, 11, correlated).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, third.id, first.id, 12, correlated).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(relation_count(*fixture.registry, first.id), std::size_t{2});
  FDR_CHECK_EQ(relation_count(*fixture.registry, second.id), std::size_t{2});
  FDR_CHECK_EQ(relation_count(*fixture.registry, third.id), std::size_t{2});

  // Writing the same edge backwards addresses the same record.
  const RegistryGeneration generation = fixture.registry->generation();
  const Outcome swapped =
      add_relation(*fixture.registry, fixture, second.id, first.id, 13, correlated);
  FDR_CHECK_EQ(swapped.code, OutcomeCode::Idempotent);
  FDR_CHECK(fixture.registry->generation() == generation);
  FDR_CHECK_EQ(relation_count(*fixture.registry, first.id), std::size_t{2});
  FDR_CHECK_EQ(relation_count(*fixture.registry, second.id), std::size_t{2});
  FDR_CHECK(has_edge(*fixture.registry, first.id, second.id, correlated));
  FDR_CHECK(has_edge(*fixture.registry, second.id, first.id, correlated));
  // The stored edge keeps the endpoint order it was first published with, and is
  // still readable from both ends.
  for (const DomainRelation& relation : fixture.registry->relations_of(second.id)) {
    if (relation.id == relation_id_for(first.id, second.id, correlated)) {
      FDR_CHECK(relation.source == first.id);
      FDR_CHECK(relation.target == second.id);
    }
  }

  // The other symmetric type forms the same triangle over the same domains.
  const DomainRelationType shared_risk = DomainRelationType::SharesRiskWith;
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, first.id, second.id, 20, shared_risk).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, second.id, third.id, 21, shared_risk).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, third.id, first.id, 22, shared_risk).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(fixture.registry->relations_of(first.id).size(), std::size_t{4});
  FDR_CHECK_EQ(fixture.registry->relations_of(second.id).size(), std::size_t{4});
  FDR_CHECK_EQ(fixture.registry->relations_of(third.id).size(), std::size_t{4});

  // A symmetric graph contributes nothing to containment.
  FDR_CHECK_EQ(fixture.registry->ancestors(first.id).size(), std::size_t{0});
  FDR_CHECK_EQ(fixture.registry->descendants(first.id).size(), std::size_t{0});

  std::string why;
  FDR_CHECK_MSG(fixture.registry->validate_state(&why), "the registry did not validate: " + why);
}

// ---------------------------------------------------------------------------
// Invalid hierarchy
// ---------------------------------------------------------------------------

FDR_TEST_CASE(hierarchy, containment_requires_containment_classes) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 1);
  const DomainHandle conduit = create_domain(*fixture.registry, fixture, DomainClass::Conduit,
                                             "dc1", "conduit-1", 2);
  const DomainHandle link = create_domain(*fixture.registry, fixture, DomainClass::Link, "dc1",
                                          "link-1", 3);
  const DomainHandle cable = create_domain(*fixture.registry, fixture, DomainClass::Cable, "dc1",
                                           "cable-1", 4);
  FDR_CHECK_EQ(rack.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(conduit.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(link.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(cable.outcome.code, OutcomeCode::Committed);
  FDR_CHECK(is_containment_class(DomainClass::Rack));
  FDR_CHECK(is_containment_class(DomainClass::Conduit));
  FDR_CHECK(!is_containment_class(DomainClass::Link));
  FDR_CHECK(!is_containment_class(DomainClass::Cable));

  // Neither endpoint of a CONTAINED_BY edge may be a non-containment class.
  const RegistryGeneration generation = fixture.registry->generation();
  const Outcome neither = add_relation(*fixture.registry, fixture, link.id, cable.id, 10);
  FDR_CHECK_EQ(neither.code, OutcomeCode::InvalidHierarchy);
  FDR_CHECK(!neither.steps.empty());
  FDR_CHECK_EQ(neither.steps.front().stage, std::string("hierarchy"));
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, rack.id, link.id, 11).code,
               OutcomeCode::InvalidHierarchy);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, link.id, rack.id, 12).code,
               OutcomeCode::InvalidHierarchy);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, cable.id, conduit.id, 13).code,
               OutcomeCode::InvalidHierarchy);
  FDR_CHECK(fixture.registry->generation() == generation);
  FDR_CHECK_EQ(relation_count(*fixture.registry, link.id), std::size_t{0});
  FDR_CHECK_EQ(relation_count(*fixture.registry, cable.id), std::size_t{0});
  FDR_CHECK_EQ(relation_count(*fixture.registry, rack.id), std::size_t{0});

  // The rule is the class, not a particular pair: a conduit is not a rack and the
  // edge is still correct.
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, conduit.id, rack.id, 14).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(fixture.registry->ancestors(conduit.id), sorted_ids({rack.id}));

  // A non-containment type is never checked against the containment classes.
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, link.id, cable.id, 15,
                            DomainRelationType::DependsOn)
                   .code,
               OutcomeCode::Committed);

  std::string why;
  FDR_CHECK_MSG(fixture.registry->validate_state(&why), "the registry did not validate: " + why);
}

FDR_TEST_CASE(hierarchy, relation_endpoints_must_exist_be_current_and_typed) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 1);
  const DomainHandle retired = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                             "rack-2", 2);
  FDR_CHECK_EQ(rack.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(retired.outcome.code, OutcomeCode::Committed);

  RetireDomainRequest retire;
  retire.attempt = attempt_from(3);
  retire.authority = fixture.authority;
  retire.domain = retired.id;
  retire.expected_generation = FailureDomainGeneration(1);
  retire.reason = "hierarchy-suite";
  FDR_CHECK_EQ(fixture.registry->retire_domain(retire).code, OutcomeCode::Committed);
  const std::optional<failure_domain_registry::FailureDomain> closed =
      fixture.registry->domain(retired.id);
  FDR_CHECK(closed.has_value());
  FDR_CHECK_EQ(closed->lifecycle, DomainLifecycle::Retired);
  FDR_CHECK(is_terminal(closed->lifecycle));

  const FailureDomainId unknown = FailureDomainId::from_bytes(IdBytes{0xAAu});
  const RegistryGeneration generation = fixture.registry->generation();

  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, unknown, rack.id, 10).code,
               OutcomeCode::UnknownDomain);
  FDR_CHECK(fixture.registry->generation() == generation);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, rack.id, unknown, 11).code,
               OutcomeCode::UnknownDomain);
  FDR_CHECK(fixture.registry->generation() == generation);

  // A closed endpoint is refused in both directions, and the closed record is
  // never revived by the attempt.
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, retired.id, rack.id, 12).code,
               OutcomeCode::NotCurrent);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, rack.id, retired.id, 13).code,
               OutcomeCode::NotCurrent);
  FDR_CHECK(fixture.registry->generation() == generation);
  const std::optional<failure_domain_registry::FailureDomain> still_closed =
      fixture.registry->domain(retired.id);
  FDR_CHECK(still_closed.has_value());
  FDR_CHECK_EQ(still_closed->lifecycle, DomainLifecycle::Retired);

  // The type is validated before the endpoints are resolved.
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, unknown, unknown, 14,
                            DomainRelationType::Unknown)
                   .code,
               OutcomeCode::MalformedRequest);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, unknown, unknown, 15,
                            static_cast<DomainRelationType>(99))
                   .code,
               OutcomeCode::MalformedRequest);
  FDR_CHECK(fixture.registry->generation() == generation);

  // The same edge twice is one edge.
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, rack.id, retired.id, 16).code,
               OutcomeCode::NotCurrent);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, unknown, rack.id, 17).code,
               OutcomeCode::UnknownDomain);
  FDR_CHECK_EQ(relation_count(*fixture.registry, rack.id), std::size_t{0});

  std::string why;
  FDR_CHECK_MSG(fixture.registry->validate_state(&why), "the registry did not validate: " + why);
}

FDR_TEST_CASE(hierarchy, adding_the_same_edge_twice_is_idempotent) {
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

  const RegistryGeneration generation = fixture.registry->generation();
  const Outcome repeated = add_relation(*fixture.registry, fixture, rack.id, row.id, 11);
  FDR_CHECK_EQ(repeated.code, OutcomeCode::Idempotent);
  FDR_CHECK(fixture.registry->generation() == generation);
  FDR_CHECK_EQ(relation_count(*fixture.registry, rack.id), std::size_t{1});
  FDR_CHECK_EQ(relation_count(*fixture.registry, row.id), std::size_t{1});
  // An idempotent add does not produce a second ancestry either.
  FDR_CHECK_EQ(fixture.registry->ancestors(rack.id).size(), std::size_t{1});

  // The exact replay of the same attempt is idempotent for the same reason.
  const Outcome replay = add_relation(*fixture.registry, fixture, rack.id, row.id, 10);
  FDR_CHECK_EQ(replay.code, OutcomeCode::Idempotent);
  FDR_CHECK(fixture.registry->generation() == generation);
  FDR_CHECK_EQ(relation_count(*fixture.registry, rack.id), std::size_t{1});
}

FDR_TEST_CASE(hierarchy, the_idempotency_window_forgets_the_oldest_attempt_first) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_idempotency_entries_per_publisher = 2;
  Fixture fixture = make_fixture(limits);
  require_fixture(*fixture.registry, fixture);
  FDR_CHECK_EQ(fixture.registry->limits().max_idempotency_entries_per_publisher, std::size_t{2});

  const DomainHandle hub = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                         "rack-hub", 1);
  const DomainHandle first = create_domain(*fixture.registry, fixture, DomainClass::Pdu, "dc1",
                                           "pdu-a", 2);
  const DomainHandle second = create_domain(*fixture.registry, fixture, DomainClass::Pdu, "dc1",
                                            "pdu-b", 3);
  const DomainHandle third = create_domain(*fixture.registry, fixture, DomainClass::Pdu, "dc1",
                                           "pdu-c", 4);
  FDR_CHECK_EQ(hub.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(first.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(second.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(third.outcome.code, OutcomeCode::Committed);

  // Three committed edges, each from its own attempt. The window holds two, so
  // the smallest attempt id is gone by the time the third one is remembered.
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, hub.id, first.id, 100,
                            DomainRelationType::PoweredBy)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, hub.id, second.id, 101,
                            DomainRelationType::PoweredBy)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, hub.id, third.id, 102,
                            DomainRelationType::PoweredBy)
                   .code,
               OutcomeCode::Committed);

  const RegistryGeneration generation = fixture.registry->generation();
  // The forgotten attempt is re-evaluated from the state and answered by the
  // relation that is already there, not recognised as a committed replay.
  const Outcome forgotten = add_relation(*fixture.registry, fixture, hub.id, first.id, 100,
                                         DomainRelationType::PoweredBy);
  FDR_CHECK_EQ(forgotten.code, OutcomeCode::Idempotent);
  FDR_CHECK_EQ(forgotten.message, std::string("the relation already exists"));
  FDR_CHECK(forgotten.message.find("exact replay") == std::string::npos);
  FDR_CHECK(fixture.registry->generation() == generation);
  FDR_CHECK_EQ(relation_count(*fixture.registry, hub.id), std::size_t{3});

  // The two most recent attempts are still inside the window, so they are
  // recognised as exact replays of an already committed mutation.
  const Outcome recent = add_relation(*fixture.registry, fixture, hub.id, third.id, 102,
                                      DomainRelationType::PoweredBy);
  FDR_CHECK_EQ(recent.code, OutcomeCode::Idempotent);
  FDR_CHECK_EQ(recent.message, std::string("exact replay of an already committed mutation"));
  const Outcome older = add_relation(*fixture.registry, fixture, hub.id, second.id, 101,
                                     DomainRelationType::PoweredBy);
  FDR_CHECK_EQ(older.code, OutcomeCode::Idempotent);
  FDR_CHECK_EQ(older.message, std::string("exact replay of an already committed mutation"));
  FDR_CHECK(fixture.registry->generation() == generation);

  // A remembered attempt reused with different content is a conflicting replay,
  // and the refusal leaves the graph exactly as it was.
  const Outcome conflict = add_relation(*fixture.registry, fixture, hub.id, first.id, 102,
                                        DomainRelationType::PoweredBy);
  FDR_CHECK_EQ(conflict.code, OutcomeCode::ConflictingReplay);
  FDR_CHECK(fixture.registry->generation() == generation);
  FDR_CHECK_EQ(relation_count(*fixture.registry, hub.id), std::size_t{3});
  FDR_CHECK_EQ(fixture.registry->relations_of(hub.id).size(), std::size_t{3});

  // Eviction follows the attempt id, not the order the attempts arrived in: the
  // smallest id stays forgotten even after newer traffic.
  const Outcome still_forgotten = add_relation(*fixture.registry, fixture, hub.id, first.id, 100,
                                               DomainRelationType::PoweredBy);
  FDR_CHECK_EQ(still_forgotten.code, OutcomeCode::Idempotent);
  FDR_CHECK_EQ(still_forgotten.message, std::string("the relation already exists"));

  std::string why;
  FDR_CHECK_MSG(fixture.registry->validate_state(&why), "the registry did not validate: " + why);
}

// ---------------------------------------------------------------------------
// Bounded walks
// ---------------------------------------------------------------------------

FDR_TEST_CASE(hierarchy, hierarchy_walks_are_complete_under_the_cross_validated_bounds) {
  // The walk bound and the depth ceiling are cross-validated: a walk bound below
  // the ceiling could truncate silently, so validate() refuses the pair rather
  // than accepting a configuration that lies.
  RegistryLimits invalid = RegistryLimits::defaults();
  invalid.max_ancestor_walk = 4;
  FDR_CHECK(!invalid.validate().ok);
  FDR_CHECK(invalid.validate().message.find("max_ancestor_walk") != std::string::npos);

  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_hierarchy_depth = 4;
  limits.max_ancestor_walk = 4;
  FDR_CHECK_MSG(limits.validate().ok, limits.validate().message);
  Fixture fixture = make_fixture(limits);
  require_fixture(*fixture.registry, fixture);
  FDR_CHECK_EQ(fixture.registry->limits().max_hierarchy_depth, std::size_t{4});
  FDR_CHECK_EQ(fixture.registry->limits().max_ancestor_walk, std::size_t{4});

  // A containment chain exactly as deep as the ceiling admits: five domains,
  // innermost first.
  std::vector<FailureDomainId> chain;
  for (std::uint8_t index = 0; index < 5; ++index) {
    const DomainHandle handle = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                              "rack-" + std::to_string(index),
                                              static_cast<std::uint64_t>(index) + 1u);
    FDR_CHECK_EQ(handle.outcome.code, OutcomeCode::Committed);
    chain.push_back(handle.id);
  }
  for (std::size_t index = 0; index + 1 < chain.size(); ++index) {
    FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, chain[index], chain[index + 1],
                              static_cast<std::uint64_t>(100) + index)
                     .code,
                 OutcomeCode::Committed);
  }

  // Every walk is complete. The depth ceiling bounds the chain and the walk
  // bound is at least the ceiling, so nothing truncates: the walk results are the
  // whole reachable set, and they come back in identity order.
  const std::vector<FailureDomainId> ancestors = fixture.registry->ancestors(chain.front());
  FDR_CHECK_EQ(ancestors.size(), std::size_t{4});
  FDR_CHECK_EQ(ancestors, sorted_ids({chain[1], chain[2], chain[3], chain[4]}));
  const std::vector<FailureDomainId> descendants = fixture.registry->descendants(chain.back());
  FDR_CHECK_EQ(descendants.size(), std::size_t{4});
  FDR_CHECK_EQ(descendants, sorted_ids({chain[0], chain[1], chain[2], chain[3]}));

  // One level deeper would make the hierarchy deeper than the ceiling, so the
  // edge is refused by the ceiling itself, before any acyclicity probe runs.
  const DomainHandle fresh = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                           "rack-fresh", 50);
  FDR_CHECK_EQ(fresh.outcome.code, OutcomeCode::Committed);
  const RegistryGeneration generation = fixture.registry->generation();
  // fresh is declared as a further container of the outermost domain, which is
  // the edge that would make the hierarchy one level deeper than the ceiling.
  const Outcome too_deep = add_relation(*fixture.registry, fixture, chain.back(), fresh.id, 200);
  FDR_CHECK_EQ(too_deep.code, OutcomeCode::InvalidHierarchy);
  FDR_CHECK(too_deep.message.find("max_hierarchy_depth") != std::string::npos);
  FDR_CHECK(fixture.registry->generation() == generation);
  FDR_CHECK(fixture.registry->ancestors(fresh.id).empty());
  FDR_CHECK_EQ(fixture.registry->relations_of(fresh.id).size(), std::size_t{0});

  // The blast radius of the outermost domain reports itself as bounded instead
  // of presenting a possibly incomplete list as complete.
  const BlastRadius radius = fixture.registry->blast_radius(chain.back());
  FDR_CHECK(radius.truncated);
  FDR_CHECK_EQ(radius.child_domains.size(), std::size_t{4});

  // An edge that does not deepen the hierarchy is still committed: the ceiling
  // bounds the graph, not the number of edges, and a sibling at the same level
  // is inside it.
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, fresh.id, chain[1], 201).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(fixture.registry->ancestors(fresh.id),
               sorted_ids({chain[1], chain[2], chain[3], chain[4]}));

  std::string why;
  FDR_CHECK_MSG(fixture.registry->validate_state(&why), "the registry did not validate: " + why);
}

FDR_TEST_CASE(hierarchy, a_deep_containment_chain_resolves_under_the_default_limits) {
  RegistryLimits limits = RegistryLimits::defaults();
  // The default hierarchy ceiling is exactly the deepest chain a containment
  // edge may build, and the walk bound is above it, so a depth-64 chain is both
  // admitted and fully walkable.
  FDR_CHECK_EQ(limits.max_hierarchy_depth, std::size_t{64});
  FDR_CHECK_EQ(limits.max_ancestor_walk, std::size_t{1024});
  Fixture fixture = make_fixture(limits);
  require_fixture(*fixture.registry, fixture);

  constexpr std::size_t kDepth = 64;
  std::vector<FailureDomainId> chain;
  chain.reserve(kDepth);
  for (std::size_t index = 0; index < kDepth; ++index) {
    const DomainHandle handle = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                              "deep-" + std::to_string(index), index + 1u);
    FDR_CHECK_EQ(handle.outcome.code, OutcomeCode::Committed);
    chain.push_back(handle.id);
  }
  for (std::size_t index = 0; index + 1 < chain.size(); ++index) {
    const Outcome link = add_relation(*fixture.registry, fixture, chain[index], chain[index + 1],
                                      1000u + index);
    FDR_CHECK_MSG(link.committed(), "a depth-64 chain link was refused: " + link.message);
  }

  FDR_CHECK_EQ(fixture.registry->ancestors(chain.front()).size(), kDepth - 1u);
  FDR_CHECK_EQ(fixture.registry->descendants(chain.back()).size(), kDepth - 1u);
  FDR_CHECK_EQ(fixture.registry->ancestors(chain.front()),
               sorted_ids(std::vector<FailureDomainId>(chain.begin() + 1, chain.end())));
  FDR_CHECK_EQ(fixture.registry->descendants(chain.back()),
               sorted_ids(std::vector<FailureDomainId>(chain.begin(), chain.end() - 1)));
  // Neither direction contains the domain that was asked about.
  for (const FailureDomainId& id : fixture.registry->ancestors(chain.front())) {
    FDR_CHECK(!(id == chain.front()));
  }
  for (const FailureDomainId& id : fixture.registry->descendants(chain.back())) {
    FDR_CHECK(!(id == chain.back()));
  }
  const BlastRadius radius = fixture.registry->blast_radius(chain.back());
  FDR_CHECK(!radius.truncated);
  FDR_CHECK_EQ(radius.child_domains.size(), kDepth - 1u);

  std::string why;
  FDR_CHECK_MSG(fixture.registry->validate_state(&why), "the registry did not validate: " + why);
}

FDR_TEST_CASE(hierarchy, containment_stays_acyclic_beside_a_symmetric_cycle) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);

  const DomainHandle rack = create_domain(*fixture.registry, fixture, DomainClass::Rack, "dc1",
                                          "rack-1", 1);
  const DomainHandle row = create_domain(*fixture.registry, fixture, DomainClass::Row, "dc1",
                                         "row-1", 2);
  const DomainHandle pod = create_domain(*fixture.registry, fixture, DomainClass::Pod, "dc1",
                                         "pod-1", 3);
  FDR_CHECK_EQ(rack.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(row.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(pod.outcome.code, OutcomeCode::Committed);

  // A containment chain and a correlation triangle over the same three domains.
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, rack.id, row.id, 10).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, row.id, pod.id, 11).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, rack.id, row.id, 12,
                            DomainRelationType::CorrelatedWith)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, row.id, pod.id, 13,
                            DomainRelationType::CorrelatedWith)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, pod.id, rack.id, 14,
                            DomainRelationType::CorrelatedWith)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, pod.id, rack.id, 15,
                            DomainRelationType::SharesRiskWith)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(*fixture.registry, fixture, rack.id, row.id, 16,
                            DomainRelationType::SharesRiskWith)
                   .code,
               OutcomeCode::Committed);

  // Only the containment edges are ancestry, and each domain appears once.
  const std::vector<FailureDomainId> ancestors = fixture.registry->ancestors(rack.id);
  FDR_CHECK_EQ(ancestors, sorted_ids({row.id, pod.id}));
  FDR_CHECK(reports_each_domain_once(ancestors));
  const std::vector<FailureDomainId> descendants = fixture.registry->descendants(pod.id);
  FDR_CHECK_EQ(descendants, sorted_ids({rack.id, row.id}));
  FDR_CHECK(reports_each_domain_once(descendants));
  FDR_CHECK_EQ(fixture.registry->ancestors(pod.id).size(), std::size_t{0});
  FDR_CHECK_EQ(fixture.registry->descendants(rack.id).size(), std::size_t{0});

  // The symmetric edges really are present, so the finite ancestry above is not
  // the result of the triangle being missing.
  FDR_CHECK_EQ(fixture.registry->relations_of(rack.id).size(), std::size_t{5});
  FDR_CHECK_EQ(fixture.registry->relations_of(row.id).size(), std::size_t{5});
  FDR_CHECK_EQ(fixture.registry->relations_of(pod.id).size(), std::size_t{4});
  std::size_t correlated = 0;
  std::size_t contained = 0;
  for (const DomainRelation& relation : fixture.registry->relations_of(rack.id)) {
    if (relation.type == DomainRelationType::ContainedBy) {
      ++contained;
    }
    if (relation.type == DomainRelationType::CorrelatedWith) {
      ++correlated;
    }
  }
  FDR_CHECK_EQ(contained, std::size_t{1});
  FDR_CHECK_EQ(correlated, std::size_t{2});

  std::string why;
  FDR_CHECK_MSG(fixture.registry->validate_state(&why), "the registry did not validate: " + why);
}

// ---------------------------------------------------------------------------
// Longest-path depth enforcement
// ---------------------------------------------------------------------------
//
// max_hierarchy_depth is a ceiling on the true longest containment chain, and a
// containment graph is a DAG rather than a tree: one domain may have several
// containers reached by routes of different lengths. Counting the levels a
// breadth-first walk reaches measures the shortest route to each container and
// therefore undercounts the real chain, so every case below states the depth
// twice: once through the registry and once through the independent topological
// measurement in support/containment_probe.hpp, which reads the graph back from
// the public relation query.

FDR_TEST_CASE(hierarchy, multi_parent_paths_are_measured_by_the_longest_chain) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_hierarchy_depth = 3;
  limits.max_ancestor_walk = 1024;
  FDR_CHECK_MSG(limits.validate().ok, limits.validate().message);
  Fixture fixture = make_fixture(limits);
  require_fixture(*fixture.registry, fixture);
  Registry& registry = *fixture.registry;

  // A is contained by B and by C, and the two routes to Z differ in length:
  // A<B<Z is two edges while A<C<D<Z is three, so the real longest chain above A
  // is three - one short of the ceiling - and a hop count would say two.
  const std::vector<FailureDomainId> chain = create_domains(registry, fixture, "up", 5, 100);
  const FailureDomainId A = chain[0];
  const FailureDomainId B = chain[1];
  const FailureDomainId C = chain[2];
  const FailureDomainId D = chain[3];
  const FailureDomainId Z = chain[4];
  FDR_CHECK_EQ(add_relation(registry, fixture, A, B, 200).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(registry, fixture, A, C, 201).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(registry, fixture, C, D, 202).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(registry, fixture, D, Z, 203).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(registry, fixture, B, Z, 204).code, OutcomeCode::Committed);
  {
    const std::vector<fdrtest::ContainmentEdge> edges = fdrtest::containment_edges(registry);
    FDR_CHECK_EQ(edges.size(), std::size_t{5});
    FDR_CHECK_EQ(fdrtest::longest_chain(edges, A, true), std::size_t{3});
    FDR_CHECK_EQ(fdrtest::max_containment_depth(edges), limits.max_hierarchy_depth);
    // Both routes are visible to the read walk, and the walk is complete
    // because the ceiling is not above the walk bound.
    FDR_CHECK_EQ(registry.ancestors(A), sorted_ids({B, C, D, Z}));
    FDR_CHECK_EQ(registry.ancestors(A).size(), fdrtest::reachable_count(edges, A, true));
  }
  FDR_CHECK(!registry.blast_radius(A).truncated);

  // The reproduction: X contained by A would create X<A<C<D<Z, which is four
  // edges deep, one beyond the ceiling. It must be refused for that reason, and
  // the refusal must report the depth it measured.
  const std::vector<FailureDomainId> extra = create_domains(registry, fixture, "x", 3, 300);
  const FailureDomainId X = extra[0];
  const FailureDomainId Y = extra[1];
  const FailureDomainId P = extra[2];
  const RegistryGeneration before = registry.generation();
  const Outcome refused = add_relation(registry, fixture, X, A, 400);
  FDR_CHECK_EQ(refused.code, OutcomeCode::InvalidHierarchy);
  FDR_CHECK_MSG(refused.message.find("max_hierarchy_depth") != std::string::npos, refused.message);
  FDR_CHECK_MSG(reports_ceiling(refused, limits.max_hierarchy_depth, 4),
                "the refusal did not report the measured depth: " + refused.message);
  FDR_CHECK(registry.generation() == before);
  FDR_CHECK(!has_edge(registry, X, A, DomainRelationType::ContainedBy));
  FDR_CHECK_EQ(registry.ancestors(X).size(), std::size_t{0});
  FDR_CHECK_EQ(registry.relations_of(X).size(), std::size_t{0});

  // Exactly at the ceiling commits: X<C is X<C<D<Z, three edges deep.
  FDR_CHECK_EQ(add_relation(registry, fixture, X, C, 401).code, OutcomeCode::Committed);
  {
    const std::vector<fdrtest::ContainmentEdge> edges = fdrtest::containment_edges(registry);
    FDR_CHECK_EQ(fdrtest::longest_chain(edges, X, true), limits.max_hierarchy_depth);
    FDR_CHECK_EQ(fdrtest::max_containment_depth(edges), limits.max_hierarchy_depth);
    FDR_CHECK_EQ(registry.ancestors(X), sorted_ids({C, D, Z}));
    FDR_CHECK_EQ(registry.ancestors(X).size(), fdrtest::reachable_count(edges, X, true));
  }

  // One level beyond the ceiling is refused: Y<X would be four edges deep.
  const RegistryGeneration at_limit = registry.generation();
  const Outcome beyond = add_relation(registry, fixture, Y, X, 402);
  FDR_CHECK_EQ(beyond.code, OutcomeCode::InvalidHierarchy);
  FDR_CHECK_MSG(reports_ceiling(beyond, limits.max_hierarchy_depth, 4),
                "the refusal did not report the measured depth: " + beyond.message);
  FDR_CHECK(registry.generation() == at_limit);
  FDR_CHECK(!has_edge(registry, Y, X, DomainRelationType::ContainedBy));
  FDR_CHECK_EQ(registry.ancestors(Y).size(), std::size_t{0});

  // An unrelated sibling edge still commits: P contained by a fresh domain
  // shares no chain with the diamond, so it is one edge deep.
  const std::vector<FailureDomainId> siblings = create_domains(registry, fixture, "s", 2, 500);
  FDR_CHECK_EQ(add_relation(registry, fixture, siblings[0], siblings[1], 505).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(fdrtest::longest_chain(fdrtest::containment_edges(registry), siblings[0], true),
               std::size_t{1});

  // Interaction with cycle detection. The depth rule is a bound, not a
  // substitute for acyclicity: a containment closure whose chain fits under the
  // ceiling is still rejected as a cycle, so the corrected measurement cannot
  // mask one.
  const std::vector<FailureDomainId> ring = create_domains(registry, fixture, "r", 2, 600);
  FDR_CHECK_EQ(add_relation(registry, fixture, ring[0], ring[1], 610).code, OutcomeCode::Committed);
  {
    const std::vector<fdrtest::ContainmentEdge> edges = fdrtest::containment_edges(registry);
    FDR_CHECK(fdrtest::would_close_cycle(edges, ring[1], ring[0]));
    // The chain through the closing edge fits exactly at the ceiling, so the
    // depth rule lets it through and the cycle rule is the one that answers.
    FDR_CHECK_EQ(fdrtest::depth_through(edges, ring[1], ring[0]), limits.max_hierarchy_depth);
  }
  const RegistryGeneration ring_before = registry.generation();
  const Outcome cycle = add_relation(registry, fixture, ring[1], ring[0], 611);
  FDR_CHECK_EQ(cycle.code, OutcomeCode::CycleRejected);
  FDR_CHECK(registry.generation() == ring_before);
  FDR_CHECK(!has_edge(registry, ring[1], ring[0], DomainRelationType::ContainedBy));

  // The same acyclicity question for a directed type the ceiling does not apply
  // to: the closure is rejected as a cycle whatever the containment depth is.
  const std::vector<FailureDomainId> depends = create_domains(registry, fixture, "d", 3, 620);
  FDR_CHECK_EQ(add_relation(registry, fixture, depends[0], depends[1], 612,
                            DomainRelationType::DependsOn)
                   .code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(registry, fixture, depends[1], depends[2], 613,
                            DomainRelationType::DependsOn)
                   .code,
               OutcomeCode::Committed);
  const RegistryGeneration depends_before = registry.generation();
  FDR_CHECK_EQ(add_relation(registry, fixture, depends[2], depends[0], 614,
                            DomainRelationType::DependsOn)
                   .code,
               OutcomeCode::CycleRejected);
  FDR_CHECK(registry.generation() == depends_before);

  // A closing edge that would also exceed the ceiling is refused by the depth
  // rule, which is evaluated first; the edge is absent either way, so no cycle
  // is created and the state stays valid. The depth such an edge is measured at
  // is the chain above the container plus the same chain below the contained
  // domain, so a closure of a three-edge chain is measured seven edges deep: an
  // inflated number, but a refusal either way, and the refusal names the number
  // it measured.
  const std::vector<FailureDomainId> closed = create_domains(registry, fixture, "c", 4, 700);
  FDR_CHECK_EQ(add_relation(registry, fixture, closed[0], closed[1], 720).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(registry, fixture, closed[1], closed[2], 721).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(registry, fixture, closed[2], closed[3], 722).code, OutcomeCode::Committed);
  {
    const std::vector<fdrtest::ContainmentEdge> edges = fdrtest::containment_edges(registry);
    FDR_CHECK(fdrtest::would_close_cycle(edges, closed[3], closed[0]));
    FDR_CHECK_EQ(fdrtest::depth_through(edges, closed[3], closed[0]), std::size_t{7});
  }
  const RegistryGeneration closed_before = registry.generation();
  const Outcome deep_cycle = add_relation(registry, fixture, closed[3], closed[0], 723);
  FDR_CHECK_EQ(deep_cycle.code, OutcomeCode::InvalidHierarchy);
  FDR_CHECK_MSG(reports_ceiling(deep_cycle, limits.max_hierarchy_depth, 7),
                "the refusal did not report the measured depth: " + deep_cycle.message);
  FDR_CHECK(registry.generation() == closed_before);
  FDR_CHECK(!has_edge(registry, closed[3], closed[0], DomainRelationType::ContainedBy));

  // Interaction with max_ancestor_walk: a correct depth measurement does not
  // replace the probe budget. In a registry whose walk bound is two, an edge
  // that is inside the ceiling is still refused when the acyclicity probe cannot
  // finish, and the refusal names the probe bound.
  {
    RegistryLimits small = RegistryLimits::defaults();
    small.max_hierarchy_depth = 2;
    small.max_ancestor_walk = 2;
    FDR_CHECK_MSG(small.validate().ok, small.validate().message);
    Fixture bounded = make_fixture(small);
    require_fixture(*bounded.registry, bounded);
    Registry& other = *bounded.registry;
    const std::vector<FailureDomainId> bushy = create_domains(other, bounded, "b", 4, 800);
    for (std::size_t index = 1; index < bushy.size(); ++index) {
      FDR_CHECK_EQ(add_relation(other, bounded, bushy[0], bushy[index],
                                static_cast<std::uint64_t>(810 + index))
                       .code,
                   OutcomeCode::Committed);
    }
    const std::vector<FailureDomainId> fresh = create_domains(other, bounded, "f", 1, 830);
    const std::vector<fdrtest::ContainmentEdge> edges = fdrtest::containment_edges(other);
    // One level deep, so inside the ceiling, but proving acyclicity means
    // visiting four domains and the walk bound is two.
    FDR_CHECK_EQ(fdrtest::depth_through(edges, fresh[0], bushy[0]), small.max_hierarchy_depth);
    const Outcome probe_refusal = add_relation(other, bounded, fresh[0], bushy[0], 840);
    FDR_CHECK_EQ(probe_refusal.code, OutcomeCode::InvalidHierarchy);
    FDR_CHECK_MSG(probe_refusal.message.find("max_ancestor_walk") != std::string::npos,
                  "a bounded probe was not reported as bounded: " + probe_refusal.message);
    std::string why;
    FDR_CHECK_MSG(other.validate_state(&why), "the bounded registry did not validate: " + why);
  }

  // Insertion-order independence: the same five edges inserted in four different
  // orders reach the same graph, the same measured depths and the same state
  // digest, so the depth result is a property of the graph and not of the order
  // it arrived in.
  const std::pair<std::size_t, std::size_t> diamond[5] = {
      {0, 1}, {0, 2}, {2, 3}, {3, 4}, {1, 4}};
  const std::size_t orders[4][5] = {
      {0, 1, 2, 3, 4}, {4, 3, 2, 1, 0}, {1, 3, 0, 4, 2}, {2, 4, 1, 3, 0}};
  failure_domain_registry::StateDigest diamond_digest;
  bool have_digest = false;
  for (const auto& order : orders) {
    Fixture ordered = make_fixture(limits);
    require_fixture(*ordered.registry, ordered);
    const std::vector<FailureDomainId> ids = create_domains(*ordered.registry, ordered, "o", 5, 900);
    for (std::size_t position = 0; position < 5; ++position) {
      const std::size_t index = order[position];
      const Outcome outcome =
          add_relation(*ordered.registry, ordered, ids[diamond[index].first],
                       ids[diamond[index].second], static_cast<std::uint64_t>(950 + position));
      FDR_CHECK_MSG(outcome.code == OutcomeCode::Committed,
                    "an edge of a legal diamond was refused: " + outcome.message);
    }
    const std::vector<fdrtest::ContainmentEdge> edges =
        fdrtest::containment_edges(*ordered.registry);
    FDR_CHECK_EQ(edges.size(), std::size_t{5});
    FDR_CHECK_EQ(fdrtest::longest_chain(edges, ids[0], true), std::size_t{3});
    FDR_CHECK_EQ(fdrtest::max_containment_depth(edges), limits.max_hierarchy_depth);
    const failure_domain_registry::StateDigest digest = ordered.registry->state_digest();
    if (have_digest) {
      FDR_CHECK_MSG(digest == diamond_digest,
                    "the same edge set in another order reached another digest");
    } else {
      diamond_digest = digest;
      have_digest = true;
    }
  }
  FDR_CHECK(have_digest);

  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the registry did not validate: " + why);
}

FDR_TEST_CASE(hierarchy, multi_child_paths_are_measured_by_the_longest_chain) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_hierarchy_depth = 3;
  limits.max_ancestor_walk = 1024;
  Fixture fixture = make_fixture(limits);
  require_fixture(*fixture.registry, fixture);
  Registry& registry = *fixture.registry;

  // The descendant-side mirror of the case above: X contains M and N, the route
  // down to W is X<M<K<W through one child and X<N<W through the other, so the
  // real longest chain below X is three while a hop count would say two.
  const std::vector<FailureDomainId> chain = create_domains(registry, fixture, "down", 5, 100);
  const FailureDomainId M = chain[0];
  const FailureDomainId N = chain[1];
  const FailureDomainId K = chain[2];
  const FailureDomainId W = chain[3];
  const FailureDomainId X = chain[4];
  FDR_CHECK_EQ(add_relation(registry, fixture, M, X, 200).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(registry, fixture, N, X, 201).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(registry, fixture, K, M, 202).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(registry, fixture, W, K, 203).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(add_relation(registry, fixture, W, N, 204).code, OutcomeCode::Committed);
  {
    const std::vector<fdrtest::ContainmentEdge> edges = fdrtest::containment_edges(registry);
    FDR_CHECK_EQ(fdrtest::longest_chain(edges, X, false), std::size_t{3});
    FDR_CHECK_EQ(fdrtest::max_containment_depth(edges), limits.max_hierarchy_depth);
    // The two children really do have descendant depths that differ.
    FDR_CHECK_EQ(fdrtest::longest_chain(edges, M, false), std::size_t{2});
    FDR_CHECK_EQ(fdrtest::longest_chain(edges, N, false), std::size_t{1});
    // The read walk returns every descendant, not only the longest route.
    FDR_CHECK_EQ(registry.descendants(X), sorted_ids({M, N, K, W}));
    FDR_CHECK_EQ(registry.descendants(X).size(), fdrtest::reachable_count(edges, X, false));
  }

  // A container one level above X would create a chain four edges deep, so it is
  // refused for the ceiling - the descendant side is measured exactly like the
  // ancestor side.
  const std::vector<FailureDomainId> extra = create_domains(registry, fixture, "e", 2, 300);
  const FailureDomainId container = extra[0];
  const FailureDomainId other = extra[1];
  const RegistryGeneration before = registry.generation();
  const Outcome refused = add_relation(registry, fixture, X, container, 400);
  FDR_CHECK_EQ(refused.code, OutcomeCode::InvalidHierarchy);
  FDR_CHECK_MSG(reports_ceiling(refused, limits.max_hierarchy_depth, 4), refused.message);
  FDR_CHECK(registry.generation() == before);
  FDR_CHECK(!has_edge(registry, X, container, DomainRelationType::ContainedBy));
  FDR_CHECK_EQ(registry.descendants(container).size(), std::size_t{0});

  // Exactly at the ceiling commits: M contained by the new container makes the
  // chain container<M<K<W, three edges below the new container.
  {
    const std::vector<fdrtest::ContainmentEdge> edges = fdrtest::containment_edges(registry);
    FDR_CHECK_EQ(fdrtest::depth_through(edges, M, container), limits.max_hierarchy_depth);
  }
  FDR_CHECK_EQ(add_relation(registry, fixture, M, container, 401).code, OutcomeCode::Committed);
  {
    const std::vector<fdrtest::ContainmentEdge> edges = fdrtest::containment_edges(registry);
    FDR_CHECK_EQ(fdrtest::longest_chain(edges, container, false), limits.max_hierarchy_depth);
    FDR_CHECK_EQ(fdrtest::max_containment_depth(edges), limits.max_hierarchy_depth);
  }

  // One level beyond is still refused, now measured through the new route as
  // well: X contained by a second fresh container would be four edges deep.
  const RegistryGeneration at_limit = registry.generation();
  const Outcome beyond = add_relation(registry, fixture, X, other, 402);
  FDR_CHECK_EQ(beyond.code, OutcomeCode::InvalidHierarchy);
  FDR_CHECK_MSG(reports_ceiling(beyond, limits.max_hierarchy_depth, 4), beyond.message);
  FDR_CHECK(registry.generation() == at_limit);
  FDR_CHECK(!has_edge(registry, X, other, DomainRelationType::ContainedBy));

  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the registry did not validate: " + why);
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
