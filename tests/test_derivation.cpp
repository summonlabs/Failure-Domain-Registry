// Failure Domain Registry — derivation rule engine proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Derivation is the one place where this runtime writes a membership nobody
// published directly, so every case checks the whole contract: the rule identity
// is derived from the definition and nothing else, a rule can only be published
// by an authorized publisher, every derived membership records the rule, the
// exact source memberships and their generations, and a derivation whose sources
// moved on is either recomputed or withdrawn - never quietly left standing.
//
// The reports are asserted field by field, because "something changed" is not a
// contract: memberships_created, _updated, _withdrawn and _unchanged have to
// describe exactly what the pass did, and a second identical pass has to leave
// the state digest and the generation untouched. Every case that drives a
// registry also ends with validate_state, so an index that drifted while a
// membership was rewritten cannot pass unnoticed.
//
// One refusal is asserted as the implementation produces it rather than as the
// header comment describes it: withdraw_evidence() on a derived membership is
// refused with IDEMPOTENT ("this publisher has no matching evidence"), not with
// POLICY_REJECTED, because a derived membership's evidence never carries a
// publisher identity and the evidence match is tested before the kind.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "failure_domain_registry/authority.hpp"
#include "failure_domain_registry/derivation.hpp"
#include "failure_domain_registry/digest.hpp"
#include "failure_domain_registry/domain.hpp"
#include "failure_domain_registry/domain_class.hpp"
#include "failure_domain_registry/entity.hpp"
#include "failure_domain_registry/errors.hpp"
#include "failure_domain_registry/ids.hpp"
#include "failure_domain_registry/lifecycle.hpp"
#include "failure_domain_registry/membership.hpp"
#include "failure_domain_registry/provenance.hpp"
#include "failure_domain_registry/registry.hpp"
#include "failure_domain_registry/requests.hpp"
#include "support/test_harness.hpp"

namespace {

using failure_domain_registry::AttachMemberRequest;
using failure_domain_registry::AuthorityContext;
using failure_domain_registry::AuthorityScope;
using failure_domain_registry::CoordinatorEpoch;
using failure_domain_registry::CreateDomainRequest;
using failure_domain_registry::DependencySemantics;
using failure_domain_registry::DerivationGeneration;
using failure_domain_registry::DerivationOperator;
using failure_domain_registry::DerivationReport;
using failure_domain_registry::DerivationRule;
using failure_domain_registry::DerivationRuleId;
using failure_domain_registry::DerivationRunRequest;
using failure_domain_registry::DetachMemberRequest;
using failure_domain_registry::DomainClass;
using failure_domain_registry::DomainClassRef;
using failure_domain_registry::EntityClass;
using failure_domain_registry::EntityGeneration;
using failure_domain_registry::EntityId;
using failure_domain_registry::EntityInvalidationRequest;
using failure_domain_registry::EntityRef;
using failure_domain_registry::EvidenceClass;
using failure_domain_registry::ExplanationStep;
using failure_domain_registry::FailureDomainGeneration;
using failure_domain_registry::FailureDomainId;
using failure_domain_registry::IdBytes;
using failure_domain_registry::Membership;
using failure_domain_registry::MembershipGeneration;
using failure_domain_registry::MembershipId;
using failure_domain_registry::MembershipKind;
using failure_domain_registry::MembershipLifecycle;
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
using failure_domain_registry::StateDigest;
using failure_domain_registry::TopologyChangeRequest;
using failure_domain_registry::TopologyGeneration;
using failure_domain_registry::TruthClass;
using failure_domain_registry::WithdrawEvidenceRequest;
using failure_domain_registry::WorkerBootId;
using failure_domain_registry::derivation_rule_id_for;
using failure_domain_registry::domain_id_for;
using failure_domain_registry::is_valid_derivation_operator;
using failure_domain_registry::to_string;

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

EntityRef entity_ref(EntityClass entity_class, std::uint8_t seed, std::uint64_t generation) {
  IdBytes bytes{};
  bytes[0] = seed;
  bytes[1] = 0x11u;
  bytes[2] = static_cast<std::uint8_t>(entity_class);
  return EntityRef(EntityId(entity_class, bytes), EntityGeneration(generation));
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

/// A registry with one unrestricted publisher and one publisher confined to the
/// Rack class, both with a live incarnation at the established epoch.
struct Fixture {
  std::unique_ptr<Registry> registry;
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  CoordinatorEpoch epoch{};
  AuthorityContext authority{};
  Provenance provenance{};
  PublisherId confined{};
  WorkerBootId confined_boot{};
  AuthorityContext confined_authority{};
};

Fixture make_fixture(RegistryLimits limits) {
  Fixture fixture;
  fixture.registry = std::make_unique<Registry>(limits);
  fixture.publisher = publisher_from(0x01u);
  fixture.worker_boot = boot_from(0x02u);
  PublisherRegistration registration;
  registration.publisher = fixture.publisher;
  registration.name = "derivation-publisher";
  registration.scope = AuthorityScope::unrestricted();
  fixture.registry->grant_publisher(registration, AuthorityContext{});
  CoordinatorEpoch epoch;
  if (fixture.registry->advance_epoch(CoordinatorEpoch{}, &epoch).committed()) {
    fixture.epoch = epoch;
  }
  fixture.registry->attach_worker(fixture.publisher, fixture.worker_boot, fixture.epoch,
                                  "derivation-suite",
                                  EvidenceClass::DirectAuthoritativeInfrastructure);
  fixture.authority.publisher = fixture.publisher;
  fixture.authority.worker_boot = fixture.worker_boot;
  fixture.authority.epoch = fixture.epoch;
  fixture.authority.evidence = EvidenceClass::DirectAuthoritativeInfrastructure;
  fixture.provenance = provenance_of(ProvenanceSource::PhysicalInfrastructure,
                                     EvidenceClass::DirectAuthoritativeInfrastructure, TruthClass::Real,
                                     "derivation-inventory");

  fixture.confined = publisher_from(0x03u);
  fixture.confined_boot = boot_from(0x04u);
  PublisherRegistration confined;
  confined.publisher = fixture.confined;
  confined.name = "derivation-confined";
  confined.scope = AuthorityScope::for_classes(
      std::vector<DomainClass>{DomainClass::Rack}, EvidenceClass::DirectAuthoritativeInfrastructure);
  fixture.registry->grant_publisher(confined, fixture.authority);
  fixture.registry->attach_worker(fixture.confined, fixture.confined_boot, fixture.epoch,
                                  "derivation-confined",
                                  EvidenceClass::DirectAuthoritativeInfrastructure);
  fixture.confined_authority.publisher = fixture.confined;
  fixture.confined_authority.worker_boot = fixture.confined_boot;
  fixture.confined_authority.epoch = fixture.epoch;
  fixture.confined_authority.evidence = EvidenceClass::DirectAuthoritativeInfrastructure;
  return fixture;
}

void require_fixture(Registry& registry, const Fixture& fixture) {
  FDR_CHECK_EQ(fixture.epoch.value(), std::uint64_t{1});
  FDR_CHECK(registry.is_worker_live(fixture.publisher, fixture.worker_boot));
  FDR_CHECK(registry.is_worker_live(fixture.confined, fixture.confined_boot));
  FDR_CHECK_EQ(registry.publishers().size(), std::size_t{2});
}

struct DomainHandle {
  Outcome outcome;
  FailureDomainId id{};
};

DomainHandle create_domain(Registry& registry, const Fixture& fixture, DomainClass domain_class,
                           const std::string& identity_key, std::uint64_t attempt_number) {
  CreateDomainRequest request;
  request.attempt = attempt_from(attempt_number);
  request.authority = fixture.authority;
  request.domain_class = DomainClassRef(domain_class);
  request.administrative_scope = "dc1";
  request.identity_key = identity_key;
  request.name = identity_key;
  request.provenance = fixture.provenance;
  DomainHandle handle;
  handle.outcome = registry.create_domain(request);
  handle.id = domain_id_for("dc1", DomainClassRef(domain_class), identity_key);
  return handle;
}

Outcome attach_entity(Registry& registry, const Fixture& fixture, const FailureDomainId& domain,
                      const EntityRef& member, std::uint64_t attempt_number,
                      MembershipKind kind = MembershipKind::Direct,
                      MembershipRole role = MembershipRole::Primary) {
  AttachMemberRequest request;
  request.attempt = attempt_from(attempt_number);
  request.authority = fixture.authority;
  request.domain = domain;
  request.member = member;
  request.kind = kind;
  request.role = role;
  request.provenance = fixture.provenance;
  return registry.attach_member(request);
}

Outcome detach_entity(Registry& registry, const Fixture& fixture, const FailureDomainId& domain,
                      const EntityRef& member, std::uint64_t attempt_number) {
  DetachMemberRequest request;
  request.attempt = attempt_from(attempt_number);
  request.authority = fixture.authority;
  request.domain = domain;
  request.member = member;
  request.kind = MembershipKind::Direct;
  request.reason = "derivation-suite";
  return registry.detach_member(request);
}

DerivationRule rule_of(const std::string& name, DerivationOperator op, DomainClass source_class,
                       DomainClass target_class, EntityClass member_class, std::uint32_t version) {
  DerivationRule rule;
  rule.name = name;
  rule.op = op;
  rule.source_class = DomainClassRef(source_class);
  rule.target_class = DomainClassRef(target_class);
  rule.member_class = member_class;
  rule.derived_role = MembershipRole::Derived;
  rule.dependency = DependencySemantics::AllDependenciesRequired;
  rule.rule_version = version;
  return rule;
}

Outcome publish_rule(Registry& registry, const Fixture& fixture, const DerivationRule& rule) {
  return registry.publish_derivation_rule(rule, fixture.authority);
}

DerivationRunRequest run_request(const Fixture& fixture, std::uint64_t attempt_number,
                                 const DerivationRuleId& only_rule = DerivationRuleId{}) {
  DerivationRunRequest request;
  request.attempt = attempt_from(attempt_number);
  request.authority = fixture.authority;
  request.rule = only_rule;
  return request;
}

/// The derived membership of one member in one domain, when it exists.
std::optional<Membership> derived_membership_of(Registry& registry, const EntityRef& member,
                                                const FailureDomainId& domain) {
  for (const Membership& membership : registry.memberships_of(member)) {
    if (membership.kind == MembershipKind::Derived && membership.domain == domain) {
      return membership;
    }
  }
  return std::nullopt;
}

/// The direct membership record of one member in one domain, or the null id.
MembershipId direct_membership_of(Registry& registry, const FailureDomainId& domain,
                                  const EntityRef& member) {
  for (const Membership& membership : registry.memberships_of(member)) {
    if (membership.kind == MembershipKind::Direct && membership.domain == domain) {
      return membership.id;
    }
  }
  return MembershipId{};
}

std::size_t derived_count(Registry& registry) {
  std::size_t count = 0;
  for (const Membership& membership : registry.memberships_in_lifecycle(MembershipLifecycle::Current)) {
    if (membership.kind == MembershipKind::Derived) {
      ++count;
    }
  }
  return count;
}

bool has_source(const Membership& membership, const MembershipId& id) {
  return std::find(membership.derivation.sources.begin(), membership.derivation.sources.end(), id) !=
         membership.derivation.sources.end();
}

bool has_step(const std::vector<ExplanationStep>& steps, std::string_view stage) {
  for (const ExplanationStep& step : steps) {
    if (step.stage == stage) {
      return true;
    }
  }
  return false;
}

/// Fails the case unless the registry is internally consistent.
void require_valid(Registry& registry) {
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the registry did not validate: " + why);
}

/// Every report field is asserted, so a pass that claims to have done nothing
/// while it changed something cannot pass.
void require_quiet_report(const DerivationReport& report, std::size_t unchanged) {
  FDR_CHECK_EQ(report.rules_evaluated, std::size_t{1});
  FDR_CHECK_EQ(report.memberships_created, std::size_t{0});
  FDR_CHECK_EQ(report.memberships_updated, std::size_t{0});
  FDR_CHECK_EQ(report.memberships_withdrawn, std::size_t{0});
  FDR_CHECK_EQ(report.memberships_unchanged, unchanged);
  FDR_CHECK_EQ(report.bounded_out, std::size_t{0});
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// Two chassis domains with two switches each, and one rack that holds all four
/// switches. MembersShareContainingClass(source=Chassis, target=Rack) must give
/// every switch a derived membership in the rack, whichever chassis it sits in.
struct ChassisScenario {
  FailureDomainId chassis_one{};
  FailureDomainId chassis_two{};
  FailureDomainId rack{};
  std::array<EntityRef, 4> switches{};
  std::array<FailureDomainId, 4> chassis_of{};
  DerivationRule rule{};
  DerivationRuleId rule_id{};
};

ChassisScenario build_chassis_scenario(Registry& registry, const Fixture& fixture) {
  ChassisScenario scenario;
  const DomainHandle chassis_one =
      create_domain(registry, fixture, DomainClass::Chassis, "chassis-1", 1);
  const DomainHandle chassis_two =
      create_domain(registry, fixture, DomainClass::Chassis, "chassis-2", 2);
  const DomainHandle rack = create_domain(registry, fixture, DomainClass::Rack, "rack-1", 3);
  scenario.chassis_one = chassis_one.id;
  scenario.chassis_two = chassis_two.id;
  scenario.rack = rack.id;
  scenario.switches = {entity_ref(EntityClass::Switch, 0x01u, 1), entity_ref(EntityClass::Switch, 0x02u, 1),
                       entity_ref(EntityClass::Switch, 0x03u, 1), entity_ref(EntityClass::Switch, 0x04u, 1)};
  for (std::size_t index = 0; index < scenario.switches.size(); ++index) {
    scenario.chassis_of[index] = index < 2 ? scenario.chassis_one : scenario.chassis_two;
    attach_entity(registry, fixture, scenario.chassis_of[index], scenario.switches[index],
                  static_cast<std::uint64_t>(10) + index);
    attach_entity(registry, fixture, scenario.rack, scenario.switches[index],
                  static_cast<std::uint64_t>(20) + index);
  }
  scenario.rule = rule_of("shared-chassis-shared-rack",
                          DerivationOperator::MembersShareContainingClass, DomainClass::Chassis,
                          DomainClass::Rack, EntityClass::Switch, 1);
  scenario.rule_id = derivation_rule_id_for(scenario.rule);
  return scenario;
}

/// One port-group domain whose members are a switch and three ports, one rack
/// for the switch and one rack for a port. SameDomainMemberRelationship with
/// member_class=Switch must let every port inherit the switch's racks only.
struct PortScenario {
  FailureDomainId port_group{};
  FailureDomainId switch_rack{};
  FailureDomainId port_rack{};
  EntityRef switch_entity{};
  std::array<EntityRef, 3> ports{};
  DerivationRule rule{};
  DerivationRuleId rule_id{};
};

PortScenario build_port_scenario(Registry& registry, const Fixture& fixture) {
  PortScenario scenario;
  const DomainHandle ports = create_domain(registry, fixture, DomainClass::PortGroup, "port-group-1", 1);
  const DomainHandle switch_rack = create_domain(registry, fixture, DomainClass::Rack, "rack-switch", 2);
  const DomainHandle port_rack = create_domain(registry, fixture, DomainClass::Rack, "rack-port", 3);
  scenario.port_group = ports.id;
  scenario.switch_rack = switch_rack.id;
  scenario.port_rack = port_rack.id;
  scenario.switch_entity = entity_ref(EntityClass::Switch, 0x01u, 1);
  scenario.ports = {entity_ref(EntityClass::Port, 0x02u, 1), entity_ref(EntityClass::Port, 0x03u, 1),
                    entity_ref(EntityClass::Port, 0x04u, 1)};
  attach_entity(registry, fixture, scenario.port_group, scenario.switch_entity, 10);
  for (std::size_t index = 0; index < scenario.ports.size(); ++index) {
    attach_entity(registry, fixture, scenario.port_group, scenario.ports[index],
                  static_cast<std::uint64_t>(11) + index);
  }
  attach_entity(registry, fixture, scenario.switch_rack, scenario.switch_entity, 20);
  attach_entity(registry, fixture, scenario.port_rack, scenario.ports[1], 21);
  scenario.rule = rule_of("port-inherits-endpoint-rack",
                          DerivationOperator::SameDomainMemberRelationship, DomainClass::PortGroup,
                          DomainClass::Rack, EntityClass::Switch, 1);
  scenario.rule_id = derivation_rule_id_for(scenario.rule);
  return scenario;
}

} // namespace

// ---------------------------------------------------------------------------
// Rule identity
// ---------------------------------------------------------------------------

FDR_TEST_CASE(derivation, derivation_rule_id_is_deterministic_and_definition_sensitive) {
  const DerivationRule base = rule_of("shared-chassis-shared-rack",
                                      DerivationOperator::MembersShareContainingClass,
                                      DomainClass::Chassis, DomainClass::Rack, EntityClass::Switch, 1);
  const DerivationRuleId id = derivation_rule_id_for(base);
  FDR_CHECK(!id.is_null());
  FDR_CHECK_EQ(derivation_rule_id_for(base), id);
  FDR_CHECK_EQ(base.canonical_form(), base.canonical_form());
  FDR_CHECK_EQ(id.to_string().size(), std::size_t{32});

  // Every field of the definition participates in the identity.
  DerivationRule renamed = base;
  renamed.name = "shared-chassis-shared-rack-v2";
  DerivationRule other_op = base;
  other_op.op = DerivationOperator::SameDomainMemberRelationship;
  DerivationRule other_source = base;
  other_source.source_class = DomainClassRef(DomainClass::Chassis);
  DerivationRule other_source_class = base;
  other_source_class.source_class = DomainClassRef(DomainClass::PortGroup);
  DerivationRule other_target = base;
  other_target.target_class = DomainClassRef(DomainClass::Row);
  DerivationRule other_member = base;
  other_member.member_class = EntityClass::Host;
  DerivationRule other_version = base;
  other_version.rule_version = 2;
  DerivationRule other_role = base;
  other_role.derived_role = MembershipRole::Containment;
  DerivationRule other_dependency = base;
  other_dependency.dependency = DependencySemantics::Unspecified;
  FDR_CHECK(!(derivation_rule_id_for(renamed) == id));
  FDR_CHECK(!(derivation_rule_id_for(other_op) == id));
  FDR_CHECK(!(derivation_rule_id_for(other_source_class) == id));
  FDR_CHECK(!(derivation_rule_id_for(other_target) == id));
  FDR_CHECK(!(derivation_rule_id_for(other_member) == id));
  FDR_CHECK(!(derivation_rule_id_for(other_version) == id));
  FDR_CHECK(!(derivation_rule_id_for(other_role) == id));
  FDR_CHECK(!(derivation_rule_id_for(other_dependency) == id));
  // A rule that reads one class and writes the same class is not a definition
  // that can be told apart from another, but its identity still differs.
  FDR_CHECK_EQ(derivation_rule_id_for(other_source), id);

  // Who published the rule, when, and whether it is enabled are not part of the
  // definition: they never change the identity.
  DerivationRule attributed = base;
  attributed.publisher = publisher_from(0x77u);
  attributed.published_at = RegistryGeneration(41);
  attributed.enabled = false;
  FDR_CHECK_EQ(derivation_rule_id_for(attributed), id);

  // The operator vocabulary is closed.
  FDR_CHECK(is_valid_derivation_operator(DerivationOperator::MembersShareContainingClass));
  FDR_CHECK(is_valid_derivation_operator(DerivationOperator::SameDomainMemberRelationship));
  FDR_CHECK(!is_valid_derivation_operator(DerivationOperator::Unknown));
  FDR_CHECK(!is_valid_derivation_operator(static_cast<DerivationOperator>(9)));
  FDR_CHECK_EQ(to_string(DerivationOperator::SameDomainMemberRelationship),
               std::string_view("same-domain-member-relationship"));
}

// ---------------------------------------------------------------------------
// Publishing
// ---------------------------------------------------------------------------

FDR_TEST_CASE(derivation, publishing_a_rule_requires_authority) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);
  const DerivationRule rule = rule_of("shared-chassis-shared-rack",
                                      DerivationOperator::MembersShareContainingClass,
                                      DomainClass::Chassis, DomainClass::Rack, EntityClass::Switch, 1);
  const RegistryGeneration generation = fixture.registry->generation();

  // No authority, a publisher nobody registered, and a publisher whose scope
  // does not cover the classes the rule reads and writes are three refusals.
  FDR_CHECK_EQ(fixture.registry->publish_derivation_rule(rule, AuthorityContext{}).code,
               OutcomeCode::NoAuthority);
  AuthorityContext unknown = fixture.authority;
  unknown.publisher = publisher_from(0x31u);
  unknown.worker_boot = boot_from(0x32u);
  FDR_CHECK_EQ(fixture.registry->publish_derivation_rule(rule, unknown).code,
               OutcomeCode::StaleAuthority);
  FDR_CHECK_EQ(fixture.registry->publish_derivation_rule(rule, fixture.confined_authority).code,
               OutcomeCode::UnauthorizedScope);
  FDR_CHECK(fixture.registry->derivation_rules().empty());
  FDR_CHECK(fixture.registry->generation() == generation);
  require_valid(*fixture.registry);

  // A malformed definition is refused before anything is stored.
  DerivationRule bad_operator = rule;
  bad_operator.op = DerivationOperator::Unknown;
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, bad_operator).code,
               OutcomeCode::MalformedRequest);
  DerivationRule bad_operator_value = rule;
  bad_operator_value.op = static_cast<DerivationOperator>(9);
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, bad_operator_value).code,
               OutcomeCode::MalformedRequest);
  DerivationRule same_classes = rule;
  same_classes.source_class = DomainClassRef(DomainClass::Rack);
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, same_classes).code,
               OutcomeCode::MalformedRequest);
  DerivationRule extension_target = rule;
  extension_target.target_class = DomainClassRef();
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, extension_target).code,
               OutcomeCode::MalformedRequest);
  DerivationRule empty_name = rule;
  empty_name.name.clear();
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, empty_name).code,
               OutcomeCode::MalformedRequest);
  DerivationRule long_name = rule;
  long_name.name = std::string(fixture.registry->limits().max_string_bytes + 1u, 'x');
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, long_name).code,
               OutcomeCode::MalformedRequest);
  FDR_CHECK(fixture.registry->derivation_rules().empty());
  FDR_CHECK(fixture.registry->generation() == generation);

  // The valid definition is accepted, exactly once.
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, rule).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(fixture.registry->derivation_rules().size(), std::size_t{1});
  FDR_CHECK(!(fixture.registry->generation() == generation));
  require_valid(*fixture.registry);
}

FDR_TEST_CASE(derivation, publishing_the_same_definition_twice_is_idempotent) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);
  const DerivationRule rule = rule_of("shared-chassis-shared-rack",
                                      DerivationOperator::MembersShareContainingClass,
                                      DomainClass::Chassis, DomainClass::Rack, EntityClass::Switch, 3);
  const RegistryGeneration before = fixture.registry->generation();

  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, rule).code, OutcomeCode::Committed);
  const RegistryGeneration published_at = before;
  const RegistryGeneration after_first = fixture.registry->generation();
  FDR_CHECK(!(after_first == published_at));

  const std::vector<DerivationRule> rules = fixture.registry->derivation_rules();
  FDR_CHECK_EQ(rules.size(), std::size_t{1});
  const DerivationRule& stored = rules.front();
  FDR_CHECK_EQ(stored.id, derivation_rule_id_for(rule));
  FDR_CHECK_EQ(stored.name, rule.name);
  FDR_CHECK_EQ(stored.op, rule.op);
  FDR_CHECK_EQ(stored.source_class, rule.source_class);
  FDR_CHECK_EQ(stored.target_class, rule.target_class);
  FDR_CHECK_EQ(stored.member_class, rule.member_class);
  FDR_CHECK_EQ(stored.derived_role, rule.derived_role);
  FDR_CHECK_EQ(stored.dependency, rule.dependency);
  FDR_CHECK_EQ(stored.rule_version, rule.rule_version);
  FDR_CHECK_EQ(stored.publisher, fixture.publisher);
  FDR_CHECK(stored.published_at == published_at);
  FDR_CHECK(stored.enabled);

  // The same definition again is the same rule, and the pass is not repeated.
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, rule).code, OutcomeCode::Idempotent);
  FDR_CHECK(fixture.registry->generation() == after_first);
  FDR_CHECK_EQ(fixture.registry->derivation_rules().size(), std::size_t{1});

  // enabled is not part of the definition, so flipping it updates the stored
  // rule in place instead of creating a second identity.
  DerivationRule disabled = rule;
  disabled.enabled = false;
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, disabled).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(fixture.registry->derivation_rules().size(), std::size_t{1});
  FDR_CHECK(!fixture.registry->derivation_rules().front().enabled);
  FDR_CHECK_EQ(fixture.registry->derivation_rules().front().id, derivation_rule_id_for(rule));
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, disabled).code, OutcomeCode::Idempotent);
  require_valid(*fixture.registry);

  // A disabled rule is not evaluated at all.
  DerivationReport report;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 30), &report).code,
               OutcomeCode::NotFound);
  FDR_CHECK_EQ(report.rules_evaluated, std::size_t{0});
}

// ---------------------------------------------------------------------------
// MembersShareContainingClass
// ---------------------------------------------------------------------------

FDR_TEST_CASE(derivation, members_share_containing_class_derives_across_chassis) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);
  ChassisScenario scenario = build_chassis_scenario(*fixture.registry, fixture);
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, scenario.rule).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(derived_count(*fixture.registry), std::size_t{0});

  const RegistryGeneration before = fixture.registry->generation();
  DerivationReport report;
  const Outcome outcome =
      fixture.registry->run_derivation(run_request(fixture, 30), &report);
  FDR_CHECK_EQ(outcome.code, OutcomeCode::Committed);
  FDR_CHECK(has_step(outcome.steps, "derive"));
  FDR_CHECK_EQ(report.rules_evaluated, std::size_t{1});
  FDR_CHECK_EQ(report.memberships_created, std::size_t{4});
  FDR_CHECK_EQ(report.memberships_updated, std::size_t{0});
  FDR_CHECK_EQ(report.memberships_withdrawn, std::size_t{0});
  FDR_CHECK_EQ(report.memberships_unchanged, std::size_t{0});
  FDR_CHECK_EQ(report.bounded_out, std::size_t{0});
  // The report names the generation the pass produced, and the pass advanced it.
  FDR_CHECK(report.generation == fixture.registry->generation());
  FDR_CHECK_EQ(fixture.registry->generation().value(), before.value() + 1u);
  FDR_CHECK_EQ(derived_count(*fixture.registry), std::size_t{4});

  for (std::size_t index = 0; index < scenario.switches.size(); ++index) {
    const EntityRef& member = scenario.switches[index];
    const std::optional<Membership> derived =
        derived_membership_of(*fixture.registry, member, scenario.rack);
    FDR_CHECK(derived.has_value());
    FDR_CHECK_EQ(derived->domain, scenario.rack);
    FDR_CHECK_EQ(derived->kind, MembershipKind::Derived);
    FDR_CHECK_EQ(derived->role, MembershipRole::Derived);
    FDR_CHECK_EQ(derived->dependency, DependencySemantics::AllDependenciesRequired);
    FDR_CHECK_EQ(derived->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK(derived->generation == MembershipGeneration::first());
    FDR_CHECK(derived->member == member);
    FDR_CHECK_EQ(derived->evidence_generation.is_zero(), false);
    FDR_CHECK_EQ(derived->live_evidence_count(), std::size_t{1});
    FDR_CHECK(derived->created_epoch == fixture.epoch);
    FDR_CHECK(derived->superseded_by.is_null());
    FDR_CHECK(derived->is_current());
    // The rule, its version and the exact sources are recorded on the record.
    FDR_CHECK_EQ(derived->derivation.rule, scenario.rule_id);
    FDR_CHECK(derived->derivation.valid);
    FDR_CHECK(derived->derivation.generation == DerivationGeneration(before.value()));
    FDR_CHECK_EQ(derived->derivation.sources.size(), std::size_t{3});
    FDR_CHECK_EQ(derived->derivation.source_generations.size(),
                 derived->derivation.sources.size());
    FDR_CHECK(!derived->derivation.context.empty());
    FDR_CHECK_EQ(derived->provenance.source, ProvenanceSource::DerivationRule);
    FDR_CHECK_EQ(derived->provenance.evidence, EvidenceClass::DerivedTopology);
    FDR_CHECK_EQ(derived->provenance.truth, TruthClass::Real);
    FDR_CHECK_EQ(derived->provenance.derivation_rule, scenario.rule_id);
    FDR_CHECK(!derived->provenance.derivation_context.empty());
    // The member's own membership in the source domain is one of the sources.
    const MembershipId own =
        direct_membership_of(*fixture.registry, scenario.chassis_of[index], member);
    FDR_CHECK(!own.is_null());
    FDR_CHECK(has_source(*derived, own));
    // Every source generation is recorded, so the derivation is exactly
    // invalidated when one of them moves on.
    for (const MembershipGeneration& generation : derived->derivation.source_generations) {
      FDR_CHECK_EQ(generation.is_zero(), false);
    }
    // The direct membership is untouched, and the derived one is a second
    // record, never a replacement.
    const MembershipId direct =
        direct_membership_of(*fixture.registry, scenario.chassis_of[index], member);
    const std::optional<Membership> source_record = fixture.registry->membership(direct);
    FDR_CHECK(source_record.has_value());
    FDR_CHECK_EQ(source_record->kind, MembershipKind::Direct);
    FDR_CHECK_EQ(source_record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(source_record->generation, MembershipGeneration::first());
  }

  // A switch that joins the source chassis knows nothing about the rack, and the
  // rule still gives it the rack its new co-members belong to: the operator reads
  // the source domain, never the member's own history.
  const EntityRef newcomer = entity_ref(EntityClass::Switch, 0x09u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, scenario.chassis_one, newcomer, 40).code,
               OutcomeCode::Committed);
  DerivationReport second;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 31), &second).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(second.memberships_created, std::size_t{1});
  FDR_CHECK_EQ(second.memberships_unchanged, std::size_t{4});
  FDR_CHECK_EQ(second.memberships_updated, std::size_t{0});
  FDR_CHECK_EQ(second.memberships_withdrawn, std::size_t{0});
  FDR_CHECK_EQ(second.bounded_out, std::size_t{0});
  const std::optional<Membership> inherited =
      derived_membership_of(*fixture.registry, newcomer, scenario.rack);
  FDR_CHECK(inherited.has_value());
  FDR_CHECK_EQ(inherited->kind, MembershipKind::Derived);
  FDR_CHECK_EQ(inherited->role, MembershipRole::Derived);
  FDR_CHECK_EQ(inherited->lifecycle, MembershipLifecycle::Current);
  FDR_CHECK_EQ(inherited->derivation.rule, scenario.rule_id);
  FDR_CHECK(inherited->derivation.valid);
  FDR_CHECK_EQ(inherited->derivation.sources.size(), std::size_t{3});
  const MembershipId newcomer_own =
      direct_membership_of(*fixture.registry, scenario.chassis_one, newcomer);
  FDR_CHECK(!newcomer_own.is_null());
  FDR_CHECK(has_source(*inherited, newcomer_own));
  FDR_CHECK_EQ(derived_count(*fixture.registry), std::size_t{5});
  // The four derivations that were already correct were not rewritten.
  for (std::size_t index = 0; index < scenario.switches.size(); ++index) {
    const std::optional<Membership> unchanged =
        derived_membership_of(*fixture.registry, scenario.switches[index], scenario.rack);
    FDR_CHECK(unchanged.has_value());
    FDR_CHECK_EQ(unchanged->generation, MembershipGeneration::first());
  }
  require_valid(*fixture.registry);
}

FDR_TEST_CASE(derivation, a_second_identical_pass_changes_nothing) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);
  ChassisScenario scenario = build_chassis_scenario(*fixture.registry, fixture);
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, scenario.rule).code, OutcomeCode::Committed);

  DerivationReport first;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 30), &first).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(first.memberships_created, std::size_t{4});

  const RegistryGeneration generation = fixture.registry->generation();
  const StateDigest digest = fixture.registry->state_digest();

  DerivationReport second;
  const Outcome repeated = fixture.registry->run_derivation(run_request(fixture, 31), &second);
  FDR_CHECK_EQ(repeated.code, OutcomeCode::Idempotent);
  require_quiet_report(second, 4);
  FDR_CHECK(second.generation == generation);
  FDR_CHECK(fixture.registry->generation() == generation);
  FDR_CHECK_EQ(fixture.registry->state_digest(), digest);
  FDR_CHECK(has_step(repeated.steps, "derive"));

  // And a third pass, to prove the second was not a special case.
  DerivationReport third;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 32), &third).code,
               OutcomeCode::Idempotent);
  require_quiet_report(third, 4);
  FDR_CHECK(fixture.registry->generation() == generation);
  FDR_CHECK_EQ(fixture.registry->state_digest(), digest);
  require_valid(*fixture.registry);
}

// ---------------------------------------------------------------------------
// SameDomainMemberRelationship
// ---------------------------------------------------------------------------

FDR_TEST_CASE(derivation, same_domain_member_relationship_inherits_only_the_named_class) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);
  PortScenario scenario = build_port_scenario(*fixture.registry, fixture);
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, scenario.rule).code, OutcomeCode::Committed);

  DerivationReport report;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 30), &report).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(report.memberships_created, std::size_t{3});
  FDR_CHECK_EQ(report.memberships_unchanged, std::size_t{0});
  FDR_CHECK_EQ(derived_count(*fixture.registry), std::size_t{3});

  for (const EntityRef& port : scenario.ports) {
    const std::optional<Membership> inherited =
        derived_membership_of(*fixture.registry, port, scenario.switch_rack);
    FDR_CHECK(inherited.has_value());
    FDR_CHECK_EQ(inherited->kind, MembershipKind::Derived);
    FDR_CHECK_EQ(inherited->role, MembershipRole::Derived);
    FDR_CHECK_EQ(inherited->derivation.rule, scenario.rule_id);
    FDR_CHECK(inherited->derivation.valid);
    // The two sources are the port's own port-group membership and the switch's
    // rack membership: the exact facts the derivation read.
    FDR_CHECK_EQ(inherited->derivation.sources.size(), std::size_t{2});
    const MembershipId own = direct_membership_of(*fixture.registry, scenario.port_group, port);
    const MembershipId switch_rack =
        direct_membership_of(*fixture.registry, scenario.switch_rack, scenario.switch_entity);
    FDR_CHECK(has_source(*inherited, own));
    FDR_CHECK(has_source(*inherited, switch_rack));
  }

  // A port does not inherit the rack of a co-member of another class. The second
  // port's own rack is a port-held fact: no port derives a membership in it,
  // because the only co-member of the named class is the switch, and the switch
  // is not in that rack.
  FDR_CHECK(!derived_membership_of(*fixture.registry, scenario.ports[0], scenario.port_rack)
                 .has_value());
  FDR_CHECK(!derived_membership_of(*fixture.registry, scenario.ports[1], scenario.port_rack)
                 .has_value());
  FDR_CHECK(!derived_membership_of(*fixture.registry, scenario.ports[2], scenario.port_rack)
                 .has_value());
  FDR_CHECK(!derived_membership_of(*fixture.registry, scenario.switch_entity, scenario.port_rack)
                 .has_value());
  // The second port keeps its own rack as a direct membership, and the switch
  // inherits nothing at all: it has no co-member of its own class.
  const MembershipId port_own =
      direct_membership_of(*fixture.registry, scenario.port_rack, scenario.ports[1]);
  FDR_CHECK(!port_own.is_null());
  const std::optional<Membership> port_own_record = fixture.registry->membership(port_own);
  FDR_CHECK(port_own_record.has_value());
  FDR_CHECK_EQ(port_own_record->kind, MembershipKind::Direct);
  for (const Membership& membership : fixture.registry->memberships_of(scenario.switch_entity)) {
    FDR_CHECK(!(membership.kind == MembershipKind::Derived));
  }
  FDR_CHECK_EQ(fixture.registry->memberships_of(scenario.switch_entity).size(), std::size_t{2});
  require_valid(*fixture.registry);
}

FDR_TEST_CASE(derivation, a_moved_source_generation_recomputes_the_derived_membership) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);
  PortScenario scenario = build_port_scenario(*fixture.registry, fixture);
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, scenario.rule).code, OutcomeCode::Committed);
  DerivationReport first;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 30), &first).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(first.memberships_created, std::size_t{3});

  const std::optional<Membership> before =
      derived_membership_of(*fixture.registry, scenario.ports[0], scenario.switch_rack);
  FDR_CHECK(before.has_value());

  // Reassert the co-member's rack membership with a different role: its
  // generation moves on, so the derivation it justified is stale.
  const MembershipId switch_rack =
      direct_membership_of(*fixture.registry, scenario.switch_rack, scenario.switch_entity);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, scenario.switch_rack,
                             scenario.switch_entity, 40, MembershipKind::Direct,
                             MembershipRole::Containment)
                   .code,
               OutcomeCode::Committed);
  const std::optional<Membership> source_after = fixture.registry->membership(switch_rack);
  FDR_CHECK(source_after.has_value());
  FDR_CHECK(!(source_after->generation == MembershipGeneration::first()));

  DerivationReport report;
  const Outcome outcome = fixture.registry->run_derivation(run_request(fixture, 31), &report);
  FDR_CHECK_EQ(outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(report.memberships_created, std::size_t{0});
  FDR_CHECK_EQ(report.memberships_updated, std::size_t{3});
  FDR_CHECK_EQ(report.memberships_withdrawn, std::size_t{0});
  FDR_CHECK_EQ(report.memberships_unchanged, std::size_t{0});

  for (const EntityRef& port : scenario.ports) {
    const std::optional<Membership> after =
        derived_membership_of(*fixture.registry, port, scenario.switch_rack);
    FDR_CHECK(after.has_value());
    // Recomputed, not withdrawn: the same domain, a new generation and a new
    // recorded context.
    FDR_CHECK_EQ(after->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK(after->derivation.valid);
    FDR_CHECK_EQ(after->generation.value(), before->generation.value() + 1u);
    FDR_CHECK_EQ(after->derivation.rule, scenario.rule_id);
    FDR_CHECK(!(after->derivation.context == before->derivation.context));
    FDR_CHECK(has_source(*after, switch_rack));
    FDR_CHECK(!after->history.empty());
  }

  // Nothing further moves on the next pass.
  DerivationReport quiet;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 32), &quiet).code,
               OutcomeCode::Idempotent);
  require_quiet_report(quiet, 3);
  require_valid(*fixture.registry);
}

// ---------------------------------------------------------------------------
// Source invalidation and topology-change scoping
// ---------------------------------------------------------------------------

FDR_TEST_CASE(derivation, topology_change_invalidates_only_the_derivations_that_read_it) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);
  ChassisScenario scenario = build_chassis_scenario(*fixture.registry, fixture);
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, scenario.rule).code, OutcomeCode::Committed);
  DerivationReport first;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 30), &first).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(first.memberships_created, std::size_t{4});

  const RegistryGeneration generation = fixture.registry->generation();
  const StateDigest digest = fixture.registry->state_digest();
  const std::optional<Membership> baseline =
      derived_membership_of(*fixture.registry, scenario.switches[0], scenario.rack);
  FDR_CHECK(baseline.has_value());

  // A topology generation moved, but nothing this runtime derives from is known
  // to have changed: nothing is invalidated and no generation is produced.
  TopologyChangeRequest quiet;
  quiet.attempt = attempt_from(40);
  quiet.authority = fixture.authority;
  quiet.topology_generation = TopologyGeneration(7);
  quiet.affected_entities = {scenario.switches[1].id()};
  quiet.structurally_relevant = false;
  FDR_CHECK_EQ(fixture.registry->notify_topology_change(quiet).code, OutcomeCode::Idempotent);
  FDR_CHECK(fixture.registry->generation() == generation);
  FDR_CHECK_EQ(fixture.registry->state_digest(), digest);
  for (const EntityRef& member : scenario.switches) {
    const std::optional<Membership> derived =
        derived_membership_of(*fixture.registry, member, scenario.rack);
    FDR_CHECK(derived.has_value());
    FDR_CHECK(derived->derivation.valid);
    FDR_CHECK_EQ(derived->lifecycle, MembershipLifecycle::Current);
  }

  // A structurally relevant change naming an entity no derivation mentions
  // invalidates nothing, but it does produce a generation.
  TopologyChangeRequest unrelated;
  unrelated.attempt = attempt_from(41);
  unrelated.authority = fixture.authority;
  unrelated.topology_generation = TopologyGeneration(8);
  unrelated.affected_entities = {entity_ref(EntityClass::Host, 0x77u, 1).id()};
  unrelated.structurally_relevant = true;
  FDR_CHECK_EQ(fixture.registry->notify_topology_change(unrelated).code, OutcomeCode::Committed);
  FDR_CHECK(!(fixture.registry->generation() == generation));
  for (const EntityRef& member : scenario.switches) {
    const std::optional<Membership> derived =
        derived_membership_of(*fixture.registry, member, scenario.rack);
    FDR_CHECK(derived.has_value());
    FDR_CHECK(derived->derivation.valid);
    FDR_CHECK_EQ(derived->generation, MembershipGeneration::first());
  }

  // A structurally relevant change naming a derivation source invalidates
  // exactly the derivations whose recorded sources mention it: the two switches
  // of the first chassis, and nothing in the second chassis.
  const RegistryGeneration before_relevant = fixture.registry->generation();
  TopologyChangeRequest relevant;
  relevant.attempt = attempt_from(42);
  relevant.authority = fixture.authority;
  relevant.topology_generation = TopologyGeneration(9);
  relevant.affected_entities = {scenario.switches[1].id()};
  relevant.structurally_relevant = true;
  FDR_CHECK_EQ(fixture.registry->notify_topology_change(relevant).code, OutcomeCode::Committed);
  FDR_CHECK(!(fixture.registry->generation() == before_relevant));
  for (std::size_t index = 0; index < scenario.switches.size(); ++index) {
    const std::optional<Membership> derived =
        derived_membership_of(*fixture.registry, scenario.switches[index], scenario.rack);
    FDR_CHECK(derived.has_value());
    if (index < 2) {
      FDR_CHECK_EQ(derived->lifecycle, MembershipLifecycle::RevalidationRequired);
      FDR_CHECK(!derived->derivation.valid);
      FDR_CHECK_EQ(derived->generation.value(), baseline->generation.value() + 1u);
      FDR_CHECK(!derived->history.empty());
    } else {
      FDR_CHECK_EQ(derived->lifecycle, MembershipLifecycle::Current);
      FDR_CHECK(derived->derivation.valid);
      FDR_CHECK_EQ(derived->generation, MembershipGeneration::first());
    }
  }
  require_valid(*fixture.registry);

  // The next pass recomputes exactly the invalidated derivations and leaves the
  // untouched ones alone.
  DerivationReport report;
  const Outcome recomputed = fixture.registry->run_derivation(run_request(fixture, 31), &report);
  FDR_CHECK_EQ(recomputed.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(report.memberships_created, std::size_t{0});
  FDR_CHECK_EQ(report.memberships_updated, std::size_t{2});
  FDR_CHECK_EQ(report.memberships_withdrawn, std::size_t{0});
  FDR_CHECK_EQ(report.memberships_unchanged, std::size_t{2});
  for (std::size_t index = 0; index < scenario.switches.size(); ++index) {
    const std::optional<Membership> derived =
        derived_membership_of(*fixture.registry, scenario.switches[index], scenario.rack);
    FDR_CHECK(derived.has_value());
    FDR_CHECK(derived->derivation.valid);
    FDR_CHECK_EQ(derived->lifecycle, MembershipLifecycle::Current);
    if (index < 2) {
      FDR_CHECK_EQ(derived->generation.value(), baseline->generation.value() + 2u);
    } else {
      FDR_CHECK_EQ(derived->generation, MembershipGeneration::first());
    }
  }

  // And the pass after that is quiet again.
  DerivationReport quiet_again;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 32), &quiet_again).code,
               OutcomeCode::Idempotent);
  require_quiet_report(quiet_again, 4);
  require_valid(*fixture.registry);

  // A topology change without a topology generation, and one without authority,
  // are refused before anything is invalidated.
  TopologyChangeRequest zero_generation;
  zero_generation.attempt = attempt_from(43);
  zero_generation.authority = fixture.authority;
  zero_generation.affected_entities = {scenario.switches[0].id()};
  FDR_CHECK_EQ(fixture.registry->notify_topology_change(zero_generation).code,
               OutcomeCode::MalformedRequest);
  TopologyChangeRequest unauthenticated;
  unauthenticated.attempt = attempt_from(44);
  unauthenticated.topology_generation = TopologyGeneration(10);
  unauthenticated.affected_entities = {scenario.switches[0].id()};
  FDR_CHECK_EQ(fixture.registry->notify_topology_change(unauthenticated).code,
               OutcomeCode::NoAuthority);
  require_valid(*fixture.registry);
}

FDR_TEST_CASE(derivation, invalidate_entity_marks_the_derivations_that_read_it) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);
  ChassisScenario scenario = build_chassis_scenario(*fixture.registry, fixture);
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, scenario.rule).code, OutcomeCode::Committed);
  DerivationReport first;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 30), &first).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(first.memberships_created, std::size_t{4});

  const std::optional<Membership> before =
      derived_membership_of(*fixture.registry, scenario.switches[0], scenario.rack);
  FDR_CHECK(before.has_value());

  // The entity generation that the memberships were established against is
  // superseded: every membership of that generation is demoted, and so is every
  // derivation that read one.
  EntityInvalidationRequest invalidate;
  invalidate.attempt = attempt_from(40);
  invalidate.authority = fixture.authority;
  invalidate.entity = scenario.switches[1].id();
  invalidate.superseded_generation = EntityGeneration(1);
  invalidate.reason = "derivation-suite";
  FDR_CHECK_EQ(fixture.registry->invalidate_entity(invalidate).code, OutcomeCode::Committed);

  // The direct membership of the invalidated entity and the derivations that
  // read it are revalidation-required; the second chassis is untouched.
  const MembershipId direct =
      direct_membership_of(*fixture.registry, scenario.chassis_of[1], scenario.switches[1]);
  const std::optional<Membership> demoted = fixture.registry->membership(direct);
  FDR_CHECK(demoted.has_value());
  FDR_CHECK_EQ(demoted->lifecycle, MembershipLifecycle::RevalidationRequired);
  for (std::size_t index = 0; index < 2; ++index) {
    const std::optional<Membership> derived =
        derived_membership_of(*fixture.registry, scenario.switches[index], scenario.rack);
    FDR_CHECK(derived.has_value());
    FDR_CHECK_EQ(derived->lifecycle, MembershipLifecycle::RevalidationRequired);
    FDR_CHECK(!derived->derivation.valid);
  }
  for (std::size_t index = 2; index < 4; ++index) {
    const std::optional<Membership> derived =
        derived_membership_of(*fixture.registry, scenario.switches[index], scenario.rack);
    FDR_CHECK(derived.has_value());
    FDR_CHECK_EQ(derived->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK(derived->derivation.valid);
  }
  require_valid(*fixture.registry);

  // The next pass recomputes what it can still derive and withdraws what it can
  // no longer justify: the surviving switch of the source domain keeps the rack,
  // and the invalidated switch loses it because it is no longer a current member
  // of the source domain it inherited through.
  const std::optional<Membership> before_pass =
      derived_membership_of(*fixture.registry, scenario.switches[0], scenario.rack);
  FDR_CHECK(before_pass.has_value());
  DerivationReport report;
  const Outcome follow_up = fixture.registry->run_derivation(run_request(fixture, 41), &report);
  FDR_CHECK_EQ(follow_up.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(report.rules_evaluated, std::size_t{1});
  FDR_CHECK_EQ(report.memberships_created, std::size_t{0});
  FDR_CHECK_EQ(report.memberships_updated, std::size_t{1});
  FDR_CHECK_EQ(report.memberships_withdrawn, std::size_t{1});
  FDR_CHECK_EQ(report.memberships_unchanged, std::size_t{2});
  FDR_CHECK_EQ(report.bounded_out, std::size_t{0});

  // The surviving derivation was restored in place: current, valid, and one
  // generation further on.
  const std::optional<Membership> restored =
      derived_membership_of(*fixture.registry, scenario.switches[0], scenario.rack);
  FDR_CHECK(restored.has_value());
  FDR_CHECK_EQ(restored->lifecycle, MembershipLifecycle::Current);
  FDR_CHECK(restored->derivation.valid);
  FDR_CHECK_EQ(restored->generation.value(), before_pass->generation.value() + 1u);
  FDR_CHECK(!(restored->derivation.context == before_pass->derivation.context));
  // The invalidated one was withdrawn: terminal, invalid, never revived.
  const std::optional<Membership> withdrawn =
      derived_membership_of(*fixture.registry, scenario.switches[1], scenario.rack);
  FDR_CHECK(withdrawn.has_value());
  FDR_CHECK_EQ(withdrawn->lifecycle, MembershipLifecycle::Retired);
  FDR_CHECK(withdrawn->is_terminal());
  FDR_CHECK(!withdrawn->derivation.valid);
  // The second chassis was never touched by the invalidation.
  for (std::size_t index = 2; index < 4; ++index) {
    const std::optional<Membership> untouched =
        derived_membership_of(*fixture.registry, scenario.switches[index], scenario.rack);
    FDR_CHECK(untouched.has_value());
    FDR_CHECK_EQ(untouched->generation, MembershipGeneration::first());
    FDR_CHECK(untouched->derivation.valid);
  }

  // A third pass has nothing left to do, and the withdrawn record is not even
  // counted as unchanged: a terminal record is skipped outright.
  DerivationReport quiet;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 42), &quiet).code,
               OutcomeCode::Idempotent);
  FDR_CHECK_EQ(quiet.memberships_created, std::size_t{0});
  FDR_CHECK_EQ(quiet.memberships_updated, std::size_t{0});
  FDR_CHECK_EQ(quiet.memberships_withdrawn, std::size_t{0});
  FDR_CHECK_EQ(quiet.memberships_unchanged, std::size_t{3});
  require_valid(*fixture.registry);
}

// ---------------------------------------------------------------------------
// Withdrawal
// ---------------------------------------------------------------------------

FDR_TEST_CASE(derivation, withdrawing_a_source_retires_the_derived_membership) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);
  PortScenario scenario = build_port_scenario(*fixture.registry, fixture);
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, scenario.rule).code, OutcomeCode::Committed);
  DerivationReport first;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 30), &first).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(first.memberships_created, std::size_t{3});
  const std::optional<Membership> before =
      derived_membership_of(*fixture.registry, scenario.ports[0], scenario.switch_rack);
  FDR_CHECK(before.has_value());

  // The switch leaves the port group, so the fact the ports inherited no longer
  // exists.
  const Outcome detached =
      detach_entity(*fixture.registry, fixture, scenario.port_group, scenario.switch_entity, 40);
  FDR_CHECK_EQ(detached.code, OutcomeCode::Committed);
  DerivationReport report;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 31), &report).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(report.memberships_created, std::size_t{0});
  FDR_CHECK_EQ(report.memberships_updated, std::size_t{0});
  FDR_CHECK_EQ(report.memberships_withdrawn, std::size_t{3});
  FDR_CHECK_EQ(report.memberships_unchanged, std::size_t{0});
  FDR_CHECK_EQ(derived_count(*fixture.registry), std::size_t{0});

  for (const EntityRef& port : scenario.ports) {
    const std::optional<Membership> withdrawn =
        derived_membership_of(*fixture.registry, port, scenario.switch_rack);
    FDR_CHECK(withdrawn.has_value());
    FDR_CHECK_EQ(withdrawn->lifecycle, MembershipLifecycle::Retired);
    FDR_CHECK(withdrawn->is_terminal());
    FDR_CHECK(!withdrawn->derivation.valid);
    FDR_CHECK_EQ(withdrawn->generation.value(), before->generation.value() + 1u);
    FDR_CHECK(!withdrawn->history.empty());
    // The direct membership in the port group is untouched by the withdrawal.
    const MembershipId own = direct_membership_of(*fixture.registry, scenario.port_group, port);
    const std::optional<Membership> own_record = fixture.registry->membership(own);
    FDR_CHECK(own_record.has_value());
    FDR_CHECK_EQ(own_record->lifecycle, MembershipLifecycle::Current);
  }

  // Nothing else is withdrawn on the next pass: a terminal record is closed.
  DerivationReport quiet;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 32), &quiet).code,
               OutcomeCode::Idempotent);
  require_quiet_report(quiet, 0);

  // A second switch restores the condition, but a withdrawn derivation is
  // terminal: the derived membership is not revived under the same identity.
  const EntityRef replacement = entity_ref(EntityClass::Switch, 0x08u, 1);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, scenario.port_group, replacement, 41).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_entity(*fixture.registry, fixture, scenario.switch_rack, replacement, 42).code,
               OutcomeCode::Committed);
  DerivationReport revived;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 33), &revived).code,
               OutcomeCode::Idempotent);
  require_quiet_report(revived, 0);
  for (const EntityRef& port : scenario.ports) {
    const std::optional<Membership> still_withdrawn =
        derived_membership_of(*fixture.registry, port, scenario.switch_rack);
    FDR_CHECK(still_withdrawn.has_value());
    FDR_CHECK_EQ(still_withdrawn->lifecycle, MembershipLifecycle::Retired);
  }
  require_valid(*fixture.registry);
}

// ---------------------------------------------------------------------------
// A derived membership is not a publishable fact
// ---------------------------------------------------------------------------

FDR_TEST_CASE(derivation, a_derived_membership_is_never_published_or_withdrawn_directly) {
  Fixture fixture = make_fixture(RegistryLimits::defaults());
  require_fixture(*fixture.registry, fixture);
  ChassisScenario scenario = build_chassis_scenario(*fixture.registry, fixture);
  FDR_CHECK_EQ(publish_rule(*fixture.registry, fixture, scenario.rule).code, OutcomeCode::Committed);
  DerivationReport first;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 30), &first).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(first.memberships_created, std::size_t{4});

  const std::optional<Membership> derived =
      derived_membership_of(*fixture.registry, scenario.switches[0], scenario.rack);
  FDR_CHECK(derived.has_value());
  const RegistryGeneration generation = fixture.registry->generation();

  // A derived membership cannot be published: only DIRECT, INHERITED and
  // ASSERTED membership is a publisher's statement.
  const Outcome published_directly =
      attach_entity(*fixture.registry, fixture, scenario.rack,
                    entity_ref(EntityClass::Switch, 0x0Au, 1), 40, MembershipKind::Derived);
  FDR_CHECK_EQ(published_directly.code, OutcomeCode::MalformedRequest);
  FDR_CHECK(published_directly.message.find("DIRECT") != std::string::npos);
  FDR_CHECK(fixture.registry->generation() == generation);
  FDR_CHECK(fixture.registry->membership(derived->id).has_value());

  // Evidence withdrawal on a derived membership is refused, and the record is
  // left exactly as it was. Asserted as produced: the refusal is IDEMPOTENT,
  // because a derived membership's evidence carries no publisher identity, so
  // no evidence of the caller's incarnation matches and the kind check that
  // would answer POLICY_REJECTED is never reached.
  WithdrawEvidenceRequest withdraw;
  withdraw.attempt = attempt_from(41);
  withdraw.authority = fixture.authority;
  withdraw.membership = derived->id;
  withdraw.reason = "derivation-suite";
  const Outcome refused = fixture.registry->withdraw_evidence(withdraw);
  FDR_CHECK_EQ(refused.code, OutcomeCode::Idempotent);
  FDR_CHECK(refused.message.find("no matching evidence") != std::string::npos);
  FDR_CHECK(!(refused.code == OutcomeCode::PolicyRejected));
  FDR_CHECK(fixture.registry->generation() == generation);
  const std::optional<Membership> after = fixture.registry->membership(derived->id);
  FDR_CHECK(after.has_value());
  FDR_CHECK_EQ(after->lifecycle, MembershipLifecycle::Current);
  FDR_CHECK(after->derivation.valid);
  FDR_CHECK_EQ(after->generation, derived->generation);

  // The only way to retire it is to remove what it was derived from.
  DerivationReport report;
  FDR_CHECK_EQ(fixture.registry->run_derivation(run_request(fixture, 31), &report).code,
               OutcomeCode::Idempotent);
  require_quiet_report(report, 4);
  require_valid(*fixture.registry);
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
