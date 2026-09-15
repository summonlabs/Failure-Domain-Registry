// Example 10 - derivation, invalidation and recomputation.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A publisher should not have to restate "this switch is on PDU P3A" for every
// switch that shares the rack of a switch that is. A published, versioned rule
// derives that membership, records the exact source memberships and generations
// it read, and recomputes or withdraws the result as soon as a source moves on.
// This example derives, re-derives (which changes nothing), invalidates one
// source generation, and then shows one derived membership withdrawn while the
// ones the surviving members still justify are recomputed.

#include "support.hpp"

namespace fdr = failure_domain_registry;

namespace {

void print_derived(const fdr::Registry& registry, const fdr::FailureDomainId& pdu,
                   std::string_view label) {
  std::cout << label << ":\n";
  for (const fdr::Membership& membership : registry.members_of(pdu)) {
    if (membership.kind != fdr::MembershipKind::Derived) {
      continue;
    }
    std::cout << "  member=" << membership.member.to_string()
              << " domain=" << membership.domain.to_string()
              << " lifecycle=" << fdr::to_string(membership.lifecycle)
              << " derivation-valid=" << (membership.derivation.valid ? "yes" : "no")
              << " sources=" << membership.derivation.sources.size()
              << " role=" << fdr::to_string(membership.role) << "\n";
  }
}

void print_report(const fdr::DerivationReport& report) {
  std::cout << "  rules-evaluated=" << report.rules_evaluated
            << " created=" << report.memberships_created
            << " updated=" << report.memberships_updated
            << " withdrawn=" << report.memberships_withdrawn
            << " unchanged=" << report.memberships_unchanged
            << " bounded-out=" << report.bounded_out
            << " generation=" << report.generation.to_string() << "\n";
}

std::size_t derived_in_lifecycle(const fdr::Registry& registry, const fdr::FailureDomainId& pdu,
                                 fdr::MembershipLifecycle lifecycle) {
  std::size_t count = 0;
  for (const fdr::Membership& membership : registry.members_of(pdu)) {
    if (membership.kind == fdr::MembershipKind::Derived && membership.lifecycle == lifecycle) {
      ++count;
    }
  }
  return count;
}

} // namespace

int main() {
  try {
    fdr::Registry registry;
    const example::Session operations = example::open_registry(registry, "dc1-derivation");

    const fdr::DomainClassRef rack_class(fdr::DomainClass::Rack);
    const fdr::DomainClassRef pdu_class(fdr::DomainClass::Pdu);
    const fdr::FailureDomainId rack = example::declare_domain(
        registry, operations, rack_class, "dc1", "rack-r7", "Rack R7", "v-rack",
        example::durable_provenance("dcim/rack-r7"));
    const fdr::FailureDomainId pdu = example::declare_domain(
        registry, operations, pdu_class, "dc1", "pdu-p3-a", "PDU P3 feed A", "v-pdu",
        example::durable_provenance("power/pdu-p3-a"));

    const fdr::EntityRef leaf_a(example::entity_from(fdr::EntityClass::Switch, "leaf-a"),
                                fdr::EntityGeneration(1));
    const fdr::EntityRef leaf_b(example::entity_from(fdr::EntityClass::Switch, "leaf-b"),
                                fdr::EntityGeneration(1));
    const fdr::EntityRef leaf_c(example::entity_from(fdr::EntityClass::Switch, "leaf-c"),
                                fdr::EntityGeneration(1));

    // All three switches are in rack R7. The PDU feed is directly known for two
    // of them; the third one is what the rule is for.
    example::attach_required(registry, operations, rack, leaf_a, "v-leaf-a-rack",
                             example::durable_provenance("dcim/rack-r7/leaf-a"));
    example::attach_required(registry, operations, rack, leaf_b, "v-leaf-b-rack",
                             example::durable_provenance("dcim/rack-r7/leaf-b"));
    example::attach_required(registry, operations, rack, leaf_c, "v-leaf-c-rack",
                             example::durable_provenance("dcim/rack-r7/leaf-c"));
    example::attach_required(registry, operations, pdu, leaf_a, "v-leaf-a-pdu",
                             example::durable_provenance("power/pdu-p3-a/leaf-a"));
    example::attach_required(registry, operations, pdu, leaf_c, "v-leaf-c-pdu",
                             example::durable_provenance("power/pdu-p3-a/leaf-c"));

    std::cout << "example 10: derivation, then invalidation of a source\n";
    std::cout << "direct memberships: rack R7 holds 3 switches, PDU P3A holds 2 of them\n";

    fdr::DerivationRule rule;
    rule.name = "shared-rack-implies-shared-pdu";
    rule.op = fdr::DerivationOperator::MembersShareContainingClass;
    rule.source_class = rack_class;
    rule.target_class = pdu_class;
    rule.member_class = fdr::EntityClass::Switch;
    rule.derived_role = fdr::MembershipRole::Derived;
    rule.dependency = fdr::DependencySemantics::AnyDependencyFailureAffectsMember;
    rule.rule_version = 1;
    const fdr::DerivationRuleId rule_id = fdr::derivation_rule_id_for(rule);
    example::report(registry.publish_derivation_rule(rule, operations.authority()), "publish rule");
    std::cout << "  rule=" << rule.name << " id=" << rule_id.to_string()
              << " operator=" << fdr::to_string(rule.op)
              << " source=" << rule.source_class.to_string()
              << " target=" << rule.target_class.to_string() << "\n";

    fdr::DerivationRunRequest run;
    run.attempt = fdr::MutationAttempt{example::attempt_from("v-run-1"), fdr::RequestDigest{}};
    run.authority = operations.authority();
    fdr::DerivationReport report;
    example::report(registry.run_derivation(run, &report), "\nfirst derivation pass");
    print_report(report);
    print_derived(registry, pdu, "derived memberships after the first pass");
    example::require(report.memberships_created == 3,
                     "every switch in the rack inherits the feed its co-members are on");

    // The registry is idempotent about derivation too: nothing changed, so the
    // second pass produces no new generation.
    fdr::DerivationRunRequest again = run;
    again.attempt = fdr::MutationAttempt{example::attempt_from("v-run-2"), fdr::RequestDigest{}};
    const fdr::RegistryGeneration before_second = registry.generation();
    example::report(registry.run_derivation(again, &report), "\nsecond derivation pass");
    print_report(report);
    std::cout << "  registry generation " << before_second.to_string() << " -> "
              << registry.generation().to_string() << "\n";
    example::require(report.memberships_unchanged == 3 && report.memberships_created == 0,
                     "a second pass over unchanged sources changes nothing");
    example::require(registry.generation() == before_second,
                     "a derivation pass that changes nothing produces no generation");

    // Fabric Registry reports that leaf-a generation 1 was replaced.
    fdr::EntityInvalidationRequest invalidation;
    invalidation.attempt = fdr::MutationAttempt{example::attempt_from("v-invalidate"), fdr::RequestDigest{}};
    invalidation.authority = operations.authority();
    invalidation.entity = leaf_a.id();
    invalidation.superseded_generation = fdr::EntityGeneration(1);
    invalidation.successor_class = fdr::EntityClass::Switch;
    invalidation.successor_id = leaf_a.id().bytes();
    invalidation.successor_generation = fdr::EntityGeneration(2);
    invalidation.reason = "switch replaced";
    example::report(registry.invalidate_entity(invalidation), "\ninvalidate the source entity");
    print_derived(registry, pdu, "derived memberships after the invalidation");
    for (const fdr::Membership& membership : registry.members_of(pdu)) {
      if (membership.kind == fdr::MembershipKind::Derived) {
        example::require(membership.lifecycle == fdr::MembershipLifecycle::RevalidationRequired,
                         "derived membership does not stay current when a source moves on");
      }
    }
    std::cout << "  no derived membership is left claiming to be current\n";

    fdr::DerivationRunRequest reconcile;
    reconcile.attempt = fdr::MutationAttempt{example::attempt_from("v-run-3"), fdr::RequestDigest{}};
    reconcile.authority = operations.authority();
    example::report(registry.run_derivation(reconcile, &report), "\nderivation pass after the change");
    print_report(report);
    print_derived(registry, pdu, "derived memberships after the reconciliation");
    example::require(report.memberships_withdrawn == 1,
                     "the derived membership of the replaced switch is withdrawn");
    example::require(report.memberships_updated == 2,
                     "the derived memberships the surviving members still justify are recomputed");

    const std::size_t current_derived =
        derived_in_lifecycle(registry, pdu, fdr::MembershipLifecycle::Current);
    const std::size_t retired_derived =
        derived_in_lifecycle(registry, pdu, fdr::MembershipLifecycle::Retired);
    for (const fdr::Membership& membership : registry.members_of(pdu)) {
      if (membership.kind != fdr::MembershipKind::Derived) {
        continue;
      }
      if (membership.lifecycle == fdr::MembershipLifecycle::Current) {
        example::require(membership.derivation.valid,
                         "a recomputed derived membership records a valid derivation");
      } else if (membership.lifecycle == fdr::MembershipLifecycle::Retired) {
        example::require(!membership.derivation.valid,
                         "a withdrawn derived membership records an invalid derivation");
      }
    }
    std::cout << "\nderived memberships now: " << current_derived << " current, "
              << retired_derived << " retired\n";
    std::cout << "leaf-a's own memberships after the replacement:\n";
    for (const fdr::Membership& membership : registry.memberships_of(leaf_a)) {
      std::cout << "  " << example::membership_line(registry, membership)
                << " derivation-valid=" << (membership.derivation.valid ? "yes" : "no") << "\n";
    }
    example::require(current_derived == 2 && retired_derived == 1,
                     "the derived set tracks the members that are still current");
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "example failed: " << error.what() << "\n";
    return 1;
  }
}
