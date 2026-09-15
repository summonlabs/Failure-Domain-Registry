// Example 7 - entity replacement does not move membership.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Fabric Registry owns canonical entity identity, and a replaced switch is a new
// generation of the same canonical id. The membership that was established
// against generation 3 was evidence about generation 3: when generation 4
// arrives the old membership is fenced and the new one has to be published. The
// registry never transfers a membership across generations by itself.

#include "support.hpp"

namespace fdr = failure_domain_registry;

namespace {

void print_memberships(const fdr::Registry& registry, std::string_view label,
                       const std::vector<fdr::Membership>& memberships) {
  std::cout << label << " (" << memberships.size() << "):\n";
  for (const fdr::Membership& membership : memberships) {
    std::cout << "  " << example::membership_line(registry, membership)
              << " member-generation=" << membership.member.generation().to_string() << "\n";
  }
}

} // namespace

int main() {
  try {
    fdr::Registry registry;
    const example::Session operations = example::open_registry(registry, "dc1-operator");

    const fdr::FailureDomainId rack = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::Rack), "dc1", "rack-r7",
        "Rack R7", "e-rack", example::durable_provenance("dcim/rack-r7"));
    const fdr::FailureDomainId pdu = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::Pdu), "dc1", "pdu-p3-a",
        "PDU P3 feed A", "e-pdu", example::durable_provenance("power/pdu-p3-a"));

    const fdr::EntityId tor = example::entity_from(fdr::EntityClass::Switch, "tor-01");
    const fdr::EntityRef tor_gen3(tor, fdr::EntityGeneration(3));
    const fdr::EntityRef tor_gen4(tor, fdr::EntityGeneration(4));

    example::attach_required(registry, operations, rack, tor_gen3, "e-tor3-rack",
                             example::durable_provenance("dcim/rack-r7/tor-01"));
    example::attach_required(registry, operations, pdu, tor_gen3, "e-tor3-pdu",
                             example::durable_provenance("power/pdu-p3-a/tor-01"));

    std::cout << "example 07: replacing a switch generation\n";
    std::cout << "canonical switch id = " << tor.to_string() << "\n";
    std::cout << "memberships before the replacement: " << registry.membership_count() << "\n";
    print_memberships(registry, "  generation 3", registry.memberships_of(tor_gen3));
    print_memberships(registry, "  generation 4", registry.memberships_of(tor_gen4));

    // Fabric Registry reports that generation 3 was replaced by generation 4 of
    // the same canonical entity.
    fdr::EntityInvalidationRequest invalidation;
    invalidation.attempt = fdr::MutationAttempt{example::attempt_from("e-invalidate"), fdr::RequestDigest{}};
    invalidation.authority = operations.authority();
    invalidation.entity = tor;
    invalidation.superseded_generation = fdr::EntityGeneration(3);
    invalidation.successor_class = fdr::EntityClass::Switch;
    invalidation.successor_id = tor.bytes();
    invalidation.successor_generation = fdr::EntityGeneration(4);
    invalidation.reason = "chassis replaced under warranty";
    const fdr::Outcome invalidated = registry.invalidate_entity(invalidation);
    example::report(invalidated, "\nentity generation 3 superseded by generation 4");
    for (const fdr::ExplanationStep& step : invalidated.steps) {
      std::cout << "  stage=" << step.stage << " field=" << step.field << " value=" << step.value
                << " detail=" << step.detail << "\n";
    }
    example::require(invalidated.committed(), "the invalidation committed");

    std::cout << "\nmemberships after the replacement: " << registry.membership_count() << "\n";
    print_memberships(registry, "  generation 3", registry.memberships_of(tor_gen3));
    print_memberships(registry, "  generation 4", registry.memberships_of(tor_gen4));

    for (const fdr::Membership& membership : registry.memberships_of(tor_gen3)) {
      example::require(membership.lifecycle == fdr::MembershipLifecycle::RevalidationRequired,
                       "every membership of the superseded generation is fenced");
      example::require(membership.member == tor_gen3,
                       "the fenced membership is still bound to the generation it was made about");
    }
    example::require(registry.memberships_of(tor_gen4).empty(),
                     "nothing was transferred to the successor generation");
    example::require(registry.membership_count() == 2,
                     "no membership record was invented by the replacement");

    // The replacement is now a fact the operator has to state explicitly.
    fdr::AttachMemberRequest republish;
    republish.attempt = fdr::MutationAttempt{example::attempt_from("e-tor4-rack"), fdr::RequestDigest{}};
    republish.authority = operations.authority();
    republish.domain = rack;
    republish.member = tor_gen4;
    republish.provenance = example::durable_provenance("dcim/rack-r7/tor-01/gen4");
    const fdr::Outcome republished = registry.attach_member(republish);
    example::report(republished, "\nexplicit publication for generation 4 in the same rack");
    example::require(republished.committed(), "an explicit publication for generation 4 commits");

    print_memberships(registry, "\n  generation 3", registry.memberships_of(tor_gen3));
    print_memberships(registry, "  generation 4", registry.memberships_of(tor_gen4));
    std::cout << "\nthe two memberships are distinct records: "
              << registry.memberships_of(tor_gen3).front().id.to_string() << " (generation 3) and "
              << registry.memberships_of(tor_gen4).front().id.to_string() << " (generation 4)\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "example failed: " << error.what() << "\n";
    return 1;
  }
}
