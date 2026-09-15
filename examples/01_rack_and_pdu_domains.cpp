// Example 1 - rack and PDU failure domains.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A rack is one common failure factor; a PDU is a completely different one, and
// the same switch belongs to both at the same time. This example builds two
// racks and two PDUs, places two switches in them, asks the overlap question and
// shows that the rack class - and only the rack class - is exclusive.

#include "support.hpp"

namespace fdr = failure_domain_registry;

namespace {

void print_shared(const fdr::OverlapResult& overlap) {
  std::cout << "shared domains: " << overlap.shared.size() << "\n";
  for (const fdr::SharedDomain& shared : overlap.shared) {
    std::cout << "  class=" << shared.domain_class.to_string()
              << " domain=" << shared.domain.to_string()
              << " generation=" << shared.generation.to_string()
              << " members=" << shared.members.size()
              << " most-specific=" << (shared.most_specific ? "yes" : "no") << "\n";
  }
  std::cout << "uncovered classes: " << overlap.uncovered_classes.size() << "\n";
}

} // namespace

int main() {
  try {
    fdr::Registry registry;
    const example::Session operations = example::open_registry(registry, "dc1-operator");

    const fdr::DomainClassRef rack_class(fdr::DomainClass::Rack);
    const fdr::DomainClassRef pdu_class(fdr::DomainClass::Pdu);

    const fdr::FailureDomainId rack_r7 = example::declare_domain(
        registry, operations, rack_class, "dc1", "rack-r7", "Rack R7", "d-rack-r7",
        example::durable_provenance("dcim/rack-r7"));
    const fdr::FailureDomainId rack_r8 = example::declare_domain(
        registry, operations, rack_class, "dc1", "rack-r8", "Rack R8", "d-rack-r8",
        example::durable_provenance("dcim/rack-r8"));
    const fdr::FailureDomainId pdu_p3a = example::declare_domain(
        registry, operations, pdu_class, "dc1", "pdu-p3-a", "PDU P3 feed A", "d-pdu-p3-a",
        example::durable_provenance("power/pdu-p3-a"));
    const fdr::FailureDomainId pdu_p3b = example::declare_domain(
        registry, operations, pdu_class, "dc1", "pdu-p3-b", "PDU P3 feed B", "d-pdu-p3-b",
        example::durable_provenance("power/pdu-p3-b"));

    std::cout << "example 01: rack and PDU failure domains\n";
    std::cout << "rack R7  = " << rack_r7.to_string() << "\n";
    std::cout << "rack R8  = " << rack_r8.to_string() << "\n";
    std::cout << "pdu P3A  = " << pdu_p3a.to_string() << "\n";
    std::cout << "pdu P3B  = " << pdu_p3b.to_string() << "\n";

    const fdr::EntityId leaf01 = example::entity_from(fdr::EntityClass::Switch, "leaf-01");
    const fdr::EntityId leaf02 = example::entity_from(fdr::EntityClass::Switch, "leaf-02");
    const fdr::EntityRef leaf01_gen1(leaf01, fdr::EntityGeneration(1));
    const fdr::EntityRef leaf02_gen1(leaf02, fdr::EntityGeneration(1));

    // Both leaf switches sit in rack R7: a rack is a physical position, so each
    // switch is in exactly one rack.
    example::attach_required(registry, operations, rack_r7, leaf01_gen1, "m-leaf01-rack",
                             example::durable_provenance("dcim/rack-r7/leaf-01"));
    example::attach_required(registry, operations, rack_r7, leaf02_gen1, "m-leaf02-rack",
                             example::durable_provenance("dcim/rack-r7/leaf-02"));

    // Both are also powered by the same PDU feed. That is a second, orthogonal
    // membership: a PDU is not a position, so multiple membership is normal.
    example::attach_required(registry, operations, pdu_p3a, leaf01_gen1, "m-leaf01-pdu",
                             example::durable_provenance("power/pdu-p3-a/leaf-01"));
    example::attach_required(registry, operations, pdu_p3a, leaf02_gen1, "m-leaf02-pdu",
                             example::durable_provenance("power/pdu-p3-a/leaf-02"));

    std::cout << "\nmemberships of the first switch (entity -> domains):\n";
    for (const fdr::Membership& membership : registry.memberships_of(leaf01)) {
      std::cout << "  " << example::membership_line(registry, membership) << "\n";
    }

    std::cout << "\nmembers of rack R7 (domain -> members):\n";
    for (const fdr::Membership& membership : registry.members_of(rack_r7)) {
      std::cout << "  " << example::membership_line(registry, membership) << "\n";
    }

    std::cout << "\noverlap query for the two switches:\n";
    const fdr::OverlapResult overlap = registry.overlap(leaf01, leaf02);
    std::cout << "  state=" << fdr::to_string(overlap.state) << "\n";
    print_shared(overlap);
    example::require(overlap.state == fdr::IndependenceState::SharedDomain,
                     "the two switches share rack R7 and PDU P3A");

    // Rack is an exclusive class: the same switch cannot be in two racks at
    // once. The registry rejects the attempt and names the rack already held.
    fdr::AttachMemberRequest reattach;
    reattach.attempt = fdr::MutationAttempt{example::attempt_from("m-leaf01-rack-r8"), fdr::RequestDigest{}};
    reattach.authority = operations.authority();
    reattach.domain = rack_r8;
    reattach.member = leaf01_gen1;
    reattach.provenance = example::durable_provenance("dcim/rack-r8/leaf-01");
    const fdr::Outcome rejected = registry.attach_member(reattach);
    example::report(rejected, "\nsecond rack for the same switch");
    std::cout << "  related domain kept: ";
    if (!rejected.related_domains.empty()) {
      std::cout << example::class_text(registry, rejected.related_domains.front()) << " "
                << rejected.related_domains.front().to_string();
    }
    std::cout << "\n";
    example::require(rejected.code == fdr::OutcomeCode::ExclusivityViolation,
                     "rack is exclusive: a switch occupies one rack");

    // A PDU is not exclusive, so the second feed is a legitimate second
    // membership rather than a violation.
    example::attach_required(registry, operations, pdu_p3b, leaf01_gen1, "m-leaf01-pdu-b",
                             example::durable_provenance("power/pdu-p3-b/leaf-01"));
    std::cout << "\nafter adding the second PDU feed, the first switch is a member of "
              << registry.memberships_of(leaf01).size() << " domains and the registry holds "
              << registry.domain_count() << " domains and " << registry.membership_count()
              << " memberships\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "example failed: " << error.what() << "\n";
    return 1;
  }
}
