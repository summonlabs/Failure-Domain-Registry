// Example 2 - orthogonal failure domains.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// One switch is, at the same time, in a rack, on a PDU feed, inside a cooling
// zone, in a firmware group and in a control-plane group. None of those is
// "the" failure domain: they are independent common factors, and the registry
// keeps them apart because a domain class is what states which kind of common
// factor a domain is.

#include "support.hpp"

namespace fdr = failure_domain_registry;

int main() {
  try {
    fdr::Registry registry;
    const example::Session operations = example::open_registry(registry, "dc1-operator");

    const fdr::FailureDomainId rack = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::Rack), "dc1", "rack-r7",
        "Rack R7", "d-rack", example::durable_provenance("dcim/rack-r7"));
    const fdr::FailureDomainId pdu = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::Pdu), "dc1", "pdu-p3-a",
        "PDU P3 feed A", "d-pdu", example::durable_provenance("power/pdu-p3-a"));
    const fdr::FailureDomainId cooling = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::CoolingZone), "dc1",
        "cooling-cz3", "Cooling zone CZ3", "d-cooling",
        example::durable_provenance("facility/cooling-cz3"));
    const fdr::FailureDomainId firmware = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::FirmwareGroup), "dc1",
        "firmware-fw-24-1", "Firmware train 24.1", "d-firmware",
        example::durable_provenance("nms/firmware-24.1"));
    const fdr::FailureDomainId control_plane = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::ControlPlane), "dc1",
        "control-plane-cp1", "Control plane CP1", "d-control-plane",
        example::durable_provenance("control/plane-cp1"));

    const fdr::EntityId leaf01 = example::entity_from(fdr::EntityClass::Switch, "leaf-01");
    const fdr::EntityRef leaf01_gen1(leaf01, fdr::EntityGeneration(1));

    example::attach_required(registry, operations, rack, leaf01_gen1, "o-leaf01-rack",
                             example::durable_provenance("dcim/rack-r7/leaf-01"),
                             fdr::MembershipKind::Direct, fdr::MembershipRole::Containment);
    example::attach_required(registry, operations, pdu, leaf01_gen1, "o-leaf01-pdu",
                             example::durable_provenance("power/pdu-p3-a/leaf-01"),
                             fdr::MembershipKind::Direct, fdr::MembershipRole::SharedRisk);
    example::attach_required(registry, operations, cooling, leaf01_gen1, "o-leaf01-cooling",
                             example::durable_provenance("facility/cooling-cz3/leaf-01"),
                             fdr::MembershipKind::Direct, fdr::MembershipRole::SharedRisk);
    example::attach_required(registry, operations, firmware, leaf01_gen1, "o-leaf01-firmware",
                             example::durable_provenance("nms/firmware-24.1/leaf-01"),
                             fdr::MembershipKind::Direct, fdr::MembershipRole::SharedRisk);
    example::attach_required(registry, operations, control_plane, leaf01_gen1, "o-leaf01-cp",
                             example::durable_provenance("control/plane-cp1/leaf-01"),
                             fdr::MembershipKind::Direct, fdr::MembershipRole::SharedRisk);

    std::cout << "example 02: orthogonal failure domains of one switch\n";
    std::cout << "switch " << leaf01.to_string() << " belongs to "
              << registry.memberships_of(leaf01).size() << " current domains:\n";
    for (const fdr::Membership& membership : registry.memberships_of(leaf01)) {
      std::cout << "  " << example::membership_line(registry, membership) << "\n";
    }

    // The classes are orthogonal containers, so each membership is independent:
    // no membership was refused, and no domain has a second member.
    bool exclusive_classes_only = true;
    for (const fdr::Membership& membership : registry.memberships_of(leaf01)) {
      const std::optional<fdr::FailureDomain> record = registry.domain(membership.domain);
      example::require(record.has_value(), "a membership always names a domain that exists");
      if (registry.members_of(membership.domain).size() != 1) {
        exclusive_classes_only = false;
      }
    }
    std::cout << "every domain holds exactly this one switch: "
              << (exclusive_classes_only ? "yes" : "no") << "\n";

    // Remove one orthogonal factor and the others are untouched: losing the
    // firmware group says nothing about the rack.
    fdr::DetachMemberRequest detach;
    detach.attempt = fdr::MutationAttempt{example::attempt_from("o-leaf01-firmware-detach"), fdr::RequestDigest{}};
    detach.authority = operations.authority();
    detach.domain = firmware;
    detach.member = leaf01_gen1;
    detach.reason = "firmware train retired";
    example::report(registry.detach_member(detach), "detach firmware group");

    std::size_t current = 0;
    for (const fdr::Membership& membership : registry.memberships_of(leaf01)) {
      if (membership.is_current()) {
        ++current;
      }
    }
    std::cout << "after the detach the switch still belongs to " << current
              << " current domains; the rack, PDU, cooling zone and control plane are untouched\n";

    const fdr::OverlapResult self = registry.overlap(leaf01, leaf01);
    std::cout << "overlap of the switch with itself: state=" << fdr::to_string(self.state)
              << " shared=" << self.shared.size() << "\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "example failed: " << error.what() << "\n";
    return 1;
  }
}
