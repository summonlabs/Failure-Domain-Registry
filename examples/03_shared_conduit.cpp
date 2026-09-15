// Example 3 - two links through one conduit and one fibre span.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Two links that never touch each other still fail together when the duct they
// are pulled through is cut, or when the fibre span they are spliced onto is
// damaged. Neither fact is visible in the link records: it is the shared
// membership that states it. This example asks the overlap question and then
// asks for the blast radius of the shared factors.

#include "support.hpp"

namespace fdr = failure_domain_registry;

namespace {

void print_blast_radius(const fdr::Registry& registry, const fdr::BlastRadius& radius) {
  std::cout << "  class=" << radius.domain_class.to_string()
            << " domain=" << radius.domain.to_string()
            << " generation=" << radius.generation.to_string()
            << " lifecycle=" << fdr::to_string(radius.lifecycle) << "\n";
  std::cout << "  members (" << radius.members.size() << "):";
  for (const fdr::EntityRef& member : radius.members) {
    std::cout << " " << member.to_string();
  }
  std::cout << "\n";
  std::cout << "  child domains (" << radius.child_domains.size() << "):";
  for (const fdr::FailureDomainId& child : radius.child_domains) {
    std::cout << " " << registry.domain(child)->domain_class.to_string() << ":" << child.to_string();
  }
  std::cout << "\n";
  std::cout << "  related domains (" << radius.related_domains.size() << "):";
  for (const fdr::FailureDomainId& related : radius.related_domains) {
    std::cout << " " << registry.domain(related)->domain_class.to_string() << ":" << related.to_string();
  }
  std::cout << "\n";
  std::cout << "  member domain classes (" << radius.member_domain_classes.size() << "):";
  for (const fdr::DomainClassRef& klass : radius.member_domain_classes) {
    std::cout << " " << klass.to_string();
  }
  std::cout << "\n";
}

} // namespace

int main() {
  try {
    fdr::Registry registry;
    const example::Session operations = example::open_registry(registry, "dc1-operator");
    const fdr::Provenance cable_evidence = example::durable_provenance("cable-inventory/ducts");

    const fdr::FailureDomainId conduit = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::Conduit), "dc1", "conduit-c12",
        "Conduit C12 (rack R7 -> pod P2)", "d-conduit", cable_evidence);
    const fdr::FailureDomainId segment = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::Conduit), "dc1",
        "conduit-c12-seg3", "Conduit C12 segment 3", "d-conduit-seg", cable_evidence);
    const fdr::FailureDomainId span = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::Cable), "dc1",
        "fibre-span-fs-7", "Fibre span FS-7 (48F)", "d-span", cable_evidence);

    const fdr::EntityRef link_a(example::entity_from(fdr::EntityClass::Link, "leaf-01/leaf-09"),
                                fdr::EntityGeneration(1));
    const fdr::EntityRef link_b(example::entity_from(fdr::EntityClass::Link, "leaf-02/leaf-10"),
                                fdr::EntityGeneration(1));

    // Both links are pulled through the same duct and spliced onto the same span.
    example::attach_required(registry, operations, conduit, link_a, "s-link-a-conduit", cable_evidence);
    example::attach_required(registry, operations, conduit, link_b, "s-link-b-conduit", cable_evidence);
    example::attach_required(registry, operations, span, link_a, "s-link-a-span", cable_evidence);
    example::attach_required(registry, operations, span, link_b, "s-link-b-span", cable_evidence);
    // One of them also runs through the last segment, which is a domain in its
    // own right and is contained by the whole duct.
    example::attach_required(registry, operations, segment, link_b, "s-link-b-segment", cable_evidence);

    const fdr::Outcome related = example::add_relation(
        registry, operations, conduit, span, fdr::DomainRelationType::CorrelatedWith,
        "s-conduit-span", cable_evidence);
    example::require(related.succeeded(), "the conduit and the span can be correlated");

    std::cout << "example 03: two links sharing a conduit and a fibre span\n";
    std::cout << "conduit  = " << conduit.to_string() << "\n";
    std::cout << "segment  = " << segment.to_string() << "\n";
    std::cout << "span     = " << span.to_string() << "\n";

    const fdr::OverlapResult overlap = registry.overlap(link_a.id(), link_b.id());
    std::cout << "\noverlap(" << link_a.id().to_string() << ", " << link_b.id().to_string()
              << "): state=" << fdr::to_string(overlap.state) << "\n";
    for (const fdr::SharedDomain& shared : overlap.shared) {
      std::cout << "  class=" << shared.domain_class.to_string()
                << " domain=" << shared.domain.to_string()
                << " members=" << shared.members.size()
                << " most-specific=" << (shared.most_specific ? "yes" : "no") << "\n";
    }
    example::require(overlap.state == fdr::IndependenceState::SharedDomain,
                     "two links in one duct share a failure domain");

    std::cout << "\nblast radius of the shared conduit:\n";
    print_blast_radius(registry, registry.blast_radius(conduit));

    std::cout << "blast radius of the contained segment:\n";
    print_blast_radius(registry, registry.blast_radius(segment));

    std::cout << "blast radius of the fibre span:\n";
    print_blast_radius(registry, registry.blast_radius(span));

    const std::vector<fdr::DomainRelation> relations = registry.relations_of(conduit);
    std::cout << "relations of the conduit: " << relations.size() << "\n";
    for (const fdr::DomainRelation& relation : relations) {
      std::cout << "  type=" << fdr::to_string(relation.type)
                << " other=" << (relation.source == conduit ? relation.target : relation.source).to_string()
                << "\n";
    }
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "example failed: " << error.what() << "\n";
    return 1;
  }
}
