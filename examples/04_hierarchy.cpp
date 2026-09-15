// Example 4 - the containment hierarchy.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Containment is a typed relation between failure domains, not a field of a
// domain record: port-group -> asic -> chassis -> rack -> pod -> site. Only
// classes the taxonomy marks as containment classes may carry CONTAINED_BY, the
// relation must stay acyclic, and ancestors()/descendants() walk exactly those
// edges.

#include "support.hpp"

namespace fdr = failure_domain_registry;

namespace {

struct Level {
  const char* label;
  fdr::FailureDomainId id;
};

fdr::FailureDomainId declare(fdr::Registry& registry, const example::Session& session,
                             fdr::DomainClass domain_class, const char* key, const char* name,
                             const char* attempt_label) {
  return example::declare_domain(registry, session, fdr::DomainClassRef(domain_class), "dc1", key,
                                 name, attempt_label, example::durable_provenance(key));
}

void print_walk(const char* verb, const fdr::Registry& registry, const Level& from,
                const std::vector<fdr::FailureDomainId>& ids) {
  std::cout << verb << "(" << from.label << ") = " << ids.size() << ":";
  for (const fdr::FailureDomainId& id : ids) {
    std::cout << " " << example::class_text(registry, id);
  }
  std::cout << "\n";
}

fdr::Outcome contain(fdr::Registry& registry, const example::Session& session, const Level& inner,
                     const Level& outer, std::string_view attempt_label) {
  return example::add_relation(registry, session, inner.id, outer.id,
                               fdr::DomainRelationType::ContainedBy, attempt_label,
                               example::durable_provenance("topology/containment"));
}

} // namespace

int main() {
  try {
    fdr::Registry registry;
    const example::Session topology = example::open_registry(registry, "dc1-topology");

    const Level port_group{"port-group", declare(registry, topology, fdr::DomainClass::PortGroup,
                                                 "port-group-pg0", "ASIC port group 0", "h-port-group")};
    const Level asic{"asic", declare(registry, topology, fdr::DomainClass::Asic, "asic-a0",
                                     "Switch ASIC A0", "h-asic")};
    const Level chassis{"chassis", declare(registry, topology, fdr::DomainClass::Chassis, "chassis-ch1",
                                           "Chassis CH1", "h-chassis")};
    const Level rack{"rack", declare(registry, topology, fdr::DomainClass::Rack, "rack-r7", "Rack R7",
                                     "h-rack")};
    const Level pod{"pod", declare(registry, topology, fdr::DomainClass::Pod, "pod-p2", "Pod P2",
                                   "h-pod")};
    const Level site{"site", declare(registry, topology, fdr::DomainClass::Site, "site-s1",
                                     "Site S1", "h-site")};

    constexpr std::size_t kLevelCount = 6;
    const Level* chain[kLevelCount] = {&port_group, &asic, &chassis, &rack, &pod, &site};
    for (std::size_t index = 0; index + 1 < kLevelCount; ++index) {
      const std::string label = "h-edge-" + std::to_string(index);
      const fdr::Outcome outcome = contain(registry, topology, *chain[index], *chain[index + 1],
                                           label);
      example::require(outcome.succeeded(),
                       "containment edge " + label + " rejected: " + outcome.render());
    }

    std::cout << "example 04: containment hierarchy\n";
    std::cout << "edges (inner CONTAINED_BY outer):\n";
    for (std::size_t index = 0; index + 1 < kLevelCount; ++index) {
      std::cout << "  " << chain[index]->label << " " << chain[index]->id.to_string()
                << " CONTAINED_BY " << chain[index + 1]->label << " "
                << chain[index + 1]->id.to_string() << "\n";
    }
    std::cout << "relations in the registry: " << registry.relations_of(rack.id).size()
              << " touching the rack\n";

    print_walk("ancestors", registry, port_group, registry.ancestors(port_group.id));
    print_walk("ancestors", registry, rack, registry.ancestors(rack.id));
    print_walk("ancestors", registry, site, registry.ancestors(site.id));
    print_walk("descendants", registry, site, registry.descendants(site.id));
    print_walk("descendants", registry, rack, registry.descendants(rack.id));
    print_walk("descendants", registry, port_group, registry.descendants(port_group.id));

    example::require(registry.ancestors(port_group.id).size() == 5,
                     "the port group is contained by five enclosing domains");
    example::require(registry.descendants(site.id).size() == 5,
                     "the site contains the other five domains");
    example::require(registry.ancestors(site.id).empty(), "the site has no container here");
    example::require(registry.descendants(port_group.id).empty(),
                     "the port group contains nothing here");

    // The hierarchy is acyclic: closing the loop is rejected before anything is
    // committed, so no walk can ever spin.
    const fdr::Outcome cycle = contain(registry, topology, site, port_group, "h-cycle");
    example::report(cycle, "\nclosing the loop (site CONTAINED_BY port-group)");
    for (const fdr::ExplanationStep& step : cycle.steps) {
      std::cout << "  stage=" << step.stage << " field=" << step.field << " value=" << step.value
                << " detail=" << step.detail << "\n";
    }
    example::require(cycle.code == fdr::OutcomeCode::CycleRejected, "a containment cycle is rejected");

    // A class that is not a containment class cannot take part at all.
    const fdr::FailureDomainId firmware = declare(registry, topology, fdr::DomainClass::FirmwareGroup,
                                                  "firmware-fw-24-1", "Firmware train 24.1",
                                                  "h-firmware");
    const fdr::Outcome invalid = contain(registry, topology,
                                         Level{"firmware", firmware}, rack, "h-invalid");
    example::report(invalid, "firmware group CONTAINED_BY rack");
    example::require(invalid.code == fdr::OutcomeCode::InvalidHierarchy,
                     "CONTAINED_BY needs containment classes at both ends");

    std::cout << "\nthe hierarchy is still intact: ancestors(port-group)="
              << registry.ancestors(port_group.id).size()
              << " descendants(site)=" << registry.descendants(site.id).size() << "\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "example failed: " << error.what() << "\n";
    return 1;
  }
}
