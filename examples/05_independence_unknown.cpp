// Example 5 - independence that is unknown, then proven.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// "These two switches share no failure domain" is only a proof when the registry
// knows that the classes it was asked about are completely classified in the
// scope. This example walks the honest sequence: nothing declared, partial
// coverage, complete coverage - and then shows that complete coverage is not a
// rubber stamp either, because a genuine shared domain still wins.

#include "support.hpp"

namespace fdr = failure_domain_registry;

namespace {

void print_independence(const fdr::IndependenceResult& result) {
  std::cout << "  state=" << fdr::to_string(result.state)
            << " shared=" << result.shared.size()
            << " complete-for-all=" << (result.coverage.complete_for_all ? "yes" : "no")
            << " has-partial=" << (result.coverage.has_partial ? "yes" : "no")
            << " has-unknown=" << (result.coverage.has_unknown ? "yes" : "no") << "\n";
  for (const fdr::CoverageEntry& entry : result.coverage.entries) {
    std::cout << "    coverage class=" << entry.domain_class.to_string()
              << " scope=" << (entry.administrative_scope.empty() ? std::string("<none>")
                                                                  : entry.administrative_scope)
              << " state=" << fdr::to_string(entry.state)
              << " declared=" << (entry.declared ? "yes" : "no")
              << " evidence=" << fdr::to_string(entry.evidence) << "\n";
  }
  for (const fdr::SharedDomain& shared : result.shared) {
    std::cout << "    shared class=" << shared.domain_class.to_string()
              << " domain=" << shared.domain.to_string()
              << " members=" << shared.members.size() << "\n";
  }
  for (const fdr::ExplanationStep& step : result.steps) {
    std::cout << "    step stage=" << step.stage << " field=" << step.field
              << " value=" << step.value << " detail=" << step.detail << "\n";
  }
}

} // namespace

int main() {
  try {
    fdr::Registry registry;
    const example::Session operations = example::open_registry(registry, "dc1-operator");
    const fdr::Provenance coverage_evidence = example::durable_provenance("dcim/coverage/dc1");

    const fdr::FailureDomainId rack_r7 = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::Rack), "dc1", "rack-r7",
        "Rack R7", "i-rack-r7", example::durable_provenance("dcim/rack-r7"));
    const fdr::FailureDomainId rack_r8 = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::Rack), "dc1", "rack-r8",
        "Rack R8", "i-rack-r8", example::durable_provenance("dcim/rack-r8"));
    const fdr::FailureDomainId pdu_a = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::Pdu), "dc1", "pdu-p3-a",
        "PDU P3 feed A", "i-pdu-a", example::durable_provenance("power/pdu-p3-a"));
    const fdr::FailureDomainId pdu_c = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::Pdu), "dc1", "pdu-p3-c",
        "PDU P3 feed C", "i-pdu-c", example::durable_provenance("power/pdu-p3-c"));

    const fdr::EntityId leaf01 = example::entity_from(fdr::EntityClass::Switch, "leaf-01");
    const fdr::EntityId leaf02 = example::entity_from(fdr::EntityClass::Switch, "leaf-02");
    const fdr::EntityId leaf03 = example::entity_from(fdr::EntityClass::Switch, "leaf-03");
    const fdr::EntityRef leaf01_gen1(leaf01, fdr::EntityGeneration(1));
    const fdr::EntityRef leaf02_gen1(leaf02, fdr::EntityGeneration(1));
    const fdr::EntityRef leaf03_gen1(leaf03, fdr::EntityGeneration(1));

    example::attach_required(registry, operations, rack_r7, leaf01_gen1, "i-leaf01-rack",
                             example::durable_provenance("dcim/rack-r7/leaf-01"));
    example::attach_required(registry, operations, pdu_a, leaf01_gen1, "i-leaf01-pdu",
                             example::durable_provenance("power/pdu-p3-a/leaf-01"));
    example::attach_required(registry, operations, rack_r8, leaf02_gen1, "i-leaf02-rack",
                             example::durable_provenance("dcim/rack-r8/leaf-02"));
    example::attach_required(registry, operations, pdu_c, leaf02_gen1, "i-leaf02-pdu",
                             example::durable_provenance("power/pdu-p3-c/leaf-02"));
    // The third switch shares a rack and a PDU feed with the first one.
    example::attach_required(registry, operations, rack_r7, leaf03_gen1, "i-leaf03-rack",
                             example::durable_provenance("dcim/rack-r7/leaf-03"));
    example::attach_required(registry, operations, pdu_a, leaf03_gen1, "i-leaf03-pdu",
                             example::durable_provenance("power/pdu-p3-a/leaf-03"));

    const std::vector<fdr::EntityId> pair{leaf01, leaf02};
    const std::vector<fdr::DomainClassRef> classes{fdr::DomainClassRef(fdr::DomainClass::Rack),
                                                   fdr::DomainClassRef(fdr::DomainClass::Pdu)};

    std::cout << "example 05: independence over rack and PDU classes\n";
    std::cout << "leaf-01 is in rack R7 and on PDU P3A; leaf-02 is in rack R8 and on PDU P3C\n";

    std::cout << "\n1) nothing has been declared for this scope yet\n";
    const fdr::IndependenceResult unknown = registry.independence(pair, classes);
    print_independence(unknown);
    example::require(unknown.state == fdr::IndependenceState::NoKnowledge,
                     "with no declaration at all the registry knows nothing");

    std::cout << "\n2) the operator declares partial coverage\n";
    example::report(example::declare_coverage(registry, operations, "dc1",
                                              fdr::DomainClassRef(fdr::DomainClass::Rack),
                                              fdr::CoverageState::Partial, "i-cov-rack-partial",
                                              coverage_evidence),
                    "declare coverage");
    example::report(example::declare_coverage(registry, operations, "dc1",
                                              fdr::DomainClassRef(fdr::DomainClass::Pdu),
                                              fdr::CoverageState::Partial, "i-cov-pdu-partial",
                                              coverage_evidence),
                    "declare coverage");
    const fdr::IndependenceResult partial = registry.independence(pair, classes);
    print_independence(partial);
    example::require(partial.state == fdr::IndependenceState::UnknownCoverage,
                     "partial coverage makes absence of a shared domain unproven");

    std::cout << "\n3) the operator declares complete coverage for both classes\n";
    example::report(example::declare_coverage(registry, operations, "dc1",
                                              fdr::DomainClassRef(fdr::DomainClass::Rack),
                                              fdr::CoverageState::Complete, "i-cov-rack-complete",
                                              coverage_evidence),
                    "declare coverage");
    example::report(example::declare_coverage(registry, operations, "dc1",
                                              fdr::DomainClassRef(fdr::DomainClass::Pdu),
                                              fdr::CoverageState::Complete, "i-cov-pdu-complete",
                                              coverage_evidence),
                    "declare coverage");
    const fdr::IndependenceResult proven = registry.independence(pair, classes);
    print_independence(proven);
    std::cout << "    (the coverage class= lines above report the same declarations the\n"
                 "     independence decision used)\n";
    example::require(proven.proven_independent(),
                     "complete coverage and no shared domain is a proof");

    std::cout << "\n4) the same complete coverage, but a genuinely shared domain\n";
    const std::vector<fdr::EntityId> overlapping{leaf01, leaf03};
    const fdr::IndependenceResult shared = registry.independence(overlapping, classes);
    print_independence(shared);
    example::require(shared.state == fdr::IndependenceState::SharedDomain,
                     "complete coverage never hides a shared domain");

    const fdr::CoverageReport report = registry.coverage(
        "dc1", std::vector<fdr::DomainClassRef>{fdr::DomainClassRef(fdr::DomainClass::Rack),
                                                fdr::DomainClassRef(fdr::DomainClass::Pdu)});
    std::cout << "\nexplicit coverage query for scope dc1: entries=" << report.entries.size()
              << " complete-for-all=" << (report.complete_for_all ? "yes" : "no") << "\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "example failed: " << error.what() << "\n";
    return 1;
  }
}
