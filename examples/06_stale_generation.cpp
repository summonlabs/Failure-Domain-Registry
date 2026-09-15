// Example 6 - stale expectations and the two kinds of replay.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every mutation names the generation it expects and carries a caller-supplied
// attempt identity. That combination is what separates three situations that
// look identical on the wire: a request built from a state that has moved on, an
// exact replay of a request that already committed, and a reused attempt
// identity that carries different content.

#include "support.hpp"

namespace fdr = failure_domain_registry;

namespace {

fdr::UpdateDomainRequest rename_request(const example::Session& session,
                                        const fdr::FailureDomainId& domain,
                                        fdr::FailureDomainGeneration expected, std::string name,
                                        std::string_view attempt_label) {
  fdr::UpdateDomainRequest request;
  request.attempt = fdr::MutationAttempt{example::attempt_from(attempt_label), fdr::RequestDigest{}};
  request.authority = session.authority();
  request.domain = domain;
  request.expected_generation = expected;
  request.name = std::move(name);
  return request;
}

void print_domain_state(const fdr::Registry& registry, const fdr::FailureDomainId& id) {
  const std::optional<fdr::FailureDomain> record = registry.domain(id);
  example::require(record.has_value(), "the domain exists");
  std::cout << "  name='" << record->name << "' generation=" << record->generation.to_string()
            << " lifecycle=" << fdr::to_string(record->lifecycle) << "\n";
}

} // namespace

int main() {
  try {
    fdr::Registry registry;
    const example::Session operations = example::open_registry(registry, "dc1-operator");

    const fdr::FailureDomainId rack = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::Rack), "dc1", "rack-r7",
        "Rack R7", "r-rack", example::durable_provenance("dcim/rack-r7"));

    std::cout << "example 06: stale expectations, exact replay, conflicting replay\n";
    std::cout << "domain " << rack.to_string() << " after creation:\n";
    print_domain_state(registry, rack);

    // 1) The update that commits, carrying the generation it read.
    const fdr::UpdateDomainRequest first = rename_request(
        operations, rack, fdr::FailureDomainGeneration(1), "Rack R7 (row 2)", "r-rename");
    const fdr::RegistryGeneration before_commit = registry.generation();
    const fdr::Outcome committed = registry.update_domain(first);
    example::report(committed, "\n1) update with the current expected generation");
    std::cout << "  registry generation " << before_commit.to_string() << " -> "
              << registry.generation().to_string() << "\n";
    print_domain_state(registry, rack);
    example::require(committed.committed() && committed.domain_generation.has_value() &&
                         committed.domain_generation->value() == 2,
                     "the update committed a new domain generation");

    // 2) The same intent built from a state that has moved on.
    const fdr::UpdateDomainRequest stale = rename_request(
        operations, rack, fdr::FailureDomainGeneration(1), "Rack R7 (row 2)", "r-rename-stale");
    const fdr::RegistryGeneration before_stale = registry.generation();
    const fdr::Outcome stale_outcome = registry.update_domain(stale);
    example::report(stale_outcome, "\n2) update still expecting generation 1");
    for (const fdr::ExplanationStep& step : stale_outcome.steps) {
      std::cout << "  stage=" << step.stage << " field=" << step.field << " value=" << step.value
                << " detail=" << step.detail << "\n";
    }
    std::cout << "  registry generation " << before_stale.to_string() << " -> "
              << registry.generation().to_string() << "\n";
    example::require(stale_outcome.code == fdr::OutcomeCode::StaleGeneration,
                     "a stale expected generation is rejected");
    example::require(registry.generation() == before_stale, "a rejection changes nothing");

    // 3) The exact same request again: same attempt id, same content.
    const fdr::RegistryGeneration before_replay = registry.generation();
    const fdr::Outcome replay = registry.update_domain(first);
    example::report(replay, "\n3) exact replay of the committed update");
    std::cout << "  registry generation " << before_replay.to_string() << " -> "
              << registry.generation().to_string() << "\n";
    print_domain_state(registry, rack);
    example::require(replay.code == fdr::OutcomeCode::Idempotent,
                     "an exact replay is idempotent");
    example::require(registry.generation() == before_replay,
                     "an exact replay produces no new generation");

    // 4) The same attempt id, different content.
    const fdr::UpdateDomainRequest conflicting = rename_request(
        operations, rack, fdr::FailureDomainGeneration(1), "Rack R7 (row 3)", "r-rename");
    const fdr::RegistryGeneration before_conflict = registry.generation();
    const fdr::Outcome conflict = registry.update_domain(conflicting);
    example::report(conflict, "\n4) the same attempt id with different content");
    std::cout << "  registry generation " << before_conflict.to_string() << " -> "
              << registry.generation().to_string() << "\n";
    print_domain_state(registry, rack);
    example::require(conflict.code == fdr::OutcomeCode::ConflictingReplay,
                     "a reused attempt id with new content is a conflicting replay");
    example::require(registry.generation() == before_conflict,
                     "a conflicting replay changes nothing");

    std::cout << "\nthree requests, one committed generation: the domain is still at generation "
              << registry.domain(rack)->generation.to_string() << " and the registry holds "
              << registry.domain_count() << " domain\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "example failed: " << error.what() << "\n";
    return 1;
  }
}
