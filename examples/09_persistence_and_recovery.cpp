// Example 9 - persistence and recovery.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The persisted image carries durable classification and nothing else. Loading it
// into a fresh Registry reproduces exactly the same semantic state - the state
// digest matches - but it does not reproduce a single live publisher session:
// durability is not process authority, so every publisher has to reattach.

#include "support.hpp"

#include <cstdio>
#include <filesystem>

namespace fdr = failure_domain_registry;

int main() {
  try {
    const std::filesystem::path state_path =
        std::filesystem::temp_directory_path() / "fdr-example-09-state.bin";
    std::error_code ignored;
    std::filesystem::remove(state_path, ignored);

    fdr::PersistenceConfig config;
    config.path = state_path.string();
    config.durable = true;
    config.atomic = true;

    fdr::Registry registry;
    const example::Session operations = example::open_registry(registry, "dc1-operator");
    const fdr::FailureDomainId rack = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::Rack), "dc1", "rack-r7",
        "Rack R7", "p-rack", example::durable_provenance("dcim/rack-r7"));
    const fdr::FailureDomainId pdu = example::declare_domain(
        registry, operations, fdr::DomainClassRef(fdr::DomainClass::Pdu), "dc1", "pdu-p3-a",
        "PDU P3 feed A", "p-pdu", example::process_bound_provenance("power/pdu-p3-a"));
    const fdr::EntityRef leaf01(example::entity_from(fdr::EntityClass::Switch, "leaf-01"),
                                fdr::EntityGeneration(1));
    example::attach_required(registry, operations, rack, leaf01, "p-leaf01-rack",
                             example::durable_provenance("dcim/rack-r7/leaf-01"));
    example::attach_required(registry, operations, pdu, leaf01, "p-leaf01-pdu",
                             example::process_bound_provenance("power/pdu-p3-a/leaf-01"));
    example::report(example::declare_coverage(registry, operations, "dc1",
                                              fdr::DomainClassRef(fdr::DomainClass::Rack),
                                              fdr::CoverageState::Complete, "p-coverage",
                                              example::durable_provenance("dcim/coverage/dc1")),
                    "declare coverage");

    const fdr::StateDigest digest_before = registry.state_digest();
    std::cout << "example 09: persistence and recovery\n";
    std::cout << "state before saving: domains=" << registry.domain_count()
              << " memberships=" << registry.membership_count()
              << " live-sessions=" << registry.live_sessions().size()
              << " generation=" << registry.generation().to_string()
              << " epoch=" << registry.epoch().to_string() << "\n";
    std::cout << "state digest before saving: " << digest_before.to_string() << "\n";

    const fdr::Outcome saved = registry.save(config);
    example::report(saved, "\nsave");
    for (const fdr::ExplanationStep& step : saved.steps) {
      std::cout << "  stage=" << step.stage << " field=" << step.field << " value=" << step.value
                << " detail=" << step.detail << "\n";
    }
    example::require(saved.committed(), "the state was written to disk");

    fdr::PersistenceReport report;
    const fdr::Outcome inspected = fdr::inspect_persistence(config, &report);
    example::report(inspected, "inspect the image without trusting it");
    std::cout << "  file=" << state_path.filename().string() << " bytes=" << report.bytes
              << " format=" << report.format_version
              << " domains=" << report.domains
              << " memberships=" << report.memberships
              << " relations=" << report.relations
              << " coverage=" << report.coverage_declarations
              << " publishers=" << report.publishers
              << " fences=" << report.fences
              << " rules=" << report.derivation_rules
              << " generation=" << report.generation.to_string()
              << " epoch=" << report.epoch.to_string() << "\n";
    example::require(inspected.committed(), "the image verifies");

    // A completely fresh registry, as after a coordinator restart.
    fdr::Registry recovered;
    const fdr::Outcome loaded = recovered.load(config);
    example::report(loaded, "\nload into a fresh registry");
    for (const fdr::ExplanationStep& step : loaded.steps) {
      std::cout << "  stage=" << step.stage << " field=" << step.field << " value=" << step.value
                << " detail=" << step.detail << "\n";
    }
    example::require(loaded.committed(), "the fresh registry loaded the image");

    const fdr::StateDigest digest_after = recovered.state_digest();
    std::cout << "\nstate after loading: domains=" << recovered.domain_count()
              << " memberships=" << recovered.membership_count()
              << " live-sessions=" << recovered.live_sessions().size()
              << " generation=" << recovered.generation().to_string()
              << " epoch=" << recovered.epoch().to_string() << "\n";
    std::cout << "state digest after loading: " << digest_after.to_string() << "\n";
    std::cout << "digest matches: " << (digest_after == digest_before ? "yes" : "no") << "\n";
    std::cout << "live authority restored: "
              << (recovered.live_sessions().empty() ? "no" : "yes") << "\n";
    example::require(digest_after == digest_before,
                     "the reloaded registry holds exactly the same semantic state");
    example::require(recovered.live_sessions().empty(),
                     "no live publisher session survives a restart");
    example::require(recovered.domain_count() == registry.domain_count() &&
                         recovered.membership_count() == registry.membership_count(),
                     "every record came back");

    std::size_t incarnation_count = 0;
    for (const std::pair<fdr::PublisherId, fdr::WorkerBootId>& incarnation :
         recovered.process_bound_incarnations()) {
      std::cout << "  process-bound incarnation to fence on recovery: publisher="
                << incarnation.first.to_string() << " boot=" << incarnation.second.to_string() << "\n";
      ++incarnation_count;
    }
    example::require(incarnation_count >= 1,
                     "recovery can name exactly the incarnations whose evidence is process bound");

    // The old authority is gone: the publisher identity is known, its process is
    // not attached, so it has no authority at all.
    fdr::AttachMemberRequest stale;
    stale.attempt = fdr::MutationAttempt{example::attempt_from("p-stale"), fdr::RequestDigest{}};
    stale.authority = operations.authority();
    stale.domain = rack;
    stale.member = leaf01;
    stale.provenance = example::durable_provenance("dcim/rack-r7/leaf-01");
    const fdr::Outcome refused = recovered.attach_member(stale);
    example::report(refused, "\nthe pre-restart authority tries to mutate");
    example::require(refused.code == fdr::OutcomeCode::StaleAuthority,
                     "a mutation from a session that no longer exists is refused");

    // Recovery reattaches the publisher identity with a fresh incarnation; the
    // previous incarnation is fenced by that very act.
    const fdr::WorkerBootId restarted_boot =
        example::worker_boot_from("dc1-operator/restart-1");
    const fdr::Outcome reattached = recovered.attach_worker(operations.publisher, restarted_boot,
                                                            recovered.epoch(), "dc1-operator",
                                                            fdr::EvidenceClass::DirectAuthoritativeInfrastructure);
    example::report(reattached, "reattach the same publisher with a fresh incarnation");
    example::require(reattached.committed(), "the publisher reattached at the recovered epoch");

    fdr::AttachMemberRequest fresh = stale;
    fresh.attempt = fdr::MutationAttempt{example::attempt_from("p-fresh"), fdr::RequestDigest{}};
    fresh.authority.worker_boot = restarted_boot;
    fresh.authority.epoch = recovered.epoch();
    fresh.provenance = example::process_bound_provenance("discovery/leaf-01/metadata");
    example::report(recovered.attach_member(fresh), "mutate again under the new incarnation");

    std::filesystem::remove(state_path, ignored);
    std::cout << "\nreused the same publisher identity after recovery: "
              << recovered.publishers().size() << " publisher registration(s), "
              << recovered.live_sessions().size() << " live session(s), "
              << recovered.fences().size() << " fence record(s)\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "example failed: " << error.what() << "\n";
    return 1;
  }
}
