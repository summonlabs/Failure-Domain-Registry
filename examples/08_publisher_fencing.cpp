// Example 8 - fencing one publisher without touching the other.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Two publishers publish into the same registry. One of them is fenced. The
// evidence that depended on the fenced process - the direct hardware reading it
// made - is demoted, while the durable administrative classification published by
// the other publisher, which never depended on a process, survives untouched.

#include "support.hpp"

namespace fdr = failure_domain_registry;

namespace {

void print_domain_lifecycle(const fdr::Registry& registry, std::string_view label,
                            const fdr::FailureDomainId& id) {
  const std::optional<fdr::FailureDomain> record = registry.domain(id);
  example::require(record.has_value(), "the domain exists");
  std::cout << label << ": class=" << record->domain_class.to_string()
            << " lifecycle=" << fdr::to_string(record->lifecycle)
            << " evidence=" << fdr::to_string(record->provenance.evidence) << "\n";
}

void print_membership_state(const fdr::Registry& registry, std::string_view label,
                            const fdr::EntityRef& member) {
  const std::vector<fdr::Membership> memberships = registry.memberships_of(member);
  example::require(memberships.size() == 1, "the member has exactly one membership here");
  const fdr::Membership& membership = memberships.front();
  std::cout << label << ": lifecycle=" << fdr::to_string(membership.lifecycle)
            << " evidence-entries=" << membership.evidence.size()
            << " live-evidence=" << membership.live_evidence_count()
            << " headline-evidence=" << fdr::to_string(membership.provenance.evidence) << "\n";
}

} // namespace

int main() {
  try {
    fdr::Registry registry;
    // The discovering publisher bootstraps the registry; the inventory publisher
    // is granted authority by it and gets its own incarnation.
    const example::Session discovery = example::open_registry(registry, "discovery-agent-a");
    const example::Session inventory = example::add_publisher(registry, discovery, "inventory-b");

    const fdr::FailureDomainId discovered_rack = example::declare_domain(
        registry, discovery, fdr::DomainClassRef(fdr::DomainClass::Rack), "dc1", "rack-r7",
        "Rack R7 (discovered)", "f-rack-discovered", example::process_bound_provenance("discovery/rack-r7"));
    const fdr::FailureDomainId declared_rack = example::declare_domain(
        registry, inventory, fdr::DomainClassRef(fdr::DomainClass::Rack), "dc1", "rack-r8",
        "Rack R8 (inventory)", "f-rack-declared", example::durable_provenance("cmdb/rack-r8"));

    const fdr::EntityRef leaf01(example::entity_from(fdr::EntityClass::Switch, "leaf-01"),
                                fdr::EntityGeneration(1));
    const fdr::EntityRef leaf02(example::entity_from(fdr::EntityClass::Switch, "leaf-02"),
                                fdr::EntityGeneration(1));

    example::attach_required(registry, discovery, discovered_rack, leaf01, "f-leaf01-rack",
                             example::process_bound_provenance("discovery/leaf-01"));
    example::attach_required(registry, inventory, declared_rack, leaf02, "f-leaf02-rack",
                             example::durable_provenance("cmdb/rack-r8/leaf-02"));

    std::cout << "example 08: fencing one publisher of two\n";
    std::cout << "publisher A (discovery) boot = " << discovery.worker_boot.to_string() << "\n";
    std::cout << "publisher B (inventory) boot = " << inventory.worker_boot.to_string() << "\n";
    std::cout << "live sessions before the fence: " << registry.live_sessions().size() << "\n";
    print_domain_lifecycle(registry, "A rack-r7 before", discovered_rack);
    print_domain_lifecycle(registry, "B rack-r8 before", declared_rack);
    print_membership_state(registry, "A leaf-01 before", leaf01);
    print_membership_state(registry, "B leaf-02 before", leaf02);

    const fdr::Outcome fenced = registry.fence_worker(discovery.publisher, discovery.worker_boot,
                                                      fdr::FenceReason::SessionLost, discovery.epoch);
    example::report(fenced, "\nfence publisher A");
    example::require(fenced.committed(), "the fence committed");

    std::cout << "live sessions after the fence: " << registry.live_sessions().size() << "\n";
    for (const fdr::FenceRecord& fence : registry.fences()) {
      std::cout << "  fence publisher=" << fence.publisher.to_string()
                << " boot=" << fence.worker_boot.to_string()
                << " reason=" << fdr::to_string(fence.reason)
                << " at-generation=" << fence.at_generation.to_string() << "\n";
    }

    std::cout << "\nA's process-bound evidence was demoted:\n";
    print_domain_lifecycle(registry, "  A rack-r7 after", discovered_rack);
    print_membership_state(registry, "  A leaf-01 after", leaf01);
    std::cout << "B's unrelated durable evidence survived:\n";
    print_domain_lifecycle(registry, "  B rack-r8 after", declared_rack);
    print_membership_state(registry, "  B leaf-02 after", leaf02);

    example::require(registry.domain(discovered_rack)->lifecycle ==
                         fdr::DomainLifecycle::RevalidationRequired,
                     "a process-bound domain loses authority with its process");
    example::require(registry.memberships_of(leaf01).front().lifecycle ==
                         fdr::MembershipLifecycle::RevalidationRequired,
                     "process-bound membership evidence is withdrawn");
    example::require(registry.memberships_of(leaf01).front().live_evidence_count() == 0,
                     "no live evidence remains for the fenced publisher's membership");
    example::require(registry.domain(declared_rack)->lifecycle == fdr::DomainLifecycle::Current,
                     "an unrelated durable domain is untouched");
    example::require(registry.memberships_of(leaf02).front().lifecycle ==
                         fdr::MembershipLifecycle::Current,
                     "an unrelated durable membership is untouched");
    example::require(registry.memberships_of(leaf02).front().live_evidence_count() == 1,
                     "the surviving publisher still has live evidence");

    // The fenced incarnation cannot mutate any more. Its own domain is refused
    // first because it no longer carries authority either, so the attempt is made
    // against a domain that is still current: the refusal is about the process,
    // not about the target.
    fdr::AttachMemberRequest retry;
    retry.attempt = fdr::MutationAttempt{example::attempt_from("f-leaf01-retry"), fdr::RequestDigest{}};
    retry.authority = discovery.authority();
    retry.domain = declared_rack;
    retry.member = leaf01;
    retry.provenance = example::process_bound_provenance("discovery/leaf-01");
    const fdr::Outcome refused = registry.attach_member(retry);
    example::report(refused, "\nfenced publisher A mutates into a domain that is still current");
    example::require(refused.code == fdr::OutcomeCode::StaleWorkerBoot,
                     "a fenced incarnation cannot mutate");

    fdr::DetachMemberRequest repair;
    repair.attempt = fdr::MutationAttempt{example::attempt_from("f-leaf01-detach"), fdr::RequestDigest{}};
    repair.authority = discovery.authority();
    repair.domain = discovered_rack;
    repair.member = leaf01;
    repair.reason = "attempted repair";
    const fdr::Outcome repair_refused = registry.detach_member(repair);
    example::report(repair_refused, "fenced publisher A addresses its own fenced domain");
    example::require(repair_refused.code != fdr::OutcomeCode::Committed,
                     "a fenced incarnation changes nothing");

    const fdr::EntityRef leaf03(example::entity_from(fdr::EntityClass::Switch, "leaf-03"),
                                fdr::EntityGeneration(1));
    example::attach_required(registry, inventory, declared_rack, leaf03, "f-leaf03-rack",
                             example::durable_provenance("cmdb/rack-r8/leaf-03"));
    std::cout << "publisher B published another member while A is fenced: "
              << registry.members_of(declared_rack).size() << " members in rack R8\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "example failed: " << error.what() << "\n";
    return 1;
  }
}
