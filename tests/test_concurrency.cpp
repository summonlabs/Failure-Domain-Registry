// Failure Domain Registry — concurrency and deterministic race proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Two kinds of proof live here.
//
// 1. A stress phase: real threads mutate, query, snapshot, fence and invalidate
//    the same Registry at the same time for a fixed number of iterations. Every
//    outcome must be one of the outcomes the contract permits for that
//    operation, no operation may report an internal failure, and the registry
//    must still validate at the end.
//
// 2. Deterministic races: two threads are released together by a std::barrier so
//    that two genuinely conflicting operations are in flight at the same instant.
//    Each race is repeated many times, and the pair of outcomes is required to be
//    an element of the set of outcomes the two possible serial orderings would
//    produce. The registry must never reach a state that neither ordering could
//    have produced.

#include <atomic>
#include <barrier>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "failure_domain_registry/failure_domain_registry.hpp"
#include "support/test_harness.hpp"
#include "support/test_process.hpp"

namespace {

using namespace failure_domain_registry;

template <class Id>
Id id_from(std::string_view label) {
  return Id::from_digest(sha256(label));
}

IdBytes entity_bytes(std::string_view label, std::size_t index) {
  const DigestBytes digest = sha256(std::string(label) + "/" + std::to_string(index));
  IdBytes bytes{};
  for (std::size_t position = 0; position < bytes.size(); ++position) {
    bytes[position] = digest[position];
  }
  return bytes;
}

bool one_of(OutcomeCode code, std::initializer_list<OutcomeCode> allowed) {
  for (OutcomeCode candidate : allowed) {
    if (candidate == code) {
      return true;
    }
  }
  return false;
}

bool one_of(MembershipLifecycle code, std::initializer_list<MembershipLifecycle> allowed) {
  for (MembershipLifecycle candidate : allowed) {
    if (candidate == code) {
      return true;
    }
  }
  return false;
}

/// Outcomes that mean the runtime itself failed rather than the request losing.
bool is_internal(OutcomeCode code) {
  return one_of(code, {OutcomeCode::InternalFailure, OutcomeCode::ProtocolViolation,
                       OutcomeCode::UnsupportedCapability, OutcomeCode::IntegrityFailure});
}

std::string describe(const Outcome& outcome) {
  return std::string(to_string(outcome.code)) + " (" + outcome.message + ")";
}

/// One registry plus the publisher incarnations that may mutate it.
struct Rig {
  Registry registry;
  CoordinatorEpoch epoch;
  std::vector<PublisherId> publishers;
  std::vector<WorkerBootId> boots;
  std::size_t reincarnations{0};
  std::atomic<std::size_t> attempts{0};

  explicit Rig(std::size_t count, std::uint64_t salt) {
    for (std::size_t index = 0; index < count; ++index) {
      const std::string label =
          "fdr/test/concurrency/" + std::to_string(salt) + "/" + std::to_string(index);
      publishers.push_back(id_from<PublisherId>("publisher/" + label));
      boots.push_back(id_from<WorkerBootId>("boot/" + label + "/0"));
    }
    for (std::size_t index = 0; index < count; ++index) {
      PublisherRegistration registration;
      registration.publisher = publishers[index];
      registration.name = "concurrency-" + std::to_string(index);
      registration.scope = AuthorityScope::unrestricted();
      registration.scope.max_evidence = EvidenceClass::DirectAuthoritativeInfrastructure;
      FDR_CHECK_EQ(registry.grant_publisher(registration, AuthorityContext{}).code,
                   OutcomeCode::Committed);
    }
    CoordinatorEpoch advanced;
    FDR_CHECK_EQ(registry.advance_epoch(CoordinatorEpoch(0), &advanced).code,
                 OutcomeCode::Committed);
    epoch = advanced;
    for (std::size_t index = 0; index < count; ++index) {
      FDR_CHECK_EQ(attach(index).code, OutcomeCode::Committed);
    }
  }

  Outcome attach(std::size_t index) {
    return registry.attach_worker(publishers[index], boots[index], epoch, "concurrency",
                                  EvidenceClass::DirectAuthoritativeInfrastructure);
  }

  /// A fresh incarnation for the same publisher. The previous one is fenced.
  void reincarnate(std::size_t index) {
    ++reincarnations;
    boots[index] = id_from<WorkerBootId>("fdr/test/concurrency/boot/reincarnation/" +
                                         std::to_string(reincarnations));
    FDR_CHECK_EQ(attach(index).code, OutcomeCode::Committed);
  }

  AuthorityContext authority(std::size_t index, const WorkerBootId& boot) const {
    AuthorityContext context;
    context.publisher = publishers[index];
    context.worker_boot = boot;
    context.epoch = epoch;
    context.evidence = EvidenceClass::DirectAuthoritativeInfrastructure;
    return context;
  }

  AuthorityContext authority(std::size_t index) const { return authority(index, boots[index]); }

  MutationAttempt next_attempt() {
    const std::size_t index = attempts.fetch_add(1) + 1u;
    return MutationAttempt(
        MutationAttemptId::from_digest(sha256("fdr/test/concurrency/attempt/" +
                                              std::to_string(index))),
        RequestDigest{});
  }

  static Provenance provenance_value() {
    Provenance value;
    value.source = ProvenanceSource::OperatorInventory;
    value.evidence = EvidenceClass::DirectAuthoritativeInfrastructure;
    value.truth = TruthClass::Real;
    value.source_identity = "concurrency";
    return value;
  }

  FailureDomainId make_domain(std::size_t index, const std::string& scope,
                              const std::string& key,
                              DomainClass klass = DomainClass::Rack) {
    CreateDomainRequest request;
    request.attempt = next_attempt();
    request.authority = authority(index);
    request.domain_class = DomainClassRef(klass);
    request.administrative_scope = scope;
    request.identity_key = key;
    request.provenance = provenance_value();
    const Outcome outcome = registry.create_domain(request);
    if (!outcome.committed() || !outcome.domain.has_value()) {
      ::fdrtest::fail(__FILE__, __LINE__, "domain creation failed: " + describe(outcome));
    }
    return *outcome.domain;
  }

  std::vector<Membership> current_memberships(const FailureDomainId& domain) const {
    std::vector<Membership> out;
    for (const Membership& membership : registry.members_of(domain)) {
      if (membership.is_current()) {
        out.push_back(membership);
      }
    }
    return out;
  }
};

/// Releases two operations together and reports their outcome pair. Threads are
/// created per round so that a failing assertion can never leave a thread
/// waiting on a barrier.
template <class Left, class Right, class Inspect>
void run_race(std::size_t rounds, Left left, Right right, Inspect inspect) {
  for (std::size_t round = 0; round < rounds; ++round) {
    std::barrier<> gate(2);
    Outcome left_outcome;
    Outcome right_outcome;
    std::thread first([&]() {
      gate.arrive_and_wait();
      left_outcome = left(round);
    });
    std::thread second([&]() {
      gate.arrive_and_wait();
      right_outcome = right(round);
    });
    first.join();
    second.join();
    inspect(round, left_outcome, right_outcome);
  }
}

void require_valid(Registry& registry, const std::string& context) {
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), context + ": " + why);
}

} // namespace

FDR_TEST_CASE(concurrency, concurrent_mutations_queries_snapshots_fencing_and_invalidation) {
  Rig rig(5, 1u);
  const std::size_t kMutators = 4;
  const std::size_t kIterations = 120;

  std::vector<FailureDomainId> domains;
  std::vector<EntityRef> entities;
  for (std::size_t index = 0; index < kMutators; ++index) {
    domains.push_back(rig.make_domain(index, "dc1", "rack-" + std::to_string(index)));
    for (std::size_t entity = 0; entity < 4; ++entity) {
      entities.push_back(EntityRef(EntityClass::Switch,
                                   entity_bytes("concurrency/entity", index * 4u + entity),
                                   EntityGeneration(1)));
    }
  }

  std::mutex outcome_mutex;
  std::vector<Outcome> outcomes;
  const auto record = [&outcome_mutex, &outcomes](const Outcome& outcome) {
    std::lock_guard<std::mutex> guard(outcome_mutex);
    outcomes.push_back(outcome);
  };
  std::vector<std::size_t> commits(kMutators, 0);

  std::vector<std::thread> threads;

  for (std::size_t index = 0; index < kMutators; ++index) {
    threads.emplace_back([&, index]() {
      std::atomic<std::size_t> local_commits{0};
      for (std::size_t iteration = 0; iteration < kIterations; ++iteration) {
        const std::size_t operation = (iteration + index) % 8u;
        Outcome outcome;
        if (operation == 0) {
          AttachMemberRequest request;
          request.attempt = rig.next_attempt();
          request.authority = rig.authority(index);
          request.domain = domains[index];
          request.member = entities[(iteration + index) % entities.size()];
          request.kind = MembershipKind::Direct;
          request.role = MembershipRole::Primary;
          request.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
          request.provenance = Rig::provenance_value();
          outcome = rig.registry.attach_member(request);
        } else if (operation == 1) {
          const std::vector<Membership> current = rig.current_memberships(domains[index]);
          if (current.empty()) {
            continue;
          }
          const Membership& chosen = current[iteration % current.size()];
          DetachMemberRequest request;
          request.attempt = rig.next_attempt();
          request.authority = rig.authority(index);
          request.domain = chosen.domain;
          request.member = chosen.member;
          request.kind = chosen.kind;
          request.expected_membership_generation = chosen.generation;
          request.reason = "concurrency detach";
          outcome = rig.registry.detach_member(request);
        } else if (operation == 2) {
          const std::vector<Membership> current = rig.current_memberships(domains[index]);
          if (current.empty()) {
            continue;
          }
          const Membership& chosen = current[iteration % current.size()];
          ReplaceMembershipRequest request;
          request.attempt = rig.next_attempt();
          request.authority = rig.authority(index);
          request.membership = chosen.id;
          request.expected_generation = chosen.generation;
          request.role = MembershipRole::Redundant;
          outcome = rig.registry.replace_membership(request);
        } else if (operation == 3) {
          UpdateDomainRequest request;
          request.attempt = rig.next_attempt();
          request.authority = rig.authority(index);
          request.domain = domains[index];
          request.name = "rack-name-" + std::to_string(iteration);
          outcome = rig.registry.update_domain(request);
        } else if (operation == 4) {
          MembershipBatchRequest request;
          request.attempt = rig.next_attempt();
          request.authority = rig.authority(index);
          request.mode = PublicationMode::Incremental;
          request.administrative_scope = "dc1";
          MembershipBatchEntry entry;
          entry.domain = domains[index];
          entry.member = entities[(iteration * 3u + index) % entities.size()];
          entry.kind = MembershipKind::Direct;
          entry.role = MembershipRole::Primary;
          entry.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
          entry.provenance = Rig::provenance_value();
          request.entries.push_back(entry);
          outcome = rig.registry.publish_memberships(request);
        } else if (operation == 5) {
          MarkRevalidationRequest request;
          request.attempt = rig.next_attempt();
          request.authority = rig.authority(index);
          request.domain = domains[index];
          request.reason = "concurrency demand";
          outcome = rig.registry.mark_revalidation_required(request);
        } else if (operation == 6) {
          const std::vector<Membership> current = rig.current_memberships(domains[index]);
          if (current.empty()) {
            continue;
          }
          const Membership& chosen = current[iteration % current.size()];
          ReconcileMembershipRequest request;
          request.attempt = rig.next_attempt();
          request.authority = rig.authority(index);
          request.domain = chosen.domain;
          request.member = chosen.member;
          request.kind = chosen.kind;
          outcome = rig.registry.reconcile_membership(request);
        } else {
          const std::vector<Membership> current = rig.current_memberships(domains[index]);
          if (current.empty()) {
            continue;
          }
          const Membership& chosen = current[iteration % current.size()];
          WithdrawEvidenceRequest request;
          request.attempt = rig.next_attempt();
          request.authority = rig.authority(index);
          request.membership = chosen.id;
          request.expected_generation = chosen.generation;
          request.reason = "concurrency withdrawal";
          outcome = rig.registry.withdraw_evidence(request);
        }
        if (outcome.committed()) {
          local_commits.fetch_add(1);
        }
        record(outcome);
        if (iteration % 16u == 0u) {
          require_valid(rig.registry, "mutator " + std::to_string(index));
        }
      }
      commits[index] = local_commits.load();
    });
  }

  threads.emplace_back([&]() {
    const std::vector<DomainClassRef> classes{DomainClassRef(DomainClass::Rack)};
    for (std::size_t iteration = 0; iteration < 250; ++iteration) {
      const std::vector<EntityId> set{entities[iteration % entities.size()].id(),
                                      entities[(iteration + 1u) % entities.size()].id()};
      const OverlapResult overlap = rig.registry.overlap(set);
      FDR_CHECK_MSG(overlap.state != IndependenceState::Unknown,
                    "an overlap answer is never an unset state");
      // independence() and blast_radius() both used to call a public method
      // while already holding the registry shared lock (Registry::coverage and
      // Registry::relations_of), which is a recursive shared acquisition and
      // deadlocked the process at 0% CPU the moment a writer was waiting on the
      // SRWLock. Both are repaired in src/registry_query.cpp and are now called
      // here under concurrent mutation as a standing regression proof.
      const IndependenceResult independence = rig.registry.independence(set, classes);
      FDR_CHECK_EQ(independence.coverage.entries.size(), classes.size());
      static_cast<void>(rig.registry.blast_radius(domains[iteration % domains.size()]));
      const CoverageReport coverage = rig.registry.coverage("dc1", classes);
      FDR_CHECK_EQ(coverage.entries.size(), classes.size());
      const std::vector<EntityId> pair{set.front(), set.back()};
      const OverlapResult pair_overlap = rig.registry.overlap(pair);
      FDR_CHECK_MSG(pair_overlap.state != IndependenceState::Unknown ||
                        pair.front() == pair.back(),
                    "a two-entity overlap answer is never an unset state");
      const SetCorrelation correlation = rig.registry.correlate_member_sets(set, set, classes);
      FDR_CHECK_MSG(correlation.state != IndependenceState::Unknown,
                    "a self correlation is never an unset state");
      for (const Membership& membership : rig.registry.memberships_of(set.front())) {
        FDR_CHECK_MSG(!membership.id.is_null(), "a membership is never identified by a null id");
      }
    }
  });

  threads.emplace_back([&]() {
    Snapshot previous = rig.registry.snapshot("dc1");
    for (std::size_t iteration = 0; iteration < 80; ++iteration) {
      const Snapshot current = rig.registry.snapshot("dc1");
      FDR_CHECK_MSG(current.sequence >= previous.sequence,
                    "the snapshot sequence must not go backwards");
      FDR_CHECK_MSG(current.state_generation >= previous.state_generation,
                    "the snapshot generation must not go backwards");
      const SnapshotDiff diff = rig.registry.diff(previous, current);
      FDR_CHECK_EQ(diff.before, previous.id);
      FDR_CHECK_EQ(diff.after, current.id);
      const BlastRadius radius =
          rig.registry.blast_radius(domains[iteration % domains.size()]);
      FDR_CHECK_EQ(radius.domain, domains[iteration % domains.size()]);
      previous = current;
    }
  });

  threads.emplace_back([&]() {
    // A dedicated victim incarnation is fenced and immediately replaced, so the
    // fencing path runs concurrently with every other mutation.
    FailureDomainId victim_domain;
    {
      std::lock_guard<std::mutex> guard(outcome_mutex);
      victim_domain = domains[domains.size() - 1];
    }
    static_cast<void>(victim_domain);
    for (std::size_t iteration = 0; iteration < 40; ++iteration) {
      const WorkerBootId boot =
          id_from<WorkerBootId>("fdr/test/concurrency/boot/victim/" + std::to_string(iteration));
      const Outcome attached = rig.registry.attach_worker(
          rig.publishers[4], boot, rig.epoch, "victim",
          EvidenceClass::DirectAuthoritativeInfrastructure);
      FDR_CHECK_MSG(attached.committed() || attached.code == OutcomeCode::Idempotent,
                    "attaching a fresh victim incarnation failed: " + describe(attached));
      MembershipBatchRequest request;
      request.attempt = rig.next_attempt();
      request.authority = rig.authority(4, boot);
      request.mode = PublicationMode::Incremental;
      request.administrative_scope = "dc1";
      MembershipBatchEntry entry;
      entry.domain = domains[4 % domains.size()];
      entry.member = EntityRef(EntityClass::Switch,
                               entity_bytes("concurrency/victim", iteration),
                               EntityGeneration(1));
      entry.kind = MembershipKind::Direct;
      entry.role = MembershipRole::Primary;
      entry.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
      entry.provenance = Rig::provenance_value();
      request.entries.push_back(entry);
      const Outcome published = rig.registry.publish_memberships(request);
      FDR_CHECK_MSG(!is_internal(published.code),
                    "a victim publication failed internally: " + describe(published));
      const Outcome fenced = rig.registry.fence_worker(rig.publishers[4], boot,
                                                       FenceReason::SessionLost, rig.epoch);
      FDR_CHECK_MSG(fenced.committed() || fenced.code == OutcomeCode::Idempotent,
                    "fencing a known incarnation failed: " + describe(fenced));
      record(attached);
      record(published);
      record(fenced);
    }
  });

  threads.emplace_back([&]() {
    for (std::size_t iteration = 0; iteration < 100; ++iteration) {
      EntityInvalidationRequest request;
      request.attempt = rig.next_attempt();
      request.authority = rig.authority(0);
      request.entity = entities[iteration % entities.size()].id();
      request.superseded_generation = EntityGeneration(1);
      request.reason = "concurrency invalidation";
      const Outcome outcome = rig.registry.invalidate_entity(request);
      FDR_CHECK_MSG(!is_internal(outcome.code),
                    "an invalidation failed internally: " + describe(outcome));
      record(outcome);
    }
  });

  for (std::thread& thread : threads) {
    thread.join();
  }

  require_valid(rig.registry, "after the concurrent phase");
  for (std::size_t index = 0; index < kMutators; ++index) {
    FDR_CHECK_MSG(commits[index] > 0,
                  "mutator " + std::to_string(index) + " never committed anything");
  }
  for (const Outcome& outcome : outcomes) {
    FDR_CHECK_MSG(!is_internal(outcome.code),
                  "a concurrent operation failed internally: " + describe(outcome));
  }

  // Every exclusive class still holds at most one current domain per entity.
  std::vector<std::pair<EntityId, std::string>> exclusive;
  for (const Membership& membership :
       rig.registry.memberships_in_lifecycle(MembershipLifecycle::Current)) {
    const std::optional<FailureDomain> domain = rig.registry.domain(membership.domain);
    if (!domain.has_value() || !domain->domain_class.is_exclusive()) {
      continue;
    }
    const std::pair<EntityId, std::string> key{membership.member.id(),
                                               domain->domain_class.to_string()};
    for (const std::pair<EntityId, std::string>& seen : exclusive) {
      FDR_CHECK_MSG(!(seen.first == key.first && seen.second == key.second),
                    "an exclusive class holds two current domains for one entity");
    }
    exclusive.push_back(key);
  }
}

FDR_TEST_CASE(concurrency, two_publishers_contend_for_an_exclusive_domain) {
  Rig rig(2, 2u);
  const FailureDomainId left_domain = rig.make_domain(0, "dc1", "contend-left");
  const FailureDomainId right_domain = rig.make_domain(1, "dc1", "contend-right");
  FDR_CHECK_MSG(!(left_domain == right_domain), "two identity keys must address two domains");

  run_race(
      24,
      [&](std::size_t round) {
        AttachMemberRequest request;
        request.attempt = rig.next_attempt();
        request.authority = rig.authority(0);
        request.domain = left_domain;
        request.member = EntityRef(EntityClass::Switch, entity_bytes("contend", round),
                                   EntityGeneration(1));
        request.kind = MembershipKind::Direct;
        request.role = MembershipRole::Primary;
        request.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
        request.provenance = Rig::provenance_value();
        return rig.registry.attach_member(request);
      },
      [&](std::size_t round) {
        AttachMemberRequest request;
        request.attempt = rig.next_attempt();
        request.authority = rig.authority(1);
        request.domain = right_domain;
        request.member = EntityRef(EntityClass::Switch, entity_bytes("contend", round),
                                   EntityGeneration(1));
        request.kind = MembershipKind::Direct;
        request.role = MembershipRole::Primary;
        request.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
        request.provenance = Rig::provenance_value();
        return rig.registry.attach_member(request);
      },
      [&](std::size_t round, const Outcome& left, const Outcome& right) {
        FDR_CHECK_MSG(one_of(left.code, {OutcomeCode::Committed, OutcomeCode::ExclusivityViolation}),
                      "round " + std::to_string(round) + ": left answered " + describe(left));
        FDR_CHECK_MSG(
            one_of(right.code, {OutcomeCode::Committed, OutcomeCode::ExclusivityViolation}),
            "round " + std::to_string(round) + ": right answered " + describe(right));
        FDR_CHECK_MSG(left.committed() != right.committed(),
                      "round " + std::to_string(round) +
                          ": exactly one publisher may win the exclusive domain");
        const Outcome& loser = left.committed() ? right : left;
        FDR_CHECK_EQ(loser.code, OutcomeCode::ExclusivityViolation);

        const EntityRef member(EntityClass::Switch, entity_bytes("contend", round),
                               EntityGeneration(1));
        const std::vector<Membership> memberships = rig.registry.memberships_of(member);
        std::size_t current = 0;
        for (const Membership& membership : memberships) {
          if (membership.is_current()) {
            ++current;
          }
        }
        FDR_CHECK_EQ(current, std::size_t{1});
        require_valid(rig.registry, "exclusive contention");

        // Reset for the next round: retire whichever membership won.
        for (const Membership& membership : memberships) {
          if (!membership.is_current()) {
            continue;
          }
          DetachMemberRequest detach;
          detach.attempt = rig.next_attempt();
          detach.authority = rig.authority(0);
          detach.domain = membership.domain;
          detach.member = membership.member;
          detach.kind = membership.kind;
          detach.expected_membership_generation = membership.generation;
          detach.reason = "round reset";
          FDR_CHECK_EQ(rig.registry.detach_member(detach).code, OutcomeCode::Committed);
        }
      });
}

FDR_TEST_CASE(concurrency, add_versus_remove) {
  Rig rig(2, 3u);
  const FailureDomainId domain = rig.make_domain(0, "dc1", "add-remove");

  run_race(
      24,
      [&](std::size_t round) {
        AttachMemberRequest request;
        request.attempt = rig.next_attempt();
        request.authority = rig.authority(0);
        request.domain = domain;
        request.member = EntityRef(EntityClass::Switch, entity_bytes("add-remove", round),
                                   EntityGeneration(1));
        request.kind = MembershipKind::Direct;
        request.role = MembershipRole::Primary;
        request.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
        request.provenance = Rig::provenance_value();
        return rig.registry.attach_member(request);
      },
      [&](std::size_t round) {
        DetachMemberRequest request;
        request.attempt = rig.next_attempt();
        request.authority = rig.authority(1);
        request.domain = domain;
        request.member = EntityRef(EntityClass::Switch, entity_bytes("add-remove", round),
                                   EntityGeneration(1));
        request.kind = MembershipKind::Direct;
        request.reason = "race removal";
        return rig.registry.detach_member(request);
      },
      [&](std::size_t round, const Outcome& added, const Outcome& removed) {
        FDR_CHECK_MSG(
            one_of(added.code, {OutcomeCode::Committed, OutcomeCode::Retired}),
            "round " + std::to_string(round) + ": attach answered " + describe(added));
        FDR_CHECK_MSG(one_of(removed.code, {OutcomeCode::Committed, OutcomeCode::NotFound}),
                      "round " + std::to_string(round) + ": detach answered " + describe(removed));
        // Both serial orderings are legal, and the final state must be the one
        // the winning ordering produces.
        const EntityRef member(EntityClass::Switch, entity_bytes("add-remove", round),
                               EntityGeneration(1));
        const std::vector<Membership> memberships = rig.registry.memberships_of(member);
        if (removed.committed()) {
          FDR_CHECK_EQ(memberships.size(), std::size_t{1});
          FDR_CHECK_EQ(memberships.front().lifecycle, MembershipLifecycle::Retired);
        } else {
          FDR_CHECK_MSG(added.committed(), "an attach that lost to a missing removal must commit");
          FDR_CHECK_EQ(memberships.size(), std::size_t{1});
          FDR_CHECK_EQ(memberships.front().lifecycle, MembershipLifecycle::Current);
        }
        require_valid(rig.registry, "add versus remove");
        for (const Membership& membership : memberships) {
          if (!membership.is_current()) {
            continue;
          }
          DetachMemberRequest detach;
          detach.attempt = rig.next_attempt();
          detach.authority = rig.authority(0);
          detach.domain = membership.domain;
          detach.member = membership.member;
          detach.kind = membership.kind;
          detach.expected_membership_generation = membership.generation;
          detach.reason = "round reset";
          static_cast<void>(rig.registry.detach_member(detach));
        }
      });
}

FDR_TEST_CASE(concurrency, membership_replace_versus_entity_supersession) {
  Rig rig(2, 4u);
  const FailureDomainId domain = rig.make_domain(0, "dc1", "replace-supersede");

  // Every round races a replace against a supersession of its OWN membership, so
  // the membership must exist before the round starts.
  const auto prepare = [&](std::size_t round) {
    AttachMemberRequest request;
    request.attempt = rig.next_attempt();
    request.authority = rig.authority(0);
    request.domain = domain;
    request.member = EntityRef(EntityClass::Switch, entity_bytes("replace", round),
                               EntityGeneration(1));
    request.kind = MembershipKind::Direct;
    request.role = MembershipRole::Primary;
    request.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
    request.provenance = Rig::provenance_value();
    FDR_CHECK_EQ(rig.registry.attach_member(request).code, OutcomeCode::Committed);
  };
  prepare(0);

  run_race(
      24,
      [&](std::size_t round) {
        const EntityRef member(EntityClass::Switch, entity_bytes("replace", round),
                               EntityGeneration(1));
        const MembershipId id = membership_id_for(
            MembershipKey{domain, member.id(), member.generation(), MembershipKind::Direct});
        const std::optional<Membership> current = rig.registry.membership(id);
        ReplaceMembershipRequest request;
        request.attempt = rig.next_attempt();
        request.authority = rig.authority(0);
        request.membership = id;
        request.expected_generation =
            MembershipGeneration(current.has_value() ? current->generation.value() : 0u);
        request.role = MembershipRole::Redundant;
        return rig.registry.replace_membership(request);
      },
      [&](std::size_t round) {
        EntityInvalidationRequest request;
        request.attempt = rig.next_attempt();
        request.authority = rig.authority(1);
        request.entity = EntityRef(EntityClass::Switch, entity_bytes("replace", round),
                                   EntityGeneration(1))
                             .id();
        request.superseded_generation = EntityGeneration(1);
        request.reason = "race supersession";
        return rig.registry.invalidate_entity(request);
      },
      [&](std::size_t round, const Outcome& replaced, const Outcome& invalidated) {
        FDR_CHECK_MSG(one_of(replaced.code, {OutcomeCode::Committed, OutcomeCode::StaleMembership,
                                             OutcomeCode::NotFound}),
                      "round " + std::to_string(round) + ": replace answered " + describe(replaced));
        FDR_CHECK_MSG(one_of(invalidated.code, {OutcomeCode::Committed}),
                      "round " + std::to_string(round) + ": invalidate answered " +
                          describe(invalidated));
        const EntityRef member(EntityClass::Switch, entity_bytes("replace", round),
                               EntityGeneration(1));
        const std::vector<Membership> memberships = rig.registry.memberships_of(member);
        FDR_CHECK_EQ(memberships.size(), std::size_t{1});
        // Whatever the order, the supersession wins the lifecycle: the membership
        // is never Current once the entity generation is gone.
        FDR_CHECK_EQ(memberships.front().lifecycle, MembershipLifecycle::RevalidationRequired);
        FDR_CHECK_EQ(memberships.front().role,
                     replaced.committed() ? MembershipRole::Redundant : MembershipRole::Primary);
        require_valid(rig.registry, "replace versus supersession");
        if (round + 1u < 24u) {
          prepare(round + 1u);
        }
      });
}

FDR_TEST_CASE(concurrency, domain_supersession_versus_membership_add) {
  const std::size_t kRounds = 24;
  for (std::size_t round = 0; round < kRounds; ++round) {
    Rig rig(2, 100u + static_cast<std::uint64_t>(round));
    const FailureDomainId domain = rig.make_domain(0, "dc1", "supersede-source");
    const FailureDomainId successor = rig.make_domain(0, "dc1", "supersede-successor");
    const EntityRef member(EntityClass::Switch, entity_bytes("supersede", round),
                           EntityGeneration(1));

    std::barrier<> gate(2);
    Outcome superseded;
    Outcome attached;
    std::thread first([&]() {
      gate.arrive_and_wait();
      SupersedeDomainRequest request;
      request.attempt = rig.next_attempt();
      request.authority = rig.authority(0);
      request.domain = domain;
      request.successor = successor;
      request.demote_memberships = true;
      superseded = rig.registry.supersede_domain(request);
    });
    std::thread second([&]() {
      gate.arrive_and_wait();
      AttachMemberRequest request;
      request.attempt = rig.next_attempt();
      request.authority = rig.authority(1);
      request.domain = domain;
      request.member = member;
      request.kind = MembershipKind::Direct;
      request.role = MembershipRole::Primary;
      request.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
      request.provenance = Rig::provenance_value();
      attached = rig.registry.attach_member(request);
    });
    first.join();
    second.join();

    const std::string prefix = "round " + std::to_string(round) + ": ";
    FDR_CHECK_MSG(one_of(superseded.code, {OutcomeCode::Committed}),
                  prefix + "supersede answered " + describe(superseded));
    FDR_CHECK_MSG(one_of(attached.code, {OutcomeCode::Committed, OutcomeCode::Superseded}),
                  prefix + "attach answered " + describe(attached));
    const std::optional<FailureDomain> source = rig.registry.domain(domain);
    FDR_CHECK_MSG(source.has_value(), prefix + "the superseded domain disappeared");
    FDR_CHECK_EQ(source->lifecycle, DomainLifecycle::Superseded);
    const std::vector<Membership> memberships = rig.registry.memberships_of(member);
    if (attached.committed()) {
      FDR_CHECK_EQ(memberships.size(), std::size_t{1});
      FDR_CHECK_EQ(memberships.front().lifecycle, MembershipLifecycle::RevalidationRequired);
    } else {
      FDR_CHECK_EQ(memberships.size(), std::size_t{0});
    }
    require_valid(rig.registry, prefix + "domain supersession versus membership add");
  }
}

FDR_TEST_CASE(concurrency, publisher_fence_versus_publication) {
  Rig rig(2, 5u);
  const FailureDomainId domain = rig.make_domain(0, "dc1", "fence-publication");

  run_race(
      24,
      [&](std::size_t round) {
        static_cast<void>(round);
        return rig.registry.fence_worker(rig.publishers[0], rig.boots[0],
                                         FenceReason::Administrative, rig.epoch);
      },
      [&](std::size_t round) {
        MembershipBatchRequest request;
        request.attempt = rig.next_attempt();
        request.authority = rig.authority(0);
        request.mode = PublicationMode::Incremental;
        request.administrative_scope = "dc1";
        MembershipBatchEntry entry;
        entry.domain = domain;
        entry.member = EntityRef(EntityClass::Switch, entity_bytes("fence", round),
                                 EntityGeneration(1));
        entry.kind = MembershipKind::Direct;
        entry.role = MembershipRole::Primary;
        entry.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
        entry.provenance = Rig::provenance_value();
        request.entries.push_back(entry);
        return rig.registry.publish_memberships(request);
      },
      [&](std::size_t round, const Outcome& fenced, const Outcome& published) {
        FDR_CHECK_MSG(one_of(fenced.code, {OutcomeCode::Committed, OutcomeCode::Idempotent}),
                      "round " + std::to_string(round) + ": fence answered " + describe(fenced));
        FDR_CHECK_MSG(
            one_of(published.code,
                   {OutcomeCode::Committed, OutcomeCode::StaleWorkerBoot,
                    OutcomeCode::StaleAuthority}),
            "round " + std::to_string(round) + ": publication answered " + describe(published));
        const EntityRef member(EntityClass::Switch, entity_bytes("fence", round),
                               EntityGeneration(1));
        const std::vector<Membership> memberships = rig.registry.memberships_of(member);
        if (published.committed()) {
          // A publication that won the race loses its authority immediately: the
          // fence demotes exactly the evidence the fenced incarnation published.
          FDR_CHECK_EQ(memberships.size(), std::size_t{1});
          FDR_CHECK_EQ(memberships.front().lifecycle, MembershipLifecycle::RevalidationRequired);
        } else {
          FDR_CHECK_EQ(memberships.size(), std::size_t{0});
        }
        require_valid(rig.registry, "fence versus publication");
        rig.reincarnate(0);
      });
}

FDR_TEST_CASE(concurrency, epoch_advance_versus_publication) {
  const std::size_t kRounds = 16;
  for (std::size_t round = 0; round < kRounds; ++round) {
    Rig rig(2, 200u + static_cast<std::uint64_t>(round));
    const FailureDomainId domain = rig.make_domain(0, "dc1", "epoch-publication");
    const CoordinatorEpoch expected = rig.epoch;
    const EntityRef member(EntityClass::Switch, entity_bytes("epoch", round), EntityGeneration(1));

    std::barrier<> gate(2);
    Outcome advanced;
    Outcome published;
    std::thread first([&]() {
      gate.arrive_and_wait();
      CoordinatorEpoch next;
      advanced = rig.registry.advance_epoch(expected, &next);
    });
    std::thread second([&]() {
      gate.arrive_and_wait();
      MembershipBatchRequest request;
      request.attempt = rig.next_attempt();
      request.authority = rig.authority(1);
      request.mode = PublicationMode::Incremental;
      request.administrative_scope = "dc1";
      MembershipBatchEntry entry;
      entry.domain = domain;
      entry.member = member;
      entry.kind = MembershipKind::Direct;
      entry.role = MembershipRole::Primary;
      entry.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
      entry.provenance = Rig::provenance_value();
      request.entries.push_back(entry);
      published = rig.registry.publish_memberships(request);
    });
    first.join();
    second.join();

    const std::string prefix = "round " + std::to_string(round) + ": ";
    FDR_CHECK_MSG(one_of(advanced.code, {OutcomeCode::Committed}),
                  prefix + "epoch advance answered " + describe(advanced));
    FDR_CHECK_MSG(
        one_of(published.code,
               {OutcomeCode::Committed, OutcomeCode::StaleEpoch, OutcomeCode::StaleWorkerBoot,
                OutcomeCode::StaleAuthority}),
        prefix + "publication answered " + describe(published));
    FDR_CHECK_EQ(rig.registry.epoch().value(), expected.value() + 1u);
    const std::vector<Membership> memberships = rig.registry.memberships_of(member);
    if (published.committed()) {
      FDR_CHECK_EQ(memberships.size(), std::size_t{1});
      FDR_CHECK_EQ(memberships.front().lifecycle, MembershipLifecycle::RevalidationRequired);
    } else {
      FDR_CHECK_EQ(memberships.size(), std::size_t{0});
    }
    FDR_CHECK_MSG(rig.registry.live_sessions().empty(),
                  prefix + "advancing the epoch must fence every live incarnation");
    require_valid(rig.registry, prefix + "epoch advance versus publication");
  }
}

FDR_TEST_CASE(concurrency, authoritative_publication_versus_incremental_mutation) {
  const std::size_t kRounds = 16;
  for (std::size_t round = 0; round < kRounds; ++round) {
    Rig rig(1, 300u + static_cast<std::uint64_t>(round));
    const FailureDomainId domain = rig.make_domain(0, "dc1", "authoritative");
    const EntityRef listed(EntityClass::Switch, entity_bytes("authoritative-listed", round),
                           EntityGeneration(1));
    const EntityRef added(EntityClass::Switch, entity_bytes("authoritative-added", round),
                          EntityGeneration(1));

    std::barrier<> gate(2);
    Outcome authoritative;
    Outcome incremental;
    std::thread first([&]() {
      gate.arrive_and_wait();
      MembershipBatchRequest request;
      request.attempt = rig.next_attempt();
      request.authority = rig.authority(0);
      request.mode = PublicationMode::Authoritative;
      request.administrative_scope = "dc1";
      request.authoritative_entity_class = EntityClass::Switch;
      request.authoritative_domains.push_back(domain);
      MembershipBatchEntry entry;
      entry.domain = domain;
      entry.member = listed;
      entry.kind = MembershipKind::Direct;
      entry.role = MembershipRole::Primary;
      entry.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
      entry.provenance = Rig::provenance_value();
      request.entries.push_back(entry);
      authoritative = rig.registry.publish_memberships(request);
    });
    std::thread second([&]() {
      gate.arrive_and_wait();
      AttachMemberRequest request;
      request.attempt = rig.next_attempt();
      request.authority = rig.authority(0);
      request.domain = domain;
      request.member = added;
      request.kind = MembershipKind::Direct;
      request.role = MembershipRole::Primary;
      request.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
      request.provenance = Rig::provenance_value();
      incremental = rig.registry.attach_member(request);
    });
    first.join();
    second.join();

    const std::string prefix = "round " + std::to_string(round) + ": ";
    FDR_CHECK_MSG(authoritative.committed(), prefix + "authoritative publication answered " +
                                                 describe(authoritative));
    FDR_CHECK_MSG(incremental.committed(),
                  prefix + "incremental attach answered " + describe(incremental));
    const std::vector<Membership> memberships = rig.registry.members_of(domain);
    FDR_CHECK_EQ(memberships.size(), std::size_t{2});
    for (const Membership& membership : memberships) {
      // Two serial orderings are legal: the added member is Current when the
      // publication ran first, and Retired when it ran second. Both are
      // deterministic and neither destroys a record.
      FDR_CHECK_MSG(one_of(membership.lifecycle,
                           {MembershipLifecycle::Current, MembershipLifecycle::Retired}),
                    prefix + "an unexpected membership lifecycle " +
                        std::string(to_string(membership.lifecycle)));
    }
    const std::vector<Membership> added_memberships = rig.registry.memberships_of(added);
    FDR_CHECK_EQ(added_memberships.size(), std::size_t{1});
    FDR_CHECK_MSG(one_of(added_memberships.front().lifecycle,
                         {MembershipLifecycle::Current, MembershipLifecycle::Retired}),
                  prefix + "the added membership reached an unexpected lifecycle");
    require_valid(rig.registry, prefix + "authoritative versus incremental");
  }
}

FDR_TEST_CASE(concurrency, persistence_save_versus_mutation) {
  Rig rig(2, 6u);
  const FailureDomainId domain = rig.make_domain(0, "dc1", "save-mutation");

  const std::string directory = fdrtest::make_temporary_directory("concurrency-persistence");
  FDR_CHECK_MSG(!directory.empty(), "the temporary directory could not be created");
  struct DirectoryGuard {
    std::string path;
    ~DirectoryGuard() { fdrtest::remove_directory(path); }
  } guard{directory};

  PersistenceConfig config;
  config.path = directory + "\\concurrent.fdr";

  run_race(
      16,
      [&](std::size_t round) {
        static_cast<void>(round);
        return rig.registry.save(config);
      },
      [&](std::size_t round) {
        AttachMemberRequest request;
        request.attempt = rig.next_attempt();
        request.authority = rig.authority(1);
        request.domain = domain;
        request.member = EntityRef(EntityClass::Switch, entity_bytes("save", round),
                                   EntityGeneration(1));
        request.kind = MembershipKind::Direct;
        request.role = MembershipRole::Primary;
        request.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
        request.provenance = Rig::provenance_value();
        return rig.registry.attach_member(request);
      },
      [&](std::size_t round, const Outcome& saved, const Outcome& attached) {
        FDR_CHECK_MSG(saved.committed(),
                      "round " + std::to_string(round) + ": save answered " + describe(saved));
        FDR_CHECK_MSG(one_of(attached.code, {OutcomeCode::Committed, OutcomeCode::Idempotent,
                                             OutcomeCode::ResourceLimit}),
                      "round " + std::to_string(round) + ": attach answered " +
                          describe(attached));
        // A saved image is always a consistent point-in-time state, and loading
        // it never produces an inconsistent registry.
        PersistenceConfig read_config = config;
        PersistenceReport report;
        const Outcome inspected = inspect_persistence(read_config, &report);
        FDR_CHECK_MSG(inspected.succeeded(),
                      "round " + std::to_string(round) + ": inspect answered " +
                          describe(inspected));
        FDR_CHECK_MSG(report.generation <= rig.registry.generation(),
                      "round " + std::to_string(round) +
                          ": a written image cannot be newer than the live registry");
        Registry image;
        const Outcome loaded = image.load(read_config);
        FDR_CHECK_MSG(loaded.succeeded(),
                      "round " + std::to_string(round) + ": load answered " + describe(loaded));
        // Registry::load() bumps the generation by one, so the recovered registry
        // sits exactly one generation above the generation the image recorded.
        FDR_CHECK_EQ(image.generation().value(), report.generation.value() + 1u);
        require_valid(image, "round " + std::to_string(round) + ": reloaded image");
      });
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
