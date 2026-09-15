// Failure Domain Registry — seeded randomized property proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A deterministic driver applies a seeded schedule of real mutations and real
// queries to one Registry and after EVERY operation asserts the invariants the
// contract promises:
//
//   * the registry generation never decreases, and every commit advances it;
//   * a request carrying a stale generation never commits;
//   * a terminal record is never resurrected;
//   * an exclusive domain class never holds two current domains for one member;
//   * the relation graph stays acyclic over every acyclic relation type;
//   * every maintained index still agrees with the record tables;
//   * an exact replay is Idempotent and does not advance the generation;
//   * the same seed always produces the same digest and the same canonical
//     snapshot form, and a save/load round trip preserves both.
//
// The seed is printed before the schedule runs and is repeated in every failure
// message, so any failure is reproducible by rerunning the same case.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "failure_domain_registry/failure_domain_registry.hpp"
#include "support/containment_probe.hpp"
#include "support/test_harness.hpp"
#include "support/test_process.hpp"

namespace {

using namespace failure_domain_registry;

// ---------------------------------------------------------------------------
// Deterministic identities and the fixture
// ---------------------------------------------------------------------------

template <class Id>
Id id_from(std::string_view label) {
  return Id::from_digest(sha256(label));
}

IdBytes entity_bytes(std::uint32_t index) {
  const DigestBytes digest = sha256("fdr/test/property/entity/" + std::to_string(index));
  IdBytes bytes{};
  for (std::size_t position = 0; position < bytes.size(); ++position) {
    bytes[position] = digest[position];
  }
  return bytes;
}

/// A directly constructed registry still owes authority to its callers: it has
/// to install a grant, establish an epoch and attach an incarnation before any
/// mutation is authorized.
struct Fixture {
  explicit Fixture(RegistryLimits limits_in = RegistryLimits::defaults())
      : registry(limits_in), limits(limits_in) {}

  Registry registry;
  RegistryLimits limits;
  PublisherId publisher;
  WorkerBootId boot;
  CoordinatorEpoch epoch;
  EvidenceClass evidence{EvidenceClass::DirectAuthoritativeInfrastructure};
};

void build_fixture(Fixture& fixture, std::uint64_t seed) {
  fixture.publisher =
      id_from<PublisherId>("fdr/test/property/publisher/" + std::to_string(seed));
  fixture.boot = id_from<WorkerBootId>("fdr/test/property/boot/" + std::to_string(seed));

  PublisherRegistration registration;
  registration.publisher = fixture.publisher;
  registration.name = "property-publisher";
  registration.scope = AuthorityScope::unrestricted();
  registration.scope.max_evidence = fixture.evidence;
  FDR_CHECK_EQ(fixture.registry.grant_publisher(registration, AuthorityContext{}).code,
               OutcomeCode::Committed);

  CoordinatorEpoch epoch;
  FDR_CHECK_EQ(fixture.registry.advance_epoch(CoordinatorEpoch(0), &epoch).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(epoch.value(), std::uint64_t{1});
  fixture.epoch = epoch;

  FDR_CHECK_EQ(fixture.registry
                   .attach_worker(fixture.publisher, fixture.boot, fixture.epoch, "property",
                                  fixture.evidence)
                   .code,
               OutcomeCode::Committed);
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

/// Every maintained index is recomputed from the record tables and compared.
void require_indexes_match(Registry& registry, const std::string& context) {
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), context + ": validate_state reported: " + why);

  const std::vector<FailureDomain> domains = registry.domains(1000000);
  FDR_CHECK_MSG(domains.size() == registry.domain_count(),
                context + ": the domain query disagrees with domain_count()");

  std::size_t memberships = 0;
  const MembershipLifecycle lifecycles[] = {
      MembershipLifecycle::Current,   MembershipLifecycle::RevalidationRequired,
      MembershipLifecycle::Superseded, MembershipLifecycle::Retired,
      MembershipLifecycle::Conflicted, MembershipLifecycle::Rejected};
  for (MembershipLifecycle lifecycle : lifecycles) {
    memberships += registry.memberships_in_lifecycle(lifecycle).size();
  }
  FDR_CHECK_MSG(memberships == registry.membership_count(),
                context + ": the lifecycle index disagrees with membership_count(): " +
                    std::to_string(memberships) + " vs " +
                    std::to_string(registry.membership_count()));

  for (const FailureDomain& domain : domains) {
    FDR_CHECK_MSG(domain.id == registry.domain(domain.id)->id,
                  context + ": a domain query result does not round trip");
    for (const Membership& membership : registry.members_of(domain.id)) {
      const std::optional<Membership> direct = registry.membership(membership.id);
      FDR_CHECK_MSG(direct.has_value(), context + ": a domain member is not in the table");
      FDR_CHECK_EQ(direct->domain, domain.id);
    }
  }

  // The containment ceiling bounds the true longest chain, measured here by an
  // independent topological pass over the graph read back from the public
  // relation query. A graph that is deeper than the ceiling, or that holds a
  // containment cycle, is a failure whatever any single mutation reported.
  const std::vector<fdrtest::ContainmentEdge> containment = fdrtest::containment_edges(registry);
  FDR_CHECK_MSG(!fdrtest::containment_graph_has_cycle(containment),
                context + ": the containment graph holds a cycle");
  const std::size_t deepest = fdrtest::max_containment_depth(containment);
  FDR_CHECK_MSG(deepest <= registry.limits().max_hierarchy_depth,
                context + ": the containment graph is " + std::to_string(deepest) +
                    " deep, beyond max_hierarchy_depth " +
                    std::to_string(registry.limits().max_hierarchy_depth));
}

/// No entity may hold two current memberships of the same exclusive class.
void require_exclusivity_holds(Registry& registry, const std::string& context) {
  std::map<std::string, std::size_t> counts;
  for (const Membership& membership :
       registry.memberships_in_lifecycle(MembershipLifecycle::Current)) {
    const std::optional<FailureDomain> domain = registry.domain(membership.domain);
    if (!domain.has_value() || !domain->domain_class.is_exclusive()) {
      continue;
    }
    const std::string key =
        membership.member.id().to_string() + "|" + domain->domain_class.to_string();
    const std::size_t seen = ++counts[key];
    FDR_CHECK_MSG(seen <= 1, context + ": entity " + membership.member.id().to_string() +
                                 " holds " + std::to_string(seen) +
                                 " current memberships of exclusive class " +
                                 domain->domain_class.to_string());
  }
}

/// No node may reach itself over an acyclic relation type.
void require_hierarchy_is_acyclic(Registry& registry, const std::string& context) {
  for (const FailureDomain& domain : registry.domains(1000000)) {
    for (const DomainRelation& relation : registry.relations_of(domain.id)) {
      if (!is_acyclic_relation(relation.type)) {
        continue;
      }
      FDR_CHECK_MSG(!(relation.source == relation.target),
                    context + ": a self relation exists");
    }
  }
  for (const FailureDomain& domain : registry.domains(1000000)) {
    std::vector<FailureDomainId> frontier{domain.id};
    std::vector<FailureDomainId> seen{domain.id};
    while (!frontier.empty()) {
      const FailureDomainId current = frontier.back();
      frontier.pop_back();
      for (const DomainRelation& relation : registry.relations_of(current)) {
        if (!is_acyclic_relation(relation.type) || relation.source != current) {
          continue;
        }
        FDR_CHECK_MSG(!(relation.target == domain.id),
                      context + ": a cycle exists over an acyclic relation type starting at " +
                          domain.id.to_string());
        bool known = false;
        for (const FailureDomainId& visited : seen) {
          if (visited == relation.target) {
            known = true;
            break;
          }
        }
        if (!known) {
          seen.push_back(relation.target);
          frontier.push_back(relation.target);
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// The randomized driver
// ---------------------------------------------------------------------------

struct Driver {
  Fixture& fixture;
  std::uint64_t seed{0};
  std::size_t step{0};
  std::uint64_t attempts{0};
  fdrtest::Rng rng;
  std::vector<FailureDomainId> domains;
  std::map<FailureDomainId, DomainLifecycle> terminal;
  std::vector<EntityRef> entities;
  std::vector<std::string> scopes;
  RegistryGeneration generation;
  std::size_t commits{0};

  explicit Driver(Fixture& fixture_in, std::uint64_t seed_in)
      : fixture(fixture_in), seed(seed_in), rng(seed_in) {
    scopes = {"dc1", "dc2"};
    for (std::uint32_t index = 0; index < 6; ++index) {
      entities.push_back(EntityRef(EntityClass::Switch, entity_bytes(index),
                                   EntityGeneration(1 + (index % 2))));
    }
    generation = fixture.registry.generation();
  }

  std::string describe(const std::string& what) const {
    return "seed=" + std::to_string(seed) + " step=" + std::to_string(step) + ": " + what;
  }

  MutationAttempt next_attempt() {
    ++attempts;
    const std::string canonical =
        "fdr/test/property/attempt/" + std::to_string(seed) + "/" + std::to_string(attempts);
    return MutationAttempt(MutationAttemptId::from_digest(sha256(canonical)), RequestDigest{});
  }

  AuthorityContext authority() const {
    AuthorityContext context;
    context.publisher = fixture.publisher;
    context.worker_boot = fixture.boot;
    context.epoch = fixture.epoch;
    context.evidence = fixture.evidence;
    return context;
  }

  Provenance provenance(std::uint32_t variant) const {
    Provenance value;
    value.source = ProvenanceSource::OperatorInventory;
    value.evidence = fixture.evidence;
    value.truth = TruthClass::Real;
    value.source_identity = "property/" + std::to_string(variant);
    return value;
  }

  static DomainClassRef random_class(fdrtest::Rng& rng) {
    const DomainClass classes[] = {
        DomainClass::Rack,       DomainClass::Row,        DomainClass::Pod,
        DomainClass::PowerFeed,  DomainClass::CoolingZone, DomainClass::Conduit,
        DomainClass::Pdu,        DomainClass::NetworkProvider};
    return DomainClassRef(classes[rng.below(sizeof(classes) / sizeof(classes[0]))]);
  }

  static MetadataEntry metadata_entry(std::uint32_t index) {
    MetadataEntry entry;
    entry.key = "k" + std::to_string(index);
    entry.value = "v" + std::to_string(index);
    return entry;
  }

  // --- requests ------------------------------------------------------------

  Outcome create_domain(std::uint32_t variant) {
    CreateDomainRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    request.domain_class = random_class(rng);
    request.administrative_scope = scopes[rng.below(scopes.size())];
    request.identity_key = "key-" + std::to_string(rng.below(4));
    request.name = "name-" + std::to_string(rng.below(3));
    request.provenance = provenance(variant % 3);
    request.activate = true;
    if (rng.chance(30)) {
      request.metadata.push_back(metadata_entry(static_cast<std::uint32_t>(rng.below(3))));
    }
    return fixture.registry.create_domain(request);
  }

  Outcome attach_member() {
    if (domains.empty()) {
      return Outcome::make(OutcomeCode::UnknownDomain, "no domain yet");
    }
    AttachMemberRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    request.domain = domains[rng.below(domains.size())];
    request.member = entities[rng.below(entities.size())];
    request.kind = MembershipKind::Direct;
    request.role = MembershipRole::Primary;
    request.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
    request.provenance = provenance(static_cast<std::uint32_t>(rng.below(3)));
    return fixture.registry.attach_member(request);
  }

  // --- the schedule --------------------------------------------------------

  Outcome perform(std::size_t operation);
  std::vector<Membership> current_memberships() const;
  void require_stale(const Outcome& outcome, RegistryGeneration expected);
  void check(const std::string& what, const Outcome& outcome);
};

Outcome Driver::perform(std::size_t operation) {
  const RegistryGeneration before = fixture.registry.generation();
  Outcome outcome = Outcome::make(OutcomeCode::Idempotent, "unused");

  if (operation < 20) {
    outcome = create_domain(static_cast<std::uint32_t>(operation));
    if (outcome.committed() && outcome.domain.has_value()) {
      bool known = false;
      for (const FailureDomainId& id : domains) {
        if (id == *outcome.domain) {
          known = true;
          break;
        }
      }
      if (!known) {
        domains.push_back(*outcome.domain);
      }
    }
  } else if (operation < 30 && !domains.empty()) {
    UpdateDomainRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    request.domain = domains[rng.below(domains.size())];
    const std::optional<FailureDomain> current = fixture.registry.domain(request.domain);
    if (!current.has_value()) {
      return Outcome::make(OutcomeCode::UnknownDomain, "the model is out of date");
    }
    request.expected_generation = current->generation;
    if (rng.chance(50)) {
      request.name = "renamed-" + std::to_string(rng.below(4));
    }
    if (rng.chance(30)) {
      request.replace_metadata = true;
      request.metadata.push_back(metadata_entry(static_cast<std::uint32_t>(rng.below(3))));
    }
    if (current->lifecycle == DomainLifecycle::Candidate) {
      request.transition = DomainLifecycle::Current;
    } else if (current->lifecycle == DomainLifecycle::Current && rng.chance(20)) {
      request.transition = DomainLifecycle::RevalidationRequired;
    }
    outcome = fixture.registry.update_domain(request);
  } else if (operation < 40) {
    outcome = attach_member();
  } else if (operation < 45) {
    const std::vector<Membership> members = current_memberships();
    if (members.empty()) {
      return Outcome::make(OutcomeCode::NotFound, "no current membership");
    }
    const Membership& chosen = members[rng.below(members.size())];
    DetachMemberRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    request.domain = chosen.domain;
    request.member = chosen.member;
    request.kind = chosen.kind;
    request.expected_membership_generation = chosen.generation;
    request.reason = "property detach";
    outcome = fixture.registry.detach_member(request);
  } else if (operation < 52) {
    const std::vector<Membership> members = current_memberships();
    if (members.empty()) {
      return Outcome::make(OutcomeCode::NotFound, "no current membership");
    }
    const Membership& chosen = members[rng.below(members.size())];
    ReplaceMembershipRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    request.membership = chosen.id;
    request.expected_generation = chosen.generation;
    request.role = rng.chance(50) ? MembershipRole::Redundant : MembershipRole::Backup;
    outcome = fixture.registry.replace_membership(request);
  } else if (operation < 57 && domains.size() >= 2) {
    SupersedeDomainRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    request.domain = domains[rng.below(domains.size())];
    request.successor = domains[rng.below(domains.size())];
    request.demote_memberships = rng.chance(70);
    outcome = fixture.registry.supersede_domain(request);
  } else if (operation < 61 && !domains.empty()) {
    RetireDomainRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    request.domain = domains[rng.below(domains.size())];
    request.reason = "property retire";
    request.retire_memberships = rng.chance(70);
    outcome = fixture.registry.retire_domain(request);
  } else if (operation < 69 && domains.size() >= 2) {
    AddRelationRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    request.source = domains[rng.below(domains.size())];
    request.target = domains[rng.below(domains.size())];
    const DomainRelationType types[] = {DomainRelationType::ContainedBy,
                                        DomainRelationType::DependsOn,
                                        DomainRelationType::CorrelatedWith,
                                        DomainRelationType::SharesRiskWith,
                                        DomainRelationType::PoweredBy};
    request.type = types[rng.below(sizeof(types) / sizeof(types[0]))];
    request.provenance = provenance(0);
    outcome = fixture.registry.add_relation(request);
  } else if (operation < 74) {
    DeclareCoverageRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    request.administrative_scope = scopes[rng.below(scopes.size())];
    request.domain_class = random_class(rng);
    request.state = rng.chance(50) ? CoverageState::Complete : CoverageState::Partial;
    request.provenance = provenance(0);
    outcome = fixture.registry.declare_coverage(request);
  } else if (operation < 79) {
    EntityInvalidationRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    request.entity = entities[rng.below(entities.size())].id();
    request.superseded_generation = entities[rng.below(entities.size())].generation();
    request.reason = "property invalidation";
    outcome = fixture.registry.invalidate_entity(request);
  } else if (operation < 83 && domains.size() >= 2) {
    MergeDomainsRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    request.survivor = domains[rng.below(domains.size())];
    request.absorbed = domains[rng.below(domains.size())];
    request.memberships_equivalent = rng.chance(50);
    request.reason = "property merge";
    outcome = fixture.registry.merge_domains(request);
  } else if (operation < 90 && !domains.empty()) {
    MembershipBatchRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    request.mode = rng.chance(25) ? PublicationMode::Authoritative : PublicationMode::Incremental;
    request.administrative_scope = scopes[rng.below(scopes.size())];
    request.authoritative_entity_class = EntityClass::Switch;
    MembershipBatchEntry entry;
    entry.domain = domains[rng.below(domains.size())];
    entry.member = entities[rng.below(entities.size())];
    entry.kind = MembershipKind::Direct;
    entry.role = MembershipRole::Primary;
    entry.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
    entry.provenance = provenance(static_cast<std::uint32_t>(rng.below(3)));
    request.entries.push_back(entry);
    if (request.mode == PublicationMode::Authoritative) {
      request.authoritative_domains.push_back(entry.domain);
    }
    outcome = fixture.registry.publish_memberships(request);
  } else if (operation < 93) {
    const std::vector<Membership> members = current_memberships();
    if (members.empty()) {
      return Outcome::make(OutcomeCode::NotFound, "no current membership");
    }
    const Membership& chosen = members[rng.below(members.size())];
    WithdrawEvidenceRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    request.membership = chosen.id;
    request.expected_generation = chosen.generation;
    request.reason = "property withdrawal";
    outcome = fixture.registry.withdraw_evidence(request);
  } else if (operation < 96) {
    const std::vector<Membership> members = current_memberships();
    if (members.empty()) {
      return Outcome::make(OutcomeCode::NotFound, "no current membership");
    }
    const Membership& chosen = members[rng.below(members.size())];
    ReconcileMembershipRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    request.domain = chosen.domain;
    request.member = chosen.member;
    request.kind = chosen.kind;
    outcome = fixture.registry.reconcile_membership(request);
  } else if (operation < 98 && !domains.empty()) {
    MarkRevalidationRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    request.domain = domains[rng.below(domains.size())];
    request.reason = "property revalidation demand";
    outcome = fixture.registry.mark_revalidation_required(request);
  } else if (operation == 98 && !domains.empty()) {
    // Stale domain generation: the expectation is deliberately wrong, so this
    // must never commit and must never change the state.
    UpdateDomainRequest request;
    request.attempt = next_attempt();
    request.authority = authority();
    // Only a non-terminal domain can reach the generation check: a closed one is
    // refused earlier with Retired or Superseded.
    FailureDomainId mutable_domain;
    bool found = false;
    for (const FailureDomainId& candidate : domains) {
      const std::optional<FailureDomain> record = fixture.registry.domain(candidate);
      if (record.has_value() && !record->is_terminal()) {
        mutable_domain = candidate;
        found = true;
        break;
      }
    }
    if (!found) {
      return Outcome::make(OutcomeCode::NotFound, "no domain can carry a stale expectation");
    }
    request.domain = mutable_domain;
    const std::optional<FailureDomain> current = fixture.registry.domain(request.domain);
    if (!current.has_value()) {
      return Outcome::make(OutcomeCode::UnknownDomain, "the model is out of date");
    }
    request.expected_generation =
        FailureDomainGeneration(current->generation.value() + 1000u);
    request.name = "stale";
    const Outcome stale = fixture.registry.update_domain(request);
    require_stale(stale, before);
    outcome = stale;
  } else {
    // Queries never mutate anything.
    const std::vector<EntityId> ids{entities[0].id(), entities[1].id()};
    const std::vector<DomainClassRef> classes{DomainClassRef(DomainClass::Rack)};
    static_cast<void>(fixture.registry.overlap(ids));
    static_cast<void>(fixture.registry.independence(ids, classes));
    for (const std::string& scope : scopes) {
      static_cast<void>(fixture.registry.coverage(scope, classes));
    }
    if (!domains.empty()) {
      static_cast<void>(fixture.registry.blast_radius(domains[rng.below(domains.size())]));
    }
    static_cast<void>(fixture.registry.correlate_member_sets(ids, ids, classes));
    const Snapshot snapshot = fixture.registry.snapshot("dc1");
    if (!fixture.registry.snapshot_is_current(snapshot) ||
        !(fixture.registry.generation() == before)) {
      ::fdrtest::fail(__FILE__, __LINE__, "a query changed the registry generation");
    }
    outcome = Outcome::make(OutcomeCode::Idempotent, "queries are pure");
  }
  return outcome;
}

std::vector<Membership> Driver::current_memberships() const {
  return fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current);
}

/// The stale-generation property is asserted here rather than inside perform()
/// because the harness macros abort a VOID function: they expand to a bare
/// return statement, which a function with a result cannot contain.
void Driver::require_stale(const Outcome& outcome, RegistryGeneration expected) {
  FDR_CHECK_EQ(outcome.code, OutcomeCode::StaleGeneration);
  FDR_CHECK_EQ(fixture.registry.generation(), expected);
}

void Driver::check(const std::string& what, const Outcome& outcome) {
  const RegistryGeneration now = fixture.registry.generation();
  FDR_CHECK_MSG(now >= generation,
                describe(what + ": the registry generation went backwards"));
  if (outcome.committed()) {
    ++commits;
    FDR_CHECK_MSG(now > generation,
                  describe(what + ": a committed mutation did not advance the generation"));
  } else if (outcome.code == OutcomeCode::DomainConflict ||
             outcome.code == OutcomeCode::MembershipConflict) {
    // A conflict is not a commit, but it is a state change: the record is marked
    // CONFLICTED and its own generation advances. Exactly one generation is
    // consumed, and only when the runtime recorded the conflict.
    FDR_CHECK_MSG(now == generation || now == RegistryGeneration(generation.value() + 1u),
                  describe(what + ": a conflict consumed more than one generation"));
  } else {
    FDR_CHECK_MSG(now == generation,
                  describe(what + ": a rejected operation advanced the generation (" +
                                      std::to_string(generation.value()) + " -> " +
                                      std::to_string(now.value()) + ")"));
  }
  generation = now;

  if (outcome.domain.has_value()) {
    const std::optional<FailureDomain> record = fixture.registry.domain(*outcome.domain);
    if (record.has_value() && record->is_terminal()) {
      terminal[record->id] = record->lifecycle;
    }
  }
  for (const std::pair<const FailureDomainId, DomainLifecycle>& entry : terminal) {
    const std::optional<FailureDomain> record = fixture.registry.domain(entry.first);
    FDR_CHECK_MSG(record.has_value(), describe(what + ": a terminal domain disappeared"));
    FDR_CHECK_MSG(record->lifecycle == entry.second,
                  describe(what + ": a terminal domain changed lifecycle from " +
                                      std::string(to_string(entry.second)) + " to " +
                                      std::string(to_string(record->lifecycle))));
    FDR_CHECK_MSG(record->is_terminal(),
                  describe(what + ": a terminal domain was resurrected"));
  }

  require_exclusivity_holds(fixture.registry, describe(what));
  require_hierarchy_is_acyclic(fixture.registry, describe(what));
  require_indexes_match(fixture.registry, describe(what));
}

/// Runs one full seeded schedule and reports what the registry settled on.
struct Serialization {
  StateDigest digest{};
  std::string snapshot_form;
  std::size_t domains{0};
  std::size_t memberships{0};
  std::size_t commits{0};
  bool consistent{false};
};

void run_schedule(Fixture& fixture, std::uint64_t seed, std::size_t steps, Serialization* out) {
  Driver driver(fixture, seed);
  std::printf("property: seed %llu, %zu steps\n",
              static_cast<unsigned long long>(seed), steps);
  for (std::size_t index = 0; index < steps; ++index) {
    driver.step = index;
    const std::size_t operation = static_cast<std::size_t>(driver.rng.below(100));
    const Outcome outcome = driver.perform(operation);
    driver.check("operation " + std::to_string(operation), outcome);
  }
  out->digest = fixture.registry.state_digest();
  out->snapshot_form = fixture.registry.snapshot("dc1").canonical_form();
  out->domains = fixture.registry.domain_count();
  out->memberships = fixture.registry.membership_count();
  out->commits = driver.commits;
  std::string why;
  out->consistent = fixture.registry.validate_state(&why);
  FDR_CHECK_MSG(out->consistent, "seed=" + std::to_string(seed) + ": " + why);
}

} // namespace

FDR_TEST_CASE(property, seeded_schedule_holds_every_invariant) {
  const std::uint64_t seeds[] = {1u, 7u, 12345u, 0x5eedu};
  for (std::uint64_t seed : seeds) {
    Fixture fixture;
    build_fixture(fixture, seed);
    Serialization result;
    run_schedule(fixture, seed, 260, &result);
    FDR_CHECK_MSG(result.commits > 0, "seed=" + std::to_string(seed) + ": nothing committed");
    FDR_CHECK_MSG(result.domains > 0, "seed=" + std::to_string(seed) + ": no domain survived");
    FDR_CHECK_MSG(result.memberships > 0,
                  "seed=" + std::to_string(seed) + ": no membership survived");
  }
}

FDR_TEST_CASE(property, a_stale_expectation_never_commits) {
  Fixture fixture;
  build_fixture(fixture, 99u);
  Driver driver(fixture, 99u);

  const Outcome created = driver.create_domain(0);
  FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
  FDR_CHECK_MSG(created.domain.has_value(), "a committed create names its domain");
  const std::optional<FailureDomain> domain = fixture.registry.domain(*created.domain);
  FDR_CHECK_MSG(domain.has_value(), "the created domain must exist");

  const RegistryGeneration before = fixture.registry.generation();

  UpdateDomainRequest update;
  update.attempt = driver.next_attempt();
  update.authority = driver.authority();
  update.domain = *created.domain;
  update.expected_generation = FailureDomainGeneration(domain->generation.value() + 1u);
  update.name = "stale";
  const Outcome stale_update = fixture.registry.update_domain(update);
  FDR_CHECK_EQ(stale_update.code, OutcomeCode::StaleGeneration);
  FDR_CHECK_MSG(stale_update.domain_generation.has_value(),
                "a stale rejection reports the current generation");
  FDR_CHECK_EQ(*stale_update.domain_generation, domain->generation);
  FDR_CHECK_EQ(fixture.registry.generation(), before);

  AttachMemberRequest attach;
  attach.attempt = driver.next_attempt();
  attach.authority = driver.authority();
  attach.domain = *created.domain;
  attach.expected_domain_generation = FailureDomainGeneration(domain->generation.value() + 5u);
  attach.member = driver.entities.front();
  attach.kind = MembershipKind::Direct;
  attach.provenance = driver.provenance(0);
  const Outcome stale_attach = fixture.registry.attach_member(attach);
  FDR_CHECK_EQ(stale_attach.code, OutcomeCode::StaleDomain);
  FDR_CHECK_EQ(fixture.registry.generation(), before);
  FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{0});

  AttachMemberRequest good = attach;
  good.attempt = driver.next_attempt();
  good.expected_domain_generation = domain->generation;
  const Outcome attached = fixture.registry.attach_member(good);
  FDR_CHECK_EQ(attached.code, OutcomeCode::Committed);
  FDR_CHECK_MSG(attached.membership.has_value(), "a committed attach names its membership");
  const std::optional<Membership> membership = fixture.registry.membership(*attached.membership);
  FDR_CHECK_MSG(membership.has_value(), "the attached membership must exist");

  const RegistryGeneration after_attach = fixture.registry.generation();
  DetachMemberRequest detach;
  detach.attempt = driver.next_attempt();
  detach.authority = driver.authority();
  detach.domain = membership->domain;
  detach.member = membership->member;
  detach.kind = membership->kind;
  detach.expected_membership_generation =
      MembershipGeneration(membership->generation.value() + 3u);
  const Outcome stale_detach = fixture.registry.detach_member(detach);
  FDR_CHECK_EQ(stale_detach.code, OutcomeCode::StaleMembership);
  FDR_CHECK_EQ(fixture.registry.generation(), after_attach);
  FDR_CHECK_EQ(fixture.registry.membership(*attached.membership)->lifecycle,
                MembershipLifecycle::Current);
}

FDR_TEST_CASE(property, an_exact_replay_is_idempotent_and_does_not_advance) {
  Fixture fixture;
  build_fixture(fixture, 4242u);
  Driver driver(fixture, 4242u);

  CreateDomainRequest create;
  create.attempt = driver.next_attempt();
  create.authority = driver.authority();
  create.domain_class = DomainClassRef(DomainClass::Rack);
  create.administrative_scope = "dc1";
  create.identity_key = "replay-rack";
  create.provenance = driver.provenance(0);
  const Outcome first = fixture.registry.create_domain(create);
  FDR_CHECK_EQ(first.code, OutcomeCode::Committed);

  const RegistryGeneration after_create = fixture.registry.generation();
  const Outcome replay = fixture.registry.create_domain(create);
  FDR_CHECK_EQ(replay.code, OutcomeCode::Idempotent);
  FDR_CHECK_EQ(fixture.registry.generation(), after_create);
  FDR_CHECK_MSG(replay.domain.has_value(), "a replay names the same domain");
  FDR_CHECK_EQ(*replay.domain, *first.domain);

  AttachMemberRequest attach;
  attach.attempt = driver.next_attempt();
  attach.authority = driver.authority();
  attach.domain = *first.domain;
  attach.member = driver.entities.front();
  attach.kind = MembershipKind::Direct;
  attach.role = MembershipRole::Primary;
  attach.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
  attach.provenance = driver.provenance(0);
  const Outcome attached = fixture.registry.attach_member(attach);
  FDR_CHECK_EQ(attached.code, OutcomeCode::Committed);

  const RegistryGeneration after_attach = fixture.registry.generation();
  const Outcome attach_replay = fixture.registry.attach_member(attach);
  FDR_CHECK_EQ(attach_replay.code, OutcomeCode::Idempotent);
  FDR_CHECK_EQ(fixture.registry.generation(), after_attach);
  FDR_CHECK_MSG(attach_replay.membership.has_value(), "the replay names the membership");
  FDR_CHECK_EQ(*attach_replay.membership, *attached.membership);
  FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{1});
}

FDR_TEST_CASE(property, the_same_seed_serialises_identically) {
  const std::uint64_t seed = 20260214u;
  Serialization first;
  Serialization second;
  {
    Fixture fixture;
    build_fixture(fixture, seed);
    run_schedule(fixture, seed, 200, &first);
  }
  {
    Fixture fixture;
    build_fixture(fixture, seed);
    run_schedule(fixture, seed, 200, &second);
  }
  FDR_CHECK_EQ(first.digest, second.digest);
  FDR_CHECK_EQ(first.snapshot_form, second.snapshot_form);
  FDR_CHECK_EQ(first.domains, second.domains);
  FDR_CHECK_EQ(first.memberships, second.memberships);
  FDR_CHECK_EQ(first.commits, second.commits);

  // A different seed must reach a different state, or the corpus proves nothing.
  Serialization other;
  {
    Fixture fixture;
    build_fixture(fixture, seed + 1u);
    run_schedule(fixture, seed + 1u, 200, &other);
  }
  FDR_CHECK_MSG(!(other.digest == first.digest),
                "two different seeds produced the same state digest");
}

FDR_TEST_CASE(property, persistence_round_trip_preserves_the_state) {
  const std::uint64_t seed = 555u;
  Fixture fixture;
  build_fixture(fixture, seed);
  Serialization result;
  run_schedule(fixture, seed, 200, &result);

  const std::string directory = fdrtest::make_temporary_directory("property-persistence");
  FDR_CHECK_MSG(!directory.empty(), "the temporary directory could not be created");
  struct DirectoryGuard {
    std::string path;
    ~DirectoryGuard() { fdrtest::remove_directory(path); }
  } guard{directory};

  PersistenceConfig config;
  config.path = directory + "\\property.fdr";
  const Outcome saved = fixture.registry.save(config);
  FDR_CHECK_MSG(saved.succeeded(), "the state could not be saved: " + saved.render());

  Fixture reloaded;
  build_fixture(reloaded, seed + 1000u);
  const Outcome loaded = reloaded.registry.load(config);
  FDR_CHECK_MSG(loaded.succeeded(), "the state could not be loaded: " + loaded.render());

  // A load is itself a state change: Registry::load() bumps the recovered
  // generation by exactly one, so the image records the generation it held.
  FDR_CHECK_EQ(reloaded.registry.generation().value(),
               fixture.registry.generation().value() + 1u);
  FDR_CHECK_EQ(reloaded.registry.domain_count(), fixture.registry.domain_count());
  FDR_CHECK_EQ(reloaded.registry.membership_count(), fixture.registry.membership_count());
  FDR_CHECK_EQ(reloaded.registry.state_digest(), fixture.registry.state_digest());
  const Snapshot persisted = fixture.registry.snapshot("dc1");
  const Snapshot reloaded_snapshot = reloaded.registry.snapshot("dc1");
  FDR_CHECK_EQ(persisted.domains, reloaded_snapshot.domains);
  FDR_CHECK_EQ(persisted.memberships, reloaded_snapshot.memberships);
  FDR_CHECK_EQ(persisted.epoch, reloaded_snapshot.epoch);
  // Snapshot::digest covers the snapshot canonical form, which includes the
  // registry generation; load() advances that generation by one, so the two
  // snapshot digests must differ even though every record is identical. The
  // semantic state digest asserted above is the one that is preserved.
  FDR_CHECK_MSG(!(persisted.digest == reloaded_snapshot.digest),
                "the snapshot digest covers the registry generation that load advances");

  std::string why;
  FDR_CHECK_MSG(reloaded.registry.validate_state(&why),
                "the reloaded registry is inconsistent: " + why);

  for (const FailureDomain& domain : fixture.registry.domains(1000000)) {
    const std::optional<FailureDomain> recovered = reloaded.registry.domain(domain.id);
    FDR_CHECK_MSG(recovered.has_value(), "a domain did not survive the round trip");
    FDR_CHECK_EQ(recovered->canonical_form(), domain.canonical_form());
  }
  for (const FailureDomain& domain : fixture.registry.domains(1000000)) {
    for (const Membership& membership : fixture.registry.members_of(domain.id)) {
      const std::optional<Membership> recovered = reloaded.registry.membership(membership.id);
      FDR_CHECK_MSG(recovered.has_value(), "a membership did not survive the round trip");
      FDR_CHECK_EQ(recovered->canonical_form(), membership.canonical_form());
    }
  }
}

FDR_TEST_CASE(property, the_hierarchy_ceiling_bounds_the_true_longest_chain) {
  // One randomized schedule of CONTAINED_BY attempts over a twelve-domain graph.
  // Every attempt is decided first by an independent model of the same graph
  // (support/containment_probe.hpp), and the registry's answer has to be the
  // model's answer:
  //   * the edge would close a cycle      -> CycleRejected;
  //   * the edge would exceed the ceiling -> InvalidHierarchy naming it, with
  //                                          nothing committed;
  //   * otherwise                         -> Committed or Idempotent.
  // require_indexes_match then re-measures the graph the registry actually holds
  // after every attempt, so a state deeper than the ceiling could not pass even
  // if a single answer were wrong.
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_hierarchy_depth = 4;
  limits.max_ancestor_walk = 128;
  FDR_CHECK_MSG(limits.validate().ok, limits.validate().message);

  const std::uint64_t seed = 20260915u;
  Fixture fixture(limits);
  build_fixture(fixture, seed);
  Driver driver(fixture, seed);

  const std::size_t kDomains = 12;
  const auto create_domains = [&](Registry& registry, Driver& creator) {
    std::vector<FailureDomainId> ids;
    for (std::size_t index = 0; index < kDomains; ++index) {
      CreateDomainRequest request;
      request.attempt = creator.next_attempt();
      request.authority = creator.authority();
      request.domain_class = DomainClassRef(DomainClass::Rack);
      request.administrative_scope = "dc1";
      request.identity_key = "depth-" + std::to_string(index);
      request.name = "depth-" + std::to_string(index);
      request.provenance = creator.provenance(0);
      const Outcome outcome = registry.create_domain(request);
      if (outcome.code != OutcomeCode::Committed || !outcome.domain.has_value()) {
        ::fdrtest::fail(__FILE__, __LINE__,
                        "depth domain " + std::to_string(index) + " was refused: " + outcome.message);
      }
      ids.push_back(*outcome.domain);
    }
    return ids;
  };
  const std::vector<FailureDomainId> ids = create_domains(fixture.registry, driver);

  fdrtest::Rng rng(seed ^ 0x9E3779B97F4A7C15ull);
  std::vector<std::pair<FailureDomainId, FailureDomainId>> committed;
  std::size_t ceiling_refusals = 0;
  for (std::size_t step = 0; step < 160; ++step) {
    const FailureDomainId source = ids[rng.below(ids.size())];
    const FailureDomainId target = ids[rng.below(ids.size())];
    if (source == target) {
      continue;
    }
    const std::vector<fdrtest::ContainmentEdge> before =
        fdrtest::containment_edges(fixture.registry);
    const bool closes_cycle = fdrtest::would_close_cycle(before, source, target);
    const std::size_t depth = fdrtest::depth_through(before, source, target);
    const RegistryGeneration generation = fixture.registry.generation();

    AddRelationRequest request;
    request.attempt = driver.next_attempt();
    request.authority = driver.authority();
    request.source = source;
    request.target = target;
    request.type = DomainRelationType::ContainedBy;
    request.provenance = driver.provenance(0);
    const Outcome outcome = fixture.registry.add_relation(request);

    const std::string context = "seed=" + std::to_string(seed) + " step=" + std::to_string(step);
    // The ceiling is measured before the acyclicity probe, so an edge that would
    // both deepen the hierarchy beyond the ceiling and close a cycle is answered
    // as over-deep; the model has to mirror that order to predict the answer.
    if (depth > limits.max_hierarchy_depth) {
      FDR_CHECK_MSG(outcome.code == OutcomeCode::InvalidHierarchy,
                    context + ": an edge " + std::to_string(depth) + " deep was answered " +
                        outcome.message);
      FDR_CHECK_MSG(outcome.message.find("max_hierarchy_depth") != std::string::npos,
                    context + ": the ceiling refusal did not name the ceiling: " + outcome.message);
      FDR_CHECK_MSG(fixture.registry.generation() == generation,
                    context + ": a refused over-deep edge advanced the generation");
      ++ceiling_refusals;
    } else if (closes_cycle) {
      FDR_CHECK_MSG(outcome.code == OutcomeCode::CycleRejected,
                    context + ": a closing edge was answered " + outcome.message);
    } else {
      FDR_CHECK_MSG(outcome.code == OutcomeCode::Committed ||
                        outcome.code == OutcomeCode::Idempotent,
                    context + ": a legal edge " + std::to_string(depth) + " deep was answered " +
                        outcome.message);
      if (outcome.code == OutcomeCode::Committed) {
        committed.emplace_back(source, target);
      }
    }
    require_indexes_match(fixture.registry, context);
  }
  FDR_CHECK_MSG(committed.size() >= 6,
                "the schedule committed only " + std::to_string(committed.size()) + " edges");
  FDR_CHECK_MSG(ceiling_refusals > 0, "the schedule never reached the ceiling");

  // Every chain the registry holds is fully walkable: the ceiling is below the
  // walk bound here, so no read may truncate.
  const std::vector<fdrtest::ContainmentEdge> graph = fdrtest::containment_edges(fixture.registry);
  FDR_CHECK_MSG(fdrtest::max_containment_depth(graph) >= 2,
                "the schedule never built a chain worth measuring");
  for (const FailureDomainId& id : ids) {
    FDR_CHECK_EQ(fixture.registry.ancestors(id).size(), fdrtest::reachable_count(graph, id, true));
    FDR_CHECK_EQ(fixture.registry.descendants(id).size(),
                 fdrtest::reachable_count(graph, id, false));
  }
  const StateDigest digest = fixture.registry.state_digest();

  // Order independence: the committed edge set inserted in the opposite order
  // reaches the same graph and the same state digest. A subset of an acyclic,
  // chain-compliant edge set is itself chain-compliant, so every insertion has
  // to be accepted.
  {
    Fixture replay(limits);
    build_fixture(replay, seed);
    Driver replay_driver(replay, seed ^ 0x51u);
    const std::vector<FailureDomainId> replay_ids = create_domains(replay.registry, replay_driver);
    FDR_CHECK_EQ(replay_ids, ids);
    for (auto it = committed.rbegin(); it != committed.rend(); ++it) {
      AddRelationRequest request;
      request.attempt = replay_driver.next_attempt();
      request.authority = replay_driver.authority();
      request.source = it->first;
      request.target = it->second;
      request.type = DomainRelationType::ContainedBy;
      request.provenance = replay_driver.provenance(0);
      const Outcome outcome = replay.registry.add_relation(request);
      FDR_CHECK_MSG(outcome.code == OutcomeCode::Committed,
                    "a replayed edge was refused: " + outcome.message);
    }
    const std::vector<fdrtest::ContainmentEdge> replay_graph =
        fdrtest::containment_edges(replay.registry);
    FDR_CHECK_EQ(replay_graph.size(), committed.size());
    FDR_CHECK_EQ(fdrtest::max_containment_depth(replay_graph),
                 fdrtest::max_containment_depth(graph));
    FDR_CHECK_EQ(replay.registry.state_digest(), digest);
  }
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
