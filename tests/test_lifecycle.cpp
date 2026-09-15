// Failure Domain Registry — lifecycle table and transition enforcement proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The lifecycle tables are the single source of truth for what a record may become. This
// file asserts them twice: once as pure tables — every listed edge accepted, every pair not
// listed rejected, all 8x8 domain and 7x7 membership combinations enumerated — and once
// through the real Registry, where a domain is walked over each listed edge with
// update_domain(transition=...) and every unlisted transition must come back
// OutcomeCode::IllegalTransition without moving a single byte of state.
//
// One implemented rule differs from the obvious reading of "an illegal transition is
// IllegalTransition": update_domain refuses a terminal record before it consults the table,
// so Retired -> Current and Superseded -> Current are refused with OutcomeCode::Retired and
// OutcomeCode::Superseded. The exact behaviour is asserted here, and the difference is
// named in the comment above the assertion.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "failure_domain_registry/authority.hpp"
#include "failure_domain_registry/domain.hpp"
#include "failure_domain_registry/errors.hpp"
#include "failure_domain_registry/ids.hpp"
#include "failure_domain_registry/lifecycle.hpp"
#include "failure_domain_registry/provenance.hpp"
#include "failure_domain_registry/registry.hpp"
#include "failure_domain_registry/requests.hpp"
#include "support/test_harness.hpp"

namespace {

using failure_domain_registry::AuthorityContext;
using failure_domain_registry::AuthorityScope;
using failure_domain_registry::CoordinatorEpoch;
using failure_domain_registry::CreateDomainRequest;
using failure_domain_registry::DomainClass;
using failure_domain_registry::DomainClassRef;
using failure_domain_registry::DomainLifecycle;
using failure_domain_registry::EvidenceClass;
using failure_domain_registry::FailureDomain;
using failure_domain_registry::FailureDomainGeneration;
using failure_domain_registry::FailureDomainId;
using failure_domain_registry::IdBytes;
using failure_domain_registry::MembershipLifecycle;
using failure_domain_registry::MembershipTransitionEdge;
using failure_domain_registry::MutationAttempt;
using failure_domain_registry::MutationAttemptId;
using failure_domain_registry::Outcome;
using failure_domain_registry::OutcomeCode;
using failure_domain_registry::Provenance;
using failure_domain_registry::ProvenanceSource;
using failure_domain_registry::PublisherId;
using failure_domain_registry::PublisherRegistration;
using failure_domain_registry::Registry;
using failure_domain_registry::RegistryGeneration;
using failure_domain_registry::RequestDigest;
using failure_domain_registry::TransitionEdge;
using failure_domain_registry::TruthClass;
using failure_domain_registry::UpdateDomainRequest;
using failure_domain_registry::WorkerBootId;

/// Number of enumerators in each lifecycle. Unknown is enumerator zero, so the
/// last enumerator's value plus one is the number of states.
constexpr std::size_t kDomainStates = static_cast<std::size_t>(DomainLifecycle::Rejected) + 1u;
constexpr std::size_t kMembershipStates = static_cast<std::size_t>(MembershipLifecycle::Rejected) + 1u;

/// One edge of the documented domain table.
struct DomainEdge {
  DomainLifecycle from;
  DomainLifecycle to;
};

/// One edge of the documented membership table.
struct MembershipEdge {
  MembershipLifecycle from;
  MembershipLifecycle to;
};

/// The complete domain transition table, in the exact order the library lists
/// it. The list is ordered and is compared element by element, so reordering it
/// is a change to the contract just like adding or removing an edge.
constexpr DomainEdge kDomainEdges[] = {
    {DomainLifecycle::Candidate, DomainLifecycle::Current},
    {DomainLifecycle::Candidate, DomainLifecycle::Rejected},
    {DomainLifecycle::Candidate, DomainLifecycle::Retired},
    {DomainLifecycle::Current, DomainLifecycle::RevalidationRequired},
    {DomainLifecycle::Current, DomainLifecycle::Superseded},
    {DomainLifecycle::Current, DomainLifecycle::Retired},
    {DomainLifecycle::Current, DomainLifecycle::Conflicted},
    {DomainLifecycle::RevalidationRequired, DomainLifecycle::Current},
    {DomainLifecycle::RevalidationRequired, DomainLifecycle::Superseded},
    {DomainLifecycle::RevalidationRequired, DomainLifecycle::Retired},
    {DomainLifecycle::RevalidationRequired, DomainLifecycle::Conflicted},
    {DomainLifecycle::Conflicted, DomainLifecycle::Current},
    {DomainLifecycle::Conflicted, DomainLifecycle::Retired},
    {DomainLifecycle::Conflicted, DomainLifecycle::Rejected},
};
constexpr std::size_t kDomainEdgeCount = 14;

/// The complete membership transition table, in the exact order the library
/// lists it.
constexpr MembershipEdge kMembershipEdges[] = {
    {MembershipLifecycle::Current, MembershipLifecycle::RevalidationRequired},
    {MembershipLifecycle::Current, MembershipLifecycle::Superseded},
    {MembershipLifecycle::Current, MembershipLifecycle::Retired},
    {MembershipLifecycle::Current, MembershipLifecycle::Conflicted},
    {MembershipLifecycle::RevalidationRequired, MembershipLifecycle::Current},
    {MembershipLifecycle::RevalidationRequired, MembershipLifecycle::Superseded},
    {MembershipLifecycle::RevalidationRequired, MembershipLifecycle::Retired},
    {MembershipLifecycle::RevalidationRequired, MembershipLifecycle::Conflicted},
    {MembershipLifecycle::Conflicted, MembershipLifecycle::Current},
    {MembershipLifecycle::Conflicted, MembershipLifecycle::Retired},
};
constexpr std::size_t kMembershipEdgeCount = 10;

/// The stable names of every domain lifecycle, in enumerator order.
constexpr std::string_view kDomainNames[kDomainStates] = {"UNKNOWN",  "CANDIDATE",  "CURRENT",
                                                          "REVALIDATION_REQUIRED", "SUPERSEDED",
                                                          "RETIRED",  "CONFLICTED", "REJECTED"};

/// The stable names of every membership lifecycle, in enumerator order.
constexpr std::string_view kMembershipNames[kMembershipStates] = {
    "UNKNOWN", "CURRENT", "REVALIDATION_REQUIRED", "SUPERSEDED", "RETIRED", "CONFLICTED", "REJECTED"};

/// True only for the state that carries classification authority.
constexpr bool kDomainCurrent[kDomainStates] = {false, false, true, false, false, false, false, false};
/// True only for the states that may never transition again.
constexpr bool kDomainTerminal[kDomainStates] = {false, false, false, false, true, true, false, true};
/// True only for the states that are neither current nor terminal.
constexpr bool kDomainIndeterminate[kDomainStates] = {false, false, false, true, false, false, true, false};

constexpr bool kMembershipCurrent[kMembershipStates] = {false, true, false, false, false, false, false};
constexpr bool kMembershipTerminal[kMembershipStates] = {false, false, false, true, true, false, true};
constexpr bool kMembershipIndeterminate[kMembershipStates] = {false, false, true, false, false, true, false};

std::string name_of(DomainLifecycle value) {
  return std::string(failure_domain_registry::to_string(value));
}

std::string name_of(MembershipLifecycle value) {
  return std::string(failure_domain_registry::to_string(value));
}

bool is_listed_domain_edge(DomainLifecycle from, DomainLifecycle to) {
  for (const DomainEdge& edge : kDomainEdges) {
    if (edge.from == from && edge.to == to) {
      return true;
    }
  }
  return false;
}

bool is_listed_membership_edge(MembershipLifecycle from, MembershipLifecycle to) {
  for (const MembershipEdge& edge : kMembershipEdges) {
    if (edge.from == from && edge.to == to) {
      return true;
    }
  }
  return false;
}


// ---------------------------------------------------------------------------
// A registry with one live bootstrap publisher incarnation.
// ---------------------------------------------------------------------------

/// The authority every mutation in this suite runs under.
struct Bootstrap {
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  CoordinatorEpoch epoch{};
  AuthorityContext authority{};
};

IdBytes salted_bytes(std::uint8_t tag, std::uint8_t salt) {
  IdBytes out{};
  out[0] = tag;
  out[failure_domain_registry::kOpaqueIdBytes - 1u] = salt;
  return out;
}

MutationAttempt attempt_from(std::uint8_t salt) {
  return MutationAttempt(MutationAttemptId::from_bytes(salted_bytes(0xABu, salt)), RequestDigest{});
}

/// Fails the running case unless the operation committed, reporting the rendered
/// outcome. Preparing the fixture is not behaviour under test, so a registry that
/// cannot be prepared is reported at the line that could not prepare it.
void require_commit(const Outcome& outcome) {
  FDR_CHECK_MSG(outcome.committed(), outcome.render());
}

/// Installs the bootstrap publisher, establishes epoch one and attaches one live
/// incarnation. A freshly constructed registry has epoch zero and no session, so
/// every mutation without these three steps is refused as NO_AUTHORITY or
/// STALE_EPOCH before it ever reaches the lifecycle machine.
Bootstrap bootstrap(Registry& registry, std::uint8_t salt) {
  Bootstrap result;
  result.publisher = PublisherId::from_bytes(salted_bytes(0xD1u, salt));
  result.worker_boot = WorkerBootId::from_bytes(salted_bytes(0xD2u, salt));

  PublisherRegistration registration;
  registration.publisher = result.publisher;
  registration.name = "lifecycle-bootstrap";
  registration.scope = AuthorityScope::unrestricted();
  require_commit(registry.grant_publisher(registration, AuthorityContext{}));

  CoordinatorEpoch established{};
  require_commit(registry.advance_epoch(CoordinatorEpoch{}, &established));
  result.epoch = established;
  require_commit(registry.attach_worker(result.publisher, result.worker_boot, result.epoch,
                                       "lifecycle-test",
                                       EvidenceClass::DirectAuthoritativeInfrastructure));

  result.authority.publisher = result.publisher;
  result.authority.worker_boot = result.worker_boot;
  result.authority.epoch = result.epoch;
  result.authority.evidence = EvidenceClass::DirectAuthoritativeInfrastructure;
  return result;
}

/// Registry is neither copyable nor movable, so the fixture owns it directly and
/// performs the bootstrap in its constructor.
struct Fixture {
  Registry registry;
  Bootstrap owner;
  std::uint8_t next_salt{1};

  Fixture();
};

Fixture::Fixture() { owner = bootstrap(registry, 0x51u); }


Provenance authoritative_provenance() {
  Provenance provenance;
  provenance.source = ProvenanceSource::PhysicalInfrastructure;
  provenance.evidence = EvidenceClass::DirectAuthoritativeInfrastructure;
  provenance.truth = TruthClass::Real;
  provenance.source_identity = "test/plant-inventory";
  return provenance;
}

/// The identity of one domain together with the generation and lifecycle the
/// registry currently holds for it.
struct DomainHandle {
  FailureDomainId id{};
  FailureDomainGeneration generation{};
  DomainLifecycle lifecycle{DomainLifecycle::Unknown};
};

DomainHandle handle_of(const FailureDomain& record) {
  DomainHandle handle;
  handle.id = record.id;
  handle.generation = record.generation;
  handle.lifecycle = record.lifecycle;
  return handle;
}

/// A domain created as a Candidate. A candidate never participates in overlap or
/// independence answers, so every walk below starts from the weakest state.
Outcome create_candidate(Fixture& fixture, const std::string& identity_key) {
  CreateDomainRequest request;
  request.attempt = attempt_from(fixture.next_salt++);
  request.authority = fixture.owner.authority;
  request.domain_class = DomainClassRef(DomainClass::Rack);
  request.administrative_scope = "dc1";
  request.identity_key = identity_key;
  request.name = identity_key;
  request.provenance = authoritative_provenance();
  request.activate = false;
  return fixture.registry.create_domain(request);
}

Outcome apply_transition(Fixture& fixture, const DomainHandle& handle, DomainLifecycle target) {
  UpdateDomainRequest request;
  request.attempt = attempt_from(fixture.next_salt++);
  request.authority = fixture.owner.authority;
  request.domain = handle.id;
  request.expected_generation = handle.generation;
  request.transition = target;
  return fixture.registry.update_domain(request);
}

/// One deterministic legal path from Candidate to the target state, read off the
/// table: Candidate reaches Current directly, the indeterminate states through
/// Current, and each terminal state over its own listed edge.
std::vector<DomainLifecycle> path_to(DomainLifecycle target) {
  switch (target) {
    case DomainLifecycle::Candidate:
      return {};
    case DomainLifecycle::Current:
      return {DomainLifecycle::Current};
    case DomainLifecycle::RevalidationRequired:
      return {DomainLifecycle::Current, DomainLifecycle::RevalidationRequired};
    case DomainLifecycle::Conflicted:
      return {DomainLifecycle::Current, DomainLifecycle::Conflicted};
    case DomainLifecycle::Superseded:
      return {DomainLifecycle::Current, DomainLifecycle::Superseded};
    case DomainLifecycle::Retired:
      return {DomainLifecycle::Retired};
    case DomainLifecycle::Rejected:
      return {DomainLifecycle::Rejected};
    case DomainLifecycle::Unknown:
      return {};
  }
  return {};
}

/// Creates one domain and walks it to the requested state over listed edges,
/// asserting every step, so a case that cannot reach its starting state fails
/// where the walk broke instead of silently testing nothing.
void reach(Fixture& fixture, const std::string& identity_key, DomainLifecycle target, DomainHandle& out) {
  const Outcome created = create_candidate(fixture, identity_key);
  FDR_CHECK_MSG(created.committed(), created.render());
  FDR_CHECK(created.domain.has_value());
  const std::optional<FailureDomain> record = fixture.registry.domain(*created.domain);
  FDR_CHECK_MSG(record.has_value(), "the created domain is not readable back");
  DomainHandle handle = handle_of(*record);
  FDR_CHECK_EQ(handle.lifecycle, DomainLifecycle::Candidate);
  FDR_CHECK_EQ(handle.generation.value(), std::uint64_t{1});

  for (DomainLifecycle step : path_to(target)) {
    const Outcome outcome = apply_transition(fixture, handle, step);
    FDR_CHECK_MSG(outcome.committed(), outcome.render());
    const std::optional<FailureDomain> stepped = fixture.registry.domain(handle.id);
    FDR_CHECK_MSG(stepped.has_value(), "the walked domain is not readable back");
    FDR_CHECK_EQ(stepped->lifecycle, step);
    handle = handle_of(*stepped);
  }
  FDR_CHECK_EQ(handle.lifecycle, target);
  out = handle;
}


// ---------------------------------------------------------------------------
// The tables as pure functions
// ---------------------------------------------------------------------------

FDR_TEST_CASE(lifecycle, domain_transition_table_is_the_ordered_contract) {
  static_assert(kDomainStates == 8, "the domain lifecycle has eight enumerators");

  std::size_t count = 0;
  const TransitionEdge* table = failure_domain_registry::domain_transition_table(count);
  FDR_CHECK(table != nullptr);
  FDR_CHECK_EQ(count, kDomainEdgeCount);
  for (std::size_t index = 0; index < count; ++index) {
    FDR_CHECK_EQ(table[index].from, kDomainEdges[index].from);
    FDR_CHECK_EQ(table[index].to, kDomainEdges[index].to);
    FDR_CHECK(failure_domain_registry::is_legal_domain_transition(table[index].from, table[index].to));
    // A listed edge appears exactly once.
    for (std::size_t other = index + 1u; other < count; ++other) {
      FDR_CHECK(!(table[index].from == table[other].from && table[index].to == table[other].to));
    }
    // A state is never its own successor.
    FDR_CHECK(!(table[index].from == table[index].to));
  }

  // The list is static and ordered: a second call returns the same pointer and
  // the same count, whatever the caller does with it.
  std::size_t again = 0;
  const TransitionEdge* second = failure_domain_registry::domain_transition_table(again);
  FDR_CHECK_EQ(again, count);
  FDR_CHECK(second == table);
}

FDR_TEST_CASE(lifecycle, membership_transition_table_is_the_ordered_contract) {
  static_assert(kMembershipStates == 7, "the membership lifecycle has seven enumerators");

  std::size_t count = 0;
  const MembershipTransitionEdge* table = failure_domain_registry::membership_transition_table(count);
  FDR_CHECK(table != nullptr);
  FDR_CHECK_EQ(count, kMembershipEdgeCount);
  for (std::size_t index = 0; index < count; ++index) {
    FDR_CHECK_EQ(table[index].from, kMembershipEdges[index].from);
    FDR_CHECK_EQ(table[index].to, kMembershipEdges[index].to);
    FDR_CHECK(failure_domain_registry::is_legal_membership_transition(table[index].from, table[index].to));
    for (std::size_t other = index + 1u; other < count; ++other) {
      FDR_CHECK(!(table[index].from == table[other].from && table[index].to == table[other].to));
    }
    FDR_CHECK(!(table[index].from == table[index].to));
  }

  std::size_t again = 0;
  const MembershipTransitionEdge* second = failure_domain_registry::membership_transition_table(again);
  FDR_CHECK_EQ(again, count);
  FDR_CHECK(second == table);
}

FDR_TEST_CASE(lifecycle, transition_tables_admit_exactly_the_listed_pairs) {
  // All 64 domain pairs and all 49 membership pairs are enumerated: a transition
  // is legal exactly when the table lists it, so no extra edge can hide anywhere.
  std::size_t accepted = 0;
  for (std::size_t from_raw = 0; from_raw < kDomainStates; ++from_raw) {
    for (std::size_t to_raw = 0; to_raw < kDomainStates; ++to_raw) {
      const DomainLifecycle from = static_cast<DomainLifecycle>(from_raw);
      const DomainLifecycle to = static_cast<DomainLifecycle>(to_raw);
      const bool expected = is_listed_domain_edge(from, to);
      FDR_CHECK_MSG(failure_domain_registry::is_legal_domain_transition(from, to) == expected,
                   "domain transition " + name_of(from) + " -> " + name_of(to) + " disagrees with the table");
      if (expected) {
        ++accepted;
      }
    }
  }
  FDR_CHECK_EQ(accepted, kDomainEdgeCount);

  std::size_t membership_accepted = 0;
  for (std::size_t from_raw = 0; from_raw < kMembershipStates; ++from_raw) {
    for (std::size_t to_raw = 0; to_raw < kMembershipStates; ++to_raw) {
      const MembershipLifecycle from = static_cast<MembershipLifecycle>(from_raw);
      const MembershipLifecycle to = static_cast<MembershipLifecycle>(to_raw);
      const bool expected = is_listed_membership_edge(from, to);
      FDR_CHECK_MSG(failure_domain_registry::is_legal_membership_transition(from, to) == expected,
                   "membership transition " + name_of(from) + " -> " + name_of(to) +
                       " disagrees with the table");
      if (expected) {
        ++membership_accepted;
      }
    }
  }
  FDR_CHECK_EQ(membership_accepted, kMembershipEdgeCount);
}


FDR_TEST_CASE(lifecycle, terminal_states_have_no_exit_and_others_do) {
  std::size_t terminal_count = 0;
  for (std::size_t from_raw = 0; from_raw < kDomainStates; ++from_raw) {
    const DomainLifecycle from = static_cast<DomainLifecycle>(from_raw);
    std::size_t exits = 0;
    for (std::size_t to_raw = 0; to_raw < kDomainStates; ++to_raw) {
      if (failure_domain_registry::is_legal_domain_transition(from,
                                                              static_cast<DomainLifecycle>(to_raw))) {
        ++exits;
      }
    }
    if (failure_domain_registry::is_terminal(from)) {
      // A terminal record may never transition again: not even to itself.
      FDR_CHECK_MSG(exits == 0u, "terminal state has a legal successor: " + name_of(from));
      ++terminal_count;
    } else if (failure_domain_registry::is_valid_domain_lifecycle(from)) {
      // Every reachable state can leave; a state with no exit would be a trap
      // that is neither current, terminal nor indeterminate.
      FDR_CHECK_MSG(exits > 0u, "non-terminal state has no legal successor: " + name_of(from));
    }
  }
  FDR_CHECK_EQ(terminal_count, std::size_t{3});

  // Unknown is a sentinel rather than a state: it is not terminal and it has no
  // exit either, because no record is ever stored in it.
  FDR_CHECK(!failure_domain_registry::is_terminal(DomainLifecycle::Unknown));
  FDR_CHECK(!failure_domain_registry::is_valid_domain_lifecycle(DomainLifecycle::Unknown));

  std::size_t membership_terminal_count = 0;
  for (std::size_t from_raw = 0; from_raw < kMembershipStates; ++from_raw) {
    const MembershipLifecycle from = static_cast<MembershipLifecycle>(from_raw);
    std::size_t exits = 0;
    for (std::size_t to_raw = 0; to_raw < kMembershipStates; ++to_raw) {
      if (failure_domain_registry::is_legal_membership_transition(
              from, static_cast<MembershipLifecycle>(to_raw))) {
        ++exits;
      }
    }
    if (failure_domain_registry::is_terminal(from)) {
      FDR_CHECK_MSG(exits == 0u, "terminal membership state has a legal successor: " + name_of(from));
      ++membership_terminal_count;
    } else if (failure_domain_registry::is_valid_membership_lifecycle(from)) {
      FDR_CHECK_MSG(exits > 0u, "non-terminal membership state has no legal successor: " + name_of(from));
    }
  }
  FDR_CHECK_EQ(membership_terminal_count, std::size_t{3});
  FDR_CHECK(!failure_domain_registry::is_terminal(MembershipLifecycle::Unknown));
}

FDR_TEST_CASE(lifecycle, self_transitions_are_never_legal) {
  // Implementing the rule exactly: no state is its own successor in either
  // table, including Unknown.
  for (std::size_t raw = 0; raw < kDomainStates; ++raw) {
    const DomainLifecycle value = static_cast<DomainLifecycle>(raw);
    FDR_CHECK(!failure_domain_registry::is_legal_domain_transition(value, value));
  }
  for (std::size_t raw = 0; raw < kMembershipStates; ++raw) {
    const MembershipLifecycle value = static_cast<MembershipLifecycle>(raw);
    FDR_CHECK(!failure_domain_registry::is_legal_membership_transition(value, value));
  }
  for (const DomainEdge& edge : kDomainEdges) {
    FDR_CHECK(!(edge.from == edge.to));
  }
  for (const MembershipEdge& edge : kMembershipEdges) {
    FDR_CHECK(!(edge.from == edge.to));
  }
}


FDR_TEST_CASE(lifecycle, classifications_partition_the_enumerations) {
  std::size_t current_count = 0;
  std::size_t terminal_count = 0;
  std::size_t indeterminate_count = 0;
  for (std::size_t raw = 0; raw < kDomainStates; ++raw) {
    const DomainLifecycle value = static_cast<DomainLifecycle>(raw);
    const bool current = failure_domain_registry::is_current(value);
    const bool terminal = failure_domain_registry::is_terminal(value);
    const bool indeterminate = failure_domain_registry::is_indeterminate(value);
    FDR_CHECK_EQ(current, kDomainCurrent[raw]);
    FDR_CHECK_EQ(terminal, kDomainTerminal[raw]);
    FDR_CHECK_EQ(indeterminate, kDomainIndeterminate[raw]);

    const int flags = (current ? 1 : 0) + (terminal ? 1 : 0) + (indeterminate ? 1 : 0);
    // No state belongs to two of the three classes at once.
    FDR_CHECK_MSG(flags <= 1, "state is in more than one class: " + name_of(value));
    if (value == DomainLifecycle::Candidate || value == DomainLifecycle::Unknown) {
      // Candidate and Unknown are in none of them: a candidate carries no
      // authority, is not indeterminate and is not terminal, so the three
      // predicates do not partition the enumeration.
      FDR_CHECK_EQ(flags, 0);
    } else {
      FDR_CHECK_MSG(flags == 1, "state is in no class: " + name_of(value));
    }
    if (current) {
      ++current_count;
    }
    if (terminal) {
      ++terminal_count;
    }
    if (indeterminate) {
      ++indeterminate_count;
    }
  }
  FDR_CHECK_EQ(current_count, std::size_t{1});
  FDR_CHECK_EQ(terminal_count, std::size_t{3});
  FDR_CHECK_EQ(indeterminate_count, std::size_t{2});

  std::size_t membership_current = 0;
  std::size_t membership_terminal = 0;
  std::size_t membership_indeterminate = 0;
  for (std::size_t raw = 0; raw < kMembershipStates; ++raw) {
    const MembershipLifecycle value = static_cast<MembershipLifecycle>(raw);
    const bool current = failure_domain_registry::is_current(value);
    const bool terminal = failure_domain_registry::is_terminal(value);
    const bool indeterminate = failure_domain_registry::is_indeterminate(value);
    FDR_CHECK_EQ(current, kMembershipCurrent[raw]);
    FDR_CHECK_EQ(terminal, kMembershipTerminal[raw]);
    FDR_CHECK_EQ(indeterminate, kMembershipIndeterminate[raw]);

    const int flags = (current ? 1 : 0) + (terminal ? 1 : 0) + (indeterminate ? 1 : 0);
    if (failure_domain_registry::is_valid_membership_lifecycle(value)) {
      FDR_CHECK_MSG(flags == 1, "membership state is not in exactly one class: " + name_of(value));
    } else {
      FDR_CHECK_EQ(flags, 0);
    }
    if (current) {
      ++membership_current;
    }
    if (terminal) {
      ++membership_terminal;
    }
    if (indeterminate) {
      ++membership_indeterminate;
    }
  }
  FDR_CHECK_EQ(membership_current, std::size_t{1});
  FDR_CHECK_EQ(membership_terminal, std::size_t{3});
  FDR_CHECK_EQ(membership_indeterminate, std::size_t{2});

  // The semantics behind the flags, stated one state at a time.
  FDR_CHECK(failure_domain_registry::is_current(DomainLifecycle::Current));
  FDR_CHECK(failure_domain_registry::is_terminal(DomainLifecycle::Retired));
  FDR_CHECK(failure_domain_registry::is_terminal(DomainLifecycle::Superseded));
  FDR_CHECK(failure_domain_registry::is_terminal(DomainLifecycle::Rejected));
  FDR_CHECK(failure_domain_registry::is_indeterminate(DomainLifecycle::RevalidationRequired));
  FDR_CHECK(failure_domain_registry::is_indeterminate(DomainLifecycle::Conflicted));
  FDR_CHECK(!failure_domain_registry::is_current(DomainLifecycle::Candidate));
  FDR_CHECK(!failure_domain_registry::is_terminal(DomainLifecycle::Conflicted));
  FDR_CHECK(!failure_domain_registry::is_indeterminate(DomainLifecycle::Superseded));
  FDR_CHECK(failure_domain_registry::is_current(MembershipLifecycle::Current));
  FDR_CHECK(failure_domain_registry::is_terminal(MembershipLifecycle::Rejected));
  FDR_CHECK(failure_domain_registry::is_indeterminate(MembershipLifecycle::Conflicted));
}


FDR_TEST_CASE(lifecycle, validity_over_the_whole_byte_range) {
  const std::uint16_t domain_last = static_cast<std::uint16_t>(DomainLifecycle::Rejected);
  const std::uint16_t membership_last = static_cast<std::uint16_t>(MembershipLifecycle::Rejected);
  std::size_t domain_valid = 0;
  std::size_t membership_valid = 0;
  for (std::uint16_t raw = 0; raw <= 255u; ++raw) {
    const DomainLifecycle domain = static_cast<DomainLifecycle>(raw);
    const bool domain_expected = raw >= 1u && raw <= domain_last;
    FDR_CHECK_EQ(failure_domain_registry::is_valid_domain_lifecycle(domain), domain_expected);
    if (domain_expected) {
      FDR_CHECK(!name_of(domain).empty());
      FDR_CHECK(!(name_of(domain) == std::string("UNKNOWN")));
      ++domain_valid;
    } else {
      FDR_CHECK_EQ(failure_domain_registry::to_string(domain), std::string_view("UNKNOWN"));
    }

    const MembershipLifecycle membership = static_cast<MembershipLifecycle>(raw);
    const bool membership_expected = raw >= 1u && raw <= membership_last;
    FDR_CHECK_EQ(failure_domain_registry::is_valid_membership_lifecycle(membership), membership_expected);
    if (membership_expected) {
      FDR_CHECK(!name_of(membership).empty());
      FDR_CHECK(!(name_of(membership) == std::string("UNKNOWN")));
      ++membership_valid;
    } else {
      FDR_CHECK_EQ(failure_domain_registry::to_string(membership), std::string_view("UNKNOWN"));
    }
  }
  FDR_CHECK_EQ(domain_valid, kDomainStates - 1u);
  FDR_CHECK_EQ(membership_valid, kMembershipStates - 1u);
}

FDR_TEST_CASE(lifecycle, names_are_non_empty_unique_and_deterministic) {
  std::set<std::string_view> domain_names;
  for (std::size_t raw = 0; raw < kDomainStates; ++raw) {
    const DomainLifecycle value = static_cast<DomainLifecycle>(raw);
    const std::string_view name = failure_domain_registry::to_string(value);
    FDR_CHECK(!name.empty());
    FDR_CHECK_EQ(name, kDomainNames[raw]);
    // Deterministic across calls: the rendering is a constant, not a function of
    // any state.
    FDR_CHECK_EQ(failure_domain_registry::to_string(value), name);
    FDR_CHECK_MSG(domain_names.insert(name).second, "duplicate domain lifecycle name: " + std::string(name));
  }
  FDR_CHECK_EQ(domain_names.size(), kDomainStates);
  FDR_CHECK_EQ(failure_domain_registry::to_string(static_cast<DomainLifecycle>(200)), std::string_view("UNKNOWN"));

  std::set<std::string_view> membership_names;
  for (std::size_t raw = 0; raw < kMembershipStates; ++raw) {
    const MembershipLifecycle value = static_cast<MembershipLifecycle>(raw);
    const std::string_view name = failure_domain_registry::to_string(value);
    FDR_CHECK(!name.empty());
    FDR_CHECK_EQ(name, kMembershipNames[raw]);
    FDR_CHECK_EQ(failure_domain_registry::to_string(value), name);
    FDR_CHECK_MSG(membership_names.insert(name).second,
                 "duplicate membership lifecycle name: " + std::string(name));
  }
  FDR_CHECK_EQ(membership_names.size(), kMembershipStates);
  FDR_CHECK_EQ(failure_domain_registry::to_string(static_cast<MembershipLifecycle>(200)),
              std::string_view("UNKNOWN"));
}


// ---------------------------------------------------------------------------
// The tables through the real registry
// ---------------------------------------------------------------------------

FDR_TEST_CASE(lifecycle, registry_applies_exactly_the_listed_domain_transitions) {
  Fixture fixture;
  const DomainLifecycle sources[] = {DomainLifecycle::Candidate, DomainLifecycle::Current,
                                     DomainLifecycle::RevalidationRequired, DomainLifecycle::Conflicted};
  std::size_t committed = 0;
  std::size_t refused = 0;
  std::size_t idempotent = 0;

  for (DomainLifecycle from : sources) {
    for (std::size_t to_raw = 0; to_raw < kDomainStates; ++to_raw) {
      const DomainLifecycle to = static_cast<DomainLifecycle>(to_raw);
      const std::string key = "edge-" + name_of(from) + "-" + std::to_string(to_raw);
      DomainHandle handle;
      reach(fixture, key, from, handle);
      FDR_CHECK_EQ(handle.lifecycle, from);

      const std::size_t domains_before = fixture.registry.domain_count();
      const RegistryGeneration registry_before = fixture.registry.generation();
      const Outcome outcome = apply_transition(fixture, handle, to);
      const std::optional<FailureDomain> record = fixture.registry.domain(handle.id);
      FDR_CHECK_MSG(record.has_value(), "the domain disappeared during the transition");
      FDR_CHECK_EQ(fixture.registry.domain_count(), domains_before);

      if (to == from) {
        // Asking for the state a record already holds is not a transition: the
        // registry reports the request as already satisfied and changes nothing,
        // not even a generation.
        FDR_CHECK_MSG(outcome.code == OutcomeCode::Idempotent, outcome.render());
        FDR_CHECK_EQ(record->lifecycle, from);
        FDR_CHECK_EQ(record->generation, handle.generation);
        FDR_CHECK_EQ(fixture.registry.generation(), registry_before);
        ++idempotent;
      } else if (is_listed_domain_edge(from, to)) {
        FDR_CHECK_MSG(outcome.committed(), outcome.render());
        FDR_CHECK_EQ(outcome.code, OutcomeCode::Committed);
        FDR_CHECK_EQ(record->lifecycle, to);
        FDR_CHECK_EQ(record->generation.value(), handle.generation.value() + 1u);
        FDR_CHECK_EQ(fixture.registry.generation().value(), registry_before.value() + 1u);
        ++committed;
      } else {
        // An unlisted target is refused with the transition code, never with a
        // generic failure, and the record is left exactly as it was.
        FDR_CHECK_MSG(outcome.code == OutcomeCode::IllegalTransition, outcome.render());
        FDR_CHECK_EQ(outcome.code, OutcomeCode::IllegalTransition);
        FDR_CHECK(!outcome.succeeded());
        FDR_CHECK_EQ(record->lifecycle, from);
        FDR_CHECK_EQ(record->generation, handle.generation);
        FDR_CHECK_EQ(fixture.registry.generation(), registry_before);
        ++refused;
      }
    }
  }

  // 4 non-terminal states x 8 targets: 14 listed edges, 4 no-op requests and the
  // remaining 14 pairs illegal. The unknown target is illegal too: a transition
  // target is checked against the table only, and Unknown is not a state there.
  FDR_CHECK_EQ(committed, kDomainEdgeCount);
  FDR_CHECK_EQ(refused, std::size_t{14});
  FDR_CHECK_EQ(idempotent, std::size_t{4});

  std::string why;
  FDR_CHECK_MSG(fixture.registry.validate_state(&why), why);
}


FDR_TEST_CASE(lifecycle, candidate_revalidates_back_to_current) {
  Fixture fixture;
  DomainHandle handle;
  reach(fixture, "revalidation-path", DomainLifecycle::Candidate, handle);
  FDR_CHECK_EQ(handle.lifecycle, DomainLifecycle::Candidate);
  FDR_CHECK_EQ(handle.generation.value(), std::uint64_t{1});

  // Candidate -> Current: the record starts carrying authority.
  const Outcome promoted = apply_transition(fixture, handle, DomainLifecycle::Current);
  FDR_CHECK_MSG(promoted.committed(), promoted.render());
  const std::optional<FailureDomain> current = fixture.registry.domain(handle.id);
  FDR_CHECK_MSG(current.has_value(), "the promoted domain is not readable back");
  FDR_CHECK_EQ(current->lifecycle, DomainLifecycle::Current);
  FDR_CHECK(current->is_current());
  FDR_CHECK_EQ(current->generation.value(), std::uint64_t{2});
  FDR_CHECK_EQ(current->created_generation.value(), std::uint64_t{1});
  // The lineage records the state the record left, not the one it entered.
  FDR_CHECK_EQ(current->history.size(), std::size_t{1});
  FDR_CHECK_EQ(current->history.back().lifecycle, DomainLifecycle::Candidate);
  FDR_CHECK_EQ(current->history.back().cause, std::string("transition:CURRENT"));
  handle = handle_of(*current);

  // Current -> RevalidationRequired: the record is no longer authority, but it
  // is not wrong either.
  const Outcome demoted = apply_transition(fixture, handle, DomainLifecycle::RevalidationRequired);
  FDR_CHECK_MSG(demoted.committed(), demoted.render());
  const std::optional<FailureDomain> revalidating = fixture.registry.domain(handle.id);
  FDR_CHECK_MSG(revalidating.has_value(), "the demoted domain is not readable back");
  FDR_CHECK_EQ(revalidating->lifecycle, DomainLifecycle::RevalidationRequired);
  FDR_CHECK(!revalidating->is_current());
  FDR_CHECK(!revalidating->is_terminal());
  FDR_CHECK(failure_domain_registry::is_indeterminate(revalidating->lifecycle));
  FDR_CHECK_EQ(revalidating->generation.value(), std::uint64_t{3});
  FDR_CHECK_EQ(revalidating->history.size(), std::size_t{2});
  FDR_CHECK_EQ(revalidating->history.back().lifecycle, DomainLifecycle::Current);
  FDR_CHECK_EQ(revalidating->history.back().cause, std::string("transition:REVALIDATION_REQUIRED"));
  handle = handle_of(*revalidating);

  // RevalidationRequired -> Current: the documented way back.
  const Outcome restored = apply_transition(fixture, handle, DomainLifecycle::Current);
  FDR_CHECK_MSG(restored.committed(), restored.render());
  const std::optional<FailureDomain> current_again = fixture.registry.domain(handle.id);
  FDR_CHECK_MSG(current_again.has_value(), "the revalidated domain is not readable back");
  FDR_CHECK_EQ(current_again->lifecycle, DomainLifecycle::Current);
  FDR_CHECK(current_again->is_current());
  FDR_CHECK_EQ(current_again->generation.value(), std::uint64_t{4});
  FDR_CHECK_EQ(current_again->history.size(), std::size_t{3});
  FDR_CHECK_EQ(current_again->history.back().cause, std::string("transition:CURRENT"));
  FDR_CHECK_EQ(current_again->id, handle.id);
  FDR_CHECK_EQ(current_again->created_generation.value(), std::uint64_t{1});
  handle = handle_of(*current_again);

  // Asking for the state the record already holds is a no-op, and a no-op is not
  // a lineage step.
  const Outcome again = apply_transition(fixture, handle, DomainLifecycle::Current);
  FDR_CHECK_MSG(again.code == OutcomeCode::Idempotent, again.render());
  const std::optional<FailureDomain> unchanged = fixture.registry.domain(handle.id);
  FDR_CHECK_MSG(unchanged.has_value(), "the domain is not readable back after a no-op");
  FDR_CHECK_EQ(unchanged->generation, handle.generation);
  FDR_CHECK_EQ(unchanged->history.size(), std::size_t{3});

  FDR_CHECK_EQ(fixture.registry.domain_count(), std::size_t{1});
  std::string why;
  FDR_CHECK_MSG(fixture.registry.validate_state(&why), why);
}

FDR_TEST_CASE(lifecycle, terminal_domains_can_never_be_moved_back) {
  // The table refuses these pairs outright.
  FDR_CHECK(!failure_domain_registry::is_legal_domain_transition(DomainLifecycle::Retired,
                                                                DomainLifecycle::Current));
  FDR_CHECK(!failure_domain_registry::is_legal_domain_transition(DomainLifecycle::Superseded,
                                                                DomainLifecycle::Current));
  FDR_CHECK(!failure_domain_registry::is_legal_domain_transition(DomainLifecycle::Rejected,
                                                                DomainLifecycle::Current));

  Fixture fixture;
  const DomainLifecycle terminals[] = {DomainLifecycle::Superseded, DomainLifecycle::Retired,
                                       DomainLifecycle::Rejected};
  std::size_t attempts = 0;
  for (DomainLifecycle terminal : terminals) {
    DomainHandle handle;
    reach(fixture, "terminal-" + name_of(terminal), terminal, handle);
    const std::optional<FailureDomain> reached = fixture.registry.domain(handle.id);
    FDR_CHECK_MSG(reached.has_value(), "the closed domain is not readable back");
    FDR_CHECK(reached->is_terminal());
    const std::string original_name = reached->name;
    const FailureDomainGeneration original_generation = reached->generation;

    for (std::size_t raw = 0; raw < kDomainStates; ++raw) {
      const DomainLifecycle target = static_cast<DomainLifecycle>(raw);
      // The request also asks for a name change, so a refusal that still wrote
      // the record would be caught.
      UpdateDomainRequest request;
      request.attempt = attempt_from(fixture.next_salt++);
      request.authority = fixture.owner.authority;
      request.domain = handle.id;
      request.expected_generation = handle.generation;
      request.transition = target;
      request.name = "renamed-" + name_of(target);

      const RegistryGeneration registry_before = fixture.registry.generation();
      const Outcome outcome = fixture.registry.update_domain(request);
      // A closed record is refused by the terminal rule before the table is
      // consulted, so the outcome names the closure rather than the transition:
      // RETIRED for a retired record, SUPERSEDED for every other terminal one.
      // The transition really is illegal as well, which is what the table checks
      // above prove.
      const OutcomeCode expected =
          terminal == DomainLifecycle::Retired ? OutcomeCode::Retired : OutcomeCode::Superseded;
      FDR_CHECK_MSG(outcome.code == expected, outcome.render());
      FDR_CHECK_EQ(outcome.code, expected);
      FDR_CHECK(!outcome.committed());
      FDR_CHECK(!outcome.succeeded());
      FDR_CHECK(!failure_domain_registry::is_legal_domain_transition(terminal, target));

      const std::optional<FailureDomain> record = fixture.registry.domain(handle.id);
      FDR_CHECK_MSG(record.has_value(), "the closed domain disappeared during a refused update");
      FDR_CHECK_EQ(record->lifecycle, terminal);
      FDR_CHECK_EQ(record->generation, original_generation);
      FDR_CHECK_EQ(record->name, original_name);
      FDR_CHECK(!failure_domain_registry::is_current(record->lifecycle));
      FDR_CHECK(failure_domain_registry::is_terminal(record->lifecycle));
      // Nothing moved: not the record, not the registry generation.
      FDR_CHECK_EQ(fixture.registry.generation(), registry_before);
      ++attempts;
    }

    // The closed record is still addressable, still terminal and still the only
    // record in its lifecycle after every attempt to revive it.
    const std::optional<FailureDomain> final_record = fixture.registry.domain(handle.id);
    FDR_CHECK_MSG(final_record.has_value(), "the closed domain is not readable back");
    FDR_CHECK_EQ(final_record->lifecycle, terminal);
    FDR_CHECK_EQ(final_record->generation, original_generation);
    FDR_CHECK_EQ(final_record->name, original_name);
    const std::vector<FailureDomain> in_lifecycle = fixture.registry.domains_in_lifecycle(terminal);
    FDR_CHECK_EQ(in_lifecycle.size(), std::size_t{1});
    FDR_CHECK_EQ(in_lifecycle.front().id, handle.id);
  }
  FDR_CHECK_EQ(attempts, std::size_t{3} * kDomainStates);

  std::string why;
  FDR_CHECK_MSG(fixture.registry.validate_state(&why), why);
}

} // namespace

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
