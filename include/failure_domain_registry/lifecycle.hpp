// Failure Domain Registry — domain and membership lifecycle.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every legal transition is listed here and enforced by the registry. A retired
// or superseded record is terminal: it can never regain current authority, and
// no replay of older traffic can move it back.

#ifndef FAILURE_DOMAIN_REGISTRY_LIFECYCLE_HPP
#define FAILURE_DOMAIN_REGISTRY_LIFECYCLE_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "failure_domain_registry/export.hpp"

namespace failure_domain_registry {

/// Lifecycle of one failure-domain record.
enum class DomainLifecycle : std::uint8_t {
  Unknown = 0,
  /// Declared but not yet carrying authority. A candidate never participates in
  /// overlap or independence answers.
  Candidate = 1,
  /// Authoritative and current.
  Current = 2,
  /// The record exists but its evidence, entity bindings or authority are no
  /// longer known to be valid. It is not current and must not be treated as
  /// classification truth, but it is not wrong either - it is unknown.
  RevalidationRequired = 3,
  /// Replaced by a newer domain generation or by an explicit successor.
  Superseded = 4,
  /// Administratively closed. Terminal.
  Retired = 5,
  /// Conflicting evidence could not be resolved deterministically.
  Conflicted = 6,
  /// Declared and refused. Terminal.
  Rejected = 7,
};

/// Lifecycle of one membership record.
enum class MembershipLifecycle : std::uint8_t {
  Unknown = 0,
  Current = 1,
  RevalidationRequired = 2,
  Superseded = 3,
  Retired = 4,
  Conflicted = 5,
  Rejected = 6,
};

FDR_API std::string_view to_string(DomainLifecycle value) noexcept;
FDR_API std::string_view to_string(MembershipLifecycle value) noexcept;

FDR_API bool is_valid_domain_lifecycle(DomainLifecycle value) noexcept;
FDR_API bool is_valid_membership_lifecycle(MembershipLifecycle value) noexcept;

/// True only for Current: the single state that carries classification
/// authority.
FDR_API bool is_current(DomainLifecycle value) noexcept;
FDR_API bool is_current(MembershipLifecycle value) noexcept;

/// True for Superseded, Retired and Rejected: terminal states that may never
/// transition again.
FDR_API bool is_terminal(DomainLifecycle value) noexcept;
FDR_API bool is_terminal(MembershipLifecycle value) noexcept;

/// True for RevalidationRequired and Conflicted: states that are neither
/// current nor terminal, and that make an independence answer UNKNOWN.
FDR_API bool is_indeterminate(DomainLifecycle value) noexcept;
FDR_API bool is_indeterminate(MembershipLifecycle value) noexcept;

FDR_API bool is_legal_domain_transition(DomainLifecycle from, DomainLifecycle to) noexcept;
FDR_API bool is_legal_membership_transition(MembershipLifecycle from, MembershipLifecycle to) noexcept;

/// Ordered list of every legal transition, used by the CLI, the README and the
/// lifecycle tests so that the documented table cannot drift from the code.
struct TransitionEdge {
  DomainLifecycle from;
  DomainLifecycle to;
};
FDR_API const TransitionEdge* domain_transition_table(std::size_t& count) noexcept;

struct MembershipTransitionEdge {
  MembershipLifecycle from;
  MembershipLifecycle to;
};
FDR_API const MembershipTransitionEdge* membership_transition_table(std::size_t& count) noexcept;

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_LIFECYCLE_HPP
