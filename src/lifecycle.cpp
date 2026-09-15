// Failure Domain Registry — lifecycle tables.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The transition tables below are the single source of truth: the registry
// consults them, the CLI prints them and the lifecycle tests assert that no
// transition outside them is ever accepted.

#include "failure_domain_registry/lifecycle.hpp"

namespace failure_domain_registry {
namespace {

constexpr TransitionEdge kDomainTransitions[] = {
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

constexpr MembershipTransitionEdge kMembershipTransitions[] = {
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

} // namespace

std::string_view to_string(DomainLifecycle value) noexcept {
  switch (value) {
    case DomainLifecycle::Candidate: return "CANDIDATE";
    case DomainLifecycle::Current: return "CURRENT";
    case DomainLifecycle::RevalidationRequired: return "REVALIDATION_REQUIRED";
    case DomainLifecycle::Superseded: return "SUPERSEDED";
    case DomainLifecycle::Retired: return "RETIRED";
    case DomainLifecycle::Conflicted: return "CONFLICTED";
    case DomainLifecycle::Rejected: return "REJECTED";
    default: return "UNKNOWN";
  }
}

std::string_view to_string(MembershipLifecycle value) noexcept {
  switch (value) {
    case MembershipLifecycle::Current: return "CURRENT";
    case MembershipLifecycle::RevalidationRequired: return "REVALIDATION_REQUIRED";
    case MembershipLifecycle::Superseded: return "SUPERSEDED";
    case MembershipLifecycle::Retired: return "RETIRED";
    case MembershipLifecycle::Conflicted: return "CONFLICTED";
    case MembershipLifecycle::Rejected: return "REJECTED";
    default: return "UNKNOWN";
  }
}

bool is_valid_domain_lifecycle(DomainLifecycle value) noexcept {
  return value != DomainLifecycle::Unknown &&
         static_cast<std::uint8_t>(value) <= static_cast<std::uint8_t>(DomainLifecycle::Rejected);
}

bool is_valid_membership_lifecycle(MembershipLifecycle value) noexcept {
  return value != MembershipLifecycle::Unknown &&
         static_cast<std::uint8_t>(value) <= static_cast<std::uint8_t>(MembershipLifecycle::Rejected);
}

bool is_current(DomainLifecycle value) noexcept {
  return value == DomainLifecycle::Current;
}

bool is_current(MembershipLifecycle value) noexcept {
  return value == MembershipLifecycle::Current;
}

bool is_terminal(DomainLifecycle value) noexcept {
  return value == DomainLifecycle::Superseded || value == DomainLifecycle::Retired ||
         value == DomainLifecycle::Rejected;
}

bool is_terminal(MembershipLifecycle value) noexcept {
  return value == MembershipLifecycle::Superseded || value == MembershipLifecycle::Retired ||
         value == MembershipLifecycle::Rejected;
}

bool is_indeterminate(DomainLifecycle value) noexcept {
  return value == DomainLifecycle::RevalidationRequired || value == DomainLifecycle::Conflicted;
}

bool is_indeterminate(MembershipLifecycle value) noexcept {
  return value == MembershipLifecycle::RevalidationRequired || value == MembershipLifecycle::Conflicted;
}

bool is_legal_domain_transition(DomainLifecycle from, DomainLifecycle to) noexcept {
  for (const TransitionEdge& edge : kDomainTransitions) {
    if (edge.from == from && edge.to == to) {
      return true;
    }
  }
  return false;
}

bool is_legal_membership_transition(MembershipLifecycle from, MembershipLifecycle to) noexcept {
  for (const MembershipTransitionEdge& edge : kMembershipTransitions) {
    if (edge.from == from && edge.to == to) {
      return true;
    }
  }
  return false;
}

const TransitionEdge* domain_transition_table(std::size_t& count) noexcept {
  count = sizeof(kDomainTransitions) / sizeof(kDomainTransitions[0]);
  return kDomainTransitions;
}

const MembershipTransitionEdge* membership_transition_table(std::size_t& count) noexcept {
  count = sizeof(kMembershipTransitions) / sizeof(kMembershipTransitions[0]);
  return kMembershipTransitions;
}

} // namespace failure_domain_registry
