// Failure Domain Registry — outcome codes and explanation rendering.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/errors.hpp"

namespace failure_domain_registry {

std::string_view to_string(OutcomeCode value) noexcept {
  switch (value) {
    case OutcomeCode::Committed: return "COMMITTED";
    case OutcomeCode::Idempotent: return "IDEMPOTENT";
    case OutcomeCode::StaleGeneration: return "STALE_GENERATION";
    case OutcomeCode::StaleEpoch: return "STALE_EPOCH";
    case OutcomeCode::StaleWorkerBoot: return "STALE_WORKER_BOOT";
    case OutcomeCode::StaleAuthority: return "STALE_AUTHORITY";
    case OutcomeCode::UnauthorizedScope: return "UNAUTHORIZED_SCOPE";
    case OutcomeCode::StaleEntity: return "STALE_ENTITY";
    case OutcomeCode::StaleDomain: return "STALE_DOMAIN";
    case OutcomeCode::StaleMembership: return "STALE_MEMBERSHIP";
    case OutcomeCode::UnknownEntity: return "UNKNOWN_ENTITY";
    case OutcomeCode::UnknownDomain: return "UNKNOWN_DOMAIN";
    case OutcomeCode::DomainConflict: return "DOMAIN_CONFLICT";
    case OutcomeCode::MembershipConflict: return "MEMBERSHIP_CONFLICT";
    case OutcomeCode::ExclusivityViolation: return "EXCLUSIVITY_VIOLATION";
    case OutcomeCode::InvalidHierarchy: return "INVALID_HIERARCHY";
    case OutcomeCode::CycleRejected: return "CYCLE_REJECTED";
    case OutcomeCode::RevalidationRequired: return "REVALIDATION_REQUIRED";
    case OutcomeCode::Retired: return "RETIRED";
    case OutcomeCode::Superseded: return "SUPERSEDED";
    case OutcomeCode::MalformedRequest: return "MALFORMED_REQUEST";
    case OutcomeCode::ResourceLimit: return "RESOURCE_LIMIT";
    case OutcomeCode::PolicyRejected: return "POLICY_REJECTED";
    case OutcomeCode::ConflictingReplay: return "CONFLICTING_REPLAY";
    case OutcomeCode::NotFound: return "NOT_FOUND";
    case OutcomeCode::NotCurrent: return "NOT_CURRENT";
    case OutcomeCode::IllegalTransition: return "ILLEGAL_TRANSITION";
    case OutcomeCode::PersistenceFailure: return "PERSISTENCE_FAILURE";
    case OutcomeCode::TransportFailure: return "TRANSPORT_FAILURE";
    case OutcomeCode::ProtocolViolation: return "PROTOCOL_VIOLATION";
    case OutcomeCode::IntegrityFailure: return "INTEGRITY_FAILURE";
    case OutcomeCode::UnsupportedCapability: return "UNSUPPORTED_CAPABILITY";
    case OutcomeCode::NoAuthority: return "NO_AUTHORITY";
    default: return "INTERNAL_FAILURE";
  }
}

bool is_commit(OutcomeCode value) noexcept {
  return value == OutcomeCode::Committed;
}

bool is_stale(OutcomeCode value) noexcept {
  switch (value) {
    case OutcomeCode::StaleGeneration:
    case OutcomeCode::StaleEpoch:
    case OutcomeCode::StaleWorkerBoot:
    case OutcomeCode::StaleAuthority:
    case OutcomeCode::StaleEntity:
    case OutcomeCode::StaleDomain:
    case OutcomeCode::StaleMembership:
    case OutcomeCode::ConflictingReplay:
      return true;
    default:
      return false;
  }
}

bool is_closed(OutcomeCode value) noexcept {
  return value == OutcomeCode::Retired || value == OutcomeCode::Superseded;
}

bool is_retryable_after_refresh(OutcomeCode value) noexcept {
  return is_stale(value) || value == OutcomeCode::RevalidationRequired ||
         value == OutcomeCode::NotCurrent;
}

Outcome& Outcome::step(std::string stage, std::string detail) {
  steps.push_back(ExplanationStep{std::move(stage), std::string(), std::string(), std::move(detail)});
  return *this;
}

Outcome& Outcome::field_step(std::string stage, std::string field, std::string value,
                             std::string detail) {
  steps.push_back(ExplanationStep{std::move(stage), std::move(field), std::move(value),
                                  std::move(detail)});
  return *this;
}

Outcome& Outcome::with_domain(const FailureDomainId& id) {
  domain = id;
  return *this;
}

Outcome& Outcome::with_membership(const MembershipId& id) {
  membership = id;
  return *this;
}

Outcome& Outcome::with_member(const EntityRef& ref) {
  member = ref;
  return *this;
}

Outcome& Outcome::with_domain_generation(FailureDomainGeneration generation) {
  domain_generation = generation;
  return *this;
}

Outcome& Outcome::with_membership_generation(MembershipGeneration generation) {
  membership_generation = generation;
  return *this;
}

std::string Outcome::render() const {
  std::string out;
  out.append(failure_domain_registry::to_string(code));
  if (!message.empty()) {
    out.append(": ");
    out.append(message);
  }
  if (domain.has_value()) {
    out.append("\n  domain           = ");
    out.append(domain->to_string());
  }
  if (membership.has_value()) {
    out.append("\n  membership       = ");
    out.append(membership->to_string());
  }
  if (member.has_value()) {
    out.append("\n  member           = ");
    out.append(member->to_string());
  }
  if (domain_generation.has_value()) {
    out.append("\n  domain-gen       = ");
    out.append(domain_generation->to_string());
  }
  if (membership_generation.has_value()) {
    out.append("\n  membership-gen   = ");
    out.append(membership_generation->to_string());
  }
  if (state_generation.has_value()) {
    out.append("\n  registry-gen     = ");
    out.append(state_generation->to_string());
  }
  if (epoch.has_value()) {
    out.append("\n  epoch            = ");
    out.append(epoch->to_string());
  }
  if (!request_digest.is_null()) {
    out.append("\n  request-digest   = ");
    out.append(request_digest.to_string());
  }
  for (const FailureDomainId& related : related_domains) {
    out.append("\n  related-domain   = ");
    out.append(related.to_string());
  }
  out.append("\n  steps:");
  if (steps.empty()) {
    out.append(" (none)");
  }
  for (const ExplanationStep& entry : steps) {
    out.append("\n    [");
    out.append(entry.stage);
    out.append("]");
    if (!entry.field.empty()) {
      out.append(" ");
      out.append(entry.field);
      out.append("=");
      out.append(entry.value);
    }
    out.append(" ");
    out.append(entry.detail);
  }
  return out;
}

} // namespace failure_domain_registry
