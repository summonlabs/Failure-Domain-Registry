// Failure Domain Registry — structured outcomes and explanations.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// No public operation returns a bare bool. Every mutation and every query
// returns an Outcome carrying a specific code, the identities and generations
// it concerns, and an ordered list of explanation steps naming the exact stage,
// field and value that produced the result.

#ifndef FAILURE_DOMAIN_REGISTRY_ERRORS_HPP
#define FAILURE_DOMAIN_REGISTRY_ERRORS_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "failure_domain_registry/entity.hpp"
#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"

namespace failure_domain_registry {

/// The specific, stage-bearing result of an operation.
enum class OutcomeCode : std::uint8_t {
  /// The mutation was applied and produced a new authorized generation.
  Committed = 0,
  /// The exact same already-committed request was replayed under still-valid
  /// semantics. No new generation was produced and no state changed.
  Idempotent = 1,
  /// The request expected a generation that is no longer current.
  StaleGeneration = 2,
  /// The request carries a coordinator epoch that is no longer current.
  StaleEpoch = 3,
  /// The request carries a worker incarnation that has been fenced.
  StaleWorkerBoot = 4,
  /// The publisher is unknown, revoked, or lacks the authority it asserted.
  StaleAuthority = 5,
  /// The request mutated a domain class or administrative scope the publisher
  /// is not authorized for.
  UnauthorizedScope = 6,
  /// The member entity generation is no longer the current one.
  StaleEntity = 7,
  /// The membership is bound to a domain generation that is no longer current.
  StaleDomain = 8,
  /// The membership generation the request expected is not the current one.
  StaleMembership = 9,
  /// The addressed entity is not known to this registry.
  UnknownEntity = 10,
  /// The addressed domain does not exist.
  UnknownDomain = 11,
  /// Two equally strong classifications disagree.
  DomainConflict = 12,
  /// Two equally strong memberships disagree.
  MembershipConflict = 13,
  /// An exclusive domain class already has a current domain for this member.
  ExclusivityViolation = 14,
  /// The requested hierarchy edge contradicts the containment rules.
  InvalidHierarchy = 15,
  /// The requested relation would close a cycle over an acyclic relation type.
  CycleRejected = 16,
  /// The record exists but is not current; an explicit revalidation is needed.
  RevalidationRequired = 17,
  /// The record is retired and cannot be mutated back into authority.
  Retired = 18,
  /// The record was superseded by a newer generation or successor.
  Superseded = 19,
  /// The request is structurally invalid.
  MalformedRequest = 20,
  /// A configured resource bound would be exceeded.
  ResourceLimit = 21,
  /// Registry policy rejects the request.
  PolicyRejected = 22,
  /// The same mutation attempt id was reused with different content.
  ConflictingReplay = 23,
  /// The addressed record does not exist.
  NotFound = 24,
  /// The addressed record exists but is not current.
  NotCurrent = 25,
  /// The requested lifecycle transition is not legal from the current state.
  IllegalTransition = 26,
  /// The durable state could not be written or read back.
  PersistenceFailure = 27,
  /// A transport operation failed.
  TransportFailure = 28,
  /// A peer violated the framing or message protocol.
  ProtocolViolation = 29,
  /// An integrity digest did not validate.
  IntegrityFailure = 30,
  /// The capability cannot be provided truthfully in this build or
  /// environment.
  UnsupportedCapability = 31,
  /// The operation requires authority and none was supplied.
  NoAuthority = 32,
  /// An unexpected internal failure. Never used to hide a known condition.
  InternalFailure = 33,
};

inline constexpr std::uint8_t kOutcomeCodeCount = 34;

FDR_API std::string_view to_string(OutcomeCode value) noexcept;

/// True for outcomes that represent a durable, authorized state change.
FDR_API bool is_commit(OutcomeCode value) noexcept;
/// True for outcomes that mean "this request lost to a newer one".
FDR_API bool is_stale(OutcomeCode value) noexcept;
/// True for outcomes that mean "the record is permanently closed".
FDR_API bool is_closed(OutcomeCode value) noexcept;
/// True when the caller may usefully retry after obtaining fresh state.
FDR_API bool is_retryable_after_refresh(OutcomeCode value) noexcept;

/// One ordered step of a deterministic explanation.
struct ExplanationStep {
  /// Pipeline stage: validate, authority, generation, entity, domain,
  /// exclusivity, hierarchy, conflict, derive, commit, persist, snapshot.
  std::string stage;
  /// The specific field the stage examined, when it examined one.
  std::string field;
  /// The value observed, rendered canonically.
  std::string value;
  /// What was decided and why.
  std::string detail;

  friend bool operator==(const ExplanationStep&, const ExplanationStep&) = default;
};

/// The result of an operation.
struct FDR_API Outcome {
  OutcomeCode code{OutcomeCode::InternalFailure};
  /// Short human-readable summary. Deterministic for a given set of inputs.
  std::string message;

  std::optional<FailureDomainId> domain;
  std::optional<MembershipId> membership;
  std::optional<EntityRef> member;
  /// Generation of the record after the operation (commit) or before it
  /// (rejection).
  std::optional<FailureDomainGeneration> domain_generation;
  std::optional<MembershipGeneration> membership_generation;
  std::optional<RegistryGeneration> state_generation;
  std::optional<CoordinatorEpoch> epoch;
  /// Digest of the request that produced this outcome, so an exact replay is
  /// recognizable.
  RequestDigest request_digest{};
  /// Ordered explanation steps.
  std::vector<ExplanationStep> steps;
  /// Records affected by a batch, a supersession or a merge.
  std::vector<FailureDomainId> related_domains;

  Outcome() = default;
  Outcome(OutcomeCode code_in, std::string message_in)
      : code(code_in), message(std::move(message_in)) {}

  static Outcome make(OutcomeCode code_in, std::string message_in) {
    return Outcome(code_in, std::move(message_in));
  }

  bool committed() const noexcept { return code == OutcomeCode::Committed; }
  /// True for Committed and Idempotent: the caller's intent is satisfied.
  bool succeeded() const noexcept { return is_commit(code) || code == OutcomeCode::Idempotent; }
  bool stale() const noexcept { return is_stale(code); }

  Outcome& step(std::string stage, std::string detail);
  Outcome& field_step(std::string stage, std::string field, std::string value, std::string detail);
  Outcome& with_domain(const FailureDomainId& id);
  Outcome& with_membership(const MembershipId& id);
  Outcome& with_member(const EntityRef& ref);
  Outcome& with_domain_generation(FailureDomainGeneration generation);
  Outcome& with_membership_generation(MembershipGeneration generation);

  /// Deterministic multi-line rendering used by the CLI, the examples and the
  /// tests.
  std::string render() const;
};

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_ERRORS_HPP
