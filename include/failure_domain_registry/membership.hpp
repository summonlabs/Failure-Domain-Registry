// Failure Domain Registry — the membership record.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Membership is a first-class record with its own identity, generation,
// provenance, evidence set and lifecycle. It is never a vector buried inside a
// domain record, because membership has to be able to advance, be corroborated,
// lose a corroborating source, be demoted and be superseded independently of
// the domain it points at.

#ifndef FAILURE_DOMAIN_REGISTRY_MEMBERSHIP_HPP
#define FAILURE_DOMAIN_REGISTRY_MEMBERSHIP_HPP

#include <string>
#include <vector>

#include "failure_domain_registry/domain.hpp"
#include "failure_domain_registry/entity.hpp"
#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"
#include "failure_domain_registry/lifecycle.hpp"
#include "failure_domain_registry/provenance.hpp"

namespace failure_domain_registry {

/// How the membership came to exist.
enum class MembershipKind : std::uint8_t {
  Unknown = 0,
  /// Published directly by a publisher for this exact domain and member.
  Direct = 1,
  /// Produced by a published derivation rule from other memberships.
  Derived = 2,
  /// Inherited from a structurally enclosing membership under an explicit rule.
  Inherited = 3,
  /// Asserted administratively without a physical record.
  Asserted = 4,
};

/// What the membership means for redundancy. The registry records the role; it
/// never draws a resilience conclusion from it.
enum class DependencySemantics : std::uint8_t {
  Unspecified = 0,
  /// Failure of the shared factor affects the member (default shared risk).
  AnyDependencyFailureAffectsMember = 1,
  /// Every listed dependency is required for the member to operate.
  AllDependenciesRequired = 2,
  /// The member has other sources; this one is redundant.
  RedundantSource = 3,
};

/// The part a member plays in the domain.
enum class MembershipRole : std::uint8_t {
  Unspecified = 0,
  Primary = 1,
  Redundant = 2,
  Backup = 3,
  Containment = 4,
  SharedRisk = 5,
  Derived = 6,
};

FDR_API std::string_view to_string(MembershipKind value) noexcept;
FDR_API std::string_view to_string(DependencySemantics value) noexcept;
FDR_API std::string_view to_string(MembershipRole value) noexcept;
FDR_API bool is_valid_membership_kind(MembershipKind value) noexcept;
FDR_API bool is_valid_dependency_semantics(DependencySemantics value) noexcept;
FDR_API bool is_valid_membership_role(MembershipRole value) noexcept;

/// One independent corroboration of a membership.
struct MembershipEvidence {
  Provenance provenance{};
  /// False once the publishing incarnation was fenced and the class is process
  /// bound. Durable evidence stays live across publisher loss.
  bool live{true};
  friend bool operator==(const MembershipEvidence&, const MembershipEvidence&) = default;
};

/// How a derived or inherited membership was produced.
struct DerivationInfo {
  DerivationRuleId rule{};
  DerivationGeneration generation{};
  /// Memberships the derivation read, in canonical order.
  std::vector<MembershipId> sources;
  /// Source generations in the same order as sources, so invalidation is exact.
  std::vector<MembershipGeneration> source_generations;
  /// Canonical rendering of the source generations in force when derived.
  std::string context;
  /// False once a source generation has moved on; the registry then
  /// recomputes or withdraws the derived membership.
  bool valid{false};
};

/// One retained step of a membership's lineage.
struct MembershipHistoryEntry {
  MembershipGeneration previous_generation{};
  MembershipGeneration generation{};
  MembershipLifecycle lifecycle{MembershipLifecycle::Unknown};
  std::string cause;
  EvidenceClass evidence{EvidenceClass::Unknown};
  CoordinatorEpoch epoch{};
  RegistryGeneration at{};
  friend bool operator==(const MembershipHistoryEntry&, const MembershipHistoryEntry&) = default;
};

/// A membership: "this member, at this exact generation, belongs to this
/// domain, at this exact generation, according to this evidence".
struct FDR_API Membership {
  MembershipId id{};
  FailureDomainId domain{};
  /// Domain generation this membership is bound to. A membership bound to an
  /// older generation is never silently re-bound.
  FailureDomainGeneration domain_generation{};
  EntityRef member{};
  MembershipGeneration generation{};
  MembershipLifecycle lifecycle{MembershipLifecycle::Unknown};
  MembershipKind kind{MembershipKind::Unknown};
  MembershipRole role{MembershipRole::Unspecified};
  DependencySemantics dependency{DependencySemantics::Unspecified};
  /// The strongest live provenance, kept as the record's headline provenance.
  Provenance provenance{};
  std::vector<MembershipEvidence> evidence;
  DerivationInfo derivation{};
  EvidenceGeneration evidence_generation{};
  RegistryGeneration created_at{};
  CoordinatorEpoch created_epoch{};
  MembershipId superseded_by{};
  MembershipId supersedes{};
  std::vector<MetadataEntry> metadata;
  std::vector<MembershipHistoryEntry> history;

  bool is_current() const noexcept { return failure_domain_registry::is_current(lifecycle); }
  bool is_terminal() const noexcept { return failure_domain_registry::is_terminal(lifecycle); }
  /// Number of live corroborating evidence entries.
  std::size_t live_evidence_count() const noexcept;

  std::string render() const;
  std::string canonical_form() const;

  friend bool operator==(const Membership&, const Membership&) = default;
};

/// The deterministic key of a membership. Two publications of the same member
/// generation in the same domain with the same kind address the same record.
struct MembershipKey {
  FailureDomainId domain{};
  EntityId member{};
  EntityGeneration member_generation{};
  MembershipKind kind{MembershipKind::Unknown};
  friend bool operator==(const MembershipKey&, const MembershipKey&) = default;
};

/// Computes the deterministic membership id for a key. Insertion order,
/// publisher identity and wall-clock time do not participate.
FDR_API MembershipId membership_id_for(const MembershipKey& key);

} // namespace failure_domain_registry

namespace std {

template <>
struct hash<failure_domain_registry::MembershipKey> {
  std::size_t operator()(const failure_domain_registry::MembershipKey& value) const noexcept {
    std::size_t accumulator = std::hash<failure_domain_registry::FailureDomainId>{}(value.domain);
    accumulator ^= std::hash<failure_domain_registry::EntityId>{}(value.member);
    accumulator *= 1099511628211ull;
    accumulator ^= std::hash<std::uint64_t>{}(value.member_generation.value());
    accumulator *= 1099511628211ull;
    accumulator ^= static_cast<std::size_t>(value.kind);
    return accumulator;
  }
};

} // namespace std

#endif // FAILURE_DOMAIN_REGISTRY_MEMBERSHIP_HPP
