// Failure Domain Registry — immutable snapshots and stable diffs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A snapshot binds the exact registry generation, coordinator epoch, domain and
// membership generations and a deterministic digest. It is an immutable value:
// taking one copies the identity-level state, so a later mutation can never
// change what a snapshot says. A consumer tests currentness by comparing the
// snapshot's generation with the live registry generation.

#ifndef FAILURE_DOMAIN_REGISTRY_SNAPSHOT_HPP
#define FAILURE_DOMAIN_REGISTRY_SNAPSHOT_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "failure_domain_registry/domain_class.hpp"
#include "failure_domain_registry/entity.hpp"
#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"
#include "failure_domain_registry/lifecycle.hpp"
#include "failure_domain_registry/provenance.hpp"

namespace failure_domain_registry {

/// Identity-level record of one domain inside a snapshot.
struct SnapshotDomainEntry {
  FailureDomainId id{};
  DomainClassRef domain_class{};
  FailureDomainGeneration generation{};
  DomainLifecycle lifecycle{DomainLifecycle::Unknown};
  EvidenceClass evidence{EvidenceClass::Unknown};
  TruthClass truth{TruthClass::Unknown};
  ProvenanceSource source{ProvenanceSource::Unknown};
  RegistryGeneration created_at{};
  friend bool operator==(const SnapshotDomainEntry&, const SnapshotDomainEntry&) = default;
};

/// Identity-level record of one membership inside a snapshot.
struct SnapshotMembershipEntry {
  MembershipId id{};
  FailureDomainId domain{};
  FailureDomainGeneration domain_generation{};
  EntityRef member{};
  MembershipGeneration generation{};
  MembershipLifecycle lifecycle{MembershipLifecycle::Unknown};
  MembershipKind kind{MembershipKind::Unknown};
  MembershipRole role{MembershipRole::Unspecified};
  EvidenceClass evidence{EvidenceClass::Unknown};
  TruthClass truth{TruthClass::Unknown};
  ProvenanceSource source{ProvenanceSource::Unknown};
  DerivationRuleId derivation_rule{};
  DerivationGeneration derivation_generation{};
  friend bool operator==(const SnapshotMembershipEntry&, const SnapshotMembershipEntry&) = default;
};

/// An immutable, self-describing point-in-time view of the registry.
struct FDR_API Snapshot {
  SnapshotId id{};
  SnapshotSequence sequence{};
  RegistryGeneration state_generation{};
  CoordinatorEpoch epoch{};
  StateDigest digest{};
  /// Caller-supplied scope label. Bounded; never an identity.
  std::string scope;
  std::vector<SnapshotDomainEntry> domains;
  std::vector<SnapshotMembershipEntry> memberships;

  /// True when the snapshot recorded no records at all.
  bool is_empty() const noexcept { return domains.empty() && memberships.empty(); }
  /// Deterministic rendering used by the CLI.
  std::string render() const;
  /// Canonical byte string fed to the snapshot digest.
  std::string canonical_form() const;
};

/// The kind of change reported by a diff.
enum class DiffKind : std::uint8_t {
  Unknown = 0,
  DomainAdded = 1,
  DomainRemoved = 2,
  DomainSuperseded = 3,
  DomainLifecycleChanged = 4,
  DomainClassChanged = 5,
  DomainProvenanceChanged = 6,
  MembershipAdded = 7,
  MembershipRemoved = 8,
  MembershipMoved = 9,
  MembershipLifecycleChanged = 10,
  MembershipProvenanceChanged = 11,
  MembershipDerivationChanged = 12,
};

FDR_API std::string_view to_string(DiffKind value) noexcept;

/// One stable diff entry.
struct DiffEntry {
  DiffKind kind{DiffKind::Unknown};
  FailureDomainId domain{};
  MembershipId membership{};
  EntityRef member{};
  /// Canonical rendering of the value before the change (empty when added).
  std::string before;
  /// Canonical rendering of the value after the change (empty when removed).
  std::string after;
  friend bool operator==(const DiffEntry&, const DiffEntry&) = default;
};

/// A stable, totally ordered diff between two snapshots.
struct SnapshotDiff {
  SnapshotId before{};
  SnapshotId after{};
  RegistryGeneration before_generation{};
  RegistryGeneration after_generation{};
  /// Ordered by (kind, domain, membership, member).
  std::vector<DiffEntry> entries;

  bool empty() const noexcept { return entries.empty(); }
  std::string render() const;
};

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_SNAPSHOT_HPP
