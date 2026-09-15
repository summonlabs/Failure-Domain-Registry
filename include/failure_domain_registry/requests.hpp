// Failure Domain Registry — mutation requests.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// There is one request type per operation. There is no single generic "mutate"
// object: a caller that wants to create a domain says so, and a caller that
// wants to attach a member says so. Every request carries a mutation attempt
// (so an exact replay is recognizable) and an authority context (so the write
// can be fenced).

#ifndef FAILURE_DOMAIN_REGISTRY_REQUESTS_HPP
#define FAILURE_DOMAIN_REGISTRY_REQUESTS_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "failure_domain_registry/authority.hpp"
#include "failure_domain_registry/coverage.hpp"
#include "failure_domain_registry/derivation.hpp"
#include "failure_domain_registry/domain.hpp"
#include "failure_domain_registry/entity.hpp"
#include "failure_domain_registry/errors.hpp"
#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"
#include "failure_domain_registry/membership.hpp"
#include "failure_domain_registry/relation.hpp"

namespace failure_domain_registry {

/// Maximum length of a domain identity key.
inline constexpr std::size_t kMaxIdentityKeyBytes = 256;

/// Deterministic identity of a failure domain, derived from the administrative
/// scope, the domain class and a caller-supplied identity key. Two publishers
/// naming the same factor in the same scope and class therefore address the
/// same domain instead of creating duplicates.
FDR_API FailureDomainId domain_id_for(std::string_view administrative_scope,
                                      const DomainClassRef& domain_class,
                                      std::string_view identity_key);

FDR_API Outcome validate_identity_key(std::string_view key);
FDR_API Outcome validate_scope_name(std::string_view scope);

struct CreateDomainRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  DomainClassRef domain_class{};
  std::string administrative_scope;
  /// Stable, bounded identity of the common factor inside the scope and class,
  /// e.g. "rack-r7", "pdu-p3-a", "conduit-c12".
  std::string identity_key;
  std::string name;
  Provenance provenance{};
  /// Created directly in Current, or parked in Candidate until revalidated.
  bool activate{true};
  std::vector<MetadataEntry> metadata;
};

struct UpdateDomainRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  FailureDomainId domain{};
  FailureDomainGeneration expected_generation{};
  /// Replaces the canonical name when set.
  std::optional<std::string> name;
  /// Replaces the metadata set when true.
  bool replace_metadata{false};
  std::vector<MetadataEntry> metadata;
  /// Replacement provenance assertion. Leaves provenance untouched when the
  /// evidence class is Unknown.
  Provenance provenance{};
  /// Explicit lifecycle transition, e.g. RevalidationRequired -> Current.
  std::optional<DomainLifecycle> transition;
};

struct SupersedeDomainRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  FailureDomainId domain{};
  FailureDomainGeneration expected_generation{};
  /// Successor domain. Must already exist.
  FailureDomainId successor{};
  /// When true, memberships bound to the superseded generation are moved to
  /// REVALIDATION_REQUIRED. They are never re-bound automatically.
  bool demote_memberships{true};
};

struct RetireDomainRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  FailureDomainId domain{};
  FailureDomainGeneration expected_generation{};
  std::string reason;
  bool retire_memberships{true};
};

struct AddRelationRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  FailureDomainId source{};
  FailureDomainId target{};
  DomainRelationType type{DomainRelationType::Unknown};
  Provenance provenance{};
};

struct MergeDomainsRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  FailureDomainId survivor{};
  FailureDomainGeneration expected_survivor_generation{};
  FailureDomainId absorbed{};
  FailureDomainGeneration expected_absorbed_generation{};
  /// Move the absorbed domain's memberships to the survivor. The registry never
  /// guesses: the caller states whether the member sets are equivalent.
  bool memberships_equivalent{false};
  std::string reason;
};

struct AttachMemberRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  FailureDomainId domain{};
  FailureDomainGeneration expected_domain_generation{};
  EntityRef member{};
  MembershipKind kind{MembershipKind::Direct};
  MembershipRole role{MembershipRole::Unspecified};
  DependencySemantics dependency{DependencySemantics::Unspecified};
  Provenance provenance{};
  std::vector<MetadataEntry> metadata;
};

struct DetachMemberRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  FailureDomainId domain{};
  EntityRef member{};
  MembershipKind kind{MembershipKind::Direct};
  /// Optional optimistic check. A zero generation skips the check.
  MembershipGeneration expected_membership_generation{};
  std::string reason;
};

struct ReplaceMembershipRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  MembershipId membership{};
  MembershipGeneration expected_generation{};
  MembershipRole role{MembershipRole::Unspecified};
  DependencySemantics dependency{DependencySemantics::Unspecified};
  /// Replacement provenance. When the evidence class is Unknown, the existing
  /// evidence set is left alone.
  Provenance provenance{};
  bool replace_metadata{false};
  std::vector<MetadataEntry> metadata;
};

/// How much of the classification a publication claims to describe.
enum class PublicationMode : std::uint8_t {
  Unknown = 0,
  /// Adds and updates only what it names. Never removes anything.
  Incremental = 1,
  /// Adds and updates what it names; the named set is explicitly not complete.
  Partial = 2,
  /// The named set is the complete current membership of the addressed domains
  /// for the named entity class. Memberships of that class missing from the set
  /// are retired.
  Authoritative = 3,
};

FDR_API std::string_view to_string(PublicationMode value) noexcept;
FDR_API bool is_valid_publication_mode(PublicationMode value) noexcept;

/// One member inside a bulk publication.
struct MembershipBatchEntry {
  FailureDomainId domain{};
  FailureDomainGeneration expected_domain_generation{};
  EntityRef member{};
  MembershipKind kind{MembershipKind::Direct};
  MembershipRole role{MembershipRole::Unspecified};
  DependencySemantics dependency{DependencySemantics::Unspecified};
  Provenance provenance{};
  std::vector<MetadataEntry> metadata;
};

struct MembershipBatchRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  PublicationMode mode{PublicationMode::Incremental};
  std::string administrative_scope;
  /// Entity class an Authoritative publication claims to be complete for.
  /// Required for Authoritative, ignored otherwise.
  EntityClass authoritative_entity_class{EntityClass::Unknown};
  /// Domains an Authoritative publication claims to be complete for.
  std::vector<FailureDomainId> authoritative_domains;
  std::vector<MembershipBatchEntry> entries;
};

struct WithdrawEvidenceRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  MembershipId membership{};
  MembershipGeneration expected_generation{};
  /// Evidence entries published by this publisher incarnation are withdrawn.
  bool only_this_worker_boot{true};
  EvidenceClass evidence{EvidenceClass::Unknown};
  std::string reason;
};

struct ReconcileMembershipRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  FailureDomainId domain{};
  EntityRef member{};
  MembershipKind kind{MembershipKind::Direct};
};

/// Scope selector for a revalidation demand.
struct MarkRevalidationRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  /// When set, only this domain is marked.
  FailureDomainId domain{};
  /// When set, only this membership is marked.
  MembershipId membership{};
  /// When set, only memberships of this entity are marked.
  EntityId entity{};
  /// When set, only memberships whose domain has this class are marked.
  DomainClassRef domain_class{};
  /// When true, an empty selector marks everything the publisher is authorized
  /// for. An empty selector with this false is rejected.
  bool all_in_scope{false};
  std::string reason;
};

struct DeclareCoverageRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  std::string administrative_scope;
  DomainClassRef domain_class{};
  CoverageState state{CoverageState::UnknownCoverage};
  Provenance provenance{};
};

/// Fabric Registry told this runtime that an entity changed generation.
struct EntityInvalidationRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  EntityId entity{};
  /// The generation that is no longer current. Must be non-zero.
  EntityGeneration superseded_generation{};
  EntityClass successor_class{EntityClass::Unknown};
  /// Successor entity generation, when the entity was replaced rather than
  /// retired.
  IdBytes successor_id{};
  EntityGeneration successor_generation{};
  std::string reason;
};

/// Fabric Topology told this runtime that structural facts changed.
///
/// Only derivations whose recorded sources mention one of the affected entities
/// are invalidated. An unrelated topology change never invalidates unrelated
/// classification.
struct TopologyChangeRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  TopologyGeneration topology_generation{};
  std::vector<EntityId> affected_entities;
  /// True when the change is known to have altered a relationship the runtime
  /// derives from. False means "a topology generation moved but nothing this
  /// runtime derives from is known to have changed", which invalidates nothing.
  bool structurally_relevant{true};
};

/// Result of a derivation pass, published back to the caller.
struct DerivationRunRequest {
  MutationAttempt attempt{};
  AuthorityContext authority{};
  /// When set, only this rule is evaluated.
  DerivationRuleId rule{};
};

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_REQUESTS_HPP
