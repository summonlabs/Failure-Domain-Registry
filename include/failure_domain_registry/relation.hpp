// Failure Domain Registry — domain-to-domain relation types.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A failure-domain graph is not a tree: an entity is routinely a member of
// several orthogonal domains at once. Relations between domains are therefore
// typed, and only the types below exist. There is no free-form relation name.
//
// Acyclicity is a property of the relation type, not of the graph as a whole:
// containment and dependency relations must stay acyclic, while shared-risk and
// correlation relations may legitimately form arbitrary graphs.

#ifndef FAILURE_DOMAIN_REGISTRY_RELATION_HPP
#define FAILURE_DOMAIN_REGISTRY_RELATION_HPP

#include <cstdint>
#include <optional>
#include <string_view>

#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"
#include "failure_domain_registry/provenance.hpp"

namespace failure_domain_registry {

enum class DomainRelationType : std::uint8_t {
  Unknown = 0,
  /// source is physically or administratively contained by target.
  ContainedBy = 1,
  /// source requires target; failure of target affects source.
  DependsOn = 2,
  /// source and target share a common failure factor. Symmetric.
  SharesRiskWith = 3,
  /// source is powered by target.
  PoweredBy = 4,
  /// source is cooled by target.
  CooledBy = 5,
  /// source is controlled by target.
  ControlledBy = 6,
  /// source is backed by target (standby/backing resource).
  BackedBy = 7,
  /// source and target are correlated without a more specific relation.
  /// Symmetric and non-acyclic: correlation is not containment.
  CorrelatedWith = 8,
};

inline constexpr std::uint8_t kDomainRelationTypeCount = 8;

FDR_API std::string_view to_string(DomainRelationType value) noexcept;
FDR_API std::optional<DomainRelationType> domain_relation_type_from_string(std::string_view text) noexcept;
FDR_API bool is_valid_domain_relation_type(DomainRelationType value) noexcept;

/// True when the relation is stored once and read in both directions.
FDR_API bool is_symmetric_relation(DomainRelationType value) noexcept;

/// True when the relation must stay acyclic across the whole domain graph.
/// Holding a cycle over an acyclic relation type is rejected with
/// CYCLE_REJECTED before anything is committed.
FDR_API bool is_acyclic_relation(DomainRelationType value) noexcept;

/// The inverse rendering used when a directed relation is read backwards.
FDR_API std::string_view inverse_text(DomainRelationType value) noexcept;

/// One typed edge between two failure domains.
///
/// A symmetric relation is stored once, with source and target in canonical
/// order, and is read in both directions.
struct FDR_API DomainRelation {
  DomainRelationId id{};
  FailureDomainId source{};
  FailureDomainId target{};
  DomainRelationType type{DomainRelationType::Unknown};
  Provenance provenance{};
  RegistryGeneration created_at{};
  CoordinatorEpoch created_epoch{};

  std::string render() const;
  std::string canonical_form() const;
  friend bool operator==(const DomainRelation&, const DomainRelation&) = default;
};

/// Computes the deterministic relation id. Symmetric types canonicalise the
/// endpoint order, so the same edge always produces the same id.
FDR_API DomainRelationId relation_id_for(const FailureDomainId& source,
                                         const FailureDomainId& target,
                                         DomainRelationType type);

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_RELATION_HPP
