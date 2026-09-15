// Failure Domain Registry — classification coverage.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Coverage answers a different question from membership: not "does A belong to
// D" but "does anything here know about class C at all". It is what stops the
// absence of a membership record from being read as proven independence.

#ifndef FAILURE_DOMAIN_REGISTRY_COVERAGE_HPP
#define FAILURE_DOMAIN_REGISTRY_COVERAGE_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "failure_domain_registry/domain_class.hpp"
#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"
#include "failure_domain_registry/provenance.hpp"

namespace failure_domain_registry {

/// How well a domain class is classified inside one administrative scope.
enum class CoverageState : std::uint8_t {
  Unknown = 0,
  /// Every entity in scope is classified for this class, or is known not to
  /// belong to any domain of it.
  Complete = 1,
  /// Some entities are classified; the rest are simply not known.
  Partial = 2,
  /// Nothing is known. This is the default when nothing was declared.
  UnknownCoverage = 3,
};

FDR_API std::string_view to_string(CoverageState value) noexcept;
FDR_API bool is_valid_coverage_state(CoverageState value) noexcept;

/// One explicit coverage declaration by an authorized publisher.
struct CoverageDeclaration {
  std::string administrative_scope;
  DomainClassRef domain_class{};
  CoverageState state{CoverageState::UnknownCoverage};
  Provenance provenance{};
  RegistryGeneration declared_at{};
  CoordinatorEpoch epoch{};
  friend bool operator==(const CoverageDeclaration&, const CoverageDeclaration&) = default;
};

/// The coverage answer for one addressed class.
struct CoverageEntry {
  DomainClassRef domain_class{};
  CoverageState state{CoverageState::UnknownCoverage};
  std::string administrative_scope;
  /// Evidence class behind the declaration, when one exists.
  EvidenceClass evidence{EvidenceClass::Unknown};
  TruthClass truth{TruthClass::Unknown};
  bool declared{false};

  friend bool operator==(const CoverageEntry&, const CoverageEntry&) = default;
};

/// Deterministic coverage answer for a set of entities and classes.
struct CoverageReport {
  /// One entry per addressed class, in the order the caller asked for them.
  std::vector<CoverageEntry> entries;
  /// True when every addressed class is Complete.
  bool complete_for_all{false};
  /// True when at least one addressed class is Unknown.
  bool has_unknown{false};
  /// True when at least one addressed class is Partial.
  bool has_partial{false};
};

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_COVERAGE_HPP
