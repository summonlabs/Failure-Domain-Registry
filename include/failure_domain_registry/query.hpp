// Failure Domain Registry — query results.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every query result is a value: it copies what it needs and never hands out a
// mutable internal container or a reference into registry state.

#ifndef FAILURE_DOMAIN_REGISTRY_QUERY_HPP
#define FAILURE_DOMAIN_REGISTRY_QUERY_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "failure_domain_registry/coverage.hpp"
#include "failure_domain_registry/domain.hpp"
#include "failure_domain_registry/entity.hpp"
#include "failure_domain_registry/errors.hpp"
#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"
#include "failure_domain_registry/membership.hpp"

namespace failure_domain_registry {

/// The answer to an independence question.
enum class IndependenceState : std::uint8_t {
  Unknown = 0,
  /// Every addressed class has complete coverage in scope, and no current
  /// membership places the entities in a common domain of any of them.
  ProvenIndependent = 1,
  /// At least two of the entities share a current failure domain.
  SharedDomain = 2,
  /// The registry cannot answer: coverage is partial or unknown for at least
  /// one addressed class.
  UnknownCoverage = 3,
  /// A record needed for the answer is in REVALIDATION_REQUIRED.
  RevalidationRequired = 4,
  /// A record needed for the answer is CONFLICTED.
  Conflicted = 5,
  /// The registry holds no membership knowledge at all for the addressed
  /// entities and classes.
  NoKnowledge = 6,
};

FDR_API std::string_view to_string(IndependenceState value) noexcept;

/// One domain shared by the entities an overlap query addressed.
struct SharedDomain {
  FailureDomainId domain{};
  DomainClassRef domain_class{};
  FailureDomainGeneration generation{};
  /// Members of the query set that are current members of this domain, in the
  /// order the caller supplied them.
  std::vector<EntityRef> members;
  /// True when the domain is one of the most specific shared domains, i.e. no
  /// other shared domain is contained by it.
  bool most_specific{false};

  friend bool operator==(const SharedDomain&, const SharedDomain&) = default;
};

/// The result of a pairwise or multi-entity overlap query.
struct OverlapResult {
  IndependenceState state{IndependenceState::Unknown};
  /// Shared current domains, ordered by class name then domain id.
  std::vector<SharedDomain> shared;
  /// Classes for which coverage did not permit a negative answer.
  std::vector<DomainClassRef> uncovered_classes;
  /// Classes for which a record was conflicted or needs revalidation.
  std::vector<DomainClassRef> indeterminate_classes;
  /// Ordered explanation of how the answer was reached.
  std::vector<ExplanationStep> steps;
  /// True when the addressed set exceeded the configured cardinality bound and
  /// the answer covers only the first entries.
  bool truncated{false};

  bool shares_any_domain() const noexcept { return !shared.empty(); }
};

/// The result of an independence query.
struct IndependenceResult {
  IndependenceState state{IndependenceState::Unknown};
  /// Shared domains that caused a SharedDomain answer.
  std::vector<SharedDomain> shared;
  /// Coverage answer for every addressed class.
  CoverageReport coverage;
  std::vector<ExplanationStep> steps;
  /// True when the addressed set exceeded the configured cardinality bound.
  bool truncated{false};

  bool proven_independent() const noexcept { return state == IndependenceState::ProvenIndependent; }
};

/// The blast radius of one domain: current membership plus child-domain
/// structure. It states membership, never affectedness.
struct BlastRadius {
  FailureDomainId domain{};
  DomainClassRef domain_class{};
  FailureDomainGeneration generation{};
  DomainLifecycle lifecycle{DomainLifecycle::Unknown};
  /// Current members, ordered by entity class then entity id then generation.
  std::vector<EntityRef> members;
  /// Domains that are CONTAINED_BY this domain, transitively.
  std::vector<FailureDomainId> child_domains;
  /// Domains related to this domain by any other relation type.
  std::vector<FailureDomainId> related_domains;
  /// Classes represented among the members, in canonical order.
  std::vector<DomainClassRef> member_domain_classes;
  /// True when the walk hit a configured bound and the answer is incomplete.
  bool truncated{false};
};

/// The failure-domain correlation between two caller-supplied member sets.
///
/// The caller supplies the sets. This runtime never computes a path, never
/// enumerates links and never decides which path to use.
struct SetCorrelation {
  IndependenceState state{IndependenceState::Unknown};
  /// Domains whose current membership intersects both sets.
  std::vector<SharedDomain> shared_domains;
  /// Classes in which the two sets share at least one current domain.
  std::vector<DomainClassRef> shared_classes;
  /// Classes addressed by the caller whose coverage did not permit an answer.
  std::vector<DomainClassRef> unknown_classes;
  std::vector<ExplanationStep> steps;
};

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_QUERY_HPP
