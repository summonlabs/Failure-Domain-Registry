// Failure Domain Registry — the failure-domain record.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A failure-domain record states what a common failure factor is, what class of
// factor it represents, which generation of that statement is current, and
// where the statement came from. It deliberately carries no live failure state,
// no health and no probability: those belong to other runtimes.

#ifndef FAILURE_DOMAIN_REGISTRY_DOMAIN_HPP
#define FAILURE_DOMAIN_REGISTRY_DOMAIN_HPP

#include <string>
#include <vector>

#include "failure_domain_registry/domain_class.hpp"
#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"
#include "failure_domain_registry/lifecycle.hpp"
#include "failure_domain_registry/provenance.hpp"

namespace failure_domain_registry {

/// One bounded key/value annotation attached to a domain or a membership.
struct MetadataEntry {
  std::string key;
  std::string value;
  friend bool operator==(const MetadataEntry&, const MetadataEntry&) = default;
};

/// One retained step of a domain's lineage. History is bounded and is never
/// current authority.
struct DomainHistoryEntry {
  /// Generation the record was at before the change.
  FailureDomainGeneration previous_generation{};
  /// Generation produced by the change.
  FailureDomainGeneration generation{};
  DomainLifecycle lifecycle{DomainLifecycle::Unknown};
  /// Short machine-readable cause, e.g. "superseded", "retired", "revalidated".
  std::string cause;
  /// Evidence class in force after the change.
  EvidenceClass evidence{EvidenceClass::Unknown};
  CoordinatorEpoch epoch{};
  RegistryGeneration at{};
  friend bool operator==(const DomainHistoryEntry&, const DomainHistoryEntry&) = default;
};

/// A failure domain: a correlated-failure classification, not a topology node
/// and not a health record.
struct FDR_API FailureDomain {
  FailureDomainId id{};
  DomainClassRef domain_class{};
  FailureDomainGeneration generation{};
  DomainLifecycle lifecycle{DomainLifecycle::Unknown};
  /// Optional canonical name. Never an identity: two domains may share a name
  /// and a domain may have none.
  std::string name;
  /// Administrative scope the domain belongs to. Never empty for a committed
  /// domain.
  std::string administrative_scope;
  Provenance provenance{};
  /// Generation the record was created at.
  FailureDomainGeneration created_generation{};
  RegistryGeneration created_at{};
  CoordinatorEpoch created_epoch{};
  /// Successor, when the record was superseded by a newer identity.
  FailureDomainId superseded_by{};
  /// The record this one replaced, when it was created as a successor.
  FailureDomainId supersedes{};
  /// Surviving domain, when this record was merged away.
  FailureDomainId merged_into{};
  std::vector<MetadataEntry> metadata;
  std::vector<DomainHistoryEntry> history;

  bool is_current() const noexcept { return failure_domain_registry::is_current(lifecycle); }
  bool is_terminal() const noexcept { return failure_domain_registry::is_terminal(lifecycle); }

  /// Deterministic multi-line rendering used by the CLI and the tests.
  std::string render() const;
  /// Canonical byte string fed to the semantic digest. Field order is fixed and
  /// containers are written in canonical order.
  std::string canonical_form() const;

  friend bool operator==(const FailureDomain&, const FailureDomain&) = default;
};

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_DOMAIN_HPP
