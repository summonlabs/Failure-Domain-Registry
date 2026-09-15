// Failure Domain Registry — the registry itself.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Registry owns every mutable byte of classification state. It is neither
// copyable nor movable. Queries return values; no query hands out a reference
// into registry state and no query exposes a mutable container.
//
// Thread safety: every public method is safe to call from any thread. Queries
// take a shared lock and mutations take the exclusive lock; both hold it only
// for the duration of the state change, never across persistence I/O, never
// across a callback and never across a nested registry call that would
// reacquire the lock.

#ifndef FAILURE_DOMAIN_REGISTRY_REGISTRY_HPP
#define FAILURE_DOMAIN_REGISTRY_REGISTRY_HPP

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "failure_domain_registry/authority.hpp"
#include "failure_domain_registry/coverage.hpp"
#include "failure_domain_registry/derivation.hpp"
#include "failure_domain_registry/domain.hpp"
#include "failure_domain_registry/errors.hpp"
#include "failure_domain_registry/explanation.hpp"
#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"
#include "failure_domain_registry/limits.hpp"
#include "failure_domain_registry/membership.hpp"
#include "failure_domain_registry/persistence.hpp"
#include "failure_domain_registry/query.hpp"
#include "failure_domain_registry/relation.hpp"
#include "failure_domain_registry/requests.hpp"
#include "failure_domain_registry/snapshot.hpp"

namespace failure_domain_registry {

/// Record of one live publisher incarnation.
struct WorkerSession {
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  CoordinatorEpoch attached_epoch{};
  EvidenceClass max_evidence{EvidenceClass::Unknown};
  std::string client_label;
  friend bool operator==(const WorkerSession&, const WorkerSession&) = default;
};

class FDR_API Registry {
public:
  explicit Registry(RegistryLimits limits = RegistryLimits::defaults());
  ~Registry();

  Registry(const Registry&) = delete;
  Registry& operator=(const Registry&) = delete;
  Registry(Registry&&) = delete;
  Registry& operator=(Registry&&) = delete;

  const RegistryLimits& limits() const noexcept;

  // -------------------------------------------------------------------------
  // Authority and epoch
  // -------------------------------------------------------------------------

  /// Installs or replaces a durable authority grant. Requires an existing
  /// grant whose scope covers the PublisherRegistration class boundary, or an
  /// empty registry (bootstrap).
  Outcome grant_publisher(const PublisherRegistration& registration,
                          const AuthorityContext& authority);

  /// Attaches a live incarnation of a publisher at the given epoch. A new boot
  /// id fences the previous one for the same publisher.
  Outcome attach_worker(const PublisherId& publisher,
                        const WorkerBootId& worker_boot,
                        CoordinatorEpoch epoch,
                        std::string client_label,
                        EvidenceClass max_evidence);

  /// Fences one incarnation and demotes exactly the evidence that depended on
  /// it.
  Outcome fence_worker(const PublisherId& publisher,
                       const WorkerBootId& worker_boot,
                       FenceReason reason,
                       CoordinatorEpoch epoch);

  /// Advances the coordinator epoch. The caller must supply the epoch it
  /// believes is current. Every live incarnation of the previous epoch is
  /// fenced with reason CoordinatorRestart.
  Outcome advance_epoch(CoordinatorEpoch expected, CoordinatorEpoch* new_epoch);

  CoordinatorEpoch epoch() const noexcept;
  RegistryGeneration generation() const noexcept;

  std::optional<PublisherRegistration> publisher(const PublisherId& id) const;
  std::vector<PublisherRegistration> publishers() const;
  std::vector<WorkerSession> live_sessions() const;
  std::vector<FenceRecord> fences() const;
  bool is_worker_live(const PublisherId& publisher, const WorkerBootId& worker_boot) const;
  /// Every (publisher, worker boot) pair that published process-bound evidence
  /// into the current state. Conservative recovery fences exactly these after a
  /// restart, because durability never proves that the process is still there.
  std::vector<std::pair<PublisherId, WorkerBootId>> process_bound_incarnations() const;

  // -------------------------------------------------------------------------
  // Domain operations
  // -------------------------------------------------------------------------

  Outcome create_domain(const CreateDomainRequest& request);
  Outcome update_domain(const UpdateDomainRequest& request);
  Outcome supersede_domain(const SupersedeDomainRequest& request);
  Outcome retire_domain(const RetireDomainRequest& request);
  Outcome add_relation(const AddRelationRequest& request);
  Outcome merge_domains(const MergeDomainsRequest& request);

  // -------------------------------------------------------------------------
  // Membership operations
  // -------------------------------------------------------------------------

  Outcome attach_member(const AttachMemberRequest& request);
  Outcome detach_member(const DetachMemberRequest& request);
  Outcome replace_membership(const ReplaceMembershipRequest& request);
  Outcome publish_memberships(const MembershipBatchRequest& request);
  Outcome withdraw_evidence(const WithdrawEvidenceRequest& request);
  Outcome reconcile_membership(const ReconcileMembershipRequest& request);
  Outcome mark_revalidation_required(const MarkRevalidationRequest& request);
  Outcome declare_coverage(const DeclareCoverageRequest& request);

  // -------------------------------------------------------------------------
  // Invalidation
  // -------------------------------------------------------------------------

  Outcome invalidate_entity(const EntityInvalidationRequest& request);
  Outcome notify_topology_change(const TopologyChangeRequest& request);

  // -------------------------------------------------------------------------
  // Derivation
  // -------------------------------------------------------------------------

  Outcome publish_derivation_rule(const DerivationRule& rule, const AuthorityContext& authority);
  std::vector<DerivationRule> derivation_rules() const;
  Outcome run_derivation(const DerivationRunRequest& request, DerivationReport* report);

  // -------------------------------------------------------------------------
  // Queries. All of them return values.
  // -------------------------------------------------------------------------

  std::optional<FailureDomain> domain(const FailureDomainId& id) const;
  std::vector<FailureDomain> domains(std::size_t max_records) const;
  std::vector<FailureDomain> domains_of_class(const DomainClassRef& domain_class) const;
  std::vector<FailureDomain> domains_in_scope(std::string_view scope) const;
  std::vector<FailureDomain> domains_in_lifecycle(DomainLifecycle lifecycle) const;
  std::vector<DomainRelation> relations_of(const FailureDomainId& id) const;

  std::vector<Membership> memberships_of(const EntityId& entity) const;
  std::vector<Membership> memberships_of(const EntityRef& entity) const;
  std::vector<Membership> members_of(const FailureDomainId& id) const;
  std::vector<Membership> memberships_of_publisher(const PublisherId& id) const;
  std::vector<Membership> memberships_in_lifecycle(MembershipLifecycle lifecycle) const;
  std::optional<Membership> membership(const MembershipId& id) const;
  std::size_t domain_count() const;
  std::size_t membership_count() const;

  std::vector<FailureDomainId> ancestors(const FailureDomainId& id) const;
  std::vector<FailureDomainId> descendants(const FailureDomainId& id) const;

  OverlapResult overlap(const EntityId& left, const EntityId& right) const;
  OverlapResult overlap(const std::vector<EntityId>& entities) const;
  IndependenceResult independence(const std::vector<EntityId>& entities,
                                  const std::vector<DomainClassRef>& classes) const;
  /// Explicit-scope form. An empty scope means "derive the effective scope from
  /// the addressed entities' current memberships", which is what the two
  /// argument form does.
  IndependenceResult independence(const std::vector<EntityId>& entities,
                                  const std::vector<DomainClassRef>& classes,
                                  std::string_view administrative_scope) const;
  CoverageReport coverage(std::string_view administrative_scope,
                          const std::vector<DomainClassRef>& classes) const;
  BlastRadius blast_radius(const FailureDomainId& id) const;
  SetCorrelation correlate_member_sets(const std::vector<EntityId>& left,
                                       const std::vector<EntityId>& right,
                                       const std::vector<DomainClassRef>& classes) const;
  SetCorrelation correlate_member_sets(const std::vector<EntityId>& left,
                                       const std::vector<EntityId>& right,
                                       const std::vector<DomainClassRef>& classes,
                                       std::string_view administrative_scope) const;

  // -------------------------------------------------------------------------
  // Snapshots, digests and diffs
  // -------------------------------------------------------------------------

  Snapshot snapshot(std::string_view scope) const;
  bool snapshot_is_current(const Snapshot& snapshot) const;
  SnapshotDiff diff(const Snapshot& before, const Snapshot& after) const;
  StateDigest state_digest() const;

  /// Recomputes every index from the record tables and compares. Returns false
  /// and fills `why` with the first difference found.
  bool validate_state(std::string* why) const;

  // -------------------------------------------------------------------------
  // Explanations
  // -------------------------------------------------------------------------

  Explanation explain_membership(const FailureDomainId& domain, const EntityId& entity) const;
  Explanation explain_domain(const FailureDomainId& id) const;
  Explanation explain_independence(const std::vector<EntityId>& entities,
                                   const std::vector<DomainClassRef>& classes) const;
  Explanation explain_conflict(const FailureDomainId& domain, const EntityId& entity) const;
  Explanation explain_outcome(const RequestDigest& digest) const;
  Explanation explain_generation() const;
  std::vector<Outcome> recent_outcomes(std::size_t max_records) const;

  // -------------------------------------------------------------------------
  // Persistence
  // -------------------------------------------------------------------------

  Outcome save(const PersistenceConfig& config) const;
  Outcome load(const PersistenceConfig& config);
  /// Drops all state. The epoch is preserved so that a reset registry does not
  /// resurrect old-epoch traffic.
  Outcome reset();

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_REGISTRY_HPP
