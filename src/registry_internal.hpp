// Failure Domain Registry — internal registry state.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// This header is private to the implementation. Everything it declares is
// reached through Registry's public API; nothing here is installed.
//
// Locking contract, stated once and honoured everywhere below:
//
//   * The shared_mutex in Registry::Impl guards the state tables only.
//   * A mutation takes the exclusive lock, performs the whole pipeline
//     (validate, index, commit, advance) and releases it before any I/O.
//   * A query takes the shared lock and copies out plain values.
//   * No path ever reacquires the lock, calls a caller-supplied callback while
//     holding it, or touches the file system while holding it. Persistence
//     therefore always serialises a state that was copied under the lock and
//     written after the lock was released.
//   * Lock ordering is total: a caller may take the registry lock and then any
//     session lock; the reverse order never occurs, because session handling
//     never holds its own lock while calling into the registry.

#ifndef FAILURE_DOMAIN_REGISTRY_SRC_REGISTRY_INTERNAL_HPP
#define FAILURE_DOMAIN_REGISTRY_SRC_REGISTRY_INTERNAL_HPP

#include <array>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "failure_domain_registry/registry.hpp"

namespace failure_domain_registry {

/// Index of the fixed-size lifecycle tables. Enum values are 1..7.
inline constexpr std::size_t kLifecycleSlots = 8;

struct RegistryState {
  CoordinatorEpoch epoch{};
  RegistryGeneration generation{};
  SnapshotSequence next_snapshot{SnapshotSequence::first()};
  std::uint64_t next_evidence_generation{1};

  std::unordered_map<FailureDomainId, std::shared_ptr<const FailureDomain>> domains;
  std::unordered_map<MembershipId, std::shared_ptr<const Membership>> memberships;
  std::unordered_map<DomainRelationId, std::shared_ptr<const DomainRelation>> relations;
  std::unordered_map<PublisherId, PublisherRegistration> publishers;
  std::unordered_map<PublisherId, std::vector<FenceRecord>> fences;
  std::unordered_map<PublisherId, std::vector<WorkerSession>> live_sessions;
  std::vector<CoverageDeclaration> coverage;
  std::unordered_map<DerivationRuleId, DerivationRule> rules;

  // Incrementally maintained indexes. No mutation rebuilds an index.
  std::unordered_map<EntityId, std::vector<MembershipId>> by_entity;
  std::unordered_map<FailureDomainId, std::vector<MembershipId>> by_domain;
  /// Memberships this publisher owns evidence on, not only those whose
  /// headline provenance is this publisher.
  std::unordered_map<PublisherId, std::vector<MembershipId>> by_publisher;
  std::unordered_map<std::string, std::vector<FailureDomainId>> by_class;
  std::unordered_map<std::string, std::vector<FailureDomainId>> by_scope;
  std::array<std::vector<FailureDomainId>, kLifecycleSlots> domains_by_lifecycle;
  std::array<std::vector<MembershipId>, kLifecycleSlots> memberships_by_lifecycle;
  std::unordered_map<FailureDomainId, std::vector<DomainRelationId>> relations_by_domain;
  /// Contained-by edges, both directions, from CONTAINED_BY relations only.
  std::unordered_map<FailureDomainId, std::vector<FailureDomainId>> children;
  std::unordered_map<FailureDomainId, std::vector<FailureDomainId>> parents;
};

struct Registry::Impl {
  explicit Impl(RegistryLimits limits_in);

  RegistryLimits limits;
  mutable std::shared_mutex mutex;
  RegistryState state;

  /// Bounded ring of the most recent outcomes, newest last.
  std::deque<Outcome> recent;
  static constexpr std::size_t kRecentCapacity = 256;

  struct RecordedMutation {
    RequestDigest digest{};
    Outcome outcome{};
  };
  /// Ordered by attempt id so that eviction is the single cheapest erase and
  /// never depends on hash iteration order.
  std::unordered_map<PublisherId, std::map<MutationAttemptId, RecordedMutation>> idempotency;
  std::size_t idempotency_entries{0};

  // --- identity and lookup -------------------------------------------------
  std::shared_ptr<const FailureDomain> find_domain(const FailureDomainId& id) const;
  std::shared_ptr<const Membership> find_membership(const MembershipId& id) const;
  const std::vector<MembershipId>* memberships_of_entity(const EntityId& entity) const;
  const std::vector<MembershipId>* memberships_of_domain(const FailureDomainId& id) const;
  const std::vector<FailureDomainId>* domains_of_class_key(const std::string& key) const;
  const std::vector<DomainRelationId>* relations_of_domain(const FailureDomainId& id) const;
  std::vector<MembershipId> sorted_entity_memberships(const EntityId& entity) const;

  // --- index maintenance ---------------------------------------------------
  void index_domain(const FailureDomain& record);
  void unindex_domain(const FailureDomain& record);
  void index_membership(const Membership& record);
  void unindex_membership(const Membership& record);
  void index_relation(const DomainRelation& record);
  void unindex_relation(const DomainRelation& record);

  void store_domain(FailureDomain record);
  void store_membership(Membership record);
  void store_relation(DomainRelation record);

  // --- rules ---------------------------------------------------------------
  /// Appends a lineage entry. It records the generation the record is at when
  /// the change is recorded; store_domain/store_membership finalise the entry
  /// with the post-change generation and lifecycle before it is committed.
  void push_domain_history(FailureDomain& record, std::string cause, std::size_t max_entries);
  void push_membership_history(Membership& record, std::string cause, std::size_t max_entries);

  bool has_relation(const FailureDomainId& source, const FailureDomainId& target,
                    DomainRelationType type) const;
  /// True when `to` is reachable from `from` following edges of the same
  /// acyclic relation type. Sets `bounded` when the walk hit max_ancestor_walk.
  bool path_exists(const FailureDomainId& from, const FailureDomainId& to,
                   DomainRelationType type, bool* bounded) const;

  // --- authority -----------------------------------------------------------
  Outcome authorize(const AuthorityContext& authority, const DomainClassRef& domain_class,
                    const std::string& administrative_scope) const;
  Outcome authorize_any(const AuthorityContext& authority,
                        const std::string& administrative_scope) const;
  bool is_worker_fenced(const PublisherId& publisher, const WorkerBootId& worker_boot) const;

  // --- evidence and demotion ----------------------------------------------
  EvidenceGeneration next_evidence_generation();

  void demote_memberships_of_domain(const FailureDomainId& domain,
                                    MembershipLifecycle target,
                                    const std::string& cause);
  void demote_memberships_of_entity_generation(const EntityId& entity,
                                               EntityGeneration superseded_generation,
                                               MembershipLifecycle target,
                                               const std::string& cause);
  /// Demotes every process-bound domain that this incarnation established.
  /// Shared by reincarnation, explicit fencing and an epoch advance, so the
  /// three paths cannot diverge.
  void demote_process_bound_domains(const PublisherId& publisher, const WorkerBootId& worker_boot,
                                    const std::string& cause);
  void withdraw_publisher_evidence(const PublisherId& publisher, const WorkerBootId& worker_boot,
                                   bool match_boot, EvidenceClass evidence,
                                   bool only_process_bound, MembershipLifecycle target,
                                   const std::string& cause);
  void invalidate_derived_memberships(const std::vector<EntityId>& affected);

  // --- coverage ------------------------------------------------------------
  CoverageState coverage_for(const std::string& administrative_scope,
                             const std::string& class_key) const;
  /// Builds a coverage report from the state tables. The caller must already
  /// hold the registry lock; this helper never acquires it, which is what keeps
  /// independence() from reacquiring the shared lock it already holds.
  CoverageReport coverage_locked(std::string_view administrative_scope,
                                 const std::vector<DomainClassRef>& classes) const;
  std::vector<std::string> effective_scopes(const std::vector<EntityId>& entities,
                                            std::string_view explicit_scope) const;

  // --- derivation ----------------------------------------------------------
  Outcome evaluate_rule(const DerivationRule& rule, RegistryGeneration at,
                        DerivationReport& report);
  Outcome run_derivation_locked(const DerivationRuleId& only_rule, DerivationReport& report);

  // --- outcomes ------------------------------------------------------------
  Outcome record(Outcome outcome);
  void remember_mutation(const PublisherId& publisher, const MutationAttemptId& attempt,
                         const RequestDigest& digest, const Outcome& outcome);
  std::optional<RecordedMutation> find_mutation(const PublisherId& publisher,
                                                const MutationAttemptId& attempt) const;

  // --- shared pipeline steps ----------------------------------------------
  Outcome check_attempt(const MutationAttempt& attempt, RequestDigest computed,
                        const AuthorityContext& authority) const;
  Outcome check_domain_limits() const;
  Outcome check_membership_limits() const;
  /// Rejects a record whose persisted encoding would exceed max_record_bytes.
  Outcome check_record_size(const FailureDomain& record) const;
  Outcome check_record_size(const Membership& record) const;
  Outcome check_record_size(const DomainRelation& record) const;
  /// Longest containment chain above (respectively below) a domain.
  std::size_t hierarchy_depth_above(const FailureDomainId& id) const;
  std::size_t hierarchy_depth_below(const FailureDomainId& id) const;

  void bump_generation();
  StateDigest compute_state_digest() const;
  void gc_idempotency(const PublisherId& publisher);
};

/// Semantic digest of a registry state: the same classification digests the
/// same regardless of the order it arrived in.
StateDigest compute_state_digest_of(const RegistryState& state);

/// Byte width of a record in the persisted encoding.
std::size_t encoded_domain_bytes(const FailureDomain& record);
std::size_t encoded_membership_bytes(const Membership& record);
std::size_t encoded_relation_bytes(const DomainRelation& record);

/// Every publisher that owns evidence on a membership, headline included.
std::vector<PublisherId> membership_evidence_publishers(const Membership& record);

/// Canonical ordering helpers used by digests, snapshot diffs and the CLI.
bool membership_id_less(const MembershipId& left, const MembershipId& right);
bool domain_id_less(const FailureDomainId& left, const FailureDomainId& right);

/// Renders an entity-id list deterministically.
std::string render_entity_list(const std::vector<EntityId>& entities);

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_SRC_REGISTRY_INTERNAL_HPP
