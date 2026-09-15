// Failure Domain Registry - registry state, indexes and authority.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "registry_internal.hpp"

#include <algorithm>
#include <set>
#include <stdexcept>

#include "failure_domain_registry/digest.hpp"

namespace failure_domain_registry {
namespace {

std::string class_key(const DomainClassRef& value) { return value.to_string(); }

template <class T>
void erase_value(std::vector<T>& values, const T& value) {
  values.erase(std::remove(values.begin(), values.end(), value), values.end());
}

} // namespace

bool membership_id_less(const MembershipId& left, const MembershipId& right) { return left < right; }
bool domain_id_less(const FailureDomainId& left, const FailureDomainId& right) { return left < right; }

std::string render_entity_list(const std::vector<EntityId>& entities) {
  std::string out;
  for (std::size_t i = 0; i < entities.size(); ++i) {
    if (i != 0) {
      out.push_back(',');
    }
    out.append(entities[i].to_string());
  }
  return out;
}

// ---------------------------------------------------------------------------
// Impl: construction and lookup
// ---------------------------------------------------------------------------

Registry::Impl::Impl(RegistryLimits limits_in) : limits(limits_in) {
  const ValidationResult valid = limits.validate();
  if (!valid) {
    throw std::invalid_argument("invalid RegistryLimits: " + valid.message);
  }
}

std::shared_ptr<const FailureDomain> Registry::Impl::find_domain(const FailureDomainId& id) const {
  const auto it = state.domains.find(id);
  return it == state.domains.end() ? nullptr : it->second;
}

std::shared_ptr<const Membership> Registry::Impl::find_membership(const MembershipId& id) const {
  const auto it = state.memberships.find(id);
  return it == state.memberships.end() ? nullptr : it->second;
}

const std::vector<MembershipId>* Registry::Impl::memberships_of_entity(const EntityId& entity) const {
  const auto it = state.by_entity.find(entity);
  return it == state.by_entity.end() ? nullptr : &it->second;
}

const std::vector<MembershipId>* Registry::Impl::memberships_of_domain(const FailureDomainId& id) const {
  const auto it = state.by_domain.find(id);
  return it == state.by_domain.end() ? nullptr : &it->second;
}

const std::vector<FailureDomainId>* Registry::Impl::domains_of_class_key(const std::string& key) const {
  const auto it = state.by_class.find(key);
  return it == state.by_class.end() ? nullptr : &it->second;
}

const std::vector<DomainRelationId>* Registry::Impl::relations_of_domain(const FailureDomainId& id) const {
  const auto it = state.relations_by_domain.find(id);
  return it == state.relations_by_domain.end() ? nullptr : &it->second;
}

std::vector<MembershipId> Registry::Impl::sorted_entity_memberships(const EntityId& entity) const {
  std::vector<MembershipId> ids;
  const std::vector<MembershipId>* raw = memberships_of_entity(entity);
  if (raw != nullptr) {
    ids = *raw;
  }
  std::sort(ids.begin(), ids.end(), membership_id_less);
  return ids;
}

// ---------------------------------------------------------------------------
// Impl: index maintenance
// ---------------------------------------------------------------------------

void Registry::Impl::index_domain(const FailureDomain& record) {
  state.by_class[class_key(record.domain_class)].push_back(record.id);
  state.by_scope[record.administrative_scope].push_back(record.id);
  const auto slot = static_cast<std::size_t>(record.lifecycle);
  if (slot < kLifecycleSlots) {
    state.domains_by_lifecycle[slot].push_back(record.id);
  }
}

void Registry::Impl::unindex_domain(const FailureDomain& record) {
  const auto class_it = state.by_class.find(class_key(record.domain_class));
  if (class_it != state.by_class.end()) {
    erase_value(class_it->second, record.id);
    if (class_it->second.empty()) {
      state.by_class.erase(class_it);
    }
  }
  const auto scope_it = state.by_scope.find(record.administrative_scope);
  if (scope_it != state.by_scope.end()) {
    erase_value(scope_it->second, record.id);
    if (scope_it->second.empty()) {
      state.by_scope.erase(scope_it);
    }
  }
  const auto slot = static_cast<std::size_t>(record.lifecycle);
  if (slot < kLifecycleSlots) {
    erase_value(state.domains_by_lifecycle[slot], record.id);
  }
}

void Registry::Impl::index_membership(const Membership& record) {
  state.by_entity[record.member.id()].push_back(record.id);
  state.by_domain[record.domain].push_back(record.id);
  if (record.provenance.has_publisher()) {
    state.by_publisher[record.provenance.publisher].push_back(record.id);
  }
  const auto slot = static_cast<std::size_t>(record.lifecycle);
  if (slot < kLifecycleSlots) {
    state.memberships_by_lifecycle[slot].push_back(record.id);
  }
}

void Registry::Impl::unindex_membership(const Membership& record) {
  const auto entity_it = state.by_entity.find(record.member.id());
  if (entity_it != state.by_entity.end()) {
    erase_value(entity_it->second, record.id);
    if (entity_it->second.empty()) {
      state.by_entity.erase(entity_it);
    }
  }
  const auto domain_it = state.by_domain.find(record.domain);
  if (domain_it != state.by_domain.end()) {
    erase_value(domain_it->second, record.id);
    if (domain_it->second.empty()) {
      state.by_domain.erase(domain_it);
    }
  }
  if (record.provenance.has_publisher()) {
    const auto publisher_it = state.by_publisher.find(record.provenance.publisher);
    if (publisher_it != state.by_publisher.end()) {
      erase_value(publisher_it->second, record.id);
      if (publisher_it->second.empty()) {
        state.by_publisher.erase(publisher_it);
      }
    }
  }
  const auto slot = static_cast<std::size_t>(record.lifecycle);
  if (slot < kLifecycleSlots) {
    erase_value(state.memberships_by_lifecycle[slot], record.id);
  }
}

void Registry::Impl::index_relation(const DomainRelation& record) {
  state.relations_by_domain[record.source].push_back(record.id);
  state.relations_by_domain[record.target].push_back(record.id);
  if (record.type == DomainRelationType::ContainedBy) {
    state.children[record.target].push_back(record.source);
    state.parents[record.source].push_back(record.target);
  }
}

void Registry::Impl::unindex_relation(const DomainRelation& record) {
  auto source_it = state.relations_by_domain.find(record.source);
  if (source_it != state.relations_by_domain.end()) {
    erase_value(source_it->second, record.id);
    if (source_it->second.empty()) {
      state.relations_by_domain.erase(source_it);
    }
  }
  auto target_it = state.relations_by_domain.find(record.target);
  if (target_it != state.relations_by_domain.end()) {
    erase_value(target_it->second, record.id);
    if (target_it->second.empty()) {
      state.relations_by_domain.erase(target_it);
    }
  }
  if (record.type == DomainRelationType::ContainedBy) {
    auto child_it = state.children.find(record.target);
    if (child_it != state.children.end()) {
      erase_value(child_it->second, record.source);
      if (child_it->second.empty()) {
        state.children.erase(child_it);
      }
    }
    auto parent_it = state.parents.find(record.source);
    if (parent_it != state.parents.end()) {
      erase_value(parent_it->second, record.target);
      if (parent_it->second.empty()) {
        state.parents.erase(parent_it);
      }
    }
  }
}

void Registry::Impl::store_domain(FailureDomain record) {
  const auto existing = state.domains.find(record.id);
  if (existing != state.domains.end()) {
    unindex_domain(*existing->second);
  }
  index_domain(record);
  state.domains[record.id] = std::make_shared<const FailureDomain>(std::move(record));
}

void Registry::Impl::store_membership(Membership record) {
  const auto existing = state.memberships.find(record.id);
  if (existing != state.memberships.end()) {
    unindex_membership(*existing->second);
  }
  index_membership(record);
  state.memberships[record.id] = std::make_shared<const Membership>(std::move(record));
}

void Registry::Impl::store_relation(DomainRelation record) {
  const auto existing = state.relations.find(record.id);
  if (existing != state.relations.end()) {
    unindex_relation(*existing->second);
  }
  index_relation(record);
  state.relations[record.id] = std::make_shared<const DomainRelation>(std::move(record));
}

// ---------------------------------------------------------------------------
// Impl: history and relations
// ---------------------------------------------------------------------------

void Registry::Impl::push_domain_history(FailureDomain& record, std::string cause, std::size_t max_entries) {
  DomainHistoryEntry entry;
  entry.previous_generation = record.generation;
  entry.generation = record.generation;
  entry.lifecycle = record.lifecycle;
  entry.cause = std::move(cause);
  entry.evidence = record.provenance.evidence;
  entry.epoch = record.created_epoch;
  entry.at = record.created_at;
  record.history.push_back(std::move(entry));
  if (max_entries > 0 && record.history.size() > max_entries) {
    const std::size_t drop = record.history.size() - max_entries;
    record.history.erase(record.history.begin(),
                         record.history.begin() + static_cast<std::ptrdiff_t>(drop));
  }
}

void Registry::Impl::push_membership_history(Membership& record, std::string cause, std::size_t max_entries) {
  MembershipHistoryEntry entry;
  entry.previous_generation = record.generation;
  entry.generation = record.generation;
  entry.lifecycle = record.lifecycle;
  entry.cause = std::move(cause);
  entry.evidence = record.provenance.evidence;
  entry.epoch = record.created_epoch;
  entry.at = record.created_at;
  record.history.push_back(std::move(entry));
  if (max_entries > 0 && record.history.size() > max_entries) {
    const std::size_t drop = record.history.size() - max_entries;
    record.history.erase(record.history.begin(),
                         record.history.begin() + static_cast<std::ptrdiff_t>(drop));
  }
}

bool Registry::Impl::has_relation(const FailureDomainId& source, const FailureDomainId& target,
                                  DomainRelationType type) const {
  return state.relations.find(relation_id_for(source, target, type)) != state.relations.end();
}

bool Registry::Impl::path_exists(const FailureDomainId& from, const FailureDomainId& to,
                                 DomainRelationType type, bool* bounded) const {
  if (from == to) {
    return true;
  }
  std::vector<FailureDomainId> frontier{from};
  std::set<FailureDomainId> seen;
  seen.insert(from);
  std::size_t visited = 0;
  while (!frontier.empty()) {
    std::vector<FailureDomainId> next;
    for (const FailureDomainId& current : frontier) {
      if (++visited > limits.max_ancestor_walk) {
        if (bounded != nullptr) {
          *bounded = true;
        }
        return false;
      }
      const std::vector<DomainRelationId>* edges = relations_of_domain(current);
      if (edges == nullptr) {
        continue;
      }
      for (const DomainRelationId& edge_id : *edges) {
        const auto edge_it = state.relations.find(edge_id);
        if (edge_it == state.relations.end()) {
          continue;
        }
        const DomainRelation& edge = *edge_it->second;
        if (edge.type != type || edge.source != current) {
          continue;
        }
        if (edge.target == to) {
          return true;
        }
        if (seen.insert(edge.target).second) {
          next.push_back(edge.target);
        }
      }
    }
    frontier.swap(next);
  }
  return false;
}

bool Registry::Impl::is_worker_fenced(const PublisherId& publisher, const WorkerBootId& worker_boot) const {
  const auto it = state.fences.find(publisher);
  if (it == state.fences.end()) {
    return false;
  }
  for (const FenceRecord& record : it->second) {
    if (record.worker_boot == worker_boot) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Impl: authority
// ---------------------------------------------------------------------------

Outcome Registry::Impl::authorize(const AuthorityContext& authority, const DomainClassRef& domain_class,
                                  const std::string& administrative_scope) const {
  Outcome outcome = authorize_any(authority, administrative_scope);
  if (!outcome.committed()) {
    return outcome;
  }
  const PublisherRegistration& registration = state.publishers.at(authority.publisher);
  if (!registration.scope.allows_class(domain_class.classification())) {
    return Outcome::make(OutcomeCode::UnauthorizedScope,
                         "publisher is not authorized for domain class " + domain_class.to_string())
        .field_step("authority", "class", domain_class.to_string(), "scope does not allow it");
  }
  return Outcome::make(OutcomeCode::Committed, "authorized");
}

Outcome Registry::Impl::authorize_any(const AuthorityContext& authority,
                                      const std::string& administrative_scope) const {
  if (!authority.is_complete()) {
    return Outcome::make(OutcomeCode::NoAuthority,
                         "mutation requires publisher, worker boot and coordinator epoch");
  }
  const auto publisher_it = state.publishers.find(authority.publisher);
  if (publisher_it == state.publishers.end()) {
    return Outcome::make(OutcomeCode::StaleAuthority, "publisher is not registered")
        .field_step("authority", "publisher", authority.publisher.to_string(), "unknown publisher");
  }
  const PublisherRegistration& registration = publisher_it->second;
  if (!registration.scope.allows_scope(administrative_scope)) {
    return Outcome::make(OutcomeCode::UnauthorizedScope,
                         "publisher is confined to administrative scope " +
                             registration.scope.administrative_scope)
        .field_step("authority", "scope", administrative_scope, "outside the granted scope");
  }
  if (!registration.scope.allows_evidence(authority.evidence)) {
    return Outcome::make(OutcomeCode::UnauthorizedScope,
                         "publisher may not assert evidence class " +
                             std::string(failure_domain_registry::to_string(authority.evidence)))
        .field_step("authority", "evidence",
                    std::string(failure_domain_registry::to_string(authority.evidence)),
                    "weaker than or equal to the granted maximum is required");
  }
  if (authority.epoch != state.epoch) {
    return Outcome::make(OutcomeCode::StaleEpoch, "coordinator epoch is not current")
        .field_step("authority", "epoch", authority.epoch.to_string(),
                    "current epoch is " + state.epoch.to_string());
  }
  if (is_worker_fenced(authority.publisher, authority.worker_boot)) {
    return Outcome::make(OutcomeCode::StaleWorkerBoot, "worker incarnation has been fenced")
        .field_step("authority", "worker-boot", authority.worker_boot.to_string(), "fenced");
  }
  const auto session_it = state.live_sessions.find(authority.publisher);
  if (session_it == state.live_sessions.end()) {
    return Outcome::make(OutcomeCode::StaleAuthority, "publisher has no live incarnation")
        .field_step("authority", "worker-boot", authority.worker_boot.to_string(), "not attached");
  }
  bool live = false;
  for (const WorkerSession& session : session_it->second) {
    if (session.worker_boot == authority.worker_boot) {
      live = true;
      break;
    }
  }
  if (!live) {
    return Outcome::make(OutcomeCode::StaleAuthority, "worker incarnation is not attached")
        .field_step("authority", "worker-boot", authority.worker_boot.to_string(),
                    "no live session for this incarnation");
  }
  return Outcome::make(OutcomeCode::Committed, "authorized");
}

// ---------------------------------------------------------------------------
// Impl: generations, outcomes, idempotency
// ---------------------------------------------------------------------------

EvidenceGeneration Registry::Impl::next_evidence_generation() {
  const EvidenceGeneration generation = EvidenceGeneration(state.next_evidence_generation);
  ++state.next_evidence_generation;
  return generation;
}

void Registry::Impl::bump_generation() {
  const std::optional<RegistryGeneration> next = state.generation.next();
  if (next.has_value()) {
    state.generation = *next;
  }
}

Outcome Registry::Impl::record(Outcome outcome) {
  outcome.state_generation = state.generation;
  outcome.epoch = state.epoch;
  recent.push_back(outcome);
  while (recent.size() > kRecentCapacity) {
    recent.pop_front();
  }
  return outcome;
}

void Registry::Impl::remember_mutation(const PublisherId& publisher, const MutationAttemptId& attempt,
                                       const RequestDigest& digest, const Outcome& outcome) {
  auto& table = idempotency[publisher];
  if (table.find(attempt) == table.end()) {
    ++idempotency_entries;
  }
  RecordedMutation recorded;
  recorded.digest = digest;
  recorded.outcome = outcome;
  table[attempt] = std::move(recorded);
  gc_idempotency(publisher);
}

void Registry::Impl::gc_idempotency(const PublisherId& publisher) {
  const auto table_it = idempotency.find(publisher);
  if (table_it == idempotency.end()) {
    return;
  }
  // Deterministic and O(1) per evicted entry: the table is ordered by attempt
  // id, so the smallest attempt id is the first element.
  while (table_it->second.size() > limits.max_idempotency_entries_per_publisher) {
    table_it->second.erase(table_it->second.begin());
    if (idempotency_entries > 0) {
      --idempotency_entries;
    }
  }
}

std::optional<Registry::Impl::RecordedMutation> Registry::Impl::find_mutation(
    const PublisherId& publisher, const MutationAttemptId& attempt) const {
  const auto table_it = idempotency.find(publisher);
  if (table_it == idempotency.end()) {
    return std::nullopt;
  }
  const auto entry_it = table_it->second.find(attempt);
  if (entry_it == table_it->second.end()) {
    return std::nullopt;
  }
  return entry_it->second;
}

Outcome Registry::Impl::check_attempt(const MutationAttempt& attempt, RequestDigest computed,
                                      const AuthorityContext& authority) const {
  if (attempt.id().is_null()) {
    return Outcome::make(OutcomeCode::MalformedRequest, "mutation attempt id is null");
  }
  if (!attempt.digest().is_null() && !(attempt.digest() == computed)) {
    return Outcome::make(OutcomeCode::MalformedRequest,
                         "supplied request digest does not match the request content")
        .field_step("validate", "request-digest", attempt.digest().to_string(),
                    "expected " + computed.to_string());
  }
  if (!authority.is_complete()) {
    return Outcome::make(OutcomeCode::NoAuthority,
                         "mutation requires publisher, worker boot and coordinator epoch");
  }
  return Outcome::make(OutcomeCode::Committed, "attempt accepted");
}

Outcome Registry::Impl::check_domain_limits() const {
  if (state.domains.size() >= limits.max_domains) {
    return Outcome::make(OutcomeCode::ResourceLimit, "domain limit reached")
        .field_step("commit", "max_domains", std::to_string(limits.max_domains), "limit reached");
  }
  return Outcome::make(OutcomeCode::Committed, "within limits");
}

Outcome Registry::Impl::check_membership_limits() const {
  if (state.memberships.size() >= limits.max_memberships) {
    return Outcome::make(OutcomeCode::ResourceLimit, "membership limit reached")
        .field_step("commit", "max_memberships", std::to_string(limits.max_memberships),
                    "limit reached");
  }
  return Outcome::make(OutcomeCode::Committed, "within limits");
}

// ---------------------------------------------------------------------------
// Registry: construction and basic accessors
// ---------------------------------------------------------------------------

Registry::Registry(RegistryLimits limits) : impl_(std::make_unique<Impl>(limits)) {}

Registry::~Registry() = default;

const RegistryLimits& Registry::limits() const noexcept { return impl_->limits; }

CoordinatorEpoch Registry::epoch() const noexcept {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  return impl_->state.epoch;
}

RegistryGeneration Registry::generation() const noexcept {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  return impl_->state.generation;
}

std::size_t Registry::domain_count() const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  return impl_->state.domains.size();
}

std::size_t Registry::membership_count() const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  return impl_->state.memberships.size();
}

} // namespace failure_domain_registry
