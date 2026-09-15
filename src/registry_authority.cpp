// Failure Domain Registry - authority, epoch, fencing and evidence demotion.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "registry_internal.hpp"

#include <algorithm>

namespace failure_domain_registry {
namespace {

template <class T>
void erase_value(std::vector<T>& values, const T& value) {
  values.erase(std::remove(values.begin(), values.end(), value), values.end());
}

} // namespace

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

CoverageState Registry::Impl::coverage_for(const std::string& administrative_scope,
                                           const std::string& key) const {
  CoverageState result = CoverageState::UnknownCoverage;
  bool found = false;
  for (const CoverageDeclaration& declaration : state.coverage) {
    if (declaration.administrative_scope != administrative_scope) {
      continue;
    }
    if (declaration.domain_class.to_string() != key) {
      continue;
    }
    if (!found) {
      result = declaration.state;
      found = true;
      continue;
    }
    // The weakest declaration wins: a class is only complete for a scope when
    // nothing weaker was declared for that same scope and class.
    if (static_cast<std::uint8_t>(declaration.state) > static_cast<std::uint8_t>(result)) {
      result = declaration.state;
    }
  }
  return result;
}

std::vector<std::string> Registry::Impl::effective_scopes(const std::vector<EntityId>& entities,
                                                          std::string_view explicit_scope) const {
  std::vector<std::string> scopes;
  if (!explicit_scope.empty()) {
    scopes.emplace_back(explicit_scope);
    return scopes;
  }
  for (const EntityId& entity : entities) {
    const std::vector<MembershipId>* ids = memberships_of_entity(entity);
    if (ids == nullptr) {
      continue;
    }
    for (const MembershipId& id : *ids) {
      const auto it = state.memberships.find(id);
      if (it == state.memberships.end() || !it->second->is_current()) {
        continue;
      }
      const auto domain_it = state.domains.find(it->second->domain);
      if (domain_it == state.domains.end()) {
        continue;
      }
      const std::string& scope = domain_it->second->administrative_scope;
      if (std::find(scopes.begin(), scopes.end(), scope) == scopes.end()) {
        scopes.push_back(scope);
      }
    }
  }
  std::sort(scopes.begin(), scopes.end());
  return scopes;
}

// ---------------------------------------------------------------------------
// Evidence merging and demotion
// ---------------------------------------------------------------------------

void Registry::Impl::demote_memberships_of_domain(const FailureDomainId& domain,
                                                  MembershipLifecycle target,
                                                  const std::string& cause) {
  const std::vector<MembershipId>* ids = memberships_of_domain(domain);
  if (ids == nullptr) {
    return;
  }
  const std::vector<MembershipId> copy = *ids;
  for (const MembershipId& id : copy) {
    const auto it = state.memberships.find(id);
    if (it == state.memberships.end()) {
      continue;
    }
    Membership record = *it->second;
    if (record.is_terminal() || record.lifecycle == target) {
      continue;
    }
    if (!is_legal_membership_transition(record.lifecycle, target)) {
      continue;
    }
    push_membership_history(record, cause, limits.max_history_entries_per_record);
    record.lifecycle = target;
    const std::optional<MembershipGeneration> next = record.generation.next();
    if (next.has_value()) {
      record.generation = *next;
    }
    store_membership(std::move(record));
  }
}

void Registry::Impl::demote_memberships_of_entity_generation(
    const EntityId& entity, EntityGeneration superseded_generation, MembershipLifecycle target,
    const std::string& cause) {
  const std::vector<MembershipId>* ids = memberships_of_entity(entity);
  if (ids == nullptr) {
    return;
  }
  const std::vector<MembershipId> copy = *ids;
  for (const MembershipId& id : copy) {
    const auto it = state.memberships.find(id);
    if (it == state.memberships.end()) {
      continue;
    }
    Membership record = *it->second;
    if (record.is_terminal() || record.lifecycle == target) {
      continue;
    }
    if (record.member.generation() != superseded_generation) {
      continue;
    }
    if (!is_legal_membership_transition(record.lifecycle, target)) {
      continue;
    }
    push_membership_history(record, cause, limits.max_history_entries_per_record);
    record.lifecycle = target;
    if (record.kind == MembershipKind::Derived) {
      // The rule's output is no longer known to hold, so it must not claim to.
      record.derivation.valid = false;
    }
    const std::optional<MembershipGeneration> next = record.generation.next();
    if (next.has_value()) {
      record.generation = *next;
    }
    store_membership(std::move(record));
  }
}

void Registry::Impl::withdraw_publisher_evidence(const PublisherId& publisher,
                                                 const WorkerBootId& worker_boot, bool match_boot,
                                                 EvidenceClass evidence,
                                                 MembershipLifecycle target,
                                                 const std::string& cause) {
  const auto publisher_it = state.by_publisher.find(publisher);
  if (publisher_it == state.by_publisher.end()) {
    return;
  }
  const std::vector<MembershipId> ids = publisher_it->second;
  for (const MembershipId& id : ids) {
    const auto it = state.memberships.find(id);
    if (it == state.memberships.end()) {
      continue;
    }
    Membership record = *it->second;
    if (record.kind == MembershipKind::Derived) {
      // Derived membership is recomputed from its sources; it is never
      // demoted by publisher loss.
      continue;
    }
    bool changed = false;
    std::vector<MembershipEvidence> kept;
    kept.reserve(record.evidence.size());
    for (const MembershipEvidence& entry : record.evidence) {
      const bool same_publisher = entry.provenance.publisher == publisher;
      const bool same_boot = !match_boot || entry.provenance.worker_boot == worker_boot;
      const bool same_class =
          !is_valid_evidence_class(evidence) || entry.provenance.evidence == evidence;
      if (same_publisher && same_boot && same_class) {
        changed = true;
        continue;
      }
      kept.push_back(entry);
    }
    if (!changed) {
      continue;
    }
    push_membership_history(record, cause, limits.max_history_entries_per_record);
    record.evidence = std::move(kept);
    const std::optional<MembershipGeneration> next = record.generation.next();
    if (next.has_value()) {
      record.generation = *next;
    }
    std::size_t live = 0;
    EvidenceClass strongest = EvidenceClass::Unknown;
    for (const MembershipEvidence& entry : record.evidence) {
      if (!entry.live) {
        continue;
      }
      ++live;
      if (!is_valid_evidence_class(strongest) ||
          evidence_rank(entry.provenance.evidence) < evidence_rank(strongest)) {
        strongest = entry.provenance.evidence;
      }
    }
    if (live == 0) {
      if (!record.is_terminal() && is_legal_membership_transition(record.lifecycle, target)) {
        record.lifecycle = target;
      }
    } else {
      // Recompute the headline provenance from the evidence that survived.
      for (const MembershipEvidence& entry : record.evidence) {
        if (entry.live && entry.provenance.evidence == strongest) {
          record.provenance = entry.provenance;
          break;
        }
      }
    }
    store_membership(std::move(record));
  }
}

// ---------------------------------------------------------------------------
// Registry: authority operations
// ---------------------------------------------------------------------------

Outcome Registry::grant_publisher(const PublisherRegistration& registration,
                                  const AuthorityContext& authority) {
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  if (registration.publisher.is_null()) {
    return impl_->record(Outcome::make(OutcomeCode::MalformedRequest, "publisher id is null"));
  }
  if (registration.name.size() > impl_->limits.max_string_bytes) {
    return impl_->record(Outcome::make(OutcomeCode::MalformedRequest, "publisher name too long"));
  }
  const bool bootstrap = !authority.is_complete();
  if (bootstrap) {
    if (!impl_->state.live_sessions.empty()) {
      return impl_->record(Outcome::make(
          OutcomeCode::NoAuthority,
          "bootstrap grant rejected: a live publisher session exists, so grants now require "
          "authority"));
    }
  } else {
    const Outcome authorized = impl_->authorize_any(authority, std::string());
    if (!authorized.committed()) {
      return impl_->record(authorized);
    }
    const PublisherRegistration& granter = impl_->state.publishers.at(authority.publisher);
    if (granter.scope.classes.size() != static_cast<std::size_t>(kDomainClassCount)) {
      return impl_->record(Outcome::make(
          OutcomeCode::UnauthorizedScope,
          "only a publisher with an unrestricted scope may grant authority"));
    }
  }
  const auto existing = impl_->state.publishers.find(registration.publisher);
  if (existing == impl_->state.publishers.end() &&
      impl_->state.publishers.size() >= impl_->limits.max_publishers) {
    return impl_->record(Outcome::make(OutcomeCode::ResourceLimit, "publisher limit reached"));
  }
  PublisherRegistration stored = registration;
  if (existing != impl_->state.publishers.end()) {
    const std::optional<PublisherGeneration> next = existing->second.generation.next();
    stored.generation = next.has_value() ? *next : existing->second.generation;
  } else {
    stored.generation = PublisherGeneration::first();
  }
  impl_->state.publishers[stored.publisher] = stored;
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "publisher grant installed");
  outcome.steps.push_back(ExplanationStep{"authority", "publisher", stored.publisher.to_string(),
                                          bootstrap ? "bootstrap grant" : "authorized grant"});
  return impl_->record(std::move(outcome));
}

Outcome Registry::attach_worker(const PublisherId& publisher, const WorkerBootId& worker_boot,
                                CoordinatorEpoch epoch, std::string client_label,
                                EvidenceClass max_evidence) {
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  if (publisher.is_null() || worker_boot.is_null()) {
    return impl_->record(
        Outcome::make(OutcomeCode::MalformedRequest, "publisher and worker boot are required"));
  }
  const auto registration_it = impl_->state.publishers.find(publisher);
  if (registration_it == impl_->state.publishers.end()) {
    return impl_->record(Outcome::make(OutcomeCode::StaleAuthority, "publisher is not registered")
                             .field_step("authority", "publisher", publisher.to_string(),
                                         "unknown publisher"));
  }
  if (impl_->state.epoch.is_zero()) {
    return impl_->record(Outcome::make(OutcomeCode::StaleEpoch,
                                       "coordinator epoch has not been established"));
  }
  if (epoch != impl_->state.epoch) {
    return impl_->record(Outcome::make(OutcomeCode::StaleEpoch, "coordinator epoch is not current")
                             .field_step("authority", "epoch", epoch.to_string(),
                                         "current epoch is " + impl_->state.epoch.to_string()));
  }
  if (impl_->is_worker_fenced(publisher, worker_boot)) {
    return impl_->record(
        Outcome::make(OutcomeCode::StaleWorkerBoot, "worker incarnation has been fenced")
            .field_step("authority", "worker-boot", worker_boot.to_string(), "fenced"));
  }
  if (is_valid_evidence_class(max_evidence) &&
      !registration_it->second.scope.allows_evidence(max_evidence)) {
    return impl_->record(Outcome::make(OutcomeCode::UnauthorizedScope,
                                       "publisher may not assert the requested evidence class"));
  }

  std::vector<WorkerSession>& sessions = impl_->state.live_sessions[publisher];
  for (WorkerSession& session : sessions) {
    if (session.worker_boot == worker_boot) {
      session.attached_epoch = epoch;
      session.client_label = std::move(client_label);
      if (is_valid_evidence_class(max_evidence)) {
        session.max_evidence = max_evidence;
      }
      return impl_->record(
          Outcome::make(OutcomeCode::Idempotent, "worker incarnation already attached"));
    }
  }

  // A fresh incarnation permanently fences every previous one.
  const std::vector<WorkerSession> stale_sessions = sessions;
  for (const WorkerSession& stale : stale_sessions) {
    FenceRecord fence;
    fence.publisher = publisher;
    fence.worker_boot = stale.worker_boot;
    fence.reason = FenceReason::Reincarnated;
    fence.epoch = impl_->state.epoch;
    fence.at_generation = impl_->state.generation;
    std::vector<FenceRecord>& fences = impl_->state.fences[publisher];
    fences.push_back(fence);
    if (fences.size() > impl_->limits.max_fenced_boots_per_publisher) {
      fences.erase(fences.begin());
    }
    impl_->withdraw_publisher_evidence(publisher, stale.worker_boot, true, EvidenceClass::Unknown,
                                       MembershipLifecycle::RevalidationRequired,
                                       "publisher reincarnated with a fresh worker boot");
  }
  sessions.clear();

  WorkerSession session;
  session.publisher = publisher;
  session.worker_boot = worker_boot;
  session.attached_epoch = epoch;
  session.max_evidence = max_evidence;
  session.client_label = std::move(client_label);
  sessions.push_back(std::move(session));
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "worker incarnation attached");
  outcome.steps.push_back(ExplanationStep{"authority", "worker-boot", worker_boot.to_string(),
                                          "attached at epoch " + epoch.to_string()});
  return impl_->record(std::move(outcome));
}

Outcome Registry::fence_worker(const PublisherId& publisher, const WorkerBootId& worker_boot,
                               FenceReason reason, CoordinatorEpoch epoch) {
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  const auto registration_it = impl_->state.publishers.find(publisher);
  if (registration_it == impl_->state.publishers.end()) {
    return impl_->record(Outcome::make(OutcomeCode::StaleAuthority, "publisher is not registered"));
  }
  if (impl_->is_worker_fenced(publisher, worker_boot)) {
    return impl_->record(
        Outcome::make(OutcomeCode::Idempotent, "worker incarnation is already fenced"));
  }

  const auto session_it = impl_->state.live_sessions.find(publisher);
  if (session_it != impl_->state.live_sessions.end()) {
    std::vector<WorkerSession>& sessions = session_it->second;
    sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
                                  [&worker_boot](const WorkerSession& entry) {
                                    return entry.worker_boot == worker_boot;
                                  }),
                  sessions.end());
    if (sessions.empty()) {
      impl_->state.live_sessions.erase(session_it);
    }
  }

  FenceRecord fence;
  fence.publisher = publisher;
  fence.worker_boot = worker_boot;
  fence.reason = reason;
  fence.epoch = epoch.is_zero() ? impl_->state.epoch : epoch;
  fence.at_generation = impl_->state.generation;
  std::vector<FenceRecord>& fences = impl_->state.fences[publisher];
  fences.push_back(fence);
  if (fences.size() > impl_->limits.max_fenced_boots_per_publisher) {
    fences.erase(fences.begin());
  }

  impl_->withdraw_publisher_evidence(publisher, worker_boot, true, EvidenceClass::Unknown,
                                     MembershipLifecycle::RevalidationRequired,
                                     "publishing incarnation was fenced");

  // A domain whose provenance was process-bound evidence from this incarnation
  // loses its authority as well. Durable administrative classification is
  // preserved, because its evidence never depended on a live process.
  std::vector<FailureDomainId> domain_ids;
  domain_ids.reserve(impl_->state.domains.size());
  for (const auto& entry : impl_->state.domains) {
    domain_ids.push_back(entry.first);
  }
  std::sort(domain_ids.begin(), domain_ids.end(), domain_id_less);
  for (const FailureDomainId& id : domain_ids) {
    const auto it = impl_->state.domains.find(id);
    if (it == impl_->state.domains.end()) {
      continue;
    }
    FailureDomain record = *it->second;
    if (!record.provenance.has_publisher() || record.provenance.publisher != publisher ||
        record.provenance.worker_boot != worker_boot) {
      continue;
    }
    if (!is_process_bound_evidence(record.provenance.evidence)) {
      continue;
    }
    if (record.is_terminal() ||
        !is_legal_domain_transition(record.lifecycle, DomainLifecycle::RevalidationRequired)) {
      continue;
    }
    impl_->push_domain_history(record, "publishing incarnation was fenced",
                               impl_->limits.max_history_entries_per_record);
    record.lifecycle = DomainLifecycle::RevalidationRequired;
    const std::optional<FailureDomainGeneration> next = record.generation.next();
    if (next.has_value()) {
      record.generation = *next;
    }
    impl_->store_domain(std::move(record));
  }

  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "worker incarnation fenced");
  outcome.steps.push_back(ExplanationStep{
      "authority", "worker-boot", worker_boot.to_string(),
      std::string("reason=") + std::string(failure_domain_registry::to_string(reason))});
  return impl_->record(std::move(outcome));
}

Outcome Registry::advance_epoch(CoordinatorEpoch expected, CoordinatorEpoch* new_epoch) {
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  if (expected != impl_->state.epoch) {
    return impl_->record(Outcome::make(OutcomeCode::StaleEpoch, "coordinator epoch is not current")
                             .field_step("epoch", "expected", expected.to_string(),
                                         "current epoch is " + impl_->state.epoch.to_string()));
  }
  const std::optional<CoordinatorEpoch> next = impl_->state.epoch.next();
  if (!next.has_value()) {
    return impl_->record(
        Outcome::make(OutcomeCode::ResourceLimit, "coordinator epoch space exhausted"));
  }

  std::vector<std::pair<PublisherId, WorkerBootId>> live;
  for (const auto& entry : impl_->state.live_sessions) {
    for (const WorkerSession& session : entry.second) {
      live.emplace_back(entry.first, session.worker_boot);
    }
  }
  std::sort(live.begin(), live.end());
  for (const auto& entry : live) {
    FenceRecord fence;
    fence.publisher = entry.first;
    fence.worker_boot = entry.second;
    fence.reason = FenceReason::CoordinatorRestart;
    fence.epoch = *next;
    fence.at_generation = impl_->state.generation;
    std::vector<FenceRecord>& fences = impl_->state.fences[entry.first];
    fences.push_back(fence);
    if (fences.size() > impl_->limits.max_fenced_boots_per_publisher) {
      fences.erase(fences.begin());
    }
    impl_->withdraw_publisher_evidence(entry.first, entry.second, true, EvidenceClass::Unknown,
                                       MembershipLifecycle::RevalidationRequired,
                                       "coordinator epoch advanced");
  }
  impl_->state.live_sessions.clear();
  impl_->state.epoch = *next;
  impl_->bump_generation();
  if (new_epoch != nullptr) {
    *new_epoch = *next;
  }
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "coordinator epoch advanced");
  outcome.steps.push_back(ExplanationStep{"epoch", "epoch", next->to_string(),
                                          std::to_string(live.size()) +
                                              " live incarnation(s) fenced"});
  return impl_->record(std::move(outcome));
}

std::optional<PublisherRegistration> Registry::publisher(const PublisherId& id) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  const auto it = impl_->state.publishers.find(id);
  if (it == impl_->state.publishers.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::vector<PublisherRegistration> Registry::publishers() const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<PublisherRegistration> out;
  out.reserve(impl_->state.publishers.size());
  for (const auto& entry : impl_->state.publishers) {
    out.push_back(entry.second);
  }
  std::sort(out.begin(), out.end(),
            [](const PublisherRegistration& left, const PublisherRegistration& right) {
              return left.publisher < right.publisher;
            });
  return out;
}

std::vector<WorkerSession> Registry::live_sessions() const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<WorkerSession> out;
  for (const auto& entry : impl_->state.live_sessions) {
    for (const WorkerSession& session : entry.second) {
      out.push_back(session);
    }
  }
  std::sort(out.begin(), out.end(), [](const WorkerSession& left, const WorkerSession& right) {
    if (left.publisher != right.publisher) {
      return left.publisher < right.publisher;
    }
    return left.worker_boot < right.worker_boot;
  });
  return out;
}

std::vector<FenceRecord> Registry::fences() const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<FenceRecord> out;
  for (const auto& entry : impl_->state.fences) {
    for (const FenceRecord& record : entry.second) {
      out.push_back(record);
    }
  }
  std::sort(out.begin(), out.end(), [](const FenceRecord& left, const FenceRecord& right) {
    if (left.publisher != right.publisher) {
      return left.publisher < right.publisher;
    }
    return left.worker_boot < right.worker_boot;
  });
  return out;
}

std::vector<std::pair<PublisherId, WorkerBootId>> Registry::process_bound_incarnations() const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<std::pair<PublisherId, WorkerBootId>> out;
  for (const auto& entry : impl_->state.memberships) {
    const Membership& record = *entry.second;
    if (record.is_terminal()) {
      continue;
    }
    for (const MembershipEvidence& evidence : record.evidence) {
      if (!evidence.live || !evidence.provenance.has_publisher()) {
        continue;
      }
      if (!is_process_bound_evidence(evidence.provenance.evidence)) {
        continue;
      }
      const std::pair<PublisherId, WorkerBootId> pair{evidence.provenance.publisher,
                                                      evidence.provenance.worker_boot};
      if (std::find(out.begin(), out.end(), pair) == out.end()) {
        out.push_back(pair);
      }
    }
  }
  for (const auto& entry : impl_->state.domains) {
    const FailureDomain& record = *entry.second;
    if (record.is_terminal() || !record.provenance.has_publisher()) {
      continue;
    }
    if (!is_process_bound_evidence(record.provenance.evidence)) {
      continue;
    }
    const std::pair<PublisherId, WorkerBootId> pair{record.provenance.publisher,
                                                    record.provenance.worker_boot};
    if (std::find(out.begin(), out.end(), pair) == out.end()) {
      out.push_back(pair);
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

bool Registry::is_worker_live(const PublisherId& publisher, const WorkerBootId& worker_boot) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  const auto it = impl_->state.live_sessions.find(publisher);
  if (it == impl_->state.live_sessions.end()) {
    return false;
  }
  for (const WorkerSession& session : it->second) {
    if (session.worker_boot == worker_boot) {
      return true;
    }
  }
  return false;
}

} // namespace failure_domain_registry
