// Failure Domain Registry - the bounded derivation rule engine.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Derivation is deterministic, bounded and inspectable. A rule is one of a
// closed set of operators, it is published by an authorized publisher, and
// every membership it produces records the exact source memberships and source
// generations it read. When a source generation moves on, the derived
// membership is recomputed or withdrawn - it is never silently left standing.

#include "registry_internal.hpp"

#include <algorithm>
#include <map>
#include <set>

#include "failure_domain_registry/digest.hpp"

namespace failure_domain_registry {
namespace {

struct DesiredDerived {
  FailureDomainId domain;
  EntityRef member;
  std::vector<MembershipId> sources;
};

std::string derivation_context_of(const RegistryState& state,
                                  const std::vector<MembershipId>& sources) {
  std::string context;
  for (const MembershipId& id : sources) {
    const auto it = state.memberships.find(id);
    context.append(id.to_string());
    context.push_back('@');
    context.append(it == state.memberships.end() ? "0" : it->second->generation.to_string());
    context.push_back(';');
  }
  return context;
}

} // namespace

void Registry::Impl::invalidate_derived_memberships(const std::vector<EntityId>& affected) {
  if (affected.empty()) {
    return;
  }
  std::vector<MembershipId> ids;
  ids.reserve(state.memberships.size());
  for (const auto& entry : state.memberships) {
    if (entry.second->kind != MembershipKind::Derived) {
      continue;
    }
    ids.push_back(entry.first);
  }
  std::sort(ids.begin(), ids.end(), membership_id_less);
  for (const MembershipId& id : ids) {
    const auto it = state.memberships.find(id);
    if (it == state.memberships.end()) {
      continue;
    }
    Membership record = *it->second;
    if (record.is_terminal()) {
      continue;
    }
    bool hit = std::find(affected.begin(), affected.end(), record.member.id()) != affected.end();
    if (!hit) {
      for (const MembershipId& source : record.derivation.sources) {
        const auto source_it = state.memberships.find(source);
        if (source_it == state.memberships.end()) {
          hit = true;
          break;
        }
        if (std::find(affected.begin(), affected.end(), source_it->second->member.id()) !=
            affected.end()) {
          hit = true;
          break;
        }
      }
    }
    if (!hit) {
      continue;
    }
    if (!record.derivation.valid &&
        record.lifecycle == MembershipLifecycle::RevalidationRequired) {
      continue;
    }
    if (!is_legal_membership_transition(record.lifecycle,
                                        MembershipLifecycle::RevalidationRequired)) {
      continue;
    }
    push_membership_history(record, "derivation source changed",
                            limits.max_history_entries_per_record);
    record.derivation.valid = false;
    record.lifecycle = MembershipLifecycle::RevalidationRequired;
    const std::optional<MembershipGeneration> next = record.generation.next();
    if (next.has_value()) {
      record.generation = *next;
    }
    store_membership(std::move(record));
  }
}

Outcome Registry::Impl::evaluate_rule(const DerivationRule& rule, RegistryGeneration at,
                                      DerivationReport& report) {
  ++report.rules_evaluated;
  const DerivationGeneration generation = DerivationGeneration(at.value());
  const auto slot = static_cast<std::size_t>(rule.derived_role);
  (void)slot;

  std::vector<DesiredDerived> desired;
  const std::vector<FailureDomainId>* source_domains =
      domains_of_class_key(rule.source_class.to_string());
  if (source_domains != nullptr) {
    std::vector<FailureDomainId> domains = *source_domains;
    std::sort(domains.begin(), domains.end(), domain_id_less);
    for (const FailureDomainId& source_domain_id : domains) {
      const auto source_domain_it = state.domains.find(source_domain_id);
      if (source_domain_it == state.domains.end() || !source_domain_it->second->is_current()) {
        continue;
      }
      // Current direct members of the source domain.
      std::vector<std::shared_ptr<const Membership>> co_members;
      if (const std::vector<MembershipId>* ids = memberships_of_domain(source_domain_id)) {
        std::vector<MembershipId> sorted = *ids;
        std::sort(sorted.begin(), sorted.end(), membership_id_less);
        for (const MembershipId& id : sorted) {
          const auto it = state.memberships.find(id);
          if (it == state.memberships.end() || !it->second->is_current()) {
            continue;
          }
          if (it->second->kind == MembershipKind::Derived) {
            continue;
          }
          co_members.push_back(it->second);
        }
      }
      if (co_members.empty()) {
        continue;
      }
      for (const std::shared_ptr<const Membership>& subject : co_members) {
        if (is_valid_entity_class(rule.member_class) &&
            rule.op == DerivationOperator::MembersShareContainingClass &&
            subject->member.entity_class() != rule.member_class) {
          continue;
        }
        std::map<FailureDomainId, std::vector<MembershipId>> inherited;
        for (const std::shared_ptr<const Membership>& co_member : co_members) {
          if (rule.op == DerivationOperator::SameDomainMemberRelationship) {
            if (co_member->id == subject->id) {
              continue;
            }
            if (is_valid_entity_class(rule.member_class) &&
                co_member->member.entity_class() != rule.member_class) {
              continue;
            }
          }
          if (const std::vector<MembershipId>* target_ids = memberships_of_entity(
                  co_member->member.id())) {
            std::vector<MembershipId> sorted = *target_ids;
            std::sort(sorted.begin(), sorted.end(), membership_id_less);
            for (const MembershipId& target_id : sorted) {
              const auto target_it = state.memberships.find(target_id);
              if (target_it == state.memberships.end() || !target_it->second->is_current()) {
                continue;
              }
              if (target_it->second->kind == MembershipKind::Derived) {
                continue;
              }
              if (target_it->second->domain == source_domain_id) {
                continue;
              }
              const auto target_domain_it = state.domains.find(target_it->second->domain);
              if (target_domain_it == state.domains.end() ||
                  !target_domain_it->second->is_current()) {
                continue;
              }
              if (!(target_domain_it->second->domain_class == rule.target_class)) {
                continue;
              }
              std::vector<MembershipId>& sources = inherited[target_it->second->domain];
              if (std::find(sources.begin(), sources.end(), subject->id) == sources.end()) {
                sources.push_back(subject->id);
              }
              if (std::find(sources.begin(), sources.end(), target_it->second->id) ==
                  sources.end()) {
                sources.push_back(target_it->second->id);
              }
            }
          }
        }
        for (auto& entry : inherited) {
          std::vector<MembershipId> sources = entry.second;
          std::sort(sources.begin(), sources.end(), membership_id_less);
          DesiredDerived item;
          item.domain = entry.first;
          item.member = subject->member;
          item.sources = std::move(sources);
          desired.push_back(std::move(item));
          if (desired.size() > hard_limits::kMaxDerivedMembershipsPerRule) {
            ++report.bounded_out;
            desired.pop_back();
          }
        }
      }
    }
  }

  std::sort(desired.begin(), desired.end(), [](const DesiredDerived& left,
                                               const DesiredDerived& right) {
    if (left.domain != right.domain) {
      return left.domain < right.domain;
    }
    return left.member < right.member;
  });
  desired.erase(std::unique(desired.begin(), desired.end(),
                            [](const DesiredDerived& left, const DesiredDerived& right) {
                              return left.domain == right.domain && left.member == right.member;
                            }),
                desired.end());

  std::vector<MembershipId> desired_ids;
  for (const DesiredDerived& item : desired) {
    MembershipKey key;
    key.domain = item.domain;
    key.member = item.member.id();
    key.member_generation = item.member.generation();
    key.kind = MembershipKind::Derived;
    const MembershipId id = membership_id_for(key);
    desired_ids.push_back(id);
    const auto existing_it = state.memberships.find(id);
    const std::string context = derivation_context_of(state, item.sources);
    if (existing_it == state.memberships.end()) {
      if (state.memberships.size() >= limits.max_memberships) {
        ++report.bounded_out;
        continue;
      }
      Membership record;
      record.id = id;
      record.domain = item.domain;
      record.domain_generation = state.domains.at(item.domain)->generation;
      record.member = item.member;
      record.generation = MembershipGeneration::first();
      record.lifecycle = MembershipLifecycle::Current;
      record.kind = MembershipKind::Derived;
      record.role = rule.derived_role;
      record.dependency = rule.dependency;
      record.derivation.rule = rule.id;
      record.derivation.generation = generation;
      record.derivation.sources = item.sources;
      for (const MembershipId& source : item.sources) {
        const auto source_it = state.memberships.find(source);
        record.derivation.source_generations.push_back(
            source_it == state.memberships.end() ? MembershipGeneration{}
                                                 : source_it->second->generation);
      }
      record.derivation.context = context;
      record.derivation.valid = true;
      record.evidence_generation = next_evidence_generation();
      record.provenance.source = ProvenanceSource::DerivationRule;
      record.provenance.evidence = EvidenceClass::DerivedTopology;
      record.provenance.truth = TruthClass::Real;
      record.provenance.evidence_generation = record.evidence_generation;
      record.provenance.derivation_rule = rule.id;
      record.provenance.derivation_context = context;
      record.created_at = state.generation;
      record.created_epoch = state.epoch;
      MembershipEvidence evidence;
      evidence.provenance = record.provenance;
      evidence.live = true;
      record.evidence.push_back(std::move(evidence));
      store_membership(std::move(record));
      ++report.memberships_created;
      continue;
    }
    Membership record = *existing_it->second;
    if (record.is_terminal()) {
      continue;
    }
    const bool same_sources = record.derivation.context == context &&
                              record.derivation.rule == rule.id;
    if (same_sources && record.derivation.valid &&
        record.lifecycle == MembershipLifecycle::Current) {
      ++report.memberships_unchanged;
      continue;
    }
    push_membership_history(record, "derivation recomputed",
                            limits.max_history_entries_per_record);
    record.domain_generation = state.domains.at(item.domain)->generation;
    record.derivation.rule = rule.id;
    record.derivation.generation = generation;
    record.derivation.sources = item.sources;
    record.derivation.source_generations.clear();
    for (const MembershipId& source : item.sources) {
      const auto source_it = state.memberships.find(source);
      record.derivation.source_generations.push_back(
          source_it == state.memberships.end() ? MembershipGeneration{}
                                               : source_it->second->generation);
    }
    record.derivation.context = context;
    record.derivation.valid = true;
    record.lifecycle = MembershipLifecycle::Current;
    record.role = rule.derived_role;
    record.dependency = rule.dependency;
    record.provenance.derivation_context = context;
    const std::optional<MembershipGeneration> next = record.generation.next();
    if (next.has_value()) {
      record.generation = *next;
    }
    store_membership(std::move(record));
    ++report.memberships_updated;
  }

  // Withdraw derived memberships of this rule that are no longer produced.
  std::vector<MembershipId> existing_derived;
  for (const auto& entry : state.memberships) {
    if (entry.second->kind != MembershipKind::Derived) {
      continue;
    }
    if (!(entry.second->derivation.rule == rule.id)) {
      continue;
    }
    existing_derived.push_back(entry.first);
  }
  std::sort(existing_derived.begin(), existing_derived.end(), membership_id_less);
  for (const MembershipId& id : existing_derived) {
    if (std::find(desired_ids.begin(), desired_ids.end(), id) != desired_ids.end()) {
      continue;
    }
    const auto it = state.memberships.find(id);
    if (it == state.memberships.end()) {
      continue;
    }
    Membership record = *it->second;
    if (record.is_terminal()) {
      continue;
    }
    push_membership_history(record, "derivation no longer produces it",
                            limits.max_history_entries_per_record);
    record.lifecycle = MembershipLifecycle::Retired;
    record.derivation.valid = false;
    const std::optional<MembershipGeneration> next = record.generation.next();
    if (next.has_value()) {
      record.generation = *next;
    }
    store_membership(std::move(record));
    ++report.memberships_withdrawn;
  }
  return Outcome::make(OutcomeCode::Committed, "rule evaluated");
}

Outcome Registry::Impl::run_derivation_locked(const DerivationRuleId& only_rule,
                                              DerivationReport& report) {
  std::vector<DerivationRuleId> ids;
  for (const auto& entry : state.rules) {
    if (entry.second.enabled) {
      ids.push_back(entry.first);
    }
  }
  std::sort(ids.begin(), ids.end());
  report.generation = state.generation;
  bool evaluated = false;
  std::size_t before = 0;
  std::size_t after = 0;
  for (const DerivationRuleId& id : ids) {
    if (!only_rule.is_null() && !(id == only_rule)) {
      continue;
    }
    const DerivationRule& rule = state.rules.at(id);
    before = state.memberships.size();
    evaluate_rule(rule, state.generation, report);
    after = state.memberships.size();
    (void)before;
    (void)after;
    evaluated = true;
  }
  if (!evaluated) {
    return Outcome::make(OutcomeCode::NotFound, "no enabled derivation rule matched");
  }
  return Outcome::make(OutcomeCode::Committed, "derivation pass complete");
}

Outcome Registry::publish_derivation_rule(const DerivationRule& rule,
                                          const AuthorityContext& authority) {
  DerivationRuleId rule_id = derivation_rule_id_for(rule);
  RequestDigest digest;
  {
    std::string canonical;
    append_bytes(canonical, "fdr/req/publish-derivation-rule/v1");
    append_bytes(canonical, rule.canonical_form());
    digest = request_digest_of(canonical);
  }
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  if (!authority.is_complete()) {
    Outcome outcome = Outcome::make(OutcomeCode::NoAuthority,
                                    "publishing a derivation rule requires authority");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const Outcome authorized = impl_->authorize_any(authority, std::string());
  if (!authorized.committed()) {
    Outcome outcome = authorized;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (!is_valid_derivation_operator(rule.op)) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                    "derivation operator is not one of the supported operators");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (rule.name.empty() || rule.name.size() > impl_->limits.max_string_bytes) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                    "derivation rule name is empty or too long");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (!rule.source_class.is_canonical() || !rule.target_class.is_canonical()) {
    Outcome outcome = Outcome::make(
        OutcomeCode::MalformedRequest,
        "a derivation rule names canonical source and target domain classes");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (rule.source_class == rule.target_class) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                    "a derivation rule must read and write different classes");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const PublisherRegistration* registration = nullptr;
  const auto publisher_it = impl_->state.publishers.find(authority.publisher);
  if (publisher_it != impl_->state.publishers.end()) {
    registration = &publisher_it->second;
  }
  if (registration != nullptr) {
    if (!registration->scope.allows_class(rule.source_class.classification()) ||
        !registration->scope.allows_class(rule.target_class.classification())) {
      Outcome outcome = Outcome::make(
          OutcomeCode::UnauthorizedScope,
          "the publisher is not authorized for the classes the rule reads and writes");
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
  }
  const auto existing = impl_->state.rules.find(rule_id);
  if (existing != impl_->state.rules.end()) {
    if (existing->second.canonical_form() == rule.canonical_form() &&
        existing->second.enabled == rule.enabled) {
      Outcome outcome = Outcome::make(OutcomeCode::Idempotent,
                                      "the derivation rule is already published");
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    DerivationRule updated = rule;
    updated.id = rule_id;
    updated.publisher = authority.publisher;
    updated.published_at = impl_->state.generation;
    impl_->state.rules[rule_id] = updated;
    impl_->bump_generation();
    Outcome outcome = Outcome::make(OutcomeCode::Committed, "derivation rule updated");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  DerivationRule stored = rule;
  stored.id = rule_id;
  stored.publisher = authority.publisher;
  stored.published_at = impl_->state.generation;
  impl_->state.rules[rule_id] = stored;
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "derivation rule published");
  outcome.request_digest = digest;
  return impl_->record(std::move(outcome));
}

std::vector<DerivationRule> Registry::derivation_rules() const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<DerivationRule> out;
  out.reserve(impl_->state.rules.size());
  for (const auto& entry : impl_->state.rules) {
    out.push_back(entry.second);
  }
  std::sort(out.begin(), out.end(),
            [](const DerivationRule& left, const DerivationRule& right) {
              return left.id < right.id;
            });
  return out;
}

Outcome Registry::run_derivation(const DerivationRunRequest& request, DerivationReport* report) {
  RequestDigest digest;
  {
    std::string canonical;
    append_bytes(canonical, "fdr/req/run-derivation/v1");
    append_bytes(canonical, request.rule.to_string());
    digest = request_digest_of(canonical);
  }
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  const Outcome authorized = impl_->authorize_any(request.authority, std::string());
  if (!authorized.committed()) {
    Outcome outcome = authorized;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  DerivationReport local;
  const Outcome result = impl_->run_derivation_locked(request.rule, local);
  if (!result.committed()) {
    Outcome outcome = result;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const bool changed = local.memberships_created > 0 || local.memberships_updated > 0 ||
                       local.memberships_withdrawn > 0;
  if (changed) {
    impl_->bump_generation();
  }
  local.generation = impl_->state.generation;
  if (report != nullptr) {
    *report = local;
  }
  Outcome outcome = Outcome::make(changed ? OutcomeCode::Committed : OutcomeCode::Idempotent,
                                  changed ? "derivation pass committed"
                                          : "derivation pass produced no change");
  outcome.steps.push_back(ExplanationStep{
      "derive", "memberships",
      std::to_string(local.memberships_created) + " created, " +
          std::to_string(local.memberships_updated) + " updated, " +
          std::to_string(local.memberships_withdrawn) + " withdrawn, " +
          std::to_string(local.memberships_unchanged) + " unchanged",
      std::to_string(local.rules_evaluated) + " rule(s) evaluated"});
  outcome.request_digest = digest;
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

} // namespace failure_domain_registry
