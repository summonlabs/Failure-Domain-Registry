// Failure Domain Registry - queries, overlap, independence and coverage.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "registry_internal.hpp"

#include <algorithm>
#include <set>

namespace failure_domain_registry {

std::string_view to_string(IndependenceState value) noexcept {
  switch (value) {
    case IndependenceState::ProvenIndependent: return "PROVEN_INDEPENDENT";
    case IndependenceState::SharedDomain: return "SHARED_DOMAIN";
    case IndependenceState::UnknownCoverage: return "UNKNOWN";
    case IndependenceState::RevalidationRequired: return "REVALIDATION_REQUIRED";
    case IndependenceState::Conflicted: return "CONFLICTED";
    case IndependenceState::NoKnowledge: return "NO_KNOWLEDGE";
    default: return "UNKNOWN";
  }
}

namespace {

void collect_current_domains(const RegistryState& state, const EntityId& entity,
                             std::vector<FailureDomainId>* out) {
  const auto it = state.by_entity.find(entity);
  if (it == state.by_entity.end()) {
    return;
  }
  for (const MembershipId& id : it->second) {
    const auto membership_it = state.memberships.find(id);
    if (membership_it == state.memberships.end() || !membership_it->second->is_current()) {
      continue;
    }
    const FailureDomainId domain = membership_it->second->domain;
    const auto domain_it = state.domains.find(domain);
    if (domain_it == state.domains.end() || !domain_it->second->is_current()) {
      continue;
    }
    if (std::find(out->begin(), out->end(), domain) == out->end()) {
      out->push_back(domain);
    }
  }
}

bool entity_has_indeterminate(const RegistryState& state, const EntityId& entity,
                              MembershipLifecycle* worst) {
  const auto it = state.by_entity.find(entity);
  if (it == state.by_entity.end()) {
    return false;
  }
  bool found = false;
  for (const MembershipId& id : it->second) {
    const auto membership_it = state.memberships.find(id);
    if (membership_it == state.memberships.end()) {
      continue;
    }
    const MembershipLifecycle lifecycle = membership_it->second->lifecycle;
    if (!is_indeterminate(lifecycle)) {
      continue;
    }
    found = true;
    if (worst != nullptr &&
        (*worst != MembershipLifecycle::Conflicted || lifecycle == MembershipLifecycle::Conflicted)) {
      *worst = lifecycle;
    }
  }
  return found;
}

std::vector<FailureDomainId> descendants_of(const RegistryState& state, const FailureDomainId& id,
                                            std::size_t bound) {
  std::vector<FailureDomainId> out;
  std::vector<FailureDomainId> frontier{id};
  std::set<FailureDomainId> seen;
  seen.insert(id);
  while (!frontier.empty() && out.size() < bound) {
    std::vector<FailureDomainId> next;
    for (const FailureDomainId& current : frontier) {
      const auto it = state.children.find(current);
      if (it == state.children.end()) {
        continue;
      }
      for (const FailureDomainId& child : it->second) {
        if (seen.insert(child).second) {
          out.push_back(child);
          next.push_back(child);
        }
      }
    }
    frontier.swap(next);
  }
  return out;
}

std::vector<FailureDomainId> ancestors_of(const RegistryState& state, const FailureDomainId& id,
                                          std::size_t bound) {
  std::vector<FailureDomainId> out;
  std::vector<FailureDomainId> frontier{id};
  std::set<FailureDomainId> seen;
  seen.insert(id);
  while (!frontier.empty() && out.size() < bound) {
    std::vector<FailureDomainId> next;
    for (const FailureDomainId& current : frontier) {
      const auto it = state.parents.find(current);
      if (it == state.parents.end()) {
        continue;
      }
      for (const FailureDomainId& parent : it->second) {
        if (seen.insert(parent).second) {
          out.push_back(parent);
          next.push_back(parent);
        }
      }
    }
    frontier.swap(next);
  }
  return out;
}

bool class_addressed(const DomainClassRef& klass, const std::vector<DomainClassRef>& classes) {
  if (classes.empty()) {
    return true;
  }
  for (const DomainClassRef& entry : classes) {
    if (entry == klass) {
      return true;
    }
  }
  return false;
}

std::vector<DomainClassRef> default_classes(const std::vector<DomainClassRef>& classes) {
  if (!classes.empty()) {
    return classes;
  }
  std::vector<DomainClassRef> out;
  for (std::uint8_t raw = 1; raw <= kDomainClassCount; ++raw) {
    out.emplace_back(static_cast<DomainClass>(raw));
  }
  return out;
}

std::string join_scopes(const std::vector<std::string>& scopes) {
  std::string out;
  for (std::size_t i = 0; i < scopes.size(); ++i) {
    if (i != 0) {
      out.push_back(',');
    }
    out.append(scopes[i]);
  }
  return out.empty() ? std::string("<none>") : out;
}

} // namespace

// ---------------------------------------------------------------------------
// Registry: record queries
// ---------------------------------------------------------------------------

std::optional<FailureDomain> Registry::domain(const FailureDomainId& id) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  const std::shared_ptr<const FailureDomain> record = impl_->find_domain(id);
  if (record == nullptr) {
    return std::nullopt;
  }
  return *record;
}

std::vector<FailureDomain> Registry::domains(std::size_t max_records) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<FailureDomainId> ids;
  ids.reserve(impl_->state.domains.size());
  for (const auto& entry : impl_->state.domains) {
    ids.push_back(entry.first);
  }
  std::sort(ids.begin(), ids.end(), domain_id_less);
  std::vector<FailureDomain> out;
  for (const FailureDomainId& id : ids) {
    if (out.size() >= max_records) {
      break;
    }
    out.push_back(*impl_->state.domains.at(id));
  }
  return out;
}

std::vector<FailureDomain> Registry::domains_of_class(const DomainClassRef& domain_class) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<FailureDomain> out;
  const std::vector<FailureDomainId>* ids = impl_->domains_of_class_key(domain_class.to_string());
  if (ids == nullptr) {
    return out;
  }
  std::vector<FailureDomainId> sorted = *ids;
  std::sort(sorted.begin(), sorted.end(), domain_id_less);
  for (const FailureDomainId& id : sorted) {
    out.push_back(*impl_->state.domains.at(id));
  }
  return out;
}

std::vector<FailureDomain> Registry::domains_in_scope(std::string_view scope) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<FailureDomain> out;
  const auto it = impl_->state.by_scope.find(std::string(scope));
  if (it == impl_->state.by_scope.end()) {
    return out;
  }
  std::vector<FailureDomainId> sorted = it->second;
  std::sort(sorted.begin(), sorted.end(), domain_id_less);
  for (const FailureDomainId& id : sorted) {
    out.push_back(*impl_->state.domains.at(id));
  }
  return out;
}

std::vector<FailureDomain> Registry::domains_in_lifecycle(DomainLifecycle lifecycle) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<FailureDomain> out;
  const auto slot = static_cast<std::size_t>(lifecycle);
  if (slot >= kLifecycleSlots) {
    return out;
  }
  std::vector<FailureDomainId> sorted = impl_->state.domains_by_lifecycle[slot];
  std::sort(sorted.begin(), sorted.end(), domain_id_less);
  for (const FailureDomainId& id : sorted) {
    out.push_back(*impl_->state.domains.at(id));
  }
  return out;
}

std::vector<DomainRelation> Registry::relations_of(const FailureDomainId& id) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<DomainRelation> out;
  const std::vector<DomainRelationId>* ids = impl_->relations_of_domain(id);
  if (ids == nullptr) {
    return out;
  }
  std::vector<DomainRelationId> sorted = *ids;
  std::sort(sorted.begin(), sorted.end());
  for (const DomainRelationId& relation : sorted) {
    out.push_back(*impl_->state.relations.at(relation));
  }
  return out;
}

std::vector<Membership> Registry::memberships_of(const EntityId& entity) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<Membership> out;
  for (const MembershipId& id : impl_->sorted_entity_memberships(entity)) {
    out.push_back(*impl_->state.memberships.at(id));
  }
  return out;
}

std::vector<Membership> Registry::memberships_of(const EntityRef& entity) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<Membership> out;
  for (const MembershipId& id : impl_->sorted_entity_memberships(entity.id())) {
    const Membership& record = *impl_->state.memberships.at(id);
    if (record.member == entity) {
      out.push_back(record);
    }
  }
  return out;
}

std::vector<Membership> Registry::members_of(const FailureDomainId& id) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<Membership> out;
  const std::vector<MembershipId>* ids = impl_->memberships_of_domain(id);
  if (ids == nullptr) {
    return out;
  }
  std::vector<MembershipId> sorted = *ids;
  std::sort(sorted.begin(), sorted.end(), membership_id_less);
  for (const MembershipId& membership : sorted) {
    out.push_back(*impl_->state.memberships.at(membership));
  }
  return out;
}

std::vector<Membership> Registry::memberships_of_publisher(const PublisherId& id) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<Membership> out;
  const auto it = impl_->state.by_publisher.find(id);
  if (it == impl_->state.by_publisher.end()) {
    return out;
  }
  std::vector<MembershipId> sorted = it->second;
  std::sort(sorted.begin(), sorted.end(), membership_id_less);
  for (const MembershipId& membership : sorted) {
    out.push_back(*impl_->state.memberships.at(membership));
  }
  return out;
}

std::vector<Membership> Registry::memberships_in_lifecycle(MembershipLifecycle lifecycle) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<Membership> out;
  const auto slot = static_cast<std::size_t>(lifecycle);
  if (slot >= kLifecycleSlots) {
    return out;
  }
  std::vector<MembershipId> sorted = impl_->state.memberships_by_lifecycle[slot];
  std::sort(sorted.begin(), sorted.end(), membership_id_less);
  for (const MembershipId& membership : sorted) {
    out.push_back(*impl_->state.memberships.at(membership));
  }
  return out;
}

std::optional<Membership> Registry::membership(const MembershipId& id) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  const std::shared_ptr<const Membership> record = impl_->find_membership(id);
  if (record == nullptr) {
    return std::nullopt;
  }
  return *record;
}

std::vector<FailureDomainId> Registry::ancestors(const FailureDomainId& id) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<FailureDomainId> out = ancestors_of(impl_->state, id, impl_->limits.max_ancestor_walk);
  std::sort(out.begin(), out.end(), domain_id_less);
  return out;
}

std::vector<FailureDomainId> Registry::descendants(const FailureDomainId& id) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<FailureDomainId> out = descendants_of(impl_->state, id, impl_->limits.max_ancestor_walk);
  std::sort(out.begin(), out.end(), domain_id_less);
  return out;
}

// ---------------------------------------------------------------------------
// Registry: overlap
// ---------------------------------------------------------------------------

OverlapResult Registry::overlap(const EntityId& left, const EntityId& right) const {
  std::vector<EntityId> entities{left, right};
  return overlap(entities);
}

OverlapResult Registry::overlap(const std::vector<EntityId>& entities_in) const {
  OverlapResult result;
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<EntityId> entities = entities_in;
  if (entities.size() > impl_->limits.max_query_set_cardinality) {
    result.truncated = true;
    result.steps.push_back(ExplanationStep{"limit", "entities",
                                           std::to_string(entities.size()),
                                           "truncated to max_query_set_cardinality"});
    entities.resize(impl_->limits.max_query_set_cardinality);
  }
  std::vector<EntityId> addressed;
  for (const EntityId& entity : entities) {
    if (entity.is_null()) {
      result.state = IndependenceState::Unknown;
      result.steps.push_back(
          ExplanationStep{"validate", "entity", entity.to_string(), "entity id is null"});
      return result;
    }
    if (std::find(addressed.begin(), addressed.end(), entity) == addressed.end()) {
      addressed.push_back(entity);
    }
  }
  if (addressed.size() < 2) {
    result.state = IndependenceState::Unknown;
    result.steps.push_back(ExplanationStep{"validate", "entities",
                                           std::to_string(addressed.size()),
                                           "an overlap query addresses at least two entities"});
    return result;
  }

  std::vector<std::pair<FailureDomainId, EntityRef>> memberships;
  for (const EntityId& entity : addressed) {
    std::vector<FailureDomainId> current;
    collect_current_domains(impl_->state, entity, &current);
    std::sort(current.begin(), current.end(), domain_id_less);
    result.steps.push_back(ExplanationStep{"membership", "entity", entity.to_string(),
                                           std::to_string(current.size()) +
                                               " current domain(s)"});
    for (const FailureDomainId& id : current) {
      EntityRef reference;
      const std::vector<MembershipId>* ids = impl_->memberships_of_entity(entity);
      if (ids != nullptr) {
        std::vector<MembershipId> sorted = *ids;
        std::sort(sorted.begin(), sorted.end(), membership_id_less);
        for (const MembershipId& membership_id : sorted) {
          const auto it = impl_->state.memberships.find(membership_id);
          if (it == impl_->state.memberships.end()) {
            continue;
          }
          if (it->second->domain == id && it->second->is_current()) {
            reference = it->second->member;
            break;
          }
        }
      }
      memberships.emplace_back(id, reference);
    }
  }

  for (const auto& entry : memberships) {
    SharedDomain* found = nullptr;
    for (SharedDomain& candidate : result.shared) {
      if (candidate.domain == entry.first) {
        found = &candidate;
        break;
      }
    }
    if (found == nullptr) {
      SharedDomain fresh;
      fresh.domain = entry.first;
      const auto domain_it = impl_->state.domains.find(entry.first);
      if (domain_it == impl_->state.domains.end()) {
        continue;
      }
      fresh.domain_class = domain_it->second->domain_class;
      fresh.generation = domain_it->second->generation;
      result.shared.push_back(std::move(fresh));
      found = &result.shared.back();
    }
    found->members.push_back(entry.second);
  }
  result.shared.erase(std::remove_if(result.shared.begin(), result.shared.end(),
                                     [](const SharedDomain& candidate) {
                                       return candidate.members.size() < 2;
                                     }),
                      result.shared.end());
  std::sort(result.shared.begin(), result.shared.end(),
            [](const SharedDomain& left, const SharedDomain& right) {
              if (left.domain_class.to_string() != right.domain_class.to_string()) {
                return left.domain_class.to_string() < right.domain_class.to_string();
              }
              return left.domain < right.domain;
            });

  for (SharedDomain& candidate : result.shared) {
    const std::vector<FailureDomainId> below =
        descendants_of(impl_->state, candidate.domain, impl_->limits.max_ancestor_walk);
    bool has_shared_descendant = false;
    for (const FailureDomainId& other : below) {
      for (const SharedDomain& shared : result.shared) {
        if (shared.domain == other) {
          has_shared_descendant = true;
          break;
        }
      }
      if (has_shared_descendant) {
        break;
      }
    }
    candidate.most_specific = !has_shared_descendant;
  }

  if (!result.shared.empty()) {
    result.state = IndependenceState::SharedDomain;
    result.steps.push_back(ExplanationStep{"overlap", "shared-domains",
                                           std::to_string(result.shared.size()),
                                           "entities share at least one current domain"});
    return result;
  }

  MembershipLifecycle worst = MembershipLifecycle::Unknown;
  bool indeterminate = false;
  for (const EntityId& entity : addressed) {
    if (entity_has_indeterminate(impl_->state, entity, &worst)) {
      indeterminate = true;
    }
  }
  const std::vector<std::string> scopes = impl_->effective_scopes(addressed, std::string_view());
  const std::vector<DomainClassRef> considered = default_classes({});
  bool any_declared = false;
  bool all_complete = !scopes.empty();
  for (const DomainClassRef& klass : considered) {
    bool class_complete = !scopes.empty();
    for (const std::string& scope : scopes) {
      const CoverageState coverage = impl_->coverage_for(scope, klass.to_string());
      if (coverage != CoverageState::UnknownCoverage) {
        any_declared = true;
      }
      if (coverage != CoverageState::Complete) {
        class_complete = false;
      }
    }
    if (!class_complete) {
      all_complete = false;
      result.uncovered_classes.push_back(klass);
    }
  }
  if (indeterminate) {
    result.state = worst == MembershipLifecycle::Conflicted ? IndependenceState::Conflicted
                                                            : IndependenceState::RevalidationRequired;
    result.indeterminate_classes.push_back(DomainClassRef(DomainClass::Custom));
    result.steps.push_back(ExplanationStep{"overlap", "indeterminate",
                                           std::string(to_string(worst)),
                                           "a record needed for the answer is not current"});
    return result;
  }
  if (all_complete) {
    result.state = IndependenceState::ProvenIndependent;
    result.steps.push_back(ExplanationStep{"overlap", "coverage", join_scopes(scopes),
                                           "no shared domain and complete coverage"});
    return result;
  }
  if (!any_declared) {
    result.state = IndependenceState::NoKnowledge;
    result.steps.push_back(
        ExplanationStep{"overlap", "coverage", join_scopes(scopes),
                         "no coverage declaration exists for the addressed scope"});
    return result;
  }
  result.state = IndependenceState::UnknownCoverage;
  result.steps.push_back(
      ExplanationStep{"overlap", "coverage", join_scopes(scopes),
                      "coverage is incomplete, so finding no shared domain is not proof"});
  return result;
}

// ---------------------------------------------------------------------------
// Registry: independence
// ---------------------------------------------------------------------------

IndependenceResult Registry::independence(const std::vector<EntityId>& entities,
                                          const std::vector<DomainClassRef>& classes) const {
  return independence(entities, classes, std::string_view());
}

IndependenceResult Registry::independence(const std::vector<EntityId>& entities_in,
                                          const std::vector<DomainClassRef>& classes_in,
                                          std::string_view administrative_scope) const {
  IndependenceResult result;
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<EntityId> entities = entities_in;
  if (entities.size() > impl_->limits.max_query_set_cardinality) {
    result.truncated = true;
    result.steps.push_back(ExplanationStep{"limit", "entities",
                                           std::to_string(entities.size()),
                                           "truncated to max_query_set_cardinality"});
    entities.resize(impl_->limits.max_query_set_cardinality);
  }
  std::vector<EntityId> addressed;
  for (const EntityId& entity : entities) {
    if (entity.is_null()) {
      result.state = IndependenceState::Unknown;
      result.steps.push_back(
          ExplanationStep{"validate", "entity", entity.to_string(), "entity id is null"});
      return result;
    }
    if (std::find(addressed.begin(), addressed.end(), entity) == addressed.end()) {
      addressed.push_back(entity);
    }
  }
  const std::vector<DomainClassRef> classes = default_classes(classes_in);
  if (addressed.size() < 2) {
    result.state = IndependenceState::Unknown;
    result.steps.push_back(ExplanationStep{"validate", "entities",
                                           std::to_string(addressed.size()),
                                           "an independence query addresses at least two "
                                           "entities"});
    return result;
  }

  std::vector<std::pair<FailureDomainId, EntityRef>> memberships;
  for (const EntityId& entity : addressed) {
    std::vector<FailureDomainId> current;
    collect_current_domains(impl_->state, entity, &current);
    std::sort(current.begin(), current.end(), domain_id_less);
    for (const FailureDomainId& id : current) {
      const auto domain_it = impl_->state.domains.find(id);
      if (domain_it == impl_->state.domains.end()) {
        continue;
      }
      EntityRef reference;
      const std::vector<MembershipId>* ids = impl_->memberships_of_entity(entity);
      if (ids != nullptr) {
        std::vector<MembershipId> sorted = *ids;
        std::sort(sorted.begin(), sorted.end(), membership_id_less);
        for (const MembershipId& membership_id : sorted) {
          const auto it = impl_->state.memberships.find(membership_id);
          if (it == impl_->state.memberships.end()) {
            continue;
          }
          if (it->second->domain == id && it->second->is_current()) {
            reference = it->second->member;
            break;
          }
        }
      }
      memberships.emplace_back(id, reference);
    }
  }
  for (const auto& entry : memberships) {
    const auto domain_it = impl_->state.domains.find(entry.first);
    if (domain_it == impl_->state.domains.end()) {
      continue;
    }
    if (!class_addressed(domain_it->second->domain_class, classes)) {
      continue;
    }
    SharedDomain* found = nullptr;
    for (SharedDomain& candidate : result.shared) {
      if (candidate.domain == entry.first) {
        found = &candidate;
        break;
      }
    }
    if (found == nullptr) {
      SharedDomain fresh;
      fresh.domain = entry.first;
      fresh.domain_class = domain_it->second->domain_class;
      fresh.generation = domain_it->second->generation;
      result.shared.push_back(std::move(fresh));
      found = &result.shared.back();
    }
    found->members.push_back(entry.second);
  }
  result.shared.erase(std::remove_if(result.shared.begin(), result.shared.end(),
                                     [](const SharedDomain& candidate) {
                                       return candidate.members.size() < 2;
                                     }),
                      result.shared.end());
  std::sort(result.shared.begin(), result.shared.end(),
            [](const SharedDomain& left, const SharedDomain& right) {
              if (left.domain_class.to_string() != right.domain_class.to_string()) {
                return left.domain_class.to_string() < right.domain_class.to_string();
              }
              return left.domain < right.domain;
            });

  const std::vector<std::string> scopes = impl_->effective_scopes(addressed, administrative_scope);
  // Lock-free on purpose: this thread already holds the shared lock, and a
  // second shared acquisition deadlocks against a waiting writer.
  result.coverage = impl_->coverage_locked(
      scopes.size() == 1 ? std::string_view(scopes.front()) : std::string_view(), classes);

  if (!result.shared.empty()) {
    result.state = IndependenceState::SharedDomain;
    result.steps.push_back(ExplanationStep{"independence", "shared-domains",
                                           std::to_string(result.shared.size()),
                                           "entities share at least one addressed class"});
    return result;
  }

  MembershipLifecycle worst = MembershipLifecycle::Unknown;
  bool indeterminate = false;
  for (const EntityId& entity : addressed) {
    if (entity_has_indeterminate(impl_->state, entity, &worst)) {
      indeterminate = true;
    }
  }
  if (indeterminate) {
    result.state = worst == MembershipLifecycle::Conflicted ? IndependenceState::Conflicted
                                                            : IndependenceState::RevalidationRequired;
    result.steps.push_back(ExplanationStep{"independence", "indeterminate",
                                           std::string(to_string(worst)),
                                           "a record needed for the answer is not current"});
    return result;
  }

  // Recompute coverage against the effective scope set: the report above used
  // one scope, this decision uses all of them.
  bool any_declared = false;
  bool all_complete = !scopes.empty();
  for (const DomainClassRef& klass : classes) {
    bool class_complete = !scopes.empty();
    for (const std::string& scope : scopes) {
      const CoverageState coverage_state = impl_->coverage_for(scope, klass.to_string());
      if (coverage_state != CoverageState::UnknownCoverage) {
        any_declared = true;
      }
      if (coverage_state != CoverageState::Complete) {
        class_complete = false;
      }
    }
    if (!class_complete) {
      all_complete = false;
    }
  }
  if (all_complete) {
    result.state = IndependenceState::ProvenIndependent;
    result.steps.push_back(ExplanationStep{"independence", "coverage", join_scopes(scopes),
                                           "no shared domain in a completely classified scope"});
    return result;
  }
  if (!any_declared) {
    result.state = IndependenceState::NoKnowledge;
    result.steps.push_back(
        ExplanationStep{"independence", "coverage", join_scopes(scopes),
                         "no coverage declaration exists, so nothing is proven"});
    return result;
  }
  result.state = IndependenceState::UnknownCoverage;
  result.steps.push_back(
      ExplanationStep{"independence", "coverage", join_scopes(scopes),
                      "coverage is partial or unknown for at least one addressed class"});
  return result;
}

CoverageReport Registry::Impl::coverage_locked(
    std::string_view administrative_scope,
    const std::vector<DomainClassRef>& classes) const {
  CoverageReport report;
  const std::vector<DomainClassRef> addressed = default_classes(classes);
  for (const DomainClassRef& klass : addressed) {
    CoverageEntry entry;
    entry.domain_class = klass;
    entry.administrative_scope = std::string(administrative_scope);
    // Start from the neutral state and keep the weakest declaration: Complete
    // is weaker than Partial, and Partial is weaker than UnknownCoverage.
    entry.state = CoverageState::Unknown;
    for (const CoverageDeclaration& declaration : state.coverage) {
      if (!administrative_scope.empty() &&
          declaration.administrative_scope != administrative_scope) {
        continue;
      }
      if (declaration.domain_class != klass) {
        continue;
      }
      entry.declared = true;
      if (static_cast<std::uint8_t>(declaration.state) >=
          static_cast<std::uint8_t>(entry.state)) {
        // The weakest declaration decides the state *and* the evidence the
        // report attributes to it, so the two can never be read from different
        // declarations.
        entry.state = declaration.state;
        entry.evidence = declaration.provenance.evidence;
        entry.truth = declaration.provenance.truth;
        entry.administrative_scope = declaration.administrative_scope;
      }
    }
    if (!entry.declared) {
      entry.state = CoverageState::UnknownCoverage;
    }
    if (entry.state == CoverageState::Complete) {
      report.complete_for_all = true;
    } else if (entry.state == CoverageState::Partial) {
      report.has_partial = true;
    } else {
      report.has_unknown = true;
    }
    report.entries.push_back(std::move(entry));
  }
  for (const CoverageEntry& entry : report.entries) {
    if (entry.state != CoverageState::Complete) {
      report.complete_for_all = false;
    }
  }
  return report;
}

CoverageReport Registry::coverage(std::string_view administrative_scope,
                                  const std::vector<DomainClassRef>& classes) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  return impl_->coverage_locked(administrative_scope, classes);
}

BlastRadius Registry::blast_radius(const FailureDomainId& id) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  BlastRadius result;
  result.domain = id;
  const auto domain_it = impl_->state.domains.find(id);
  if (domain_it == impl_->state.domains.end()) {
    return result;
  }
  result.domain_class = domain_it->second->domain_class;
  result.generation = domain_it->second->generation;
  result.lifecycle = domain_it->second->lifecycle;
  const std::vector<MembershipId>* ids = impl_->memberships_of_domain(id);
  if (ids != nullptr) {
    std::vector<MembershipId> sorted = *ids;
    std::sort(sorted.begin(), sorted.end(), membership_id_less);
    for (const MembershipId& membership_id : sorted) {
      const auto it = impl_->state.memberships.find(membership_id);
      if (it == impl_->state.memberships.end() || !it->second->is_current()) {
        continue;
      }
      result.members.push_back(it->second->member);
      // The classes reported are the classes of the domains the members belong
      // to, not the class of the domain that was asked about.
      const auto member_memberships = impl_->state.by_entity.find(it->second->member.id());
      if (member_memberships == impl_->state.by_entity.end()) {
        continue;
      }
      for (const MembershipId& member_membership : member_memberships->second) {
        const auto entry = impl_->state.memberships.find(member_membership);
        if (entry == impl_->state.memberships.end() || !entry->second->is_current()) {
          continue;
        }
        const auto member_domain = impl_->state.domains.find(entry->second->domain);
        if (member_domain == impl_->state.domains.end() ||
            !member_domain->second->is_current()) {
          continue;
        }
        const DomainClassRef& klass = member_domain->second->domain_class;
        if (std::find(result.member_domain_classes.begin(), result.member_domain_classes.end(),
                      klass) == result.member_domain_classes.end()) {
          result.member_domain_classes.push_back(klass);
        }
      }
    }
  }
  std::sort(result.members.begin(), result.members.end());
  result.members.erase(std::unique(result.members.begin(), result.members.end()),
                       result.members.end());
  result.child_domains = descendants_of(impl_->state, id, impl_->limits.max_ancestor_walk);
  if (result.child_domains.size() >= impl_->limits.max_ancestor_walk) {
    result.truncated = true;
  }
  // Read the relations directly: the lock is already held here, so calling the
  // public relations_of() would reacquire it.
  if (const std::vector<DomainRelationId>* relation_ids = impl_->relations_of_domain(id)) {
    std::vector<DomainRelationId> sorted = *relation_ids;
    std::sort(sorted.begin(), sorted.end());
    for (const DomainRelationId& relation_id : sorted) {
      const auto relation_it = impl_->state.relations.find(relation_id);
      if (relation_it == impl_->state.relations.end()) {
        continue;
      }
      if (relation_it->second->type == DomainRelationType::ContainedBy) {
        continue;
      }
      const FailureDomainId other =
          relation_it->second->source == id ? relation_it->second->target : relation_it->second->source;
      result.related_domains.push_back(other);
    }
  }
  std::sort(result.related_domains.begin(), result.related_domains.end(), domain_id_less);
  std::sort(result.member_domain_classes.begin(), result.member_domain_classes.end(),
            [](const DomainClassRef& left, const DomainClassRef& right) {
              return left.to_string() < right.to_string();
            });
  return result;
}

SetCorrelation Registry::correlate_member_sets(const std::vector<EntityId>& left,
                                               const std::vector<EntityId>& right,
                                               const std::vector<DomainClassRef>& classes) const {
  return correlate_member_sets(left, right, classes, std::string_view());
}

SetCorrelation Registry::correlate_member_sets(const std::vector<EntityId>& left_in,
                                               const std::vector<EntityId>& right_in,
                                               const std::vector<DomainClassRef>& classes_in,
                                               std::string_view administrative_scope) const {
  SetCorrelation result;
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<EntityId> left = left_in;
  std::vector<EntityId> right = right_in;
  if (left.size() > impl_->limits.max_query_set_cardinality ||
      right.size() > impl_->limits.max_query_set_cardinality) {
    result.steps.push_back(ExplanationStep{"limit", "sets",
                                           std::to_string(left.size()) + "/" +
                                               std::to_string(right.size()),
                                           "truncated to max_query_set_cardinality"});
    left.resize(impl_->limits.max_query_set_cardinality);
    right.resize(impl_->limits.max_query_set_cardinality);
  }
  const std::vector<DomainClassRef> classes = default_classes(classes_in);
  if (left.empty() || right.empty()) {
    result.state = IndependenceState::Unknown;
    result.steps.push_back(ExplanationStep{"validate", "sets",
                                           std::to_string(left.size()) + "/" +
                                               std::to_string(right.size()),
                                           "both member sets must be non-empty"});
    return result;
  }

  std::vector<FailureDomainId> left_domains;
  std::vector<FailureDomainId> right_domains;
  for (const EntityId& entity : left) {
    collect_current_domains(impl_->state, entity, &left_domains);
  }
  for (const EntityId& entity : right) {
    collect_current_domains(impl_->state, entity, &right_domains);
  }
  std::sort(left_domains.begin(), left_domains.end(), domain_id_less);
  std::sort(right_domains.begin(), right_domains.end(), domain_id_less);
  result.steps.push_back(ExplanationStep{"compare", "left-domains",
                                         std::to_string(left_domains.size()),
                                         "distinct current domains"});
  result.steps.push_back(ExplanationStep{"compare", "right-domains",
                                         std::to_string(right_domains.size()),
                                         "distinct current domains"});
  for (const FailureDomainId& id : left_domains) {
    if (std::find(right_domains.begin(), right_domains.end(), id) == right_domains.end()) {
      continue;
    }
    const auto domain_it = impl_->state.domains.find(id);
    if (domain_it == impl_->state.domains.end()) {
      continue;
    }
    if (!class_addressed(domain_it->second->domain_class, classes)) {
      continue;
    }
    SharedDomain record;
    record.domain = id;
    record.domain_class = domain_it->second->domain_class;
    record.generation = domain_it->second->generation;
    result.shared_domains.push_back(std::move(record));
    if (std::find(result.shared_classes.begin(), result.shared_classes.end(),
                  domain_it->second->domain_class) == result.shared_classes.end()) {
      result.shared_classes.push_back(domain_it->second->domain_class);
    }
  }
  std::sort(result.shared_domains.begin(), result.shared_domains.end(),
            [](const SharedDomain& a, const SharedDomain& b) {
              if (a.domain_class.to_string() != b.domain_class.to_string()) {
                return a.domain_class.to_string() < b.domain_class.to_string();
              }
              return a.domain < b.domain;
            });
  std::sort(result.shared_classes.begin(), result.shared_classes.end(),
            [](const DomainClassRef& a, const DomainClassRef& b) {
              return a.to_string() < b.to_string();
            });

  std::vector<EntityId> combined = left;
  combined.insert(combined.end(), right.begin(), right.end());
  const std::vector<std::string> scopes = impl_->effective_scopes(combined, administrative_scope);
  bool any_declared = false;
  bool all_complete = !scopes.empty();
  for (const DomainClassRef& klass : classes) {
    bool class_complete = !scopes.empty();
    for (const std::string& scope : scopes) {
      const CoverageState coverage_state = impl_->coverage_for(scope, klass.to_string());
      if (coverage_state != CoverageState::UnknownCoverage) {
        any_declared = true;
      }
      if (coverage_state != CoverageState::Complete) {
        class_complete = false;
        if (std::find(result.unknown_classes.begin(), result.unknown_classes.end(), klass) ==
            result.unknown_classes.end()) {
          result.unknown_classes.push_back(klass);
        }
      }
    }
    if (!class_complete) {
      all_complete = false;
    }
  }
  if (!result.shared_domains.empty()) {
    result.state = IndependenceState::SharedDomain;
    return result;
  }
  if (all_complete) {
    result.state = IndependenceState::ProvenIndependent;
    return result;
  }
  result.state = any_declared ? IndependenceState::UnknownCoverage : IndependenceState::NoKnowledge;
  return result;
}

} // namespace failure_domain_registry
