// Failure Domain Registry - state digest, snapshots, diffs, validation and
// explanations.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "registry_internal.hpp"

#include <algorithm>
#include <set>

#include "failure_domain_registry/digest.hpp"
#include "failure_domain_registry/version.hpp"

namespace failure_domain_registry {
namespace {

template <class Map>
std::vector<typename Map::key_type> sorted_keys(const Map& map) {
  std::vector<typename Map::key_type> keys;
  keys.reserve(map.size());
  for (const auto& entry : map) {
    keys.push_back(entry.first);
  }
  std::sort(keys.begin(), keys.end());
  return keys;
}

bool coverage_less(const CoverageDeclaration& left, const CoverageDeclaration& right) {
  if (left.administrative_scope != right.administrative_scope) {
    return left.administrative_scope < right.administrative_scope;
  }
  return left.domain_class.to_string() < right.domain_class.to_string();
}

} // namespace

StateDigest compute_state_digest_of(const RegistryState& state) {
  Sha256 hasher;
  std::string canonical;
  append_bytes(canonical, "fdr/state/v1");
  append_u32(canonical, kDigestVersion);
  hasher.update(canonical);

  auto absorb = [&hasher](std::string_view text) {
    std::string framed;
    append_bytes(framed, text);
    hasher.update(framed);
  };

  for (const FailureDomainId& id : sorted_keys(state.domains)) {
    absorb(state.domains.at(id)->canonical_form());
  }
  for (const MembershipId& id : sorted_keys(state.memberships)) {
    absorb(state.memberships.at(id)->canonical_form());
  }
  for (const DomainRelationId& id : sorted_keys(state.relations)) {
    absorb(state.relations.at(id)->canonical_form());
  }
  std::vector<CoverageDeclaration> coverage = state.coverage;
  std::sort(coverage.begin(), coverage.end(), coverage_less);
  for (const CoverageDeclaration& declaration : coverage) {
    std::string form;
    append_bytes(form, "fdr/coverage/v1");
    append_bytes(form, declaration.administrative_scope);
    append_bytes(form, declaration.domain_class.to_string());
    append_u8(form, static_cast<std::uint8_t>(declaration.state));
    append_bytes(form, declaration.provenance.canonical_form());
    absorb(form);
  }
  for (const DerivationRuleId& id : sorted_keys(state.rules)) {
    const DerivationRule& rule = state.rules.at(id);
    std::string form = rule.canonical_form();
    append_u8(form, rule.enabled ? 1 : 0);
    absorb(form);
  }
  for (const PublisherId& id : sorted_keys(state.publishers)) {
    const PublisherRegistration& registration = state.publishers.at(id);
    std::string form;
    append_bytes(form, "fdr/publisher/v1");
    append_bytes(form, registration.publisher.to_string());
    append_bytes(form, registration.name);
    append_bytes(form, registration.scope.render());
    absorb(form);
  }
  return StateDigest::from_bytes(hasher.finish());
}

StateDigest Registry::Impl::compute_state_digest() const {
  return compute_state_digest_of(state);
}

StateDigest Registry::state_digest() const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  return impl_->compute_state_digest();
}

Snapshot Registry::snapshot(std::string_view scope) const {
  Snapshot result;
  StateDigest digest;
  {
    const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
    result.state_generation = impl_->state.generation;
    result.epoch = impl_->state.epoch;
    result.scope = std::string(scope);
    for (const FailureDomainId& id : sorted_keys(impl_->state.domains)) {
      const FailureDomain& record = *impl_->state.domains.at(id);
      SnapshotDomainEntry entry;
      entry.id = record.id;
      entry.domain_class = record.domain_class;
      entry.generation = record.generation;
      entry.lifecycle = record.lifecycle;
      entry.evidence = record.provenance.evidence;
      entry.truth = record.provenance.truth;
      entry.source = record.provenance.source;
      entry.created_at = record.created_at;
      result.domains.push_back(std::move(entry));
    }
    for (const MembershipId& id : sorted_keys(impl_->state.memberships)) {
      const Membership& record = *impl_->state.memberships.at(id);
      SnapshotMembershipEntry entry;
      entry.id = record.id;
      entry.domain = record.domain;
      entry.domain_generation = record.domain_generation;
      entry.member = record.member;
      entry.generation = record.generation;
      entry.lifecycle = record.lifecycle;
      entry.kind = record.kind;
      entry.role = record.role;
      entry.evidence = record.provenance.evidence;
      entry.truth = record.provenance.truth;
      entry.source = record.provenance.source;
      entry.derivation_rule = record.derivation.rule;
      entry.derivation_generation = record.derivation.generation;
      result.memberships.push_back(std::move(entry));
    }
    std::string canonical = result.canonical_form();
    digest = StateDigest::from_bytes(sha256(canonical));
  }
  result.digest = digest;
  SnapshotSequence sequence;
  {
    const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
    sequence = impl_->state.next_snapshot;
    const std::optional<SnapshotSequence> next = sequence.next();
    if (next.has_value()) {
      impl_->state.next_snapshot = *next;
    }
  }
  result.sequence = sequence;
  std::string identity;
  append_bytes(identity, "fdr/snapshot-id/v1");
  append_u64(identity, sequence.value());
  append_u64(identity, result.state_generation.value());
  append_bytes(identity, result.digest.to_string());
  result.id = SnapshotId::from_digest(sha256(identity));
  return result;
}

std::string Snapshot::canonical_form() const {
  std::string out;
  append_bytes(out, "fdr/snapshot/v1");
  append_u64(out, state_generation.value());
  append_u64(out, epoch.value());
  append_bytes(out, scope);
  append_u32(out, static_cast<std::uint32_t>(domains.size()));
  for (const SnapshotDomainEntry& entry : domains) {
    append_bytes(out, entry.id.to_string());
    append_bytes(out, entry.domain_class.to_string());
    append_u64(out, entry.generation.value());
    append_u8(out, static_cast<std::uint8_t>(entry.lifecycle));
    append_u8(out, static_cast<std::uint8_t>(entry.evidence));
    append_u8(out, static_cast<std::uint8_t>(entry.truth));
    append_u8(out, static_cast<std::uint8_t>(entry.source));
  }
  append_u32(out, static_cast<std::uint32_t>(memberships.size()));
  for (const SnapshotMembershipEntry& entry : memberships) {
    append_bytes(out, entry.id.to_string());
    append_bytes(out, entry.domain.to_string());
    append_u64(out, entry.domain_generation.value());
    append_bytes(out, entry.member.to_string());
    append_u64(out, entry.generation.value());
    append_u8(out, static_cast<std::uint8_t>(entry.lifecycle));
    append_u8(out, static_cast<std::uint8_t>(entry.kind));
    append_u8(out, static_cast<std::uint8_t>(entry.role));
    append_u8(out, static_cast<std::uint8_t>(entry.evidence));
    append_u8(out, static_cast<std::uint8_t>(entry.truth));
    append_u8(out, static_cast<std::uint8_t>(entry.source));
    append_bytes(out, entry.derivation_rule.to_string());
    append_u64(out, entry.derivation_generation.value());
  }
  return out;
}

std::string Snapshot::render() const {
  std::string out = "snapshot ";
  out.append(id.to_string());
  out.append("\n  sequence         = ");
  out.append(sequence.to_string());
  out.append("\n  registry-gen     = ");
  out.append(state_generation.to_string());
  out.append("\n  epoch            = ");
  out.append(epoch.to_string());
  out.append("\n  scope            = ");
  out.append(scope);
  out.append("\n  digest           = ");
  out.append(digest.to_string());
  out.append("\n  domains          = ");
  out.append(std::to_string(domains.size()));
  out.append("\n  memberships      = ");
  out.append(std::to_string(memberships.size()));
  return out;
}

bool Registry::snapshot_is_current(const Snapshot& snapshot) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  return snapshot.state_generation == impl_->state.generation;
}

std::string_view to_string(DiffKind value) noexcept {
  switch (value) {
    case DiffKind::DomainAdded: return "domain-added";
    case DiffKind::DomainRemoved: return "domain-removed";
    case DiffKind::DomainSuperseded: return "domain-superseded";
    case DiffKind::DomainLifecycleChanged: return "domain-lifecycle-changed";
    case DiffKind::DomainClassChanged: return "domain-class-changed";
    case DiffKind::DomainProvenanceChanged: return "domain-provenance-changed";
    case DiffKind::MembershipAdded: return "membership-added";
    case DiffKind::MembershipRemoved: return "membership-removed";
    case DiffKind::MembershipMoved: return "membership-moved";
    case DiffKind::MembershipLifecycleChanged: return "membership-lifecycle-changed";
    case DiffKind::MembershipProvenanceChanged: return "membership-provenance-changed";
    case DiffKind::MembershipDerivationChanged: return "membership-derivation-changed";
    default: return "unknown";
  }
}

SnapshotDiff Registry::diff(const Snapshot& before, const Snapshot& after) const {
  SnapshotDiff result;
  result.before = before.id;
  result.after = after.id;
  result.before_generation = before.state_generation;
  result.after_generation = after.state_generation;

  const auto domain_lifecycle_text = [](DomainLifecycle value) {
    return std::string(failure_domain_registry::to_string(value));
  };
  const auto membership_lifecycle_text = [](MembershipLifecycle value) {
    return std::string(failure_domain_registry::to_string(value));
  };

  for (const SnapshotDomainEntry& entry : before.domains) {
    const SnapshotDomainEntry* match = nullptr;
    for (const SnapshotDomainEntry& candidate : after.domains) {
      if (candidate.id == entry.id) {
        match = &candidate;
        break;
      }
    }
    if (match == nullptr) {
      result.entries.push_back(DiffEntry{DiffKind::DomainRemoved, entry.id, MembershipId{},
                                         EntityRef{}, entry.domain_class.to_string(),
                                         std::string()});
      continue;
    }
    if (match->domain_class != entry.domain_class) {
      result.entries.push_back(DiffEntry{DiffKind::DomainClassChanged, entry.id, MembershipId{},
                                         EntityRef{}, entry.domain_class.to_string(),
                                         match->domain_class.to_string()});
    }
    if (match->lifecycle != entry.lifecycle) {
      result.entries.push_back(DiffEntry{DiffKind::DomainLifecycleChanged, entry.id, MembershipId{},
                                         EntityRef{}, domain_lifecycle_text(entry.lifecycle),
                                         domain_lifecycle_text(match->lifecycle)});
    }
    if (match->lifecycle == DomainLifecycle::Superseded) {
      result.entries.push_back(DiffEntry{DiffKind::DomainSuperseded, entry.id, MembershipId{},
                                         EntityRef{}, std::to_string(entry.generation.value()),
                                         std::to_string(match->generation.value())});
    }
    if (match->evidence != entry.evidence || match->source != entry.source ||
        match->truth != entry.truth) {
      std::string before_text = std::string(failure_domain_registry::to_string(entry.evidence)) +
                                "/" + std::string(failure_domain_registry::to_string(entry.truth));
      std::string after_text = std::string(failure_domain_registry::to_string(match->evidence)) +
                               "/" + std::string(failure_domain_registry::to_string(match->truth));
      result.entries.push_back(DiffEntry{DiffKind::DomainProvenanceChanged, entry.id,
                                         MembershipId{}, EntityRef{}, std::move(before_text),
                                         std::move(after_text)});
    }
  }
  for (const SnapshotDomainEntry& entry : after.domains) {
    bool present = false;
    for (const SnapshotDomainEntry& candidate : before.domains) {
      if (candidate.id == entry.id) {
        present = true;
        break;
      }
    }
    if (!present) {
      result.entries.push_back(DiffEntry{DiffKind::DomainAdded, entry.id, MembershipId{},
                                         EntityRef{}, std::string(),
                                         entry.domain_class.to_string()});
    }
  }

  for (const SnapshotMembershipEntry& entry : before.memberships) {
    const SnapshotMembershipEntry* match = nullptr;
    for (const SnapshotMembershipEntry& candidate : after.memberships) {
      if (candidate.id == entry.id) {
        match = &candidate;
        break;
      }
    }
    if (match == nullptr) {
      result.entries.push_back(DiffEntry{DiffKind::MembershipRemoved, entry.domain, entry.id,
                                         entry.member, entry.member.to_string(), std::string()});
      continue;
    }
    if (match->domain != entry.domain) {
      result.entries.push_back(DiffEntry{DiffKind::MembershipMoved, entry.domain, entry.id,
                                         entry.member, entry.domain.to_string(),
                                         match->domain.to_string()});
    }
    if (match->lifecycle != entry.lifecycle) {
      result.entries.push_back(DiffEntry{DiffKind::MembershipLifecycleChanged, entry.domain,
                                         entry.id, entry.member,
                                         membership_lifecycle_text(entry.lifecycle),
                                         membership_lifecycle_text(match->lifecycle)});
    }
    if (match->evidence != entry.evidence || match->truth != entry.truth ||
        match->source != entry.source) {
      std::string before_text = std::string(failure_domain_registry::to_string(entry.evidence)) +
                                "/" + std::string(failure_domain_registry::to_string(entry.truth));
      std::string after_text = std::string(failure_domain_registry::to_string(match->evidence)) +
                               "/" + std::string(failure_domain_registry::to_string(match->truth));
      result.entries.push_back(DiffEntry{DiffKind::MembershipProvenanceChanged, entry.domain,
                                         entry.id, entry.member, std::move(before_text),
                                         std::move(after_text)});
    }
    if (match->derivation_rule != entry.derivation_rule ||
        match->derivation_generation != entry.derivation_generation) {
      result.entries.push_back(DiffEntry{DiffKind::MembershipDerivationChanged, entry.domain,
                                         entry.id, entry.member, entry.derivation_rule.to_string(),
                                         match->derivation_rule.to_string()});
    }
  }
  for (const SnapshotMembershipEntry& entry : after.memberships) {
    bool present = false;
    for (const SnapshotMembershipEntry& candidate : before.memberships) {
      if (candidate.id == entry.id) {
        present = true;
        break;
      }
    }
    if (!present) {
      result.entries.push_back(DiffEntry{DiffKind::MembershipAdded, entry.domain, entry.id,
                                         entry.member, std::string(), entry.member.to_string()});
    }
  }
  std::sort(result.entries.begin(), result.entries.end(),
            [](const DiffEntry& left, const DiffEntry& right) {
              if (left.kind != right.kind) {
                return static_cast<std::uint8_t>(left.kind) <
                       static_cast<std::uint8_t>(right.kind);
              }
              if (left.domain != right.domain) {
                return left.domain < right.domain;
              }
              if (left.membership != right.membership) {
                return left.membership < right.membership;
              }
              return left.member < right.member;
            });
  return result;
}

std::string SnapshotDiff::render() const {
  std::string out = "diff ";
  out.append(before.to_string());
  out.append(" -> ");
  out.append(after.to_string());
  out.append(" (registry-generation ");
  out.append(before_generation.to_string());
  out.append(" -> ");
  out.append(after_generation.to_string());
  out.append(")");
  if (entries.empty()) {
    out.append("\n  no semantic change");
  }
  for (const DiffEntry& entry : entries) {
    out.append("\n  ");
    out.append(failure_domain_registry::to_string(entry.kind));
    out.append(" domain=");
    out.append(entry.domain.to_string());
    if (!entry.membership.is_null()) {
      out.append(" membership=");
      out.append(entry.membership.to_string());
    }
    if (!entry.member.is_null()) {
      out.append(" member=");
      out.append(entry.member.to_string());
    }
    if (!entry.before.empty() || !entry.after.empty()) {
      out.append(" [");
      out.append(entry.before);
      out.append(" -> ");
      out.append(entry.after);
      out.append("]");
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Index validation
// ---------------------------------------------------------------------------

bool Registry::validate_state(std::string* why) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  const RegistryState& state = impl_->state;
  const auto fail = [why](const std::string& text) {
    if (why != nullptr) {
      *why = text;
    }
    return false;
  };

  std::unordered_map<EntityId, std::vector<MembershipId>> by_entity;
  std::unordered_map<FailureDomainId, std::vector<MembershipId>> by_domain;
  std::unordered_map<PublisherId, std::vector<MembershipId>> by_publisher;
  std::unordered_map<std::string, std::vector<FailureDomainId>> by_class;
  std::unordered_map<std::string, std::vector<FailureDomainId>> by_scope;
  std::array<std::vector<FailureDomainId>, kLifecycleSlots> domains_by_lifecycle;
  std::array<std::vector<MembershipId>, kLifecycleSlots> memberships_by_lifecycle;
  std::unordered_map<FailureDomainId, std::vector<DomainRelationId>> relations_by_domain;
  std::unordered_map<FailureDomainId, std::vector<FailureDomainId>> children;
  std::unordered_map<FailureDomainId, std::vector<FailureDomainId>> parents;

  for (const auto& entry : state.domains) {
    const FailureDomain& record = *entry.second;
    if (record.id != entry.first) {
      return fail("domain table key does not match the record id");
    }
    by_class[record.domain_class.to_string()].push_back(record.id);
    by_scope[record.administrative_scope].push_back(record.id);
    const auto slot = static_cast<std::size_t>(record.lifecycle);
    if (slot < kLifecycleSlots) {
      domains_by_lifecycle[slot].push_back(record.id);
    }
  }
  for (const auto& entry : state.memberships) {
    const Membership& record = *entry.second;
    if (record.id != entry.first) {
      return fail("membership table key does not match the record id");
    }
    if (state.domains.find(record.domain) == state.domains.end()) {
      return fail("membership references a domain that does not exist");
    }
    by_entity[record.member.id()].push_back(record.id);
    by_domain[record.domain].push_back(record.id);
    for (const PublisherId& publisher : membership_evidence_publishers(record)) {
      by_publisher[publisher].push_back(record.id);
    }
    const auto slot = static_cast<std::size_t>(record.lifecycle);
    if (slot < kLifecycleSlots) {
      memberships_by_lifecycle[slot].push_back(record.id);
    }
  }
  for (const auto& entry : state.relations) {
    const DomainRelation& record = *entry.second;
    if (record.id != entry.first) {
      return fail("relation table key does not match the record id");
    }
    if (state.domains.find(record.source) == state.domains.end() ||
        state.domains.find(record.target) == state.domains.end()) {
      return fail("relation references a domain that does not exist");
    }
    relations_by_domain[record.source].push_back(record.id);
    relations_by_domain[record.target].push_back(record.id);
    if (record.type == DomainRelationType::ContainedBy) {
      children[record.target].push_back(record.source);
      parents[record.source].push_back(record.target);
    }
  }

  const auto same_sorted = [](auto left, auto right) {
    std::sort(left.begin(), left.end());
    std::sort(right.begin(), right.end());
    return left == right;
  };

  if (state.by_entity.size() != by_entity.size()) {
    return fail("entity index size mismatch");
  }
  for (const auto& entry : by_entity) {
    const auto it = state.by_entity.find(entry.first);
    if (it == state.by_entity.end() || !same_sorted(it->second, entry.second)) {
      return fail("entity index mismatch for " + entry.first.to_string());
    }
  }
  if (state.by_domain.size() != by_domain.size()) {
    return fail("domain index size mismatch");
  }
  for (const auto& entry : by_domain) {
    const auto it = state.by_domain.find(entry.first);
    if (it == state.by_domain.end() || !same_sorted(it->second, entry.second)) {
      return fail("domain index mismatch for " + entry.first.to_string());
    }
  }
  if (state.by_publisher.size() != by_publisher.size()) {
    return fail("publisher index size mismatch");
  }
  for (const auto& entry : by_publisher) {
    const auto it = state.by_publisher.find(entry.first);
    if (it == state.by_publisher.end() || !same_sorted(it->second, entry.second)) {
      return fail("publisher index mismatch");
    }
  }
  if (state.by_class.size() != by_class.size()) {
    return fail("class index size mismatch");
  }
  for (const auto& entry : by_class) {
    const auto it = state.by_class.find(entry.first);
    if (it == state.by_class.end() || !same_sorted(it->second, entry.second)) {
      return fail("class index mismatch for " + entry.first);
    }
  }
  if (state.by_scope.size() != by_scope.size()) {
    return fail("scope index size mismatch");
  }
  for (const auto& entry : by_scope) {
    const auto it = state.by_scope.find(entry.first);
    if (it == state.by_scope.end() || !same_sorted(it->second, entry.second)) {
      return fail("scope index mismatch for " + entry.first);
    }
  }
  for (std::size_t slot = 0; slot < kLifecycleSlots; ++slot) {
    if (!same_sorted(state.domains_by_lifecycle[slot], domains_by_lifecycle[slot])) {
      return fail("domain lifecycle index mismatch at slot " + std::to_string(slot));
    }
    if (!same_sorted(state.memberships_by_lifecycle[slot], memberships_by_lifecycle[slot])) {
      return fail("membership lifecycle index mismatch at slot " + std::to_string(slot));
    }
  }
  if (state.relations_by_domain.size() != relations_by_domain.size()) {
    return fail("relation index size mismatch");
  }
  for (const auto& entry : relations_by_domain) {
    const auto it = state.relations_by_domain.find(entry.first);
    if (it == state.relations_by_domain.end() || !same_sorted(it->second, entry.second)) {
      return fail("relation index mismatch for " + entry.first.to_string());
    }
  }
  if (state.children.size() != children.size()) {
    return fail("children index size mismatch");
  }
  for (const auto& entry : children) {
    const auto it = state.children.find(entry.first);
    if (it == state.children.end() || !same_sorted(it->second, entry.second)) {
      return fail("children index mismatch");
    }
  }
  if (state.parents.size() != parents.size()) {
    return fail("parents index size mismatch");
  }
  for (const auto& entry : parents) {
    const auto it = state.parents.find(entry.first);
    if (it == state.parents.end() || !same_sorted(it->second, entry.second)) {
      return fail("parents index mismatch");
    }
  }
  // A maintained graph must not contain a cycle over an acyclic relation type.
  for (const auto& entry : state.relations) {
    const DomainRelation& record = *entry.second;
    if (!is_acyclic_relation(record.type)) {
      continue;
    }
    bool bounded = false;
    if (impl_->path_exists(record.target, record.source, record.type, &bounded) && !bounded) {
      return fail("acyclic relation closes a cycle");
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Explanations
// ---------------------------------------------------------------------------

std::vector<Outcome> Registry::recent_outcomes(std::size_t max_records) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  std::vector<Outcome> out;
  for (auto it = impl_->recent.rbegin(); it != impl_->recent.rend(); ++it) {
    if (out.size() >= max_records) {
      break;
    }
    out.push_back(*it);
  }
  return out;
}

Explanation Registry::explain_outcome(const RequestDigest& digest) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  Explanation explanation("request-digest " + digest.to_string());
  bool found = false;
  for (auto it = impl_->recent.rbegin(); it != impl_->recent.rend(); ++it) {
    if (!(it->request_digest == digest)) {
      continue;
    }
    found = true;
    Outcome recorded = *it;
    explanation.field_step("outcome", "code", std::string(to_string(recorded.code)),
                           recorded.message);
    for (const ExplanationStep& step : recorded.steps) {
      explanation.steps.push_back(step);
    }
    break;
  }
  if (!found) {
    explanation.complete = false;
    explanation.step("outcome", "no recorded outcome carries this request digest");
  }
  return explanation;
}

Explanation Registry::explain_generation() const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  Explanation explanation("generation");
  explanation.field_step("generation", "registry", impl_->state.generation.to_string(),
                         "advanced by every committed state change");
  explanation.field_step("generation", "epoch", impl_->state.epoch.to_string(),
                         "advanced only by advance_epoch");
  std::size_t domains_current = 0;
  std::size_t memberships_current = 0;
  std::size_t memberships_revalidation = 0;
  std::size_t memberships_conflicted = 0;
  for (const auto& entry : impl_->state.domains) {
    if (entry.second->is_current()) {
      ++domains_current;
    }
  }
  for (const auto& entry : impl_->state.memberships) {
    if (entry.second->is_current()) {
      ++memberships_current;
    } else if (entry.second->lifecycle == MembershipLifecycle::RevalidationRequired) {
      ++memberships_revalidation;
    } else if (entry.second->lifecycle == MembershipLifecycle::Conflicted) {
      ++memberships_conflicted;
    }
  }
  explanation.field_step("generation", "domains",
                         std::to_string(impl_->state.domains.size()) + " (" +
                             std::to_string(domains_current) + " current)",
                         "domain records");
  explanation.field_step("generation", "memberships",
                         std::to_string(impl_->state.memberships.size()) + " (" +
                             std::to_string(memberships_current) + " current, " +
                             std::to_string(memberships_revalidation) + " revalidation-required, " +
                             std::to_string(memberships_conflicted) + " conflicted)",
                         "membership records");
  explanation.field_step("generation", "next-evidence-generation",
                         std::to_string(impl_->state.next_evidence_generation),
                         "monotonic evidence counter");
  return explanation;
}

Explanation Registry::explain_domain(const FailureDomainId& id) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  const std::shared_ptr<const FailureDomain> record = impl_->find_domain(id);
  Explanation explanation("domain " + id.to_string());
  if (record == nullptr) {
    explanation.complete = false;
    explanation.step("lookup", "no such domain");
    return explanation;
  }
  explanation.field_step("identity", "class", record->domain_class.to_string(),
                         "canonical failure-domain class");
  explanation.field_step("state", "lifecycle",
                         std::string(to_string(record->lifecycle)),
                         record->is_current() ? "carries classification authority"
                                              : "does not carry classification authority");
  explanation.field_step("state", "generation", record->generation.to_string(),
                         "current domain generation");
  explanation.field_step("provenance", "source", record->provenance.render(),
                         "where the classification came from");
  explanation.field_step("scope", "administrative-scope", record->administrative_scope,
                         "scope the classification belongs to");
  const std::vector<MembershipId>* ids = impl_->memberships_of_domain(id);
  std::size_t current = 0;
  std::size_t total = ids == nullptr ? 0 : ids->size();
  if (ids != nullptr) {
    for (const MembershipId& membership_id : *ids) {
      const auto it = impl_->state.memberships.find(membership_id);
      if (it != impl_->state.memberships.end() && it->second->is_current()) {
        ++current;
      }
    }
  }
  explanation.field_step("members", "memberships",
                         std::to_string(total) + " (" + std::to_string(current) + " current)",
                         "membership records pointing at this domain");
  if (!record->superseded_by.is_null()) {
    explanation.field_step("lineage", "superseded-by", record->superseded_by.to_string(),
                           "successor domain");
  }
  if (!record->supersedes.is_null()) {
    explanation.field_step("lineage", "supersedes", record->supersedes.to_string(),
                           "domain this record replaced");
  }
  if (!record->merged_into.is_null()) {
    explanation.field_step("lineage", "merged-into", record->merged_into.to_string(),
                           "surviving domain of an explicit merge");
  }
  std::size_t emitted = 0;
  for (auto it = record->history.rbegin();
       it != record->history.rend() && emitted < impl_->limits.max_history_query; ++it, ++emitted) {
    explanation.field_step("history", it->cause, it->generation.to_string(),
                           std::string(to_string(it->lifecycle)));
  }
  if (record->history.size() > emitted) {
    explanation.field_step("history", "truncated", std::to_string(record->history.size() - emitted),
                           "max_history_query reached; older entries are not rendered");
  }
  return explanation;
}

Explanation Registry::explain_membership(const FailureDomainId& domain,
                                         const EntityId& entity) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  Explanation explanation("membership " + domain.to_string() + " / " + entity.to_string());
  const std::vector<MembershipId>* ids = impl_->memberships_of_entity(entity);
  if (ids == nullptr) {
    explanation.complete = false;
    explanation.field_step("lookup", "entity", entity.to_string(),
                           "no membership record names this entity at all");
    return explanation;
  }
  std::vector<MembershipId> sorted = *ids;
  std::sort(sorted.begin(), sorted.end(), membership_id_less);
  bool found = false;
  for (const MembershipId& id : sorted) {
    const auto it = impl_->state.memberships.find(id);
    if (it == impl_->state.memberships.end()) {
      continue;
    }
    const Membership& record = *it->second;
    if (record.domain != domain) {
      continue;
    }
    found = true;
    explanation.field_step("identity", "membership", record.id.to_string(),
                           std::string(to_string(record.kind)) + " membership");
    explanation.field_step("state", "lifecycle",
                           std::string(to_string(record.lifecycle)),
                           record.is_current() ? "current" : "not current");
    explanation.field_step("binding", "domain-generation", record.domain_generation.to_string(),
                           "domain generation this membership is bound to");
    explanation.field_step("binding", "member", record.member.to_string(),
                           "entity generation this membership is bound to");
    explanation.field_step("evidence", "headline", record.provenance.render(),
                           "strongest live evidence");
    for (const MembershipEvidence& entry : record.evidence) {
      explanation.field_step("evidence", entry.live ? "live" : "stale",
                             entry.provenance.render(), "corroborating evidence entry");
    }
    if (!record.derivation.rule.is_null()) {
      explanation.field_step("derivation", "rule", record.derivation.rule.to_string(),
                             record.derivation.valid ? "derivation sources are current"
                                                     : "derivation sources moved on");
      explanation.field_step("derivation", "sources",
                             std::to_string(record.derivation.sources.size()),
                             record.derivation.context);
    }
    std::size_t emitted = 0;
    for (auto entry_it = record.history.rbegin();
         entry_it != record.history.rend() && emitted < impl_->limits.max_history_query;
         ++entry_it, ++emitted) {
      explanation.field_step("history", entry_it->cause, entry_it->generation.to_string(),
                             std::string(to_string(entry_it->lifecycle)));
    }
    if (record.history.size() > emitted) {
      explanation.field_step("history", "truncated",
                             std::to_string(record.history.size() - emitted),
                             "max_history_query reached; older entries are not rendered");
    }
  }
  if (!found) {
    explanation.complete = false;
    explanation.field_step("lookup", "entity", entity.to_string(),
                           "the entity has no membership record for this domain");
    const std::shared_ptr<const FailureDomain> domain_record = impl_->find_domain(domain);
    if (domain_record == nullptr) {
      explanation.step("lookup", "the domain does not exist either");
    } else {
      explanation.field_step("lookup", "coverage",
                             std::string(to_string(impl_->coverage_for(
                                 domain_record->administrative_scope,
                                 domain_record->domain_class.to_string()))),
                             "coverage for this class in the domain's scope decides whether "
                             "absence means anything");
    }
  }
  return explanation;
}

Explanation Registry::explain_conflict(const FailureDomainId& domain,
                                       const EntityId& entity) const {
  const std::shared_lock<std::shared_mutex> guard(impl_->mutex);
  Explanation explanation("conflict " + domain.to_string() + " / " + entity.to_string());
  const std::vector<MembershipId>* ids = impl_->memberships_of_entity(entity);
  if (ids != nullptr) {
    std::vector<MembershipId> sorted = *ids;
    std::sort(sorted.begin(), sorted.end(), membership_id_less);
    for (const MembershipId& id : sorted) {
      const auto it = impl_->state.memberships.find(id);
      if (it == impl_->state.memberships.end()) {
        continue;
      }
      const Membership& record = *it->second;
      if (record.domain != domain) {
        continue;
      }
      explanation.field_step("conflict", "lifecycle",
                             std::string(to_string(record.lifecycle)),
                             record.lifecycle == MembershipLifecycle::Conflicted
                                 ? "equally strong evidence disagrees"
                                 : "no conflict recorded");
      for (const MembershipEvidence& entry : record.evidence) {
        explanation.field_step("conflict", "evidence", entry.provenance.render(),
                               std::string("rank=") +
                                   std::to_string(evidence_rank(entry.provenance.evidence)));
      }
    }
  }
  const std::shared_ptr<const FailureDomain> domain_record = impl_->find_domain(domain);
  if (domain_record != nullptr && domain_record->lifecycle == DomainLifecycle::Conflicted) {
    explanation.field_step("conflict", "domain-lifecycle",
                           std::string(to_string(domain_record->lifecycle)),
                           "the domain itself is conflicted");
  }
  return explanation;
}

Explanation Registry::explain_independence(const std::vector<EntityId>& entities,
                                           const std::vector<DomainClassRef>& classes) const {
  const IndependenceResult result = independence(entities, classes);
  Explanation explanation("independence " + render_entity_list(entities));
  explanation.field_step("result", "state", std::string(to_string(result.state)),
                         "deterministic independence answer");
  for (const SharedDomain& shared : result.shared) {
    explanation.field_step("shared", shared.domain.to_string(),
                           shared.domain_class.to_string(),
                           shared.most_specific ? "shared, and the most specific shared domain"
                                                 : "shared");
  }
  for (const CoverageEntry& entry : result.coverage.entries) {
    explanation.field_step("coverage", entry.domain_class.to_string(),
                           std::string(to_string(entry.state)),
                           entry.declared ? "declared" : "no declaration exists");
  }
  for (const ExplanationStep& step : result.steps) {
    explanation.steps.push_back(step);
  }
  return explanation;
}

Outcome Registry::reset() {
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  const std::size_t domains = impl_->state.domains.size();
  const std::size_t memberships = impl_->state.memberships.size();
  RegistryState fresh;
  // The epoch survives a reset: a reset registry must not accept traffic that
  // was addressed to the incarnation that was reset away.
  fresh.epoch = impl_->state.epoch;
  impl_->state = std::move(fresh);
  impl_->idempotency.clear();
  impl_->idempotency_entries = 0;
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "registry state reset");
  outcome.steps.push_back(ExplanationStep{"reset", "records",
                                          std::to_string(domains) + " domains, " +
                                              std::to_string(memberships) + " memberships",
                                          "dropped"});
  return impl_->record(std::move(outcome));
}

} // namespace failure_domain_registry
