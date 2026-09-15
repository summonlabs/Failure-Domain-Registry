// Failure Domain Registry - mutation operations.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every mutation follows the same pipeline, and that pipeline is the contract:
//
//   canonicalise -> check attempt -> recognise replay -> authorise -> validate
//   -> validate entity and domain bindings -> validate exclusivity and
//   hierarchy -> resolve conflicts -> prepare index changes -> commit
//   atomically -> advance generations -> remember the attempt -> return a
//   structured outcome.
//
// Nothing here performs I/O, calls a caller-supplied callback, or reacquires
// the registry lock.

#include "registry_internal.hpp"

#include <algorithm>

#include "failure_domain_registry/digest.hpp"

namespace failure_domain_registry {
namespace {

std::string canonical_metadata(const std::vector<MetadataEntry>& metadata) {
  std::vector<MetadataEntry> sorted = metadata;
  std::sort(sorted.begin(), sorted.end(),
            [](const MetadataEntry& left, const MetadataEntry& right) {
              if (left.key != right.key) {
                return left.key < right.key;
              }
              return left.value < right.value;
            });
  std::string out;
  append_u32(out, static_cast<std::uint32_t>(sorted.size()));
  for (const MetadataEntry& entry : sorted) {
    append_bytes(out, entry.key);
    append_bytes(out, entry.value);
  }
  return out;
}

Outcome validate_metadata(const std::vector<MetadataEntry>& metadata, std::size_t max_entries,
                          std::size_t max_value_bytes, std::size_t max_total_bytes) {
  if (metadata.size() > max_entries) {
    return Outcome::make(OutcomeCode::ResourceLimit, "too many metadata entries");
  }
  std::size_t total = 0;
  for (const MetadataEntry& entry : metadata) {
    if (entry.key.empty()) {
      return Outcome::make(OutcomeCode::MalformedRequest, "metadata key is empty");
    }
    if (entry.value.size() > max_value_bytes) {
      return Outcome::make(OutcomeCode::ResourceLimit, "metadata value too long");
    }
    total += entry.key.size() + entry.value.size();
    if (total > max_total_bytes) {
      return Outcome::make(OutcomeCode::ResourceLimit,
                           "metadata exceeds the per-record budget");
    }
    for (char c : entry.key) {
      const unsigned char raw = static_cast<unsigned char>(c);
      if (raw < 0x20u || raw == 0x7fu) {
        return Outcome::make(OutcomeCode::MalformedRequest,
                             "metadata key contains a control character");
      }
    }
  }
  return Outcome::make(OutcomeCode::Committed, "metadata accepted");
}

Outcome validate_provenance(const Provenance& provenance, const RegistryLimits& limits) {
  if (!is_valid_provenance_source(provenance.source)) {
    return Outcome::make(OutcomeCode::MalformedRequest,
                         "provenance source is not a known source");
  }
  if (!is_valid_evidence_class(provenance.evidence)) {
    return Outcome::make(OutcomeCode::MalformedRequest, "evidence class is not a known class");
  }
  if (!is_valid_truth_class(provenance.truth)) {
    return Outcome::make(OutcomeCode::MalformedRequest, "truth class is not a known class");
  }
  if (provenance.source_identity.size() > limits.max_string_bytes) {
    return Outcome::make(OutcomeCode::ResourceLimit, "source identity is too long");
  }
  if (provenance.derivation_context.size() > limits.max_string_bytes) {
    return Outcome::make(OutcomeCode::ResourceLimit, "derivation context is too long");
  }
  for (char c : provenance.source_identity) {
    const unsigned char raw = static_cast<unsigned char>(c);
    if (raw < 0x20u || raw == 0x7fu) {
      return Outcome::make(OutcomeCode::MalformedRequest,
                           "source identity contains a control character");
    }
  }
  return Outcome::make(OutcomeCode::Committed, "provenance accepted");
}

Provenance attribute_provenance(const Provenance& provenance, const AuthorityContext& authority) {
  Provenance out = provenance;
  if (out.publisher.is_null()) {
    out.publisher = authority.publisher;
  }
  if (out.worker_boot.is_null()) {
    out.worker_boot = authority.worker_boot;
  }
  return out;
}

EvidenceClass effective_evidence(const Provenance& provenance, const AuthorityContext& authority) {
  return is_valid_evidence_class(provenance.evidence) ? provenance.evidence : authority.evidence;
}

AuthorityContext with_evidence(const AuthorityContext& authority, EvidenceClass evidence) {
  AuthorityContext out = authority;
  out.evidence = evidence;
  return out;
}

enum class Precedence { Stronger, Weaker, EqualSameSource, EqualDifferentSource };

Precedence compare_provenance(const Provenance& existing, const Provenance& incoming) {
  if (evidence_outranks(incoming.evidence, existing.evidence)) {
    return Precedence::Stronger;
  }
  if (evidence_outranks(existing.evidence, incoming.evidence)) {
    return Precedence::Weaker;
  }
  if (incoming.source == existing.source && incoming.source_identity == existing.source_identity &&
      incoming.truth == existing.truth) {
    return Precedence::EqualSameSource;
  }
  return Precedence::EqualDifferentSource;
}

bool exclusive_conflict(const RegistryState& state, const FailureDomainId& domain,
                        const DomainClassRef& domain_class, const EntityId& entity,
                        FailureDomainId* other) {
  if (!domain_class.is_exclusive()) {
    return false;
  }
  const auto it = state.by_entity.find(entity);
  if (it == state.by_entity.end()) {
    return false;
  }
  for (const MembershipId& id : it->second) {
    const auto membership_it = state.memberships.find(id);
    if (membership_it == state.memberships.end() || !membership_it->second->is_current()) {
      continue;
    }
    if (membership_it->second->domain == domain) {
      continue;
    }
    const auto domain_it = state.domains.find(membership_it->second->domain);
    if (domain_it == state.domains.end()) {
      continue;
    }
    if (domain_it->second->domain_class == domain_class) {
      if (other != nullptr) {
        *other = membership_it->second->domain;
      }
      return true;
    }
  }
  return false;
}

std::string entity_bytes(const IdBytes& bytes) {
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

// --- request canonical forms ----------------------------------------------

std::string form_create_domain(const CreateDomainRequest& request) {
  std::string out;
  append_bytes(out, "fdr/req/create-domain/v1");
  append_bytes(out, request.domain_class.to_string());
  append_bytes(out, request.administrative_scope);
  append_bytes(out, request.identity_key);
  append_bytes(out, request.name);
  append_bytes(out, request.provenance.canonical_form());
  append_u8(out, request.activate ? 1 : 0);
  append_bytes(out, canonical_metadata(request.metadata));
  return out;
}

std::string form_update_domain(const UpdateDomainRequest& request) {
  std::string out;
  append_bytes(out, "fdr/req/update-domain/v1");
  append_bytes(out, request.domain.to_string());
  append_u64(out, request.expected_generation.value());
  append_u8(out, request.name.has_value() ? 1 : 0);
  if (request.name.has_value()) {
    append_bytes(out, *request.name);
  }
  append_u8(out, request.replace_metadata ? 1 : 0);
  append_bytes(out, canonical_metadata(request.metadata));
  append_bytes(out, request.provenance.canonical_form());
  append_u8(out, request.transition.has_value() ? static_cast<std::uint8_t>(*request.transition) : 0);
  return out;
}

std::string form_supersede_domain(const SupersedeDomainRequest& request) {
  std::string out;
  append_bytes(out, "fdr/req/supersede-domain/v1");
  append_bytes(out, request.domain.to_string());
  append_u64(out, request.expected_generation.value());
  append_bytes(out, request.successor.to_string());
  append_u8(out, request.demote_memberships ? 1 : 0);
  return out;
}

std::string form_retire_domain(const RetireDomainRequest& request) {
  std::string out;
  append_bytes(out, "fdr/req/retire-domain/v1");
  append_bytes(out, request.domain.to_string());
  append_u64(out, request.expected_generation.value());
  append_bytes(out, request.reason);
  append_u8(out, request.retire_memberships ? 1 : 0);
  return out;
}

std::string form_add_relation(const AddRelationRequest& request) {
  std::string out;
  append_bytes(out, "fdr/req/add-relation/v1");
  append_bytes(out, request.source.to_string());
  append_bytes(out, request.target.to_string());
  append_u8(out, static_cast<std::uint8_t>(request.type));
  append_bytes(out, request.provenance.canonical_form());
  return out;
}

std::string form_merge_domains(const MergeDomainsRequest& request) {
  std::string out;
  append_bytes(out, "fdr/req/merge-domains/v1");
  append_bytes(out, request.survivor.to_string());
  append_u64(out, request.expected_survivor_generation.value());
  append_bytes(out, request.absorbed.to_string());
  append_u64(out, request.expected_absorbed_generation.value());
  append_u8(out, request.memberships_equivalent ? 1 : 0);
  append_bytes(out, request.reason);
  return out;
}

std::string form_attach_member(const AttachMemberRequest& request) {
  std::string out;
  append_bytes(out, "fdr/req/attach-member/v1");
  append_bytes(out, request.domain.to_string());
  append_u64(out, request.expected_domain_generation.value());
  append_bytes(out, request.member.to_string());
  append_u8(out, static_cast<std::uint8_t>(request.kind));
  append_u8(out, static_cast<std::uint8_t>(request.role));
  append_u8(out, static_cast<std::uint8_t>(request.dependency));
  append_bytes(out, request.provenance.canonical_form());
  append_bytes(out, canonical_metadata(request.metadata));
  return out;
}

std::string form_detach_member(const DetachMemberRequest& request) {
  std::string out;
  append_bytes(out, "fdr/req/detach-member/v1");
  append_bytes(out, request.domain.to_string());
  append_bytes(out, request.member.to_string());
  append_u8(out, static_cast<std::uint8_t>(request.kind));
  append_u64(out, request.expected_membership_generation.value());
  append_bytes(out, request.reason);
  return out;
}

std::string form_replace_membership(const ReplaceMembershipRequest& request) {
  std::string out;
  append_bytes(out, "fdr/req/replace-membership/v1");
  append_bytes(out, request.membership.to_string());
  append_u64(out, request.expected_generation.value());
  append_u8(out, static_cast<std::uint8_t>(request.role));
  append_u8(out, static_cast<std::uint8_t>(request.dependency));
  append_bytes(out, request.provenance.canonical_form());
  append_u8(out, request.replace_metadata ? 1 : 0);
  append_bytes(out, canonical_metadata(request.metadata));
  return out;
}

std::string form_publish_memberships(const MembershipBatchRequest& request) {
  std::vector<FailureDomainId> domains = request.authoritative_domains;
  std::sort(domains.begin(), domains.end());
  std::vector<MembershipBatchEntry> entries = request.entries;
  std::sort(entries.begin(), entries.end(),
            [](const MembershipBatchEntry& left, const MembershipBatchEntry& right) {
              if (left.domain != right.domain) {
                return left.domain < right.domain;
              }
              if (left.member != right.member) {
                return left.member < right.member;
              }
              return static_cast<std::uint8_t>(left.kind) <
                     static_cast<std::uint8_t>(right.kind);
            });
  std::string out;
  append_bytes(out, "fdr/req/publish-memberships/v1");
  append_u8(out, static_cast<std::uint8_t>(request.mode));
  append_bytes(out, request.administrative_scope);
  append_u8(out, static_cast<std::uint8_t>(request.authoritative_entity_class));
  append_u32(out, static_cast<std::uint32_t>(domains.size()));
  for (const FailureDomainId& domain : domains) {
    append_bytes(out, domain.to_string());
  }
  append_u32(out, static_cast<std::uint32_t>(entries.size()));
  for (const MembershipBatchEntry& entry : entries) {
    append_bytes(out, entry.domain.to_string());
    append_u64(out, entry.expected_domain_generation.value());
    append_bytes(out, entry.member.to_string());
    append_u8(out, static_cast<std::uint8_t>(entry.kind));
    append_u8(out, static_cast<std::uint8_t>(entry.role));
    append_u8(out, static_cast<std::uint8_t>(entry.dependency));
    append_bytes(out, entry.provenance.canonical_form());
    append_bytes(out, canonical_metadata(entry.metadata));
  }
  return out;
}

std::string form_withdraw_evidence(const WithdrawEvidenceRequest& request) {
  std::string out;
  append_bytes(out, "fdr/req/withdraw-evidence/v1");
  append_bytes(out, request.membership.to_string());
  append_u64(out, request.expected_generation.value());
  append_u8(out, request.only_this_worker_boot ? 1 : 0);
  append_u8(out, static_cast<std::uint8_t>(request.evidence));
  append_bytes(out, request.reason);
  return out;
}

std::string form_reconcile(const ReconcileMembershipRequest& request) {
  std::string out;
  append_bytes(out, "fdr/req/reconcile-membership/v1");
  append_bytes(out, request.domain.to_string());
  append_bytes(out, request.member.to_string());
  append_u8(out, static_cast<std::uint8_t>(request.kind));
  return out;
}

std::string form_mark_revalidation(const MarkRevalidationRequest& request) {
  std::string out;
  append_bytes(out, "fdr/req/mark-revalidation/v1");
  append_bytes(out, request.domain.to_string());
  append_bytes(out, request.membership.to_string());
  append_bytes(out, request.entity.to_string());
  append_bytes(out, request.domain_class.to_string());
  append_u8(out, request.all_in_scope ? 1 : 0);
  append_bytes(out, request.reason);
  return out;
}

std::string form_declare_coverage(const DeclareCoverageRequest& request) {
  std::string out;
  append_bytes(out, "fdr/req/declare-coverage/v1");
  append_bytes(out, request.administrative_scope);
  append_bytes(out, request.domain_class.to_string());
  append_u8(out, static_cast<std::uint8_t>(request.state));
  append_bytes(out, request.provenance.canonical_form());
  return out;
}

std::string form_invalidate_entity(const EntityInvalidationRequest& request) {
  std::string out;
  append_bytes(out, "fdr/req/invalidate-entity/v1");
  append_bytes(out, request.entity.to_string());
  append_u64(out, request.superseded_generation.value());
  append_u8(out, static_cast<std::uint8_t>(request.successor_class));
  append_bytes(out, entity_bytes(request.successor_id));
  append_u64(out, request.successor_generation.value());
  append_bytes(out, request.reason);
  return out;
}

std::string form_topology_change(const TopologyChangeRequest& request) {
  std::vector<EntityId> affected = request.affected_entities;
  std::sort(affected.begin(), affected.end());
  std::string out;
  append_bytes(out, "fdr/req/topology-change/v1");
  append_u64(out, request.topology_generation.value());
  append_u32(out, static_cast<std::uint32_t>(affected.size()));
  for (const EntityId& entity : affected) {
    append_bytes(out, entity.to_string());
  }
  append_u8(out, request.structurally_relevant ? 1 : 0);
  return out;
}

} // namespace

// ---------------------------------------------------------------------------
// Registry: domain operations
// ---------------------------------------------------------------------------

Outcome Registry::create_domain(const CreateDomainRequest& request) {
  const RequestDigest digest = request_digest_of(form_create_domain(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  if (const auto recorded = impl_->find_mutation(request.authority.publisher, request.attempt.id())) {
    if (recorded->digest == digest) {
      Outcome replay = recorded->outcome;
      replay.code = OutcomeCode::Idempotent;
      replay.message = "exact replay of an already committed mutation";
      replay.steps.push_back(ExplanationStep{"replay", "attempt", request.attempt.id().to_string(),
                                             "request digest matches the committed attempt"});
      replay.request_digest = digest;
      return impl_->record(std::move(replay));
    }
    Outcome conflict = Outcome::make(OutcomeCode::ConflictingReplay,
                                     "mutation attempt id was reused with different content");
    conflict.request_digest = digest;
    return impl_->record(std::move(conflict));
  }

  const Outcome key_check = validate_identity_key(request.identity_key);
  if (!key_check.committed()) {
    Outcome outcome = key_check;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const Outcome scope_check = validate_scope_name(request.administrative_scope);
  if (!scope_check.committed()) {
    Outcome outcome = scope_check;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (!request.domain_class.is_canonical() && !request.domain_class.is_extension()) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest, "domain class is not valid");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (request.name.size() > impl_->limits.max_string_bytes) {
    Outcome outcome = Outcome::make(OutcomeCode::ResourceLimit, "domain name is too long");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  Outcome metadata_check = validate_metadata(request.metadata, impl_->limits.max_metadata_entries,
                                             impl_->limits.max_metadata_value_bytes,
                                             impl_->limits.max_metadata_bytes_per_record);
  if (!metadata_check.committed()) {
    metadata_check.request_digest = digest;
    return impl_->record(std::move(metadata_check));
  }
  Provenance provenance = attribute_provenance(request.provenance, request.authority);
  Outcome provenance_check = validate_provenance(provenance, impl_->limits);
  if (!provenance_check.committed()) {
    provenance_check.request_digest = digest;
    return impl_->record(std::move(provenance_check));
  }
  const AuthorityContext authority =
      with_evidence(request.authority, effective_evidence(provenance, request.authority));
  const Outcome authorized =
      impl_->authorize(authority, request.domain_class, request.administrative_scope);
  if (!authorized.committed()) {
    Outcome outcome = authorized;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }

  const FailureDomainId id =
      domain_id_for(request.administrative_scope, request.domain_class, request.identity_key);
  const std::shared_ptr<const FailureDomain> existing = impl_->find_domain(id);
  if (existing != nullptr) {
    if (existing->is_terminal()) {
      Outcome outcome =
          Outcome::make(existing->lifecycle == DomainLifecycle::Retired ? OutcomeCode::Retired
                                                                        : OutcomeCode::Superseded,
                        "domain is closed and cannot be recreated by replay");
      outcome.with_domain(id).with_domain_generation(existing->generation);
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    const Precedence precedence = compare_provenance(existing->provenance, provenance);
    const bool identical = precedence == Precedence::EqualSameSource &&
                           existing->name == request.name &&
                           existing->administrative_scope == request.administrative_scope &&
                           existing->metadata == request.metadata &&
                           existing->domain_class == request.domain_class &&
                           existing->lifecycle ==
                               (request.activate ? DomainLifecycle::Current
                                                 : DomainLifecycle::Candidate);
    if (identical) {
      Outcome outcome = Outcome::make(OutcomeCode::Idempotent,
                                      "domain already exists with identical content");
      outcome.with_domain(id).with_domain_generation(existing->generation);
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    if (precedence == Precedence::Weaker) {
      Outcome outcome = Outcome::make(
          OutcomeCode::PolicyRejected,
          "a weaker evidence class cannot replace a stronger existing classification");
      outcome.with_domain(id).with_domain_generation(existing->generation);
      outcome.field_step("conflict", "existing",
                         std::string(to_string(existing->provenance.evidence)),
                         "existing evidence outranks the incoming assertion");
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    FailureDomain record = *existing;
    impl_->push_domain_history(record, "redeclared", impl_->limits.max_history_entries_per_record);
    if (precedence == Precedence::EqualDifferentSource) {
      record.lifecycle = DomainLifecycle::Conflicted;
      const std::optional<FailureDomainGeneration> next = record.generation.next();
      if (next.has_value()) {
        record.generation = *next;
      }
      impl_->store_domain(record);
      impl_->bump_generation();
      Outcome outcome = Outcome::make(
          OutcomeCode::DomainConflict,
          "equally strong evidence from a different source disagrees; "
          "the domain is marked CONFLICTED");
      outcome.with_domain(id).with_domain_generation(record.generation);
      outcome.field_step("conflict", "existing", existing->provenance.render(), "existing");
      outcome.field_step("conflict", "incoming", provenance.render(), "incoming");
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    record.provenance = provenance;
    record.name = request.name;
    record.metadata = request.metadata;
    if (request.activate && record.lifecycle == DomainLifecycle::Candidate) {
      record.lifecycle = DomainLifecycle::Current;
    }
    const std::optional<FailureDomainGeneration> next = record.generation.next();
    if (next.has_value()) {
      record.generation = *next;
    }
    impl_->store_domain(std::move(record));
    impl_->bump_generation();
    Outcome outcome = Outcome::make(OutcomeCode::Committed,
                                    "domain classification updated by stronger evidence");
    outcome.with_domain(id);
    outcome.with_domain_generation(impl_->find_domain(id)->generation);
    outcome.request_digest = digest;
    impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
    return impl_->record(std::move(outcome));
  }

  const Outcome within_limits = impl_->check_domain_limits();
  if (!within_limits.committed()) {
    Outcome outcome = within_limits;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }

  FailureDomain record;
  record.id = id;
  record.domain_class = request.domain_class;
  record.generation = FailureDomainGeneration::first();
  record.created_generation = record.generation;
  record.lifecycle = request.activate ? DomainLifecycle::Current : DomainLifecycle::Candidate;
  record.name = request.name;
  record.administrative_scope = request.administrative_scope;
  record.provenance = provenance;
  record.created_at = impl_->state.generation;
  record.created_epoch = impl_->state.epoch;
  record.metadata = request.metadata;
  impl_->store_domain(std::move(record));
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "domain created");
  outcome.with_domain(id).with_domain_generation(FailureDomainGeneration::first());
  outcome.request_digest = digest;
  outcome.steps.push_back(ExplanationStep{"commit", "identity-key", request.identity_key,
                                          "derived the deterministic domain id"});
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

Outcome Registry::update_domain(const UpdateDomainRequest& request) {
  const RequestDigest digest = request_digest_of(form_update_domain(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  if (const auto recorded = impl_->find_mutation(request.authority.publisher, request.attempt.id())) {
    if (recorded->digest == digest) {
      Outcome replay = recorded->outcome;
      replay.code = OutcomeCode::Idempotent;
      replay.message = "exact replay of an already committed mutation";
      replay.request_digest = digest;
      return impl_->record(std::move(replay));
    }
    Outcome conflict = Outcome::make(OutcomeCode::ConflictingReplay,
                                     "mutation attempt id was reused with different content");
    conflict.request_digest = digest;
    return impl_->record(std::move(conflict));
  }

  const std::shared_ptr<const FailureDomain> existing = impl_->find_domain(request.domain);
  if (existing == nullptr) {
    Outcome outcome = Outcome::make(OutcomeCode::UnknownDomain, "no such domain");
    outcome.with_domain(request.domain).request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (existing->is_terminal()) {
    Outcome outcome =
        Outcome::make(existing->lifecycle == DomainLifecycle::Retired ? OutcomeCode::Retired
                                                                      : OutcomeCode::Superseded,
                      "the domain is closed and can never regain authority");
    outcome.with_domain(request.domain).with_domain_generation(existing->generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (!request.expected_generation.is_zero() &&
      request.expected_generation != existing->generation) {
    Outcome outcome = Outcome::make(OutcomeCode::StaleGeneration,
                                    "expected domain generation is not current");
    outcome.with_domain(request.domain).with_domain_generation(existing->generation);
    outcome.field_step("generation", "expected", request.expected_generation.to_string(),
                       "current is " + existing->generation.to_string());
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const Outcome authorized = impl_->authorize(request.authority, existing->domain_class,
                                              existing->administrative_scope);
  if (!authorized.committed()) {
    Outcome outcome = authorized;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (request.name.has_value() && request.name->size() > impl_->limits.max_string_bytes) {
    Outcome outcome = Outcome::make(OutcomeCode::ResourceLimit, "domain name is too long");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  Outcome metadata_check = validate_metadata(request.metadata, impl_->limits.max_metadata_entries,
                                             impl_->limits.max_metadata_value_bytes,
                                             impl_->limits.max_metadata_bytes_per_record);
  if (!metadata_check.committed()) {
    metadata_check.request_digest = digest;
    return impl_->record(std::move(metadata_check));
  }

  FailureDomain record = *existing;
  bool changed = false;
  if (request.name.has_value() && *request.name != record.name) {
    record.name = *request.name;
    changed = true;
  }
  if (request.replace_metadata && record.metadata != request.metadata) {
    record.metadata = request.metadata;
    changed = true;
  }
  if (is_valid_evidence_class(request.provenance.evidence)) {
    Provenance provenance = attribute_provenance(request.provenance, request.authority);
    Outcome provenance_check = validate_provenance(provenance, impl_->limits);
    if (!provenance_check.committed()) {
      provenance_check.request_digest = digest;
      return impl_->record(std::move(provenance_check));
    }
    const AuthorityContext authority =
        with_evidence(request.authority, effective_evidence(provenance, request.authority));
    const Outcome evidence_authorized =
        impl_->authorize(authority, record.domain_class, record.administrative_scope);
    if (!evidence_authorized.committed()) {
      Outcome outcome = evidence_authorized;
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    const Precedence precedence = compare_provenance(record.provenance, provenance);
    if (precedence == Precedence::Weaker) {
      Outcome outcome = Outcome::make(
          OutcomeCode::PolicyRejected,
          "a weaker evidence class cannot replace a stronger existing classification");
      outcome.with_domain(request.domain);
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    if (precedence == Precedence::EqualDifferentSource) {
      Outcome outcome = Outcome::make(
          OutcomeCode::DomainConflict,
          "equally strong evidence from a different source disagrees");
      outcome.with_domain(request.domain).with_domain_generation(record.generation);
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    if (!(record.provenance == provenance)) {
      record.provenance = provenance;
      changed = true;
    }
  }
  if (request.transition.has_value()) {
    const DomainLifecycle target = *request.transition;
    if (target != record.lifecycle) {
      if (!is_legal_domain_transition(record.lifecycle, target)) {
        Outcome outcome = Outcome::make(OutcomeCode::IllegalTransition,
                                        "the requested lifecycle transition is not legal");
        outcome.with_domain(request.domain).with_domain_generation(record.generation);
        outcome.field_step("lifecycle", "from",
                           std::string(to_string(record.lifecycle)),
                           "to " + std::string(to_string(target)));
        outcome.request_digest = digest;
        return impl_->record(std::move(outcome));
      }
      impl_->push_domain_history(record, std::string("transition:") + std::string(to_string(target)),
                                 impl_->limits.max_history_entries_per_record);
      record.lifecycle = target;
      changed = true;
    }
  }
  if (!changed) {
    Outcome outcome = Outcome::make(OutcomeCode::Idempotent, "nothing to change");
    outcome.with_domain(request.domain).with_domain_generation(record.generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const std::optional<FailureDomainGeneration> next = record.generation.next();
  if (!next.has_value()) {
    Outcome outcome = Outcome::make(OutcomeCode::ResourceLimit, "domain generation exhausted");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  record.generation = *next;
  impl_->store_domain(std::move(record));
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "domain updated");
  outcome.with_domain(request.domain)
      .with_domain_generation(impl_->find_domain(request.domain)->generation);
  outcome.request_digest = digest;
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

Outcome Registry::supersede_domain(const SupersedeDomainRequest& request) {
  const RequestDigest digest = request_digest_of(form_supersede_domain(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  if (const auto recorded = impl_->find_mutation(request.authority.publisher, request.attempt.id())) {
    if (recorded->digest == digest) {
      Outcome replay = recorded->outcome;
      replay.code = OutcomeCode::Idempotent;
      replay.message = "exact replay of an already committed mutation";
      replay.request_digest = digest;
      return impl_->record(std::move(replay));
    }
    Outcome conflict = Outcome::make(OutcomeCode::ConflictingReplay,
                                     "mutation attempt id was reused with different content");
    conflict.request_digest = digest;
    return impl_->record(std::move(conflict));
  }
  const std::shared_ptr<const FailureDomain> domain = impl_->find_domain(request.domain);
  const std::shared_ptr<const FailureDomain> successor = impl_->find_domain(request.successor);
  if (domain == nullptr || successor == nullptr) {
    Outcome outcome = Outcome::make(OutcomeCode::UnknownDomain,
                                    "the domain or its successor does not exist");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (request.domain == request.successor) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                    "a domain cannot supersede itself");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (domain->is_terminal()) {
    Outcome outcome = Outcome::make(
        domain->lifecycle == DomainLifecycle::Retired ? OutcomeCode::Retired : OutcomeCode::Superseded,
        "the domain is already closed");
    outcome.with_domain(request.domain).request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (!request.expected_generation.is_zero() && request.expected_generation != domain->generation) {
    Outcome outcome = Outcome::make(OutcomeCode::StaleGeneration,
                                    "expected domain generation is not current");
    outcome.with_domain(request.domain).with_domain_generation(domain->generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const Outcome authorized = impl_->authorize(request.authority, domain->domain_class,
                                              domain->administrative_scope);
  if (!authorized.committed()) {
    Outcome outcome = authorized;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }

  FailureDomain updated = *domain;
  impl_->push_domain_history(updated, "superseded", impl_->limits.max_history_entries_per_record);
  updated.lifecycle = DomainLifecycle::Superseded;
  updated.superseded_by = request.successor;
  const std::optional<FailureDomainGeneration> next = updated.generation.next();
  if (next.has_value()) {
    updated.generation = *next;
  }
  const DomainLifecycle previous_lifecycle = domain->lifecycle;
  impl_->store_domain(std::move(updated));

  FailureDomain successor_record = *successor;
  successor_record.supersedes = request.domain;
  impl_->store_domain(std::move(successor_record));

  if (request.demote_memberships) {
    impl_->demote_memberships_of_domain(request.domain,
                                        previous_lifecycle == DomainLifecycle::Current
                                            ? MembershipLifecycle::RevalidationRequired
                                            : MembershipLifecycle::Retired,
                                        "bound domain was superseded");
  }
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "domain superseded");
  outcome.with_domain(request.domain)
      .with_domain_generation(impl_->find_domain(request.domain)->generation);
  outcome.related_domains.push_back(request.successor);
  outcome.request_digest = digest;
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

Outcome Registry::retire_domain(const RetireDomainRequest& request) {
  const RequestDigest digest = request_digest_of(form_retire_domain(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  if (const auto recorded = impl_->find_mutation(request.authority.publisher, request.attempt.id())) {
    if (recorded->digest == digest) {
      Outcome replay = recorded->outcome;
      replay.code = OutcomeCode::Idempotent;
      replay.message = "exact replay of an already committed mutation";
      replay.request_digest = digest;
      return impl_->record(std::move(replay));
    }
    Outcome conflict = Outcome::make(OutcomeCode::ConflictingReplay,
                                     "mutation attempt id was reused with different content");
    conflict.request_digest = digest;
    return impl_->record(std::move(conflict));
  }
  const std::shared_ptr<const FailureDomain> domain = impl_->find_domain(request.domain);
  if (domain == nullptr) {
    Outcome outcome = Outcome::make(OutcomeCode::UnknownDomain, "no such domain");
    outcome.with_domain(request.domain).request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (domain->lifecycle == DomainLifecycle::Retired) {
    Outcome outcome = Outcome::make(OutcomeCode::Idempotent, "the domain is already retired");
    outcome.with_domain(request.domain).with_domain_generation(domain->generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (domain->is_terminal()) {
    Outcome outcome = Outcome::make(OutcomeCode::Superseded,
                                    "a superseded domain cannot be retired again");
    outcome.with_domain(request.domain).request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (!request.expected_generation.is_zero() && request.expected_generation != domain->generation) {
    Outcome outcome = Outcome::make(OutcomeCode::StaleGeneration,
                                    "expected domain generation is not current");
    outcome.with_domain(request.domain).with_domain_generation(domain->generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const Outcome authorized = impl_->authorize(request.authority, domain->domain_class,
                                              domain->administrative_scope);
  if (!authorized.committed()) {
    Outcome outcome = authorized;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  FailureDomain updated = *domain;
  impl_->push_domain_history(updated, request.reason.empty() ? "retired" : request.reason,
                             impl_->limits.max_history_entries_per_record);
  updated.lifecycle = DomainLifecycle::Retired;
  const std::optional<FailureDomainGeneration> next = updated.generation.next();
  if (next.has_value()) {
    updated.generation = *next;
  }
  impl_->store_domain(std::move(updated));
  if (request.retire_memberships) {
    impl_->demote_memberships_of_domain(request.domain, MembershipLifecycle::Retired,
                                        "bound domain was retired");
  }
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "domain retired");
  outcome.with_domain(request.domain)
      .with_domain_generation(impl_->find_domain(request.domain)->generation);
  outcome.request_digest = digest;
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

Outcome Registry::add_relation(const AddRelationRequest& request) {
  const RequestDigest digest = request_digest_of(form_add_relation(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  if (const auto recorded = impl_->find_mutation(request.authority.publisher, request.attempt.id())) {
    if (recorded->digest == digest) {
      Outcome replay = recorded->outcome;
      replay.code = OutcomeCode::Idempotent;
      replay.message = "exact replay of an already committed mutation";
      replay.request_digest = digest;
      return impl_->record(std::move(replay));
    }
    Outcome conflict = Outcome::make(OutcomeCode::ConflictingReplay,
                                     "mutation attempt id was reused with different content");
    conflict.request_digest = digest;
    return impl_->record(std::move(conflict));
  }
  if (!is_valid_domain_relation_type(request.type)) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                    "relation type is not a known relation type");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const std::shared_ptr<const FailureDomain> source = impl_->find_domain(request.source);
  const std::shared_ptr<const FailureDomain> target = impl_->find_domain(request.target);
  if (source == nullptr || target == nullptr) {
    Outcome outcome =
        Outcome::make(OutcomeCode::UnknownDomain, "a relation endpoint does not exist");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (request.source == request.target) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                    "a domain cannot be related to itself");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (source->is_terminal() || target->is_terminal()) {
    Outcome outcome = Outcome::make(OutcomeCode::NotCurrent,
                                    "a relation endpoint is closed");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const Outcome authorized = impl_->authorize(request.authority, source->domain_class,
                                              source->administrative_scope);
  if (!authorized.committed()) {
    Outcome outcome = authorized;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (request.type == DomainRelationType::ContainedBy) {
    if (!is_containment_class(source->domain_class.classification()) ||
        !is_containment_class(target->domain_class.classification())) {
      Outcome outcome = Outcome::make(
          OutcomeCode::InvalidHierarchy,
          "CONTAINED_BY requires both endpoints to be containment classes");
      outcome.field_step("hierarchy", "source-class", source->domain_class.to_string(),
                         "not a containment class");
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
  }
  const DomainRelationId id = relation_id_for(request.source, request.target, request.type);
  if (impl_->state.relations.find(id) != impl_->state.relations.end()) {
    Outcome outcome = Outcome::make(OutcomeCode::Idempotent, "the relation already exists");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (is_acyclic_relation(request.type)) {
    bool bounded = false;
    if (impl_->path_exists(request.target, request.source, request.type, &bounded) && !bounded) {
      Outcome outcome = Outcome::make(
          OutcomeCode::CycleRejected,
          "the relation would close a cycle over an acyclic relation type");
      outcome.field_step("hierarchy", "type",
                         std::string(failure_domain_registry::to_string(request.type)),
                         "acyclic by definition");
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    if (bounded) {
      Outcome outcome = Outcome::make(OutcomeCode::InvalidHierarchy,
                                      "the hierarchy walk exceeded max_ancestor_walk");
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
  }
  Provenance provenance = attribute_provenance(request.provenance, request.authority);
  Outcome provenance_check = validate_provenance(provenance, impl_->limits);
  if (!provenance_check.committed()) {
    provenance_check.request_digest = digest;
    return impl_->record(std::move(provenance_check));
  }
  if (impl_->state.relations.size() >= impl_->limits.max_relations) {
    Outcome outcome = Outcome::make(OutcomeCode::ResourceLimit, "relation limit reached");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  DomainRelation record;
  record.id = id;
  record.source = request.source;
  record.target = request.target;
  record.type = request.type;
  record.provenance = provenance;
  record.created_at = impl_->state.generation;
  record.created_epoch = impl_->state.epoch;
  impl_->store_relation(std::move(record));
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "relation created");
  outcome.with_domain(request.source);
  outcome.related_domains.push_back(request.target);
  outcome.request_digest = digest;
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

Outcome Registry::merge_domains(const MergeDomainsRequest& request) {
  const RequestDigest digest = request_digest_of(form_merge_domains(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  if (const auto recorded = impl_->find_mutation(request.authority.publisher, request.attempt.id())) {
    if (recorded->digest == digest) {
      Outcome replay = recorded->outcome;
      replay.code = OutcomeCode::Idempotent;
      replay.message = "exact replay of an already committed mutation";
      replay.request_digest = digest;
      return impl_->record(std::move(replay));
    }
    Outcome conflict = Outcome::make(OutcomeCode::ConflictingReplay,
                                     "mutation attempt id was reused with different content");
    conflict.request_digest = digest;
    return impl_->record(std::move(conflict));
  }
  const std::shared_ptr<const FailureDomain> survivor = impl_->find_domain(request.survivor);
  const std::shared_ptr<const FailureDomain> absorbed = impl_->find_domain(request.absorbed);
  if (survivor == nullptr || absorbed == nullptr) {
    Outcome outcome = Outcome::make(OutcomeCode::UnknownDomain, "a merge endpoint does not exist");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (request.survivor == request.absorbed) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                    "a domain cannot be merged into itself");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (survivor->is_terminal() || absorbed->is_terminal()) {
    Outcome outcome = Outcome::make(OutcomeCode::NotCurrent, "a merge endpoint is closed");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (survivor->domain_class != absorbed->domain_class) {
    Outcome outcome = Outcome::make(
        OutcomeCode::PolicyRejected,
        "only domains of the same class may be merged: they describe the same factor");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if ((!request.expected_survivor_generation.is_zero() &&
       request.expected_survivor_generation != survivor->generation) ||
      (!request.expected_absorbed_generation.is_zero() &&
       request.expected_absorbed_generation != absorbed->generation)) {
    Outcome outcome = Outcome::make(OutcomeCode::StaleGeneration,
                                    "expected domain generation is not current");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const Outcome authorized = impl_->authorize(request.authority, survivor->domain_class,
                                              survivor->administrative_scope);
  if (!authorized.committed()) {
    Outcome outcome = authorized;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }

  std::vector<MembershipId> absorbed_memberships;
  if (const std::vector<MembershipId>* ids = impl_->memberships_of_domain(request.absorbed)) {
    absorbed_memberships = *ids;
  }
  std::sort(absorbed_memberships.begin(), absorbed_memberships.end(), membership_id_less);
  std::size_t current_memberships = 0;
  for (const MembershipId& id : absorbed_memberships) {
    const auto it = impl_->state.memberships.find(id);
    if (it != impl_->state.memberships.end() && it->second->is_current()) {
      ++current_memberships;
    }
  }
  if (current_memberships > 0 && !request.memberships_equivalent) {
    Outcome outcome = Outcome::make(
        OutcomeCode::PolicyRejected,
        "the absorbed domain has current memberships and the caller did not state that the "
        "member sets are equivalent");
    outcome.field_step("merge", "current-memberships", std::to_string(current_memberships),
                       "explicit equivalence is required to move them");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }

  std::size_t moved = 0;
  if (request.memberships_equivalent) {
    for (const MembershipId& id : absorbed_memberships) {
      const auto it = impl_->state.memberships.find(id);
      if (it == impl_->state.memberships.end()) {
        continue;
      }
      Membership old_record = *it->second;
      if (old_record.is_terminal()) {
        continue;
      }
      MembershipKey key;
      key.domain = request.survivor;
      key.member = old_record.member.id();
      key.member_generation = old_record.member.generation();
      key.kind = old_record.kind;
      const MembershipId target_id = membership_id_for(key);
      Membership moved_record = old_record;
      moved_record.id = target_id;
      moved_record.domain = request.survivor;
      moved_record.domain_generation = survivor->generation;
      moved_record.created_at = impl_->state.generation;
      moved_record.created_epoch = impl_->state.epoch;
      moved_record.lifecycle = MembershipLifecycle::Current;
      const auto existing_target = impl_->state.memberships.find(target_id);
      if (existing_target != impl_->state.memberships.end() &&
          !existing_target->second->is_terminal()) {
        impl_->demote_memberships_of_domain(request.absorbed,
                                            MembershipLifecycle::Superseded,
                                            "absorbed by an explicit merge");
        Outcome outcome = Outcome::make(
            OutcomeCode::MembershipConflict,
            "the surviving domain already holds an equivalent membership");
        outcome.request_digest = digest;
        return impl_->record(std::move(outcome));
      }
      impl_->push_membership_history(moved_record, "merged",
                                     impl_->limits.max_history_entries_per_record);
      impl_->store_membership(std::move(moved_record));
      Membership retired = old_record;
      impl_->push_membership_history(retired, "superseded by merge",
                                     impl_->limits.max_history_entries_per_record);
      retired.lifecycle = MembershipLifecycle::Superseded;
      retired.superseded_by = target_id;
      const std::optional<MembershipGeneration> next = retired.generation.next();
      if (next.has_value()) {
        retired.generation = *next;
      }
      impl_->store_membership(std::move(retired));
      ++moved;
    }
  }

  FailureDomain absorbed_record = *absorbed;
  impl_->push_domain_history(absorbed_record, "merged",
                             impl_->limits.max_history_entries_per_record);
  absorbed_record.lifecycle = DomainLifecycle::Superseded;
  absorbed_record.merged_into = request.survivor;
  absorbed_record.superseded_by = request.survivor;
  const std::optional<FailureDomainGeneration> next_absorbed = absorbed_record.generation.next();
  if (next_absorbed.has_value()) {
    absorbed_record.generation = *next_absorbed;
  }
  impl_->store_domain(std::move(absorbed_record));
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "domains merged");
  outcome.with_domain(request.survivor);
  outcome.related_domains.push_back(request.absorbed);
  outcome.steps.push_back(ExplanationStep{"merge", "memberships-moved", std::to_string(moved),
                                          request.reason});
  outcome.request_digest = digest;
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

Outcome Registry::attach_member(const AttachMemberRequest& request) {
  const RequestDigest digest = request_digest_of(form_attach_member(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  if (const auto recorded = impl_->find_mutation(request.authority.publisher, request.attempt.id())) {
    if (recorded->digest == digest) {
      Outcome replay = recorded->outcome;
      replay.code = OutcomeCode::Idempotent;
      replay.message = "exact replay of an already committed mutation";
      replay.request_digest = digest;
      return impl_->record(std::move(replay));
    }
    Outcome conflict = Outcome::make(OutcomeCode::ConflictingReplay,
                                     "mutation attempt id was reused with different content");
    conflict.request_digest = digest;
    return impl_->record(std::move(conflict));
  }
  if (!is_valid_membership_kind(request.kind) || request.kind == MembershipKind::Derived) {
    Outcome outcome = Outcome::make(
        OutcomeCode::MalformedRequest,
        "only DIRECT, INHERITED and ASSERTED membership may be published directly");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (!is_valid_membership_role(request.role) || !is_valid_dependency_semantics(request.dependency)) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                    "membership role or dependency semantics is not valid");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (request.member.is_null()) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                    "the member entity reference is null");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const std::shared_ptr<const FailureDomain> domain = impl_->find_domain(request.domain);
  if (domain == nullptr) {
    Outcome outcome = Outcome::make(OutcomeCode::UnknownDomain, "no such domain");
    outcome.with_domain(request.domain).request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (domain->is_terminal()) {
    Outcome outcome =
        Outcome::make(domain->lifecycle == DomainLifecycle::Retired ? OutcomeCode::Retired
                                                                     : OutcomeCode::Superseded,
                      "the domain is closed");
    outcome.with_domain(request.domain).request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (domain->lifecycle == DomainLifecycle::Conflicted) {
    Outcome outcome = Outcome::make(OutcomeCode::DomainConflict,
                                    "the domain is CONFLICTED and must be resolved first");
    outcome.with_domain(request.domain).request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (domain->lifecycle == DomainLifecycle::RevalidationRequired) {
    Outcome outcome = Outcome::make(OutcomeCode::RevalidationRequired,
                                    "the domain must be revalidated before it carries members");
    outcome.with_domain(request.domain).request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (!request.expected_domain_generation.is_zero() &&
      request.expected_domain_generation != domain->generation) {
    Outcome outcome = Outcome::make(OutcomeCode::StaleDomain,
                                    "expected domain generation is not current");
    outcome.with_domain(request.domain).with_domain_generation(domain->generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  Provenance provenance = attribute_provenance(request.provenance, request.authority);
  Outcome provenance_check = validate_provenance(provenance, impl_->limits);
  if (!provenance_check.committed()) {
    provenance_check.request_digest = digest;
    return impl_->record(std::move(provenance_check));
  }
  const AuthorityContext authority =
      with_evidence(request.authority, effective_evidence(provenance, request.authority));
  const Outcome authorized =
      impl_->authorize(authority, domain->domain_class, domain->administrative_scope);
  if (!authorized.committed()) {
    Outcome outcome = authorized;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  Outcome metadata_check = validate_metadata(request.metadata, impl_->limits.max_metadata_entries,
                                             impl_->limits.max_metadata_value_bytes,
                                             impl_->limits.max_metadata_bytes_per_record);
  if (!metadata_check.committed()) {
    metadata_check.request_digest = digest;
    return impl_->record(std::move(metadata_check));
  }

  MembershipKey key;
  key.domain = request.domain;
  key.member = request.member.id();
  key.member_generation = request.member.generation();
  key.kind = request.kind;
  const MembershipId membership_id = membership_id_for(key);
  const std::shared_ptr<const Membership> existing = impl_->find_membership(membership_id);

  if (existing == nullptr) {
    FailureDomainId other;
    if (exclusive_conflict(impl_->state, request.domain, domain->domain_class,
                           request.member.id(), &other)) {
      Outcome outcome = Outcome::make(
          OutcomeCode::ExclusivityViolation,
          "domain class " + domain->domain_class.to_string() +
              " is exclusive and the member already belongs to another domain of it");
      outcome.with_domain(request.domain).with_member(request.member);
      outcome.related_domains.push_back(other);
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    const Outcome within_limits = impl_->check_membership_limits();
    if (!within_limits.committed()) {
      Outcome outcome = within_limits;
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    Membership record;
    record.id = membership_id;
    record.domain = request.domain;
    record.domain_generation = domain->generation;
    record.member = request.member;
    record.generation = MembershipGeneration::first();
    record.lifecycle = MembershipLifecycle::Current;
    record.kind = request.kind;
    record.role = request.role;
    record.dependency = request.dependency;
    record.provenance = provenance;
    record.evidence_generation = impl_->next_evidence_generation();
    provenance.evidence_generation = record.evidence_generation;
    record.provenance = provenance;
    MembershipEvidence evidence;
    evidence.provenance = provenance;
    evidence.live = true;
    record.evidence.push_back(std::move(evidence));
    record.created_at = impl_->state.generation;
    record.created_epoch = impl_->state.epoch;
    record.metadata = request.metadata;
    impl_->store_membership(std::move(record));
    impl_->bump_generation();
    Outcome outcome = Outcome::make(OutcomeCode::Committed, "member attached");
    outcome.with_domain(request.domain).with_membership(membership_id).with_member(request.member);
    outcome.with_membership_generation(MembershipGeneration::first());
    outcome.request_digest = digest;
    impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
    return impl_->record(std::move(outcome));
  }

  if (existing->is_terminal()) {
    Outcome outcome = Outcome::make(OutcomeCode::Retired,
                                    "the membership is closed and cannot be revived by replay");
    outcome.with_domain(request.domain).with_membership(membership_id).with_member(request.member);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const Precedence precedence = compare_provenance(existing->provenance, provenance);
  const bool identical = precedence == Precedence::EqualSameSource &&
                         existing->role == request.role &&
                         existing->dependency == request.dependency &&
                         existing->domain_generation == domain->generation &&
                         existing->metadata == request.metadata;
  if (identical) {
    Outcome outcome = Outcome::make(OutcomeCode::Idempotent,
                                    "the membership already exists with identical content");
    outcome.with_domain(request.domain).with_membership(membership_id).with_member(request.member);
    outcome.with_membership_generation(existing->generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (precedence == Precedence::EqualDifferentSource) {
    Membership record = *existing;
    impl_->push_membership_history(record, "conflicting evidence",
                                   impl_->limits.max_history_entries_per_record);
    record.lifecycle = MembershipLifecycle::Conflicted;
    const std::optional<MembershipGeneration> next = record.generation.next();
    if (next.has_value()) {
      record.generation = *next;
    }
    impl_->store_membership(record);
    impl_->bump_generation();
    Outcome outcome = Outcome::make(
        OutcomeCode::MembershipConflict,
        "equally strong evidence from a different source disagrees; the membership is "
        "marked CONFLICTED");
    outcome.with_domain(request.domain).with_membership(membership_id).with_member(request.member);
    outcome.with_membership_generation(record.generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (precedence == Precedence::Weaker) {
    Outcome outcome = Outcome::make(
        OutcomeCode::PolicyRejected,
        "a weaker evidence class cannot replace a stronger existing membership");
    outcome.with_domain(request.domain).with_membership(membership_id).with_member(request.member);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }

  if (exclusive_conflict(impl_->state, request.domain, domain->domain_class, request.member.id(),
                         nullptr)) {
    Outcome outcome = Outcome::make(OutcomeCode::ExclusivityViolation,
                                    "an exclusive class already holds another domain for this "
                                    "member");
    outcome.with_domain(request.domain).with_member(request.member);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (existing->evidence.size() >= impl_->limits.max_evidence_per_membership) {
    Outcome outcome = Outcome::make(OutcomeCode::ResourceLimit,
                                    "the membership already holds the maximum evidence entries");
    outcome.with_domain(request.domain).with_membership(membership_id);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  Membership record = *existing;
  impl_->push_membership_history(record, "reasserted",
                                 impl_->limits.max_history_entries_per_record);
  record.domain_generation = domain->generation;
  record.role = request.role;
  record.dependency = request.dependency;
  record.metadata = request.metadata;
  record.provenance = provenance;
  record.evidence_generation = impl_->next_evidence_generation();
  provenance.evidence_generation = record.evidence_generation;
  record.provenance = provenance;
  MembershipEvidence evidence;
  evidence.provenance = provenance;
  evidence.live = true;
  record.evidence.push_back(std::move(evidence));
  if (record.lifecycle == MembershipLifecycle::RevalidationRequired) {
    record.lifecycle = MembershipLifecycle::Current;
  }
  const std::optional<MembershipGeneration> next = record.generation.next();
  if (next.has_value()) {
    record.generation = *next;
  }
  impl_->store_membership(std::move(record));
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "membership updated");
  outcome.with_domain(request.domain).with_membership(membership_id).with_member(request.member);
  outcome.with_membership_generation(impl_->find_membership(membership_id)->generation);
  outcome.request_digest = digest;
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

Outcome Registry::detach_member(const DetachMemberRequest& request) {
  const RequestDigest digest = request_digest_of(form_detach_member(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  if (const auto recorded = impl_->find_mutation(request.authority.publisher, request.attempt.id())) {
    if (recorded->digest == digest) {
      Outcome replay = recorded->outcome;
      replay.code = OutcomeCode::Idempotent;
      replay.message = "exact replay of an already committed mutation";
      replay.request_digest = digest;
      return impl_->record(std::move(replay));
    }
    Outcome conflict = Outcome::make(OutcomeCode::ConflictingReplay,
                                     "mutation attempt id was reused with different content");
    conflict.request_digest = digest;
    return impl_->record(std::move(conflict));
  }
  MembershipKey key;
  key.domain = request.domain;
  key.member = request.member.id();
  key.member_generation = request.member.generation();
  key.kind = request.kind;
  const MembershipId membership_id = membership_id_for(key);
  const std::shared_ptr<const Membership> existing = impl_->find_membership(membership_id);
  if (existing == nullptr) {
    Outcome outcome = Outcome::make(OutcomeCode::NotFound, "no such membership");
    outcome.with_domain(request.domain).with_membership(membership_id).with_member(request.member);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const std::shared_ptr<const FailureDomain> domain = impl_->find_domain(request.domain);
  if (domain != nullptr) {
    const Outcome authorized = impl_->authorize(request.authority, domain->domain_class,
                                                domain->administrative_scope);
    if (!authorized.committed()) {
      Outcome outcome = authorized;
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
  }
  if (existing->is_terminal()) {
    Outcome outcome = Outcome::make(OutcomeCode::Idempotent, "the membership is already closed");
    outcome.with_domain(request.domain).with_membership(membership_id);
    outcome.with_membership_generation(existing->generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (!request.expected_membership_generation.is_zero() &&
      request.expected_membership_generation != existing->generation) {
    Outcome outcome = Outcome::make(OutcomeCode::StaleMembership,
                                    "expected membership generation is not current");
    outcome.with_domain(request.domain).with_membership(membership_id);
    outcome.with_membership_generation(existing->generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  Membership record = *existing;
  impl_->push_membership_history(record, request.reason.empty() ? "detached" : request.reason,
                                 impl_->limits.max_history_entries_per_record);
  record.lifecycle = MembershipLifecycle::Retired;
  const std::optional<MembershipGeneration> next = record.generation.next();
  if (next.has_value()) {
    record.generation = *next;
  }
  impl_->store_membership(std::move(record));
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "member detached");
  outcome.with_domain(request.domain).with_membership(membership_id).with_member(request.member);
  outcome.with_membership_generation(impl_->find_membership(membership_id)->generation);
  outcome.request_digest = digest;
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

Outcome Registry::replace_membership(const ReplaceMembershipRequest& request) {
  const RequestDigest digest = request_digest_of(form_replace_membership(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  if (const auto recorded = impl_->find_mutation(request.authority.publisher, request.attempt.id())) {
    if (recorded->digest == digest) {
      Outcome replay = recorded->outcome;
      replay.code = OutcomeCode::Idempotent;
      replay.message = "exact replay of an already committed mutation";
      replay.request_digest = digest;
      return impl_->record(std::move(replay));
    }
    Outcome conflict = Outcome::make(OutcomeCode::ConflictingReplay,
                                     "mutation attempt id was reused with different content");
    conflict.request_digest = digest;
    return impl_->record(std::move(conflict));
  }
  const std::shared_ptr<const Membership> existing = impl_->find_membership(request.membership);
  if (existing == nullptr) {
    Outcome outcome = Outcome::make(OutcomeCode::NotFound, "no such membership");
    outcome.with_membership(request.membership).request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (existing->is_terminal()) {
    Outcome outcome = Outcome::make(
        existing->lifecycle == MembershipLifecycle::Retired ? OutcomeCode::Retired
                                                             : OutcomeCode::Superseded,
        "the membership is closed and cannot be replaced");
    outcome.with_membership(request.membership).request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (!request.expected_generation.is_zero() && request.expected_generation != existing->generation) {
    Outcome outcome = Outcome::make(OutcomeCode::StaleMembership,
                                    "expected membership generation is not current");
    outcome.with_membership(request.membership)
        .with_membership_generation(existing->generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const std::shared_ptr<const FailureDomain> domain = impl_->find_domain(existing->domain);
  if (domain == nullptr) {
    Outcome outcome = Outcome::make(OutcomeCode::UnknownDomain,
                                    "the membership references a domain that no longer exists");
    outcome.with_membership(request.membership).request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const Outcome authorized = impl_->authorize(request.authority, domain->domain_class,
                                              domain->administrative_scope);
  if (!authorized.committed()) {
    Outcome outcome = authorized;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  Outcome metadata_check = validate_metadata(request.metadata, impl_->limits.max_metadata_entries,
                                             impl_->limits.max_metadata_value_bytes,
                                             impl_->limits.max_metadata_bytes_per_record);
  if (!metadata_check.committed()) {
    metadata_check.request_digest = digest;
    return impl_->record(std::move(metadata_check));
  }
  Membership record = *existing;
  bool changed = false;
  if (request.role != MembershipRole::Unspecified && request.role != record.role) {
    record.role = request.role;
    changed = true;
  }
  if (request.dependency != DependencySemantics::Unspecified &&
      request.dependency != record.dependency) {
    record.dependency = request.dependency;
    changed = true;
  }
  if (request.replace_metadata && record.metadata != request.metadata) {
    record.metadata = request.metadata;
    changed = true;
  }
  if (is_valid_evidence_class(request.provenance.evidence)) {
    Provenance provenance = attribute_provenance(request.provenance, request.authority);
    Outcome provenance_check = validate_provenance(provenance, impl_->limits);
    if (!provenance_check.committed()) {
      provenance_check.request_digest = digest;
      return impl_->record(std::move(provenance_check));
    }
    const Precedence precedence = compare_provenance(record.provenance, provenance);
    if (precedence == Precedence::Weaker) {
      Outcome outcome = Outcome::make(
          OutcomeCode::PolicyRejected,
          "a weaker evidence class cannot replace a stronger existing membership");
      outcome.with_membership(request.membership).request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    if (precedence == Precedence::EqualDifferentSource) {
      Outcome outcome = Outcome::make(
          OutcomeCode::MembershipConflict,
          "equally strong evidence from a different source disagrees");
      outcome.with_membership(request.membership).request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    if (record.evidence.size() >= impl_->limits.max_evidence_per_membership) {
      Outcome outcome = Outcome::make(OutcomeCode::ResourceLimit,
                                      "the membership already holds the maximum evidence entries");
      outcome.with_membership(request.membership).request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    record.evidence_generation = impl_->next_evidence_generation();
    provenance.evidence_generation = record.evidence_generation;
    MembershipEvidence evidence;
    evidence.provenance = provenance;
    evidence.live = true;
    record.evidence.push_back(std::move(evidence));
    record.provenance = provenance;
    changed = true;
  }
  if (!changed) {
    Outcome outcome = Outcome::make(OutcomeCode::Idempotent, "nothing to change");
    outcome.with_membership(request.membership)
        .with_membership_generation(record.generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  impl_->push_membership_history(record, "replaced", impl_->limits.max_history_entries_per_record);
  const std::optional<MembershipGeneration> next = record.generation.next();
  if (!next.has_value()) {
    Outcome outcome = Outcome::make(OutcomeCode::ResourceLimit,
                                    "membership generation exhausted");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  record.generation = *next;
  impl_->store_membership(std::move(record));
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "membership replaced");
  outcome.with_membership(request.membership)
      .with_membership_generation(impl_->find_membership(request.membership)->generation);
  outcome.request_digest = digest;
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

Outcome Registry::publish_memberships(const MembershipBatchRequest& request) {
  const RequestDigest digest = request_digest_of(form_publish_memberships(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  if (const auto recorded = impl_->find_mutation(request.authority.publisher, request.attempt.id())) {
    if (recorded->digest == digest) {
      Outcome replay = recorded->outcome;
      replay.code = OutcomeCode::Idempotent;
      replay.message = "exact replay of an already committed mutation";
      replay.request_digest = digest;
      return impl_->record(std::move(replay));
    }
    Outcome conflict = Outcome::make(OutcomeCode::ConflictingReplay,
                                     "mutation attempt id was reused with different content");
    conflict.request_digest = digest;
    return impl_->record(std::move(conflict));
  }
  if (!is_valid_publication_mode(request.mode)) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest, "publication mode is not valid");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (request.entries.empty()) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest, "the publication is empty");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (request.entries.size() > impl_->limits.max_members_per_batch) {
    Outcome outcome = Outcome::make(OutcomeCode::ResourceLimit,
                                    "the publication exceeds max_members_per_batch");
    outcome.field_step("limit", "entries", std::to_string(request.entries.size()),
                       "limit is " + std::to_string(impl_->limits.max_members_per_batch));
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (request.mode == PublicationMode::Authoritative) {
    if (!is_valid_entity_class(request.authoritative_entity_class) ||
        request.authoritative_domains.empty()) {
      Outcome outcome = Outcome::make(
          OutcomeCode::MalformedRequest,
          "an authoritative publication must name the entity class and the domains it is "
          "complete for");
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    if (request.authoritative_domains.size() > impl_->limits.max_members_per_batch) {
      Outcome outcome = Outcome::make(OutcomeCode::ResourceLimit,
                                      "too many domains in an authoritative publication");
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
  }
  const Outcome scope_check = request.administrative_scope.empty()
                                  ? Outcome::make(OutcomeCode::Committed, "scope omitted")
                                  : validate_scope_name(request.administrative_scope);
  if (!scope_check.committed()) {
    Outcome outcome = scope_check;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const Outcome authorized =
      impl_->authorize_any(request.authority, request.administrative_scope);
  if (!authorized.committed()) {
    Outcome outcome = authorized;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }

  // --- validation phase: nothing is applied until every entry is valid -----
  struct Prepared {
    Membership record;
    bool is_new{false};
  };
  std::vector<Prepared> prepared;
  prepared.reserve(request.entries.size());
  std::vector<MembershipId> published_ids;
  struct ExclusiveKey {
    EntityId entity;
    std::string klass;
  };
  std::vector<std::pair<ExclusiveKey, FailureDomainId>> batch_exclusivity;

  for (const MembershipBatchEntry& entry : request.entries) {
    if (entry.member.is_null()) {
      Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                      "a batch entry carries a null member entity");
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    if (!is_valid_membership_kind(entry.kind) || entry.kind == MembershipKind::Derived) {
      Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                      "a batch entry carries an invalid membership kind");
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    if (!is_valid_membership_role(entry.role) ||
        !is_valid_dependency_semantics(entry.dependency)) {
      Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                      "a batch entry carries an invalid role or dependency");
      outcome.with_member(entry.member);
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    const std::shared_ptr<const FailureDomain> domain = impl_->find_domain(entry.domain);
    if (domain == nullptr) {
      Outcome outcome = Outcome::make(OutcomeCode::UnknownDomain,
                                      "a batch entry names a domain that does not exist");
      outcome.with_domain(entry.domain).request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    if (domain->is_terminal()) {
      Outcome outcome = Outcome::make(
          domain->lifecycle == DomainLifecycle::Retired ? OutcomeCode::Retired
                                                        : OutcomeCode::Superseded,
          "a batch entry names a closed domain; the publication is rejected whole");
      outcome.with_domain(entry.domain).request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    if (domain->lifecycle == DomainLifecycle::Conflicted) {
      Outcome outcome = Outcome::make(OutcomeCode::DomainConflict,
                                      "a batch entry names a CONFLICTED domain");
      outcome.with_domain(entry.domain).request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    if (domain->lifecycle == DomainLifecycle::RevalidationRequired) {
      Outcome outcome = Outcome::make(OutcomeCode::RevalidationRequired,
                                      "a batch entry names a domain that must be revalidated");
      outcome.with_domain(entry.domain).request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    if (!request.administrative_scope.empty() &&
        domain->administrative_scope != request.administrative_scope) {
      Outcome outcome = Outcome::make(
          OutcomeCode::UnauthorizedScope,
          "a batch entry names a domain outside the publication scope");
      outcome.with_domain(entry.domain).request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    if (!entry.expected_domain_generation.is_zero() &&
        entry.expected_domain_generation != domain->generation) {
      Outcome outcome = Outcome::make(OutcomeCode::StaleDomain,
                                      "a batch entry expected a domain generation that moved on");
      outcome.with_domain(entry.domain).with_domain_generation(domain->generation);
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    Provenance provenance = attribute_provenance(entry.provenance, request.authority);
    Outcome provenance_check = validate_provenance(provenance, impl_->limits);
    if (!provenance_check.committed()) {
      provenance_check.request_digest = digest;
      return impl_->record(std::move(provenance_check));
    }
    Outcome metadata_check =
        validate_metadata(entry.metadata, impl_->limits.max_metadata_entries,
                          impl_->limits.max_metadata_value_bytes,
                          impl_->limits.max_metadata_bytes_per_record);
    if (!metadata_check.committed()) {
      metadata_check.request_digest = digest;
      return impl_->record(std::move(metadata_check));
    }
    const AuthorityContext entry_authority =
        with_evidence(request.authority, effective_evidence(provenance, request.authority));
    const Outcome entry_authorized =
        impl_->authorize(entry_authority, domain->domain_class, domain->administrative_scope);
    if (!entry_authorized.committed()) {
      Outcome outcome = entry_authorized;
      outcome.with_domain(entry.domain).with_member(entry.member);
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }

    if (domain->domain_class.is_exclusive()) {
      FailureDomainId other;
      if (exclusive_conflict(impl_->state, entry.domain, domain->domain_class, entry.member.id(),
                             &other)) {
        Outcome outcome = Outcome::make(
            OutcomeCode::ExclusivityViolation,
            "an exclusive domain class already holds another current domain for a member");
        outcome.with_domain(entry.domain).with_member(entry.member);
        outcome.related_domains.push_back(other);
        outcome.request_digest = digest;
        return impl_->record(std::move(outcome));
      }
      const ExclusiveKey exclusive_key{entry.member.id(), domain->domain_class.to_string()};
      for (const auto& seen : batch_exclusivity) {
        if (seen.first.entity == exclusive_key.entity &&
            seen.first.klass == exclusive_key.klass && seen.second != entry.domain) {
          Outcome outcome = Outcome::make(
              OutcomeCode::ExclusivityViolation,
              "the publication itself places one member in two domains of an exclusive class");
          outcome.with_domain(entry.domain).with_member(entry.member);
          outcome.related_domains.push_back(seen.second);
          outcome.request_digest = digest;
          return impl_->record(std::move(outcome));
        }
      }
      batch_exclusivity.emplace_back(exclusive_key, entry.domain);
    }

    MembershipKey key;
    key.domain = entry.domain;
    key.member = entry.member.id();
    key.member_generation = entry.member.generation();
    key.kind = entry.kind;
    const MembershipId membership_id = membership_id_for(key);
    if (std::find(published_ids.begin(), published_ids.end(), membership_id) !=
        published_ids.end()) {
      Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                      "the publication names the same membership twice");
      outcome.with_domain(entry.domain).with_member(entry.member);
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    published_ids.push_back(membership_id);

    const std::shared_ptr<const Membership> existing = impl_->find_membership(membership_id);
    Prepared item;
    if (existing == nullptr) {
      item.is_new = true;
      item.record.id = membership_id;
      item.record.domain = entry.domain;
      item.record.domain_generation = domain->generation;
      item.record.member = entry.member;
      item.record.generation = MembershipGeneration::first();
      item.record.lifecycle = MembershipLifecycle::Current;
      item.record.kind = entry.kind;
      item.record.role = entry.role;
      item.record.dependency = entry.dependency;
      item.record.created_at = impl_->state.generation;
      item.record.created_epoch = impl_->state.epoch;
      item.record.metadata = entry.metadata;
    } else {
      if (existing->is_terminal()) {
        Outcome outcome = Outcome::make(OutcomeCode::Retired,
                                        "the publication addresses a closed membership");
        outcome.with_domain(entry.domain).with_membership(membership_id);
        outcome.request_digest = digest;
        return impl_->record(std::move(outcome));
      }
      if (existing->evidence.size() >= impl_->limits.max_evidence_per_membership) {
        Outcome outcome = Outcome::make(
            OutcomeCode::ResourceLimit,
            "a membership in the publication already holds the maximum evidence entries");
        outcome.with_domain(entry.domain).with_membership(membership_id);
        outcome.request_digest = digest;
        return impl_->record(std::move(outcome));
      }
      const Precedence precedence = compare_provenance(existing->provenance, provenance);
      if (precedence == Precedence::EqualDifferentSource) {
        Outcome outcome = Outcome::make(
            OutcomeCode::MembershipConflict,
            "equally strong evidence from a different source disagrees; the publication is "
            "rejected whole");
        outcome.with_domain(entry.domain).with_membership(membership_id);
        outcome.request_digest = digest;
        return impl_->record(std::move(outcome));
      }
      if (precedence == Precedence::Weaker) {
        Outcome outcome = Outcome::make(
            OutcomeCode::PolicyRejected,
            "a weaker evidence class cannot replace a stronger existing membership");
        outcome.with_domain(entry.domain).with_membership(membership_id);
        outcome.request_digest = digest;
        return impl_->record(std::move(outcome));
      }
      item.record = *existing;
      item.record.domain_generation = domain->generation;
      item.record.role = entry.role;
      item.record.dependency = entry.dependency;
      item.record.metadata = entry.metadata;
      item.record.lifecycle = MembershipLifecycle::Current;
    }
    item.record.evidence_generation = impl_->next_evidence_generation();
    provenance.evidence_generation = item.record.evidence_generation;
    item.record.provenance = provenance;
    MembershipEvidence evidence;
    evidence.provenance = provenance;
    evidence.live = true;
    item.record.evidence.push_back(std::move(evidence));
    prepared.push_back(std::move(item));
  }

  // --- commit phase: the whole publication is applied or none of it is -----
  std::size_t added = 0;
  std::size_t updated = 0;
  for (Prepared& item : prepared) {
    impl_->push_membership_history(item.record, item.is_new ? "published" : "republished",
                                   impl_->limits.max_history_entries_per_record);
    if (!item.is_new) {
      const std::optional<MembershipGeneration> next = item.record.generation.next();
      if (next.has_value()) {
        item.record.generation = *next;
      }
    }
    if (item.is_new) {
      ++added;
    } else {
      ++updated;
    }
    impl_->store_membership(std::move(item.record));
  }

  std::size_t retired = 0;
  if (request.mode == PublicationMode::Authoritative) {
    for (const FailureDomainId& domain_id : request.authoritative_domains) {
      const std::vector<MembershipId>* ids = impl_->memberships_of_domain(domain_id);
      if (ids == nullptr) {
        continue;
      }
      const std::vector<MembershipId> copy = *ids;
      std::vector<MembershipId> sorted = copy;
      std::sort(sorted.begin(), sorted.end(), membership_id_less);
      for (const MembershipId& membership_id : sorted) {
        if (std::find(published_ids.begin(), published_ids.end(), membership_id) !=
            published_ids.end()) {
          continue;
        }
        const auto it = impl_->state.memberships.find(membership_id);
        if (it == impl_->state.memberships.end()) {
          continue;
        }
        Membership record = *it->second;
        if (!record.is_current()) {
          continue;
        }
        if (record.member.entity_class() != request.authoritative_entity_class) {
          continue;
        }
        if (record.kind == MembershipKind::Derived) {
          continue;
        }
        impl_->push_membership_history(record, "absent from an authoritative publication",
                                       impl_->limits.max_history_entries_per_record);
        record.lifecycle = MembershipLifecycle::Retired;
        const std::optional<MembershipGeneration> next = record.generation.next();
        if (next.has_value()) {
          record.generation = *next;
        }
        impl_->store_membership(std::move(record));
        ++retired;
      }
    }
  }

  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "membership publication committed");
  outcome.steps.push_back(ExplanationStep{
      "commit", "mode", std::string(failure_domain_registry::to_string(request.mode)),
      std::to_string(added) + " added, " + std::to_string(updated) + " updated, " +
          std::to_string(retired) + " retired"});
  outcome.request_digest = digest;
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

Outcome Registry::withdraw_evidence(const WithdrawEvidenceRequest& request) {
  const RequestDigest digest = request_digest_of(form_withdraw_evidence(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  if (const auto recorded = impl_->find_mutation(request.authority.publisher, request.attempt.id())) {
    if (recorded->digest == digest) {
      Outcome replay = recorded->outcome;
      replay.code = OutcomeCode::Idempotent;
      replay.message = "exact replay of an already committed mutation";
      replay.request_digest = digest;
      return impl_->record(std::move(replay));
    }
    Outcome conflict = Outcome::make(OutcomeCode::ConflictingReplay,
                                     "mutation attempt id was reused with different content");
    conflict.request_digest = digest;
    return impl_->record(std::move(conflict));
  }
  const std::shared_ptr<const Membership> existing = impl_->find_membership(request.membership);
  if (existing == nullptr) {
    Outcome outcome = Outcome::make(OutcomeCode::NotFound, "no such membership");
    outcome.with_membership(request.membership).request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (!request.expected_generation.is_zero() && request.expected_generation != existing->generation) {
    Outcome outcome = Outcome::make(OutcomeCode::StaleMembership,
                                    "expected membership generation is not current");
    outcome.with_membership(request.membership)
        .with_membership_generation(existing->generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const std::shared_ptr<const FailureDomain> domain = impl_->find_domain(existing->domain);
  if (domain != nullptr) {
    const Outcome authorized = impl_->authorize(request.authority, domain->domain_class,
                                                domain->administrative_scope);
    if (!authorized.committed()) {
      Outcome outcome = authorized;
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
  }
  bool matched = false;
  for (const MembershipEvidence& entry : existing->evidence) {
    const bool same_publisher = entry.provenance.publisher == request.authority.publisher;
    const bool same_boot = !request.only_this_worker_boot ||
                           entry.provenance.worker_boot == request.authority.worker_boot;
    const bool same_class = !is_valid_evidence_class(request.evidence) ||
                            entry.provenance.evidence == request.evidence;
    if (same_publisher && same_boot && same_class) {
      matched = true;
      break;
    }
  }
  if (!matched) {
    Outcome outcome = Outcome::make(OutcomeCode::Idempotent,
                                    "this publisher has no matching evidence on the membership");
    outcome.with_membership(request.membership)
        .with_membership_generation(existing->generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (existing->kind == MembershipKind::Derived) {
    Outcome outcome = Outcome::make(
        OutcomeCode::PolicyRejected,
        "derived membership is withdrawn by invalidating its sources, not by evidence withdrawal");
    outcome.with_membership(request.membership).request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  impl_->withdraw_publisher_evidence(request.authority.publisher, request.authority.worker_boot,
                                     request.only_this_worker_boot, request.evidence,
                                     MembershipLifecycle::RevalidationRequired,
                                     request.reason.empty() ? "evidence withdrawn" : request.reason);
  impl_->bump_generation();
  const std::shared_ptr<const Membership> after = impl_->find_membership(request.membership);
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "evidence withdrawn");
  outcome.with_membership(request.membership);
  if (after != nullptr) {
    outcome.with_membership_generation(after->generation);
    outcome.steps.push_back(ExplanationStep{"evidence", "lifecycle",
                                            std::string(to_string(after->lifecycle)),
                                            std::to_string(after->live_evidence_count()) +
                                                " live evidence entr(ies) remain"});
  }
  outcome.request_digest = digest;
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

Outcome Registry::reconcile_membership(const ReconcileMembershipRequest& request) {
  const RequestDigest digest = request_digest_of(form_reconcile(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  MembershipKey key;
  key.domain = request.domain;
  key.member = request.member.id();
  key.member_generation = request.member.generation();
  key.kind = request.kind;
  const MembershipId membership_id = membership_id_for(key);
  const std::shared_ptr<const Membership> existing = impl_->find_membership(membership_id);
  if (existing == nullptr) {
    Outcome outcome = Outcome::make(OutcomeCode::NotFound, "no such membership");
    outcome.with_domain(request.domain).with_membership(membership_id);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const std::shared_ptr<const FailureDomain> domain = impl_->find_domain(request.domain);
  if (domain != nullptr) {
    const Outcome authorized = impl_->authorize(request.authority, domain->domain_class,
                                                domain->administrative_scope);
    if (!authorized.committed()) {
      Outcome outcome = authorized;
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
  }
  if (existing->is_terminal()) {
    Outcome outcome = Outcome::make(OutcomeCode::Idempotent,
                                    "a terminal membership is never reconciled back to current");
    outcome.with_membership(membership_id).with_membership_generation(existing->generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const std::size_t live = existing->live_evidence_count();
  MembershipLifecycle target = existing->lifecycle;
  if (live == 0) {
    target = MembershipLifecycle::RevalidationRequired;
  } else if (existing->lifecycle == MembershipLifecycle::RevalidationRequired) {
    target = MembershipLifecycle::Current;
  }
  if (target == existing->lifecycle) {
    Outcome outcome = Outcome::make(OutcomeCode::Idempotent,
                                    "reconciliation produced no lifecycle change");
    outcome.with_membership(membership_id).with_membership_generation(existing->generation);
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  Membership record = *existing;
  impl_->push_membership_history(record, "reconciled", impl_->limits.max_history_entries_per_record);
  record.lifecycle = target;
  const std::optional<MembershipGeneration> next = record.generation.next();
  if (next.has_value()) {
    record.generation = *next;
  }
  impl_->store_membership(std::move(record));
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "membership reconciled");
  outcome.with_membership(membership_id)
      .with_membership_generation(impl_->find_membership(membership_id)->generation);
  outcome.request_digest = digest;
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

Outcome Registry::mark_revalidation_required(const MarkRevalidationRequest& request) {
  const RequestDigest digest = request_digest_of(form_mark_revalidation(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  const bool has_selector = !request.domain.is_null() || !request.membership.is_null() ||
                            !request.entity.is_null() || request.domain_class.is_canonical() ||
                            request.domain_class.is_extension();
  if (!has_selector && !request.all_in_scope) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                    "a revalidation demand must name a selector");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (!request.domain.is_null()) {
    const std::shared_ptr<const FailureDomain> domain = impl_->find_domain(request.domain);
    if (domain == nullptr) {
      Outcome outcome = Outcome::make(OutcomeCode::UnknownDomain, "no such domain");
      outcome.with_domain(request.domain).request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    const Outcome authorized = impl_->authorize(request.authority, domain->domain_class,
                                                domain->administrative_scope);
    if (!authorized.committed()) {
      Outcome outcome = authorized;
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
  } else {
    const Outcome authorized = impl_->authorize_any(request.authority, std::string());
    if (!authorized.committed()) {
      Outcome outcome = authorized;
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
  }

  std::vector<MembershipId> targets;
  if (!request.membership.is_null()) {
    targets.push_back(request.membership);
  } else if (!request.domain.is_null()) {
    if (const std::vector<MembershipId>* ids = impl_->memberships_of_domain(request.domain)) {
      targets = *ids;
    }
  } else if (!request.entity.is_null()) {
    if (const std::vector<MembershipId>* ids = impl_->memberships_of_entity(request.entity)) {
      targets = *ids;
    }
  } else {
    for (const auto& entry : impl_->state.memberships) {
      targets.push_back(entry.first);
    }
  }
  std::sort(targets.begin(), targets.end(), membership_id_less);
  std::size_t changed = 0;
  for (const MembershipId& id : targets) {
    const auto it = impl_->state.memberships.find(id);
    if (it == impl_->state.memberships.end()) {
      continue;
    }
    Membership record = *it->second;
    if (record.is_terminal()) {
      continue;
    }
    if (has_selector && request.domain.is_null() && request.entity.is_null() &&
        !request.membership.is_null() == false) {
      // fall through: selectors below decide
    }
    if (request.membership.is_null()) {
      const std::shared_ptr<const FailureDomain> domain = impl_->find_domain(record.domain);
      if (domain != nullptr) {
        if (!request.domain.is_null() && request.domain != record.domain) {
          continue;
        }
        if ((request.domain_class.is_canonical() || request.domain_class.is_extension()) &&
            !(domain->domain_class == request.domain_class)) {
          continue;
        }
        const PublisherRegistration* registration = nullptr;
        const auto publisher_it = impl_->state.publishers.find(request.authority.publisher);
        if (publisher_it != impl_->state.publishers.end()) {
          registration = &publisher_it->second;
        }
        if (registration != nullptr &&
            !registration->scope.allows_class(domain->domain_class.classification())) {
          continue;
        }
        if (registration != nullptr &&
            !registration->scope.allows_scope(domain->administrative_scope)) {
          continue;
        }
      }
    }
    if (!is_legal_membership_transition(record.lifecycle, MembershipLifecycle::RevalidationRequired)) {
      continue;
    }
    impl_->push_membership_history(
        record, request.reason.empty() ? "revalidation demanded" : request.reason,
        impl_->limits.max_history_entries_per_record);
    record.lifecycle = MembershipLifecycle::RevalidationRequired;
    const std::optional<MembershipGeneration> next = record.generation.next();
    if (next.has_value()) {
      record.generation = *next;
    }
    impl_->store_membership(std::move(record));
    ++changed;
  }
  if (changed == 0) {
    Outcome outcome = Outcome::make(OutcomeCode::Idempotent,
                                    "no membership matched the revalidation demand");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "revalidation demanded");
  outcome.steps.push_back(
      ExplanationStep{"revalidation", "memberships", std::to_string(changed), "demoted"});
  outcome.request_digest = digest;
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

Outcome Registry::declare_coverage(const DeclareCoverageRequest& request) {
  const RequestDigest digest = request_digest_of(form_declare_coverage(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  if (!is_valid_coverage_state(request.state)) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest, "coverage state is not valid");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (!request.domain_class.is_canonical() && !request.domain_class.is_extension()) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest, "domain class is not valid");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const Outcome scope_check = validate_scope_name(request.administrative_scope);
  if (!scope_check.committed()) {
    Outcome outcome = scope_check;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  Provenance provenance = attribute_provenance(request.provenance, request.authority);
  Outcome provenance_check = validate_provenance(provenance, impl_->limits);
  if (!provenance_check.committed()) {
    provenance_check.request_digest = digest;
    return impl_->record(std::move(provenance_check));
  }
  const AuthorityContext authority =
      with_evidence(request.authority, effective_evidence(provenance, request.authority));
  const Outcome authorized =
      impl_->authorize(authority, request.domain_class, request.administrative_scope);
  if (!authorized.committed()) {
    Outcome outcome = authorized;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  bool replaced = false;
  bool identical = false;
  for (CoverageDeclaration& declaration : impl_->state.coverage) {
    if (declaration.administrative_scope != request.administrative_scope ||
        !(declaration.domain_class == request.domain_class)) {
      continue;
    }
    if (declaration.state == request.state && declaration.provenance == provenance) {
      identical = true;
      break;
    }
    declaration.state = request.state;
    declaration.provenance = provenance;
    declaration.declared_at = impl_->state.generation;
    declaration.epoch = impl_->state.epoch;
    replaced = true;
    break;
  }
  if (identical) {
    Outcome outcome = Outcome::make(OutcomeCode::Idempotent, "the coverage declaration exists");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (!replaced) {
    if (impl_->state.coverage.size() >= impl_->limits.max_coverage_declarations) {
      Outcome outcome = Outcome::make(OutcomeCode::ResourceLimit,
                                      "coverage declaration limit reached");
      outcome.request_digest = digest;
      return impl_->record(std::move(outcome));
    }
    CoverageDeclaration declaration;
    declaration.administrative_scope = request.administrative_scope;
    declaration.domain_class = request.domain_class;
    declaration.state = request.state;
    declaration.provenance = provenance;
    declaration.declared_at = impl_->state.generation;
    declaration.epoch = impl_->state.epoch;
    impl_->state.coverage.push_back(std::move(declaration));
    std::sort(impl_->state.coverage.begin(), impl_->state.coverage.end(),
              [](const CoverageDeclaration& left, const CoverageDeclaration& right) {
                if (left.administrative_scope != right.administrative_scope) {
                  return left.administrative_scope < right.administrative_scope;
                }
                return left.domain_class.to_string() < right.domain_class.to_string();
              });
  }
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "coverage declared");
  outcome.request_digest = digest;
  outcome.steps.push_back(ExplanationStep{"coverage", request.domain_class.to_string(),
                                          std::string(to_string(request.state)),
                                          request.administrative_scope});
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

Outcome Registry::invalidate_entity(const EntityInvalidationRequest& request) {
  const RequestDigest digest = request_digest_of(form_invalidate_entity(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  if (request.entity.is_null() || request.superseded_generation.is_zero()) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                    "an entity invalidation names an entity and a generation");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const Outcome authorized = impl_->authorize_any(request.authority, std::string());
  if (!authorized.committed()) {
    Outcome outcome = authorized;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  std::size_t before = 0;
  std::size_t after = 0;
  if (const std::vector<MembershipId>* ids = impl_->memberships_of_entity(request.entity)) {
    for (const MembershipId& id : *ids) {
      const auto it = impl_->state.memberships.find(id);
      if (it == impl_->state.memberships.end()) {
        continue;
      }
      if (it->second->member.generation() != request.superseded_generation) {
        continue;
      }
      if (it->second->lifecycle == MembershipLifecycle::RevalidationRequired) {
        ++after;
      } else if (!it->second->is_terminal()) {
        ++before;
      }
    }
  }
  impl_->demote_memberships_of_entity_generation(request.entity, request.superseded_generation,
                                                 MembershipLifecycle::RevalidationRequired,
                                                 request.reason.empty()
                                                     ? "entity generation superseded"
                                                     : request.reason);
  std::vector<EntityId> affected{request.entity};
  impl_->invalidate_derived_memberships(affected);
  const bool changed = before > 0;
  if (!changed) {
    impl_->bump_generation();
    Outcome outcome = Outcome::make(OutcomeCode::Committed,
                                    "derivations were re-evaluated for the superseded entity");
    outcome.request_digest = digest;
    outcome.steps.push_back(ExplanationStep{"invalidate", "memberships", std::to_string(after),
                                            "were already revalidation-required"});
    impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
    return impl_->record(std::move(outcome));
  }
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "entity generation invalidated");
  outcome.steps.push_back(ExplanationStep{"invalidate", "memberships", std::to_string(before),
                                          "demoted to REVALIDATION_REQUIRED"});
  outcome.request_digest = digest;
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

Outcome Registry::notify_topology_change(const TopologyChangeRequest& request) {
  const RequestDigest digest = request_digest_of(form_topology_change(request));
  const std::unique_lock<std::shared_mutex> guard(impl_->mutex);
  Outcome attempt = impl_->check_attempt(request.attempt, digest, request.authority);
  if (!attempt.committed()) {
    attempt.request_digest = digest;
    return impl_->record(std::move(attempt));
  }
  if (request.topology_generation.is_zero()) {
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest,
                                    "a topology change names the new topology generation");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (request.affected_entities.size() > impl_->limits.max_query_set_cardinality) {
    Outcome outcome = Outcome::make(OutcomeCode::ResourceLimit,
                                    "too many affected entities in one topology notification");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  const Outcome authorized = impl_->authorize_any(request.authority, std::string());
  if (!authorized.committed()) {
    Outcome outcome = authorized;
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  if (!request.structurally_relevant) {
    Outcome outcome = Outcome::make(
        OutcomeCode::Idempotent,
        "the change is not structurally relevant, so no derivation is invalidated");
    outcome.request_digest = digest;
    return impl_->record(std::move(outcome));
  }
  impl_->invalidate_derived_memberships(request.affected_entities);
  impl_->bump_generation();
  Outcome outcome = Outcome::make(OutcomeCode::Committed,
                                  "topology change applied to affected derivations");
  outcome.steps.push_back(ExplanationStep{"topology", "affected-entities",
                                          std::to_string(request.affected_entities.size()),
                                          "derivations that read them were invalidated"});
  outcome.request_digest = digest;
  impl_->remember_mutation(request.authority.publisher, request.attempt.id(), digest, outcome);
  return impl_->record(std::move(outcome));
}

} // namespace failure_domain_registry
