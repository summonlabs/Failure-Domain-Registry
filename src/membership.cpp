// Failure Domain Registry — membership records and deterministic identities.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/membership.hpp"

#include <algorithm>

#include "failure_domain_registry/digest.hpp"
#include "failure_domain_registry/relation.hpp"
#include "failure_domain_registry/requests.hpp"

namespace failure_domain_registry {
namespace {

bool metadata_less(const MetadataEntry& left, const MetadataEntry& right) {
  if (left.key != right.key) {
    return left.key < right.key;
  }
  return left.value < right.value;
}

bool evidence_less(const MembershipEvidence& left, const MembershipEvidence& right) {
  const Provenance& a = left.provenance;
  const Provenance& b = right.provenance;
  if (a.publisher != b.publisher) {
    return a.publisher < b.publisher;
  }
  if (a.worker_boot != b.worker_boot) {
    return a.worker_boot < b.worker_boot;
  }
  if (a.evidence != b.evidence) {
    return static_cast<std::uint8_t>(a.evidence) < static_cast<std::uint8_t>(b.evidence);
  }
  if (a.evidence_generation != b.evidence_generation) {
    return a.evidence_generation < b.evidence_generation;
  }
  if (a.source != b.source) {
    return static_cast<std::uint8_t>(a.source) < static_cast<std::uint8_t>(b.source);
  }
  if (a.truth != b.truth) {
    return static_cast<std::uint8_t>(a.truth) < static_cast<std::uint8_t>(b.truth);
  }
  if (a.source_identity != b.source_identity) {
    return a.source_identity < b.source_identity;
  }
  return left.live && !right.live;
}

} // namespace

std::string_view to_string(MembershipKind value) noexcept {
  switch (value) {
    case MembershipKind::Direct: return "direct";
    case MembershipKind::Derived: return "derived";
    case MembershipKind::Inherited: return "inherited";
    case MembershipKind::Asserted: return "asserted";
    default: return "unknown";
  }
}

std::string_view to_string(DependencySemantics value) noexcept {
  switch (value) {
    case DependencySemantics::AnyDependencyFailureAffectsMember:
      return "ANY_DEPENDENCY_FAILURE_AFFECTS_MEMBER";
    case DependencySemantics::AllDependenciesRequired:
      return "ALL_DEPENDENCIES_REQUIRED";
    case DependencySemantics::RedundantSource:
      return "REDUNDANT_SOURCE";
    default:
      return "UNSPECIFIED";
  }
}

std::string_view to_string(MembershipRole value) noexcept {
  switch (value) {
    case MembershipRole::Primary: return "primary";
    case MembershipRole::Redundant: return "redundant";
    case MembershipRole::Backup: return "backup";
    case MembershipRole::Containment: return "containment";
    case MembershipRole::SharedRisk: return "shared-risk";
    case MembershipRole::Derived: return "derived";
    default: return "unspecified";
  }
}

bool is_valid_membership_kind(MembershipKind value) noexcept {
  return value != MembershipKind::Unknown &&
         static_cast<std::uint8_t>(value) <= static_cast<std::uint8_t>(MembershipKind::Asserted);
}

bool is_valid_dependency_semantics(DependencySemantics value) noexcept {
  return static_cast<std::uint8_t>(value) <=
         static_cast<std::uint8_t>(DependencySemantics::RedundantSource);
}

bool is_valid_membership_role(MembershipRole value) noexcept {
  return static_cast<std::uint8_t>(value) <= static_cast<std::uint8_t>(MembershipRole::Derived);
}

std::size_t Membership::live_evidence_count() const noexcept {
  std::size_t count = 0;
  for (const MembershipEvidence& entry : evidence) {
    if (entry.live) {
      ++count;
    }
  }
  return count;
}

std::string Membership::canonical_form() const {
  std::string out;
  append_bytes(out, "fdr/membership/v1");
  append_bytes(out, id.to_string());
  append_bytes(out, domain.to_string());
  append_u64(out, domain_generation.value());
  append_bytes(out, member.to_string());
  append_u64(out, generation.value());
  append_u8(out, static_cast<std::uint8_t>(lifecycle));
  append_u8(out, static_cast<std::uint8_t>(kind));
  append_u8(out, static_cast<std::uint8_t>(role));
  append_u8(out, static_cast<std::uint8_t>(dependency));
  // evidence_generation, created_at and created_epoch are process-local
  // bookkeeping, excluded so that arrival order cannot change the semantic
  // digest.
  append_bytes(out, superseded_by.to_string());
  append_bytes(out, supersedes.to_string());
  append_bytes(out, provenance.canonical_form());
  append_bytes(out, derivation.rule.to_string());
  // derivation.generation is the registry generation the pass ran at, which is
  // process-local. The source identities and source generations below are the
  // semantic part of the derivation.
  append_bytes(out, derivation.context);
  append_u8(out, derivation.valid ? 1 : 0);
  append_u32(out, static_cast<std::uint32_t>(derivation.sources.size()));
  for (std::size_t i = 0; i < derivation.sources.size(); ++i) {
    append_bytes(out, derivation.sources[i].to_string());
    const std::uint64_t source_generation =
        i < derivation.source_generations.size() ? derivation.source_generations[i].value() : 0;
    append_u64(out, source_generation);
  }
  std::vector<MembershipEvidence> evidence_canonical = evidence;
  std::sort(evidence_canonical.begin(), evidence_canonical.end(), evidence_less);
  append_u32(out, static_cast<std::uint32_t>(evidence_canonical.size()));
  for (const MembershipEvidence& entry : evidence_canonical) {
    append_bytes(out, entry.provenance.canonical_form());
    append_u8(out, entry.live ? 1 : 0);
  }
  std::vector<MetadataEntry> metadata_canonical = metadata;
  std::sort(metadata_canonical.begin(), metadata_canonical.end(), metadata_less);
  append_u32(out, static_cast<std::uint32_t>(metadata_canonical.size()));
  for (const MetadataEntry& entry : metadata_canonical) {
    append_bytes(out, entry.key);
    append_bytes(out, entry.value);
  }
  return out;
}

std::string Membership::render() const {
  std::string out = "membership ";
  out.append(id.to_string());
  out.append("\n  domain           = ");
  out.append(domain.to_string());
  out.append(" @");
  out.append(domain_generation.to_string());
  out.append("\n  member           = ");
  out.append(member.to_string());
  out.append("\n  kind             = ");
  out.append(failure_domain_registry::to_string(kind));
  out.append("\n  lifecycle        = ");
  out.append(failure_domain_registry::to_string(lifecycle));
  out.append("\n  generation       = ");
  out.append(generation.to_string());
  out.append("\n  role             = ");
  out.append(failure_domain_registry::to_string(role));
  out.append("\n  dependency       = ");
  out.append(failure_domain_registry::to_string(dependency));
  out.append("\n  evidence-gen     = ");
  out.append(evidence_generation.to_string());
  out.append("\n  provenance       = ");
  out.append(provenance.render());
  if (!derivation.rule.is_null()) {
    out.append("\n  derivation-rule  = ");
    out.append(derivation.rule.to_string());
    out.append(" valid=");
    out.append(derivation.valid ? "true" : "false");
    out.append(" gen=");
    out.append(derivation.generation.to_string());
  }
  for (const MembershipEvidence& entry : evidence) {
    out.append("\n  evidence         = ");
    out.append(entry.live ? "live " : "stale ");
    out.append(entry.provenance.render());
  }
  for (const MetadataEntry& entry : metadata) {
    out.append("\n  metadata         = ");
    out.append(entry.key);
    out.append("=");
    out.append(entry.value);
  }
  return out;
}

MembershipId membership_id_for(const MembershipKey& key) {
  std::string canonical;
  append_bytes(canonical, "fdr/membership-key/v1");
  append_u8(canonical, static_cast<std::uint8_t>(key.kind));
  append_bytes(canonical, key.domain.to_string());
  append_u8(canonical, static_cast<std::uint8_t>(key.member.entity_class()));
  append_bytes(canonical, std::string_view(reinterpret_cast<const char*>(key.member.bytes().data()),
                                           key.member.bytes().size()));
  append_u64(canonical, key.member_generation.value());
  return MembershipId::from_digest(sha256(canonical));
}

FailureDomainId domain_id_for(std::string_view administrative_scope,
                              const DomainClassRef& domain_class,
                              std::string_view identity_key) {
  std::string canonical;
  append_bytes(canonical, "fdr/domain-key/v1");
  append_bytes(canonical, administrative_scope);
  append_bytes(canonical, domain_class.to_string());
  append_bytes(canonical, identity_key);
  return FailureDomainId::from_digest(sha256(canonical));
}

Outcome validate_identity_key(std::string_view key) {
  if (key.empty()) {
    return Outcome::make(OutcomeCode::MalformedRequest, "identity key is empty");
  }
  if (key.size() > kMaxIdentityKeyBytes) {
    return Outcome::make(OutcomeCode::MalformedRequest,
                         "identity key exceeds " + std::to_string(kMaxIdentityKeyBytes) + " bytes");
  }
  for (char c : key) {
    const unsigned char raw = static_cast<unsigned char>(c);
    if (raw < 0x20u || raw == 0x7fu) {
      return Outcome::make(OutcomeCode::MalformedRequest,
                           "identity key contains a control character");
    }
  }
  return Outcome::make(OutcomeCode::Committed, "identity key accepted");
}

Outcome validate_scope_name(std::string_view scope) {
  if (scope.empty()) {
    return Outcome::make(OutcomeCode::MalformedRequest, "administrative scope is empty");
  }
  if (scope.size() > 256) {
    return Outcome::make(OutcomeCode::MalformedRequest,
                         "administrative scope exceeds 256 bytes");
  }
  for (char c : scope) {
    const unsigned char raw = static_cast<unsigned char>(c);
    if (raw < 0x20u || raw == 0x7fu) {
      return Outcome::make(OutcomeCode::MalformedRequest,
                           "administrative scope contains a control character");
    }
  }
  return Outcome::make(OutcomeCode::Committed, "administrative scope accepted");
}

std::string_view to_string(PublicationMode value) noexcept {
  switch (value) {
    case PublicationMode::Incremental: return "incremental";
    case PublicationMode::Partial: return "partial";
    case PublicationMode::Authoritative: return "authoritative";
    default: return "unknown";
  }
}

bool is_valid_publication_mode(PublicationMode value) noexcept {
  return value != PublicationMode::Unknown &&
         static_cast<std::uint8_t>(value) <= static_cast<std::uint8_t>(PublicationMode::Authoritative);
}

} // namespace failure_domain_registry
