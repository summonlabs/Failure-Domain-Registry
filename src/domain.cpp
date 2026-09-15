// Failure Domain Registry — failure-domain and relation records.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/domain.hpp"

#include <algorithm>

#include "failure_domain_registry/digest.hpp"
#include "failure_domain_registry/relation.hpp"

namespace failure_domain_registry {
namespace {

bool metadata_less(const MetadataEntry& left, const MetadataEntry& right) {
  if (left.key != right.key) {
    return left.key < right.key;
  }
  return left.value < right.value;
}

std::vector<MetadataEntry> canonical_metadata(const std::vector<MetadataEntry>& input) {
  std::vector<MetadataEntry> out = input;
  std::sort(out.begin(), out.end(), metadata_less);
  return out;
}

} // namespace

std::string FailureDomain::canonical_form() const {
  std::string out;
  append_bytes(out, "fdr/domain/v1");
  append_bytes(out, id.to_string());
  append_bytes(out, domain_class.to_string());
  append_u64(out, generation.value());
  append_u8(out, static_cast<std::uint8_t>(lifecycle));
  append_u64(out, created_generation.value());
  // created_at and created_epoch are process-local bookkeeping: two registries
  // that reached the same classification by different paths must digest
  // identically, so they are deliberately excluded here.
  append_bytes(out, superseded_by.to_string());
  append_bytes(out, supersedes.to_string());
  append_bytes(out, merged_into.to_string());
  append_bytes(out, name);
  append_bytes(out, administrative_scope);
  append_bytes(out, provenance.canonical_form());
  const std::vector<MetadataEntry> metadata_canonical = canonical_metadata(metadata);
  append_u32(out, static_cast<std::uint32_t>(metadata_canonical.size()));
  for (const MetadataEntry& entry : metadata_canonical) {
    append_bytes(out, entry.key);
    append_bytes(out, entry.value);
  }
  return out;
}

std::string FailureDomain::render() const {
  std::string out = "domain ";
  out.append(id.to_string());
  out.append("\n  class            = ");
  out.append(domain_class.to_string());
  out.append("\n  lifecycle        = ");
  out.append(failure_domain_registry::to_string(lifecycle));
  out.append("\n  generation       = ");
  out.append(generation.to_string());
  out.append("\n  created-generation = ");
  out.append(created_generation.to_string());
  out.append("\n  scope            = ");
  out.append(administrative_scope);
  if (!name.empty()) {
    out.append("\n  name             = ");
    out.append(name);
  }
  out.append("\n  provenance       = ");
  out.append(provenance.render());
  if (!superseded_by.is_null()) {
    out.append("\n  superseded-by    = ");
    out.append(superseded_by.to_string());
  }
  if (!supersedes.is_null()) {
    out.append("\n  supersedes       = ");
    out.append(supersedes.to_string());
  }
  if (!merged_into.is_null()) {
    out.append("\n  merged-into      = ");
    out.append(merged_into.to_string());
  }
  const std::vector<MetadataEntry> metadata_canonical = canonical_metadata(metadata);
  for (const MetadataEntry& entry : metadata_canonical) {
    out.append("\n  metadata         = ");
    out.append(entry.key);
    out.append("=");
    out.append(entry.value);
  }
  return out;
}

std::string DomainRelation::canonical_form() const {
  std::string out;
  append_bytes(out, "fdr/relation/v1");
  append_bytes(out, id.to_string());
  append_bytes(out, source.to_string());
  append_bytes(out, target.to_string());
  append_u8(out, static_cast<std::uint8_t>(type));
  append_bytes(out, provenance.canonical_form());
  // created_at and created_epoch are process-local creation bookkeeping, not
  // semantic identity, so they are excluded exactly as they are for domains and
  // memberships.
  return out;
}

std::string DomainRelation::render() const {
  std::string out = source.to_string();
  out.append(" -");
  out.append(failure_domain_registry::to_string(type));
  out.append("-> ");
  out.append(target.to_string());
  out.append(" [");
  out.append(provenance.render());
  out.append("]");
  return out;
}

DomainRelationId relation_id_for(const FailureDomainId& source,
                                 const FailureDomainId& target,
                                 DomainRelationType type) {
  FailureDomainId first = source;
  FailureDomainId second = target;
  if (is_symmetric_relation(type) && second < first) {
    std::swap(first, second);
  }
  std::string canonical;
  append_bytes(canonical, "fdr/relation/v1");
  append_bytes(canonical, first.to_string());
  append_bytes(canonical, second.to_string());
  append_u8(canonical, static_cast<std::uint8_t>(type));
  return DomainRelationId::from_digest(sha256(canonical));
}

} // namespace failure_domain_registry
