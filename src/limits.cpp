// Failure Domain Registry — resource bound validation.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/limits.hpp"

namespace failure_domain_registry {
namespace {

ValidationResult check_bound(const char* field, std::size_t value, std::size_t hard_max,
                             std::size_t minimum) {
  if (value < minimum) {
    std::string message = field;
    message.append(" must be at least ");
    message.append(std::to_string(minimum));
    return ValidationResult::failure(std::move(message));
  }
  if (value > hard_max) {
    std::string message = field;
    message.append(" exceeds the hard ceiling ");
    message.append(std::to_string(hard_max));
    return ValidationResult::failure(std::move(message));
  }
  return ValidationResult::success();
}

} // namespace

ValidationResult RegistryLimits::validate() const {
  ValidationResult result = check_bound("max_domains", max_domains, hard_limits::kMaxDomains, 1);
  if (!result) return result;
  result = check_bound("max_memberships", max_memberships, hard_limits::kMaxMemberships, 1);
  if (!result) return result;
  result = check_bound("max_relations", max_relations, hard_limits::kMaxRelations, 1);
  if (!result) return result;
  result = check_bound("max_string_bytes", max_string_bytes, hard_limits::kMaxStringBytes, 16);
  if (!result) return result;
  result = check_bound("max_metadata_entries", max_metadata_entries, hard_limits::kMaxMetadataEntries, 1);
  if (!result) return result;
  result = check_bound("max_metadata_value_bytes", max_metadata_value_bytes,
                       hard_limits::kMaxMetadataValueBytes, 1);
  if (!result) return result;
  result = check_bound("max_metadata_bytes_per_record", max_metadata_bytes_per_record,
                       hard_limits::kMaxMetadataBytesPerRecord, 1);
  if (!result) return result;
  result = check_bound("max_record_bytes", max_record_bytes, hard_limits::kMaxRecordBytes, 256);
  if (!result) return result;
  result = check_bound("max_evidence_per_membership", max_evidence_per_membership,
                       hard_limits::kMaxEvidencePerMembership, 1);
  if (!result) return result;
  result = check_bound("max_members_per_batch", max_members_per_batch,
                       hard_limits::kMaxMembersPerBatch, 1);
  if (!result) return result;
  result = check_bound("max_query_set_cardinality", max_query_set_cardinality,
                       hard_limits::kMaxQuerySetCardinality, 1);
  if (!result) return result;
  result = check_bound("max_hierarchy_depth", max_hierarchy_depth, hard_limits::kMaxHierarchyDepth, 1);
  if (!result) return result;
  // max_hierarchy_depth is enforced when a containment edge is added, so a walk
  // bounded by max_ancestor_walk can never truncate silently as long as the walk
  // bound is at least the hierarchy bound.
  result = check_bound("max_ancestor_walk", max_ancestor_walk, hard_limits::kMaxAncestorWalk, 1);
  if (!result) return result;
  if (max_ancestor_walk < max_hierarchy_depth) {
    return ValidationResult::failure(
        "max_ancestor_walk must be at least max_hierarchy_depth, otherwise a hierarchy walk "
        "could truncate silently");
  }
  result = check_bound("max_history_entries_per_record", max_history_entries_per_record,
                       hard_limits::kMaxHistoryEntriesPerRecord, 1);
  if (!result) return result;
  result = check_bound("max_history_query", max_history_query, hard_limits::kMaxHistoryQuery, 1);
  if (!result) return result;
  result = check_bound("max_idempotency_entries_per_publisher", max_idempotency_entries_per_publisher,
                       hard_limits::kMaxIdempotencyEntriesPerPublisher, 1);
  if (!result) return result;
  result = check_bound("max_fenced_boots_per_publisher", max_fenced_boots_per_publisher,
                       hard_limits::kMaxFencedBootsPerPublisher, 1);
  if (!result) return result;
  result = check_bound("max_publishers", max_publishers, hard_limits::kMaxPublishers, 1);
  if (!result) return result;
  return check_bound("max_coverage_declarations", max_coverage_declarations,
                     hard_limits::kMaxCoverageDeclarations, 1);
}

ValidationResult FrameLimits::validate() const {
  ValidationResult result = check_bound("max_payload_bytes", max_payload_bytes,
                                        hard_limits::kMaxFramePayloadBytes, 64);
  if (!result) return result;
  result = check_bound("max_pending_frames", max_pending_frames, 65'536, 1);
  if (!result) return result;
  result = check_bound("max_sessions", max_sessions, hard_limits::kMaxSessions, 1);
  if (!result) return result;
  return check_bound("worker_threads", worker_threads, hard_limits::kMaxWorkerThreads, 1);
}

} // namespace failure_domain_registry
