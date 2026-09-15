// Failure Domain Registry — resource bounds.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every externally influenced size is bounded before it is allocated. The hard
// ceilings below are compiled into the library; configuration may lower them
// but can never raise them. Counts read from a request or from a persisted
// image are validated with checked arithmetic before any allocation
// proportional to them takes place.

#ifndef FAILURE_DOMAIN_REGISTRY_LIMITS_HPP
#define FAILURE_DOMAIN_REGISTRY_LIMITS_HPP

#include <cstddef>
#include <string>
#include <string_view>

#include "failure_domain_registry/export.hpp"

namespace failure_domain_registry {

/// Outcome of validating caller-supplied configuration.
struct ValidationResult {
  bool ok{true};
  std::string message;

  static ValidationResult success() { return ValidationResult{}; }
  static ValidationResult failure(std::string text) { return ValidationResult{false, std::move(text)}; }

  explicit operator bool() const noexcept { return ok; }
};

namespace hard_limits {

inline constexpr std::size_t kMaxDomains = 4'000'000;
inline constexpr std::size_t kMaxMemberships = 8'000'000;
inline constexpr std::size_t kMaxRelations = 8'000'000;
inline constexpr std::size_t kMaxStringBytes = 1024;
inline constexpr std::size_t kMaxMetadataEntries = 64;
inline constexpr std::size_t kMaxMetadataValueBytes = 8'192;
inline constexpr std::size_t kMaxMetadataBytesPerRecord = 32'768;
inline constexpr std::size_t kMaxRecordBytes = 262'144;
inline constexpr std::size_t kMaxEvidencePerMembership = 32;
inline constexpr std::size_t kMaxMembersPerBatch = 65'536;
inline constexpr std::size_t kMaxQuerySetCardinality = 4'096;
inline constexpr std::size_t kMaxHierarchyDepth = 256;
inline constexpr std::size_t kMaxAncestorWalk = 4'096;
inline constexpr std::size_t kMaxHistoryEntriesPerRecord = 256;
inline constexpr std::size_t kMaxHistoryQuery = 1'024;
inline constexpr std::size_t kMaxIdempotencyEntriesPerPublisher = 65'536;
inline constexpr std::size_t kMaxFencedBootsPerPublisher = 4'096;
inline constexpr std::size_t kMaxPublishers = 65'536;
inline constexpr std::size_t kMaxCoverageDeclarations = 65'536;
inline constexpr std::size_t kMaxSnapshotsRetained = 64;
inline constexpr std::size_t kMaxSnapshotRecords = 4'000'000;
inline constexpr std::size_t kMaxFramePayloadBytes = 4u * 1024u * 1024u;
inline constexpr std::size_t kMaxSessions = 4'096;
inline constexpr std::size_t kMaxWorkerThreads = 64;
inline constexpr std::size_t kMaxDerivedMembershipsPerRule = 1'000'000;

} // namespace hard_limits

/// Bounds enforced by one Registry instance.
struct RegistryLimits {
  std::size_t max_domains{1'000'000};
  std::size_t max_memberships{2'000'000};
  std::size_t max_relations{4'000'000};
  /// Maximum length in bytes of any single name, scope or source identity.
  std::size_t max_string_bytes{1024};
  std::size_t max_metadata_entries{32};
  std::size_t max_metadata_value_bytes{4096};
  std::size_t max_metadata_bytes_per_record{16'384};
  std::size_t max_record_bytes{65'536};
  std::size_t max_evidence_per_membership{8};
  std::size_t max_members_per_batch{16'384};
  std::size_t max_query_set_cardinality{1024};
  std::size_t max_hierarchy_depth{64};
  std::size_t max_ancestor_walk{1024};
  std::size_t max_history_entries_per_record{64};
  std::size_t max_history_query{256};
  std::size_t max_idempotency_entries_per_publisher{4096};
  std::size_t max_fenced_boots_per_publisher{64};
  std::size_t max_publishers{4096};
  std::size_t max_coverage_declarations{4096};
  std::size_t max_snapshots_retained{16};

  static RegistryLimits defaults() noexcept { return RegistryLimits{}; }

  /// Returns a failure result naming the exact offending field. Configuration
  /// that is internally inconsistent or above a hard ceiling is rejected.
  ValidationResult validate() const;
};

/// Bounds enforced by the framed control transport.
struct FrameLimits {
  std::size_t max_payload_bytes{1024 * 1024};
  std::size_t max_pending_frames{64};
  std::size_t max_sessions{256};
  std::size_t worker_threads{4};
  /// Maximum time, in milliseconds, a session may sit idle before the
  /// coordinator closes it. Zero disables idle closure.
  std::uint32_t idle_timeout_ms{0};

  static FrameLimits defaults() noexcept { return FrameLimits{}; }
  ValidationResult validate() const;
};

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_LIMITS_HPP
