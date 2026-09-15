// Failure Domain Registry — provenance and evidence.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every domain and every membership carries provenance. Two rules are absolute:
// an opaque confidence score is never authority, and synthetic evidence is
// never presented as physically discovered. Where one evidence class outranks
// another, the ranking below is total, deterministic and part of the API.

#ifndef FAILURE_DOMAIN_REGISTRY_PROVENANCE_HPP
#define FAILURE_DOMAIN_REGISTRY_PROVENANCE_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"

namespace failure_domain_registry {

/// Where a classification came from.
enum class ProvenanceSource : std::uint8_t {
  Unknown = 0,
  OperatorInventory = 1,
  Cmdb = 2,
  PhysicalInfrastructure = 3,
  TopologyDerivation = 4,
  PowerManagement = 5,
  CableInventory = 6,
  VendorController = 7,
  DiscoveryAgent = 8,
  ImportedManifest = 9,
  SyntheticTestSource = 10,
  DerivationRule = 11,
  AdministrativeDeclaration = 12,
};

/// How strong the evidence is. Lower rank is stronger. The ranking is a total
/// order and is the only conflict-resolution precedence this runtime defines.
enum class EvidenceClass : std::uint8_t {
  Unknown = 0,
  /// An authoritative infrastructure record kept by the operator of the
  /// physical plant (physical inventory, DCIM).
  DirectAuthoritativeInfrastructure = 1,
  /// A direct reading from hardware or a device controller.
  DirectHardwareController = 2,
  /// An administrative statement by an authorized publisher.
  AdministrativeDeclaration = 3,
  /// A conclusion reached by a published, versioned derivation rule.
  DerivedTopology = 4,
  /// A static imported inventory snapshot.
  ImportedStaticInventory = 5,
  /// An inference that is neither measured nor declared.
  Inferred = 6,
  /// Generated data. Never proves physical structure.
  Synthetic = 7,
};

/// Truthfulness label. There is no fourth category and no "probably real".
enum class TruthClass : std::uint8_t {
  Unknown = 0,
  /// Observed from real host or process behaviour in this environment.
  Real = 1,
  /// Generated because the real information is not available here.
  Synthetic = 2,
  /// The information cannot be obtained in this environment at all.
  Unsupported = 3,
};

FDR_API std::string_view to_string(ProvenanceSource value) noexcept;
FDR_API std::string_view to_string(EvidenceClass value) noexcept;
FDR_API std::string_view to_string(TruthClass value) noexcept;

FDR_API std::optional<ProvenanceSource> provenance_source_from_string(std::string_view text) noexcept;
FDR_API std::optional<EvidenceClass> evidence_class_from_string(std::string_view text) noexcept;
FDR_API std::optional<TruthClass> truth_class_from_string(std::string_view text) noexcept;

FDR_API bool is_valid_provenance_source(ProvenanceSource value) noexcept;
FDR_API bool is_valid_evidence_class(EvidenceClass value) noexcept;
FDR_API bool is_valid_truth_class(TruthClass value) noexcept;

/// Total order over evidence classes. 0 means "no evidence"; larger is weaker.
FDR_API std::uint8_t evidence_rank(EvidenceClass value) noexcept;

/// True when `left` deterministically outranks `right`. Equal ranks are not
/// an outranking; equal-rank disagreement is a conflict.
FDR_API bool evidence_outranks(EvidenceClass left, EvidenceClass right) noexcept;

/// True when the evidence class is bound to a live publisher incarnation, so
/// that fencing that incarnation demotes the evidence. Durable classes survive
/// the loss of their publisher as classification, never as process authority.
FDR_API bool is_process_bound_evidence(EvidenceClass value) noexcept;

/// True when the evidence class may be used as a deterministic tie-breaker.
FDR_API bool is_authoritative_evidence(EvidenceClass value) noexcept;

/// The provenance of one domain, membership or evidence entry.
struct FDR_API Provenance {
  ProvenanceSource source{ProvenanceSource::Unknown};
  EvidenceClass evidence{EvidenceClass::Unknown};
  TruthClass truth{TruthClass::Unknown};
  /// Publisher that supplied the fact, when a publisher did.
  PublisherId publisher{};
  /// Incarnation of that publisher, when the evidence is process bound.
  WorkerBootId worker_boot{};
  /// Generation of the evidence this provenance describes.
  EvidenceGeneration evidence_generation{};
  /// Source-specific identity: inventory id, device instance path, ticket id.
  std::string source_identity;
  /// Rule that derived the fact, when one did.
  DerivationRuleId derivation_rule{};
  /// Entity generations the fact was derived from, when it was derived.
  std::string derivation_context;

  bool has_publisher() const noexcept { return !publisher.is_null(); }
  bool is_durable() const noexcept { return !is_process_bound_evidence(evidence); }

  /// Canonical single-line rendering, stable across runs.
  std::string render() const;
  /// Canonical byte string fed to the semantic digest.
  std::string canonical_form() const;

  friend bool operator==(const Provenance&, const Provenance&) = default;
};

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_PROVENANCE_HPP
