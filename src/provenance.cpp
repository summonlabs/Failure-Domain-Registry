// Failure Domain Registry — provenance and evidence ranking.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/provenance.hpp"

#include <algorithm>

#include "failure_domain_registry/digest.hpp"

namespace failure_domain_registry {

std::string_view to_string(ProvenanceSource value) noexcept {
  switch (value) {
    case ProvenanceSource::OperatorInventory: return "operator-inventory";
    case ProvenanceSource::Cmdb: return "cmdb";
    case ProvenanceSource::PhysicalInfrastructure: return "physical-infrastructure";
    case ProvenanceSource::TopologyDerivation: return "topology-derivation";
    case ProvenanceSource::PowerManagement: return "power-management";
    case ProvenanceSource::CableInventory: return "cable-inventory";
    case ProvenanceSource::VendorController: return "vendor-controller";
    case ProvenanceSource::DiscoveryAgent: return "discovery-agent";
    case ProvenanceSource::ImportedManifest: return "imported-manifest";
    case ProvenanceSource::SyntheticTestSource: return "synthetic-test-source";
    case ProvenanceSource::DerivationRule: return "derivation-rule";
    case ProvenanceSource::AdministrativeDeclaration: return "administrative-declaration";
    default: return "unknown";
  }
}

std::string_view to_string(EvidenceClass value) noexcept {
  switch (value) {
    case EvidenceClass::DirectAuthoritativeInfrastructure: return "direct-authoritative-infrastructure";
    case EvidenceClass::DirectHardwareController: return "direct-hardware-controller";
    case EvidenceClass::AdministrativeDeclaration: return "administrative-declaration";
    case EvidenceClass::DerivedTopology: return "derived-topology";
    case EvidenceClass::ImportedStaticInventory: return "imported-static-inventory";
    case EvidenceClass::Inferred: return "inferred";
    case EvidenceClass::Synthetic: return "synthetic";
    default: return "unknown";
  }
}

std::string_view to_string(TruthClass value) noexcept {
  switch (value) {
    case TruthClass::Real: return "REAL";
    case TruthClass::Synthetic: return "SYNTHETIC";
    case TruthClass::Unsupported: return "UNSUPPORTED";
    default: return "UNKNOWN";
  }
}

std::optional<ProvenanceSource> provenance_source_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= static_cast<std::uint8_t>(ProvenanceSource::AdministrativeDeclaration); ++raw) {
    const auto value = static_cast<ProvenanceSource>(raw);
    if (to_string(value) == text) {
      return value;
    }
  }
  return std::nullopt;
}

std::optional<EvidenceClass> evidence_class_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= static_cast<std::uint8_t>(EvidenceClass::Synthetic); ++raw) {
    const auto value = static_cast<EvidenceClass>(raw);
    if (to_string(value) == text) {
      return value;
    }
  }
  return std::nullopt;
}

std::optional<TruthClass> truth_class_from_string(std::string_view text) noexcept {
  if (text == "REAL") return TruthClass::Real;
  if (text == "SYNTHETIC") return TruthClass::Synthetic;
  if (text == "UNSUPPORTED") return TruthClass::Unsupported;
  return std::nullopt;
}

bool is_valid_provenance_source(ProvenanceSource value) noexcept {
  return value != ProvenanceSource::Unknown &&
         static_cast<std::uint8_t>(value) <= static_cast<std::uint8_t>(ProvenanceSource::AdministrativeDeclaration);
}

bool is_valid_evidence_class(EvidenceClass value) noexcept {
  return value != EvidenceClass::Unknown &&
         static_cast<std::uint8_t>(value) <= static_cast<std::uint8_t>(EvidenceClass::Synthetic);
}

bool is_valid_truth_class(TruthClass value) noexcept {
  return value != TruthClass::Unknown &&
         static_cast<std::uint8_t>(value) <= static_cast<std::uint8_t>(TruthClass::Unsupported);
}

std::uint8_t evidence_rank(EvidenceClass value) noexcept {
  return static_cast<std::uint8_t>(value);
}

bool evidence_outranks(EvidenceClass left, EvidenceClass right) noexcept {
  const std::uint8_t left_rank = evidence_rank(left);
  const std::uint8_t right_rank = evidence_rank(right);
  if (left_rank == 0 || right_rank == 0) {
    return false;
  }
  return left_rank < right_rank;
}

bool is_process_bound_evidence(EvidenceClass value) noexcept {
  switch (value) {
    case EvidenceClass::DirectHardwareController:
    case EvidenceClass::DerivedTopology:
    case EvidenceClass::Inferred:
      return true;
    default:
      return false;
  }
}

bool is_authoritative_evidence(EvidenceClass value) noexcept {
  switch (value) {
    case EvidenceClass::DirectAuthoritativeInfrastructure:
    case EvidenceClass::DirectHardwareController:
    case EvidenceClass::AdministrativeDeclaration:
      return true;
    default:
      return false;
  }
}

std::string Provenance::canonical_form() const {
  std::string out;
  append_bytes(out, "fdr/provenance/v1");
  append_u8(out, static_cast<std::uint8_t>(source));
  append_u8(out, static_cast<std::uint8_t>(evidence));
  append_u8(out, static_cast<std::uint8_t>(truth));
  append_bytes(out, publisher.to_string());
  append_bytes(out, worker_boot.to_string());
  append_u64(out, evidence_generation.value());
  append_bytes(out, source_identity);
  append_bytes(out, derivation_rule.to_string());
  append_bytes(out, derivation_context);
  return out;
}

std::string Provenance::render() const {
  std::string out;
  out.append("source=");
  out.append(failure_domain_registry::to_string(source));
  out.append(" evidence=");
  out.append(failure_domain_registry::to_string(evidence));
  out.append(" truth=");
  out.append(failure_domain_registry::to_string(truth));
  out.append(" evidence-generation=");
  out.append(evidence_generation.to_string());
  if (has_publisher()) {
    out.append(" publisher=");
    out.append(publisher.to_string());
    out.append(" worker-boot=");
    out.append(worker_boot.to_string());
  }
  if (!source_identity.empty()) {
    out.append(" source-identity=");
    out.append(source_identity);
  }
  if (!derivation_rule.is_null()) {
    out.append(" derivation-rule=");
    out.append(derivation_rule.to_string());
  }
  return out;
}

} // namespace failure_domain_registry
