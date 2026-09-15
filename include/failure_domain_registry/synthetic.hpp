// Failure Domain Registry — the synthetic failure-domain backend.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// No workstation can observe a rack power feed, a conduit, an optical amplifier
// or an upstream carrier. Those classifications are exercised with a
// deterministic generator whose every fact is labelled SYNTHETIC. Nothing in
// this header may ever be used to claim physical discovery.

#ifndef FAILURE_DOMAIN_REGISTRY_SYNTHETIC_HPP
#define FAILURE_DOMAIN_REGISTRY_SYNTHETIC_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "failure_domain_registry/domain_class.hpp"
#include "failure_domain_registry/entity.hpp"
#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"
#include "failure_domain_registry/provenance.hpp"

namespace failure_domain_registry {

/// A deterministic description of a synthetic installation.
struct SyntheticModel {
  std::uint64_t seed{1};
  std::size_t sites{2};
  std::size_t pods_per_site{2};
  std::size_t racks_per_pod{4};
  std::size_t switches_per_rack{2};
  std::size_t ports_per_switch{4};
  std::size_t conduits_per_site{2};
  std::size_t pdus_per_rack{2};
  std::size_t cooling_zones_per_site{1};
  std::size_t firmware_groups{3};
  std::size_t control_plane_groups{2};
  std::size_t providers{2};
  std::size_t wan_circuits_per_provider{2};
  /// Drop every ninth membership to model genuinely incomplete operator
  /// coverage.
  bool incomplete_coverage{true};
  /// Exercise entity replacement: supersede the first switch of the first rack.
  bool include_replacement{true};
};

/// A fully materialised synthetic model: domains, members and the memberships
/// between them. Every record is labelled SYNTHETIC.
struct SyntheticDataset {
  struct DomainRecord {
    DomainClassRef domain_class{};
    std::string administrative_scope;
    std::string identity_key;
    std::string name;
  };
  struct MemberRecord {
    EntityRef member{};
    std::string label;
  };
  struct MembershipRecord {
    std::size_t domain_index{0};
    std::size_t member_index{0};
    DomainClassRef domain_class{};
  };

  std::vector<DomainRecord> domains;
  std::vector<MemberRecord> members;
  std::vector<MembershipRecord> memberships;
  /// Declared coverage per (scope, class) that the generator actually produced
  /// completely.
  struct CoverageRecord {
    std::string administrative_scope;
    DomainClassRef domain_class{};
    bool complete{false};
  };
  std::vector<CoverageRecord> coverage;

  std::string render_summary() const;
};

/// Builds the dataset deterministically. The same seed always produces exactly
/// the same dataset.
FDR_API SyntheticDataset build_synthetic_dataset(const SyntheticModel& model);

/// The generator's own provenance for every fact it produces.
FDR_API Provenance synthetic_provenance(std::string_view source_identity);

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_SYNTHETIC_HPP
