// Failure Domain Registry - the synthetic failure-domain backend.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// No workstation can observe rack power feeds, conduits, optical components or
// upstream carriers. Those classifications are exercised with a deterministic
// generator whose every fact is labelled SYNTHETIC. Nothing here may ever be
// presented as physical discovery.

#include "failure_domain_registry/synthetic.hpp"

#include <string>

#include "failure_domain_registry/digest.hpp"

namespace failure_domain_registry {
namespace {

IdBytes deterministic_id(const SyntheticModel& model, const std::string& purpose,
                         std::size_t index) {
  std::string canonical;
  append_bytes(canonical, "fdr/synthetic/v1");
  append_u64(canonical, model.seed);
  append_bytes(canonical, purpose);
  append_u64(canonical, static_cast<std::uint64_t>(index));
  const DigestBytes digest = sha256(canonical);
  IdBytes out{};
  for (std::size_t i = 0; i < kOpaqueIdBytes; ++i) {
    out[i] = digest[i];
  }
  return out;
}

std::string numbered(const char* prefix, std::size_t index) {
  return std::string(prefix) + "-" + std::to_string(index);
}

} // namespace

Provenance synthetic_provenance(std::string_view source_identity) {
  Provenance provenance;
  provenance.source = ProvenanceSource::SyntheticTestSource;
  provenance.evidence = EvidenceClass::Synthetic;
  provenance.truth = TruthClass::Synthetic;
  provenance.source_identity.assign(source_identity);
  provenance.evidence_generation = EvidenceGeneration::first();
  return provenance;
}

SyntheticDataset build_synthetic_dataset(const SyntheticModel& model) {
  SyntheticDataset dataset;
  std::size_t member_index = 0;
  std::vector<std::size_t> switch_members;
  std::vector<std::size_t> port_members;
  std::vector<std::size_t> link_members;

  const auto add_domain = [&dataset](DomainClass klass, const std::string& scope,
                                     const std::string& key, const std::string& name) {
    SyntheticDataset::DomainRecord record;
    record.domain_class = DomainClassRef(klass);
    record.administrative_scope = scope;
    record.identity_key = key;
    record.name = name;
    dataset.domains.push_back(std::move(record));
    return dataset.domains.size() - 1;
  };
  const auto add_member = [&dataset, &member_index, &model](EntityClass klass,
                                                            const std::string& purpose,
                                                            const std::string& label) {
    SyntheticDataset::MemberRecord record;
    record.member = EntityRef(EntityId(klass, deterministic_id(model, purpose, member_index)),
                              EntityGeneration::first());
    record.label = label;
    dataset.members.push_back(std::move(record));
    ++member_index;
    return dataset.members.size() - 1;
  };
  const auto add_membership = [&dataset](std::size_t domain, std::size_t member) {
    SyntheticDataset::MembershipRecord record;
    record.domain_index = domain;
    record.member_index = member;
    record.domain_class = dataset.domains[domain].domain_class;
    dataset.memberships.push_back(std::move(record));
  };

  std::vector<std::size_t> pod_domains;
  std::vector<std::size_t> rack_domains;
  for (std::size_t site = 0; site < model.sites; ++site) {
    const std::string site_scope = numbered("site", site);
    const std::size_t site_domain =
        add_domain(DomainClass::Site, site_scope, numbered("site", site), numbered("Site", site));
    for (std::size_t provider = 0; provider < model.providers; ++provider) {
      add_domain(DomainClass::NetworkProvider, site_scope,
                 numbered("provider", provider) + "-site-" + std::to_string(site),
                 numbered("Carrier", provider));
      for (std::size_t circuit = 0; circuit < model.wan_circuits_per_provider; ++circuit) {
        const std::size_t circuit_domain = add_domain(
            DomainClass::WanCircuit, site_scope,
            numbered("circuit", circuit) + "-p" + std::to_string(provider) + "-s" +
                std::to_string(site),
            numbered("Circuit", circuit));
        const std::size_t link =
            add_member(EntityClass::Link, "wan-link", numbered("wan-link", member_index));
        link_members.push_back(link);
        add_membership(circuit_domain, link);
      }
    }
    for (std::size_t cooling = 0; cooling < model.cooling_zones_per_site; ++cooling) {
      add_domain(DomainClass::CoolingZone, site_scope,
                 numbered("cooling", cooling) + "-site-" + std::to_string(site),
                 numbered("CoolingZone", cooling));
    }
    for (std::size_t conduit = 0; conduit < model.conduits_per_site; ++conduit) {
      const std::size_t conduit_domain = add_domain(
          DomainClass::Conduit, site_scope,
          numbered("conduit", conduit) + "-site-" + std::to_string(site),
          numbered("Conduit", conduit));
      const std::size_t fibre = add_domain(
          DomainClass::Cable, site_scope,
          numbered("fibre", conduit) + "-site-" + std::to_string(site),
          numbered("FibreSpan", conduit));
      const std::size_t link =
          add_member(EntityClass::Link, "conduit-link", numbered("conduit-link", member_index));
      link_members.push_back(link);
      add_membership(conduit_domain, link);
      add_membership(fibre, link);
    }
    for (std::size_t pod = 0; pod < model.pods_per_site; ++pod) {
      const std::size_t pod_domain = add_domain(
          DomainClass::Pod, site_scope,
          numbered("pod", pod) + "-site-" + std::to_string(site),
          numbered("Pod", pod));
      pod_domains.push_back(pod_domain);
      for (std::size_t rack = 0; rack < model.racks_per_pod; ++rack) {
        const std::size_t rack_domain = add_domain(
            DomainClass::Rack, site_scope,
            numbered("rack", rack) + "-pod" + std::to_string(pod) + "-site-" +
                std::to_string(site),
            numbered("Rack", rack));
        rack_domains.push_back(rack_domain);
        for (std::size_t pdu = 0; pdu < model.pdus_per_rack; ++pdu) {
          add_domain(DomainClass::Pdu, site_scope,
                     numbered("pdu", pdu) + "-rack" + std::to_string(rack) + "-pod" +
                         std::to_string(pod) + "-site-" + std::to_string(site),
                     numbered("Pdu", pdu));
        }
        for (std::size_t index = 0; index < model.switches_per_rack; ++index) {
          const std::size_t switch_member =
              add_member(EntityClass::Switch, "switch", numbered("switch", member_index));
          switch_members.push_back(switch_member);
          add_membership(rack_domain, switch_member);
          add_membership(pod_domain, switch_member);
          add_membership(site_domain, switch_member);
          const std::string firmware_key =
              numbered("firmware", switch_members.size() % model.firmware_groups);
          const std::size_t firmware_domain = add_domain(DomainClass::FirmwareGroup, site_scope,
                                                         firmware_key, firmware_key);
          add_membership(firmware_domain, switch_member);
          const std::string control_key =
              numbered("control", switch_members.size() % model.control_plane_groups);
          const std::size_t control_domain = add_domain(DomainClass::ControlPlane, site_scope,
                                                        control_key, control_key);
          add_membership(control_domain, switch_member);
          for (std::size_t port = 0; port < model.ports_per_switch; ++port) {
            const std::size_t port_member =
                add_member(EntityClass::Port, "port", numbered("port", member_index));
            port_members.push_back(port_member);
            add_membership(rack_domain, port_member);
          }
        }
      }
    }
  }

  std::vector<SyntheticDataset::MembershipRecord> kept;
  kept.reserve(dataset.memberships.size());
  for (std::size_t i = 0; i < dataset.memberships.size(); ++i) {
    if (model.incomplete_coverage && (i % 9) == 8) {
      continue;
    }
    kept.push_back(dataset.memberships[i]);
  }
  dataset.memberships = std::move(kept);

  SyntheticDataset::CoverageRecord rack_coverage;
  rack_coverage.administrative_scope = numbered("site", 0);
  rack_coverage.domain_class = DomainClassRef(DomainClass::Rack);
  rack_coverage.complete = true;
  dataset.coverage.push_back(rack_coverage);
  SyntheticDataset::CoverageRecord pod_coverage;
  pod_coverage.administrative_scope = numbered("site", 0);
  pod_coverage.domain_class = DomainClassRef(DomainClass::Pod);
  pod_coverage.complete = true;
  dataset.coverage.push_back(pod_coverage);
  SyntheticDataset::CoverageRecord conduit_coverage;
  conduit_coverage.administrative_scope = numbered("site", 0);
  conduit_coverage.domain_class = DomainClassRef(DomainClass::Conduit);
  conduit_coverage.complete = false;
  dataset.coverage.push_back(conduit_coverage);
  return dataset;
}

std::string SyntheticDataset::render_summary() const {
  std::string out = "synthetic-dataset (truth=SYNTHETIC)\n";
  out.append("  domains          = ");
  out.append(std::to_string(domains.size()));
  out.append("\n  members          = ");
  out.append(std::to_string(members.size()));
  out.append("\n  memberships      = ");
  out.append(std::to_string(memberships.size()));
  out.append("\n  coverage records = ");
  out.append(std::to_string(coverage.size()));
  return out;
}

} // namespace failure_domain_registry
