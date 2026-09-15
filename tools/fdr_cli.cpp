// Failure Domain Registry - offline inspection tool.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every command reads either the host or a persisted image. Nothing here
// mutates a live registry and nothing here reaches the network.
//
// Usage:
//   fdr-cli version
//   fdr-cli classes
//   fdr-cli lifecycle
//   fdr-cli limits
//   fdr-cli host-evidence
//   fdr-cli synthetic [SEED]
//   fdr-cli inspect PATH
//   fdr-cli dump PATH

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "failure_domain_registry/failure_domain_registry.hpp"

namespace {

using namespace failure_domain_registry;

int command_version() {
  std::printf("Failure Domain Registry %s\n", std::string(version_string()).c_str());
  std::printf("state format version %u\n", kStateFormatVersion);
  std::printf("wire protocol version %u\n", kWireProtocolVersion);
  std::printf("digest version %u\n", kDigestVersion);
  return 0;
}

int command_classes() {
  for (std::uint8_t raw = 1; raw <= kDomainClassCount; ++raw) {
    const auto klass = static_cast<DomainClass>(raw);
    std::printf("%-24s exclusive=%s containment=%s\n",
                std::string(to_string(klass)).c_str(),
                is_exclusive_class(klass) ? "yes" : "no",
                is_containment_class(klass) ? "yes" : "no");
  }
  std::printf("extensions: vendor:<namespace>/<name>, admin:<namespace>/<name>\n");
  return 0;
}

int command_lifecycle() {
  std::size_t domain_count = 0;
  const TransitionEdge* domain_edges = domain_transition_table(domain_count);
  std::printf("domain transitions (%zu)\n", domain_count);
  for (std::size_t i = 0; i < domain_count; ++i) {
    std::printf("  %s -> %s\n", std::string(to_string(domain_edges[i].from)).c_str(),
                std::string(to_string(domain_edges[i].to)).c_str());
  }
  std::size_t membership_count = 0;
  const MembershipTransitionEdge* membership_edges = membership_transition_table(membership_count);
  std::printf("membership transitions (%zu)\n", membership_count);
  for (std::size_t i = 0; i < membership_count; ++i) {
    std::printf("  %s -> %s\n", std::string(to_string(membership_edges[i].from)).c_str(),
                std::string(to_string(membership_edges[i].to)).c_str());
  }
  return 0;
}

int command_limits() {
  const RegistryLimits limits = RegistryLimits::defaults();
  const ValidationResult valid = limits.validate();
  std::printf("default RegistryLimits valid=%s\n", valid.ok ? "yes" : "no");
  std::printf("  max_domains                 = %zu\n", limits.max_domains);
  std::printf("  max_memberships             = %zu\n", limits.max_memberships);
  std::printf("  max_relations               = %zu\n", limits.max_relations);
  std::printf("  max_members_per_batch       = %zu\n", limits.max_members_per_batch);
  std::printf("  max_query_set_cardinality   = %zu\n", limits.max_query_set_cardinality);
  std::printf("  max_evidence_per_membership = %zu\n", limits.max_evidence_per_membership);
  std::printf("  max_hierarchy_depth         = %zu\n", limits.max_hierarchy_depth);
  const FrameLimits frames = FrameLimits::defaults();
  std::printf("  frame max_payload_bytes     = %zu\n", frames.max_payload_bytes);
  std::printf("  frame max_sessions          = %zu\n", frames.max_sessions);
  std::printf("hard ceilings: domains %zu, memberships %zu, frame payload %zu\n",
              hard_limits::kMaxDomains, hard_limits::kMaxMemberships,
              hard_limits::kMaxFramePayloadBytes);
  return 0;
}

int command_host_evidence() {
  const HostDiscoveryReport report = discover_host_evidence();
  std::fputs(report.render().c_str(), stdout);
  std::fputc('\n', stdout);
  return 0;
}

int command_synthetic(const char* seed_text) {
  SyntheticModel model;
  if (seed_text != nullptr) {
    model.seed = static_cast<std::uint64_t>(std::strtoull(seed_text, nullptr, 10));
  }
  const SyntheticDataset dataset = build_synthetic_dataset(model);
  std::fputs(dataset.render_summary().c_str(), stdout);
  std::fputc('\n', stdout);
  std::printf("every record carries truth=%s and evidence=%s\n",
              std::string(to_string(TruthClass::Synthetic)).c_str(),
              std::string(to_string(EvidenceClass::Synthetic)).c_str());
  return 0;
}

int command_inspect(const char* path) {
  PersistenceConfig config;
  config.path = path;
  PersistenceReport report;
  const Outcome outcome = inspect_persistence(config, &report);
  std::fputs(outcome.render().c_str(), stdout);
  std::fputc('\n', stdout);
  if (!outcome.committed()) {
    return 1;
  }
  std::printf("bytes               = %zu\n", report.bytes);
  std::printf("format version      = %u\n", report.format_version);
  std::printf("registry generation = %s\n", report.generation.to_string().c_str());
  std::printf("coordinator epoch   = %s\n", report.epoch.to_string().c_str());
  std::printf("domains             = %zu\n", report.domains);
  std::printf("memberships         = %zu\n", report.memberships);
  std::printf("relations           = %zu\n", report.relations);
  std::printf("coverage            = %zu\n", report.coverage_declarations);
  std::printf("publishers          = %zu\n", report.publishers);
  std::printf("fences              = %zu\n", report.fences);
  std::printf("derivation rules    = %zu\n", report.derivation_rules);
  std::printf("payload digest      = %s\n", report.digest.to_string().c_str());
  return 0;
}

int command_dump(const char* path) {
  PersistenceConfig config;
  config.path = path;
  Registry registry;
  const Outcome loaded = registry.load(config);
  if (!loaded.committed()) {
    std::fprintf(stderr, "cannot load: %s\n", loaded.render().c_str());
    return 1;
  }
  std::printf("registry generation = %s\n", registry.generation().to_string().c_str());
  std::printf("coordinator epoch   = %s\n", registry.epoch().to_string().c_str());
  std::printf("state digest        = %s\n", registry.state_digest().to_string().c_str());
  for (const FailureDomain& domain : registry.domains(1000000)) {
    std::printf("%s\n", domain.render().c_str());
  }
  for (const PublisherRegistration& registration : registry.publishers()) {
    std::printf("publisher %s name=%s scope=%s generation=%s\n",
                registration.publisher.to_string().c_str(), registration.name.c_str(),
                registration.scope.render().c_str(), registration.generation.to_string().c_str());
  }
  for (const FenceRecord& fence : registry.fences()) {
    std::printf("fence publisher=%s boot=%s reason=%s epoch=%s\n",
                fence.publisher.to_string().c_str(), fence.worker_boot.to_string().c_str(),
                std::string(to_string(fence.reason)).c_str(), fence.epoch.to_string().c_str());
  }
  std::string why;
  if (!registry.validate_state(&why)) {
    std::printf("INDEX-VALIDATION-FAILED %s\n", why.c_str());
    return 1;
  }
  std::printf("indexes validated\n");
  return 0;
}

} // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fputs(
        "usage: fdr-cli <version|classes|lifecycle|limits|host-evidence|synthetic [SEED]|"
        "inspect PATH|dump PATH>\n",
        stderr);
    return 2;
  }
  const std::string command = argv[1];
  if (command == "version") {
    return command_version();
  }
  if (command == "classes") {
    return command_classes();
  }
  if (command == "lifecycle") {
    return command_lifecycle();
  }
  if (command == "limits") {
    return command_limits();
  }
  if (command == "host-evidence") {
    return command_host_evidence();
  }
  if (command == "synthetic") {
    return command_synthetic(argc >= 3 ? argv[2] : nullptr);
  }
  if (command == "inspect" && argc >= 3) {
    return command_inspect(argv[2]);
  }
  if (command == "dump" && argc >= 3) {
    return command_dump(argv[2]);
  }
  std::fprintf(stderr, "fdr-cli: unknown or incomplete command '%s'\n", command.c_str());
  return 2;
}
