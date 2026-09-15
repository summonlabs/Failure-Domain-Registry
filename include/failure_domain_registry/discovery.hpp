// Failure Domain Registry — REAL host-visible evidence.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The only physical facts this runtime can obtain without an operator CMDB are
// the ones the local operating system exposes about its own devices. On Windows
// that is the Plug and Play device tree: device instance paths, their
// parent/child relationships and the device instance containers that group the
// functions of one physical device.
//
// That evidence is REAL and is labelled REAL. It is also narrow: a container
// proves that a set of device nodes are functions of one device. It does not
// prove rack, row, pod, PDU, power feed, cooling, conduit, optical, carrier or
// site classification, and this runtime never claims that it does. Those are
// reported as UNSUPPORTED.

#ifndef FAILURE_DOMAIN_REGISTRY_DISCOVERY_HPP
#define FAILURE_DOMAIN_REGISTRY_DISCOVERY_HPP

#include <cstddef>
#include <string>
#include <vector>

#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/provenance.hpp"

namespace failure_domain_registry {

enum class HostEvidenceKind : std::uint8_t {
  Unknown = 0,
  /// A device instance container: the functions of one physical device.
  DeviceInstanceContainer = 1,
  /// A device instance path with its parent instance path.
  DeviceInstance = 2,
  /// A network interface and the device it belongs to.
  NetworkInterface = 3,
  /// A PCI bus/controller node.
  PciController = 4,
};

FDR_API std::string_view to_string(HostEvidenceKind value) noexcept;

/// One REAL host-visible fact.
struct HostEvidence {
  HostEvidenceKind kind{HostEvidenceKind::Unknown};
  /// Device instance path, container id or interface name as the OS reports it.
  std::string instance_id;
  std::string parent_instance_id;
  std::string container_id;
  std::string description;
  /// Always Real for this structure: it is read from the host, not generated.
  TruthClass truth{TruthClass::Real};
  friend bool operator==(const HostEvidence&, const HostEvidence&) = default;
};

/// The result of one host discovery pass.
struct HostDiscoveryReport {
  std::string platform;
  std::vector<HostEvidence> evidence;
  /// Number of distinct device instance containers found.
  std::size_t containers{0};
  std::size_t devices{0};
  std::size_t interfaces{0};
  /// True when the platform cannot be enumerated in this build.
  bool unsupported{false};
  /// Why enumeration was unavailable, when it was.
  std::string unsupported_reason;
  /// Classifications this runtime cannot prove in this environment, stated
  /// explicitly so that nothing downstream mistakes silence for completeness.
  std::vector<std::string> unsupported_classifications;

  std::string render() const;
};

/// Enumerates the local host. Never throws; failures are reported in the
/// returned report.
FDR_API HostDiscoveryReport discover_host_evidence();

/// The physical classification classes that host-local discovery cannot prove
/// on any platform, rendered once so that the CLI, the README and the tests
/// agree.
FDR_API const std::vector<std::string>& unsupported_physical_classifications();

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_DISCOVERY_HPP
