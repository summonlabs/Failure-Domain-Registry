// Failure Domain Registry - REAL host-visible evidence.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// This translation unit reports only what the local operating system actually
// exposes about its own devices. On Windows that is the Plug and Play device
// tree: device instance paths, parent relationships and device instance
// containers. Everything else this runtime could classify about physical
// infrastructure is reported as UNSUPPORTED rather than approximated.

#include "failure_domain_registry/discovery.hpp"

#include <algorithm>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <cfgmgr32.h>
#include <devpkey.h>
#include <objbase.h>
#include <setupapi.h>
#endif

namespace failure_domain_registry {
namespace {

const std::vector<std::string>& unsupported_classifications_storage() {
  static const std::vector<std::string> values = {
      "rack",          "row",           "pod",         "building",
      "power-feed",    "power-bus",     "pdu",         "ups",
      "generator",     "cooling-zone",  "conduit",     "cable",
      "optical-component", "transceiver-group", "wan-circuit", "network-provider",
      "site",          "fabric",        "line-card",   "asic",
      "port-group",    "chassis",       "firmware-group", "software-control-group",
      "control-plane", "administrative", "device",      "link"};
  return values;
}

#ifdef _WIN32
/// {8C7ED206-3F8A-4827-B3AB-AE9E1FAEFC6C}, property 2 - the documented
/// DEVPKEY_Device_ContainerId. It is spelled out here so the translation unit
/// does not depend on which SDK headers declare the named symbol.
constexpr DEVPROPKEY kDeviceContainerIdKey = {
    {0x8c7ed206, 0x3f8a, 0x4827, {0xb3, 0xab, 0xae, 0x9e, 0x1f, 0xae, 0xfc, 0x6c}}, 2};

std::string to_utf8(const wchar_t* text) {
  if (text == nullptr || *text == L'\0') {
    return std::string();
  }
  const int needed = ::WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
  if (needed <= 1) {
    return std::string();
  }
  std::string out(static_cast<std::size_t>(needed - 1), '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), needed, nullptr, nullptr);
  return out;
}

std::string registry_property_string(HDEVINFO set, SP_DEVINFO_DATA& info, DWORD property) {
  DWORD type = 0;
  DWORD needed = 0;
  ::SetupDiGetDeviceRegistryPropertyW(set, &info, property, &type, nullptr, 0, &needed);
  if (needed == 0 || needed > 65536) {
    return std::string();
  }
  std::vector<wchar_t> buffer(needed / sizeof(wchar_t) + 1, L'\0');
  if (::SetupDiGetDeviceRegistryPropertyW(set, &info, property, &type,
                                          reinterpret_cast<PBYTE>(buffer.data()), needed,
                                          nullptr) == FALSE) {
    return std::string();
  }
  return to_utf8(buffer.data());
}

/// The device instance container groups the functions of one physical device.
/// It is read from the Plug and Play property store, not inferred.
std::string container_id_of(HDEVINFO set, SP_DEVINFO_DATA& info) {
  DEVPROPTYPE type = 0;
  GUID container{};
  DWORD needed = 0;
  if (::SetupDiGetDevicePropertyW(set, &info, &kDeviceContainerIdKey, &type,
                                  reinterpret_cast<PBYTE>(&container), sizeof(container), &needed,
                                  0) == FALSE) {
    return std::string();
  }
  if (type != DEVPROP_TYPE_GUID || needed != sizeof(GUID)) {
    return std::string();
  }
  wchar_t text[64] = {};
  if (::StringFromGUID2(container, text, 64) == 0) {
    return std::string();
  }
  return to_utf8(text);
}

/// The parent device instance path, read from the Plug and Play device tree.
std::string parent_instance_of(SP_DEVINFO_DATA& info) {
  DEVINST parent = 0;
  if (::CM_Get_Parent(&parent, info.DevInst, 0) != CR_SUCCESS) {
    return std::string();
  }
  wchar_t buffer[MAX_DEVICE_ID_LEN] = {};
  if (::CM_Get_Device_IDW(parent, buffer, MAX_DEVICE_ID_LEN, 0) != CR_SUCCESS) {
    return std::string();
  }
  return to_utf8(buffer);
}
#endif

} // namespace

std::string_view to_string(HostEvidenceKind value) noexcept {
  switch (value) {
    case HostEvidenceKind::DeviceInstanceContainer: return "device-instance-container";
    case HostEvidenceKind::DeviceInstance: return "device-instance";
    case HostEvidenceKind::NetworkInterface: return "network-interface";
    case HostEvidenceKind::PciController: return "pci-controller";
    default: return "unknown";
  }
}

const std::vector<std::string>& unsupported_physical_classifications() {
  return unsupported_classifications_storage();
}

HostDiscoveryReport discover_host_evidence() {
  HostDiscoveryReport report;
  report.unsupported_classifications = unsupported_classifications_storage();
#ifdef _WIN32
  report.platform = "windows";
  HDEVINFO set = ::SetupDiGetClassDevsW(nullptr, nullptr, nullptr,
                                        DIGCF_ALLCLASSES | DIGCF_PRESENT);
  if (set == INVALID_HANDLE_VALUE) {
    report.unsupported = true;
    report.unsupported_reason = "the Plug and Play device set could not be enumerated";
    return report;
  }
  std::vector<std::string> containers;
  SP_DEVINFO_DATA info{};
  info.cbSize = sizeof(SP_DEVINFO_DATA);
  for (DWORD index = 0; ::SetupDiEnumDeviceInfo(set, index, &info) != FALSE; ++index) {
    wchar_t instance[4096] = {};
    if (::SetupDiGetDeviceInstanceIdW(set, &info, instance,
                                      static_cast<DWORD>(sizeof(instance) / sizeof(wchar_t)),
                                      nullptr) == FALSE) {
      continue;
    }
    const std::string instance_id = to_utf8(instance);
    if (instance_id.empty()) {
      continue;
    }
    HostEvidence record;
    record.kind = HostEvidenceKind::DeviceInstance;
    record.instance_id = instance_id;
    record.parent_instance_id = parent_instance_of(info);
    record.container_id = container_id_of(set, info);
    record.description = registry_property_string(set, info, SPDRP_FRIENDLYNAME);
    if (record.description.empty()) {
      record.description = registry_property_string(set, info, SPDRP_DEVICEDESC);
    }
    if (!record.container_id.empty() &&
        std::find(containers.begin(), containers.end(), record.container_id) == containers.end()) {
      containers.push_back(record.container_id);
      HostEvidence container;
      container.kind = HostEvidenceKind::DeviceInstanceContainer;
      container.instance_id = record.container_id;
      report.evidence.push_back(std::move(container));
    }
    report.evidence.push_back(std::move(record));
    ++report.devices;
  }
  ::SetupDiDestroyDeviceInfoList(set);
  report.containers = containers.size();
  if (report.evidence.empty()) {
    report.unsupported = true;
    report.unsupported_reason = "no present Plug and Play device was reported";
  }
#else
  report.platform = "portable";
  report.unsupported = true;
  report.unsupported_reason =
      "this build has no host device enumeration for the current platform";
#endif
  return report;
}

std::string HostDiscoveryReport::render() const {
  std::string out = "host-discovery\n";
  out.append("  platform         = ");
  out.append(platform);
  out.append("\n  truth            = REAL (read from the host)\n");
  out.append("  containers       = ");
  out.append(std::to_string(containers));
  out.append("\n  devices          = ");
  out.append(std::to_string(devices));
  out.append("\n  interfaces       = ");
  out.append(std::to_string(interfaces));
  if (unsupported) {
    out.append("\n  unavailable      = ");
    out.append(unsupported_reason);
  }
  out.append("\n  evidence:");
  for (const HostEvidence& record : evidence) {
    out.append("\n    ");
    out.append(failure_domain_registry::to_string(record.kind));
    out.append(" ");
    out.append(record.instance_id);
    if (!record.parent_instance_id.empty()) {
      out.append(" parent=");
      out.append(record.parent_instance_id);
    }
    if (!record.description.empty()) {
      out.append(" desc=");
      out.append(record.description);
    }
  }
  out.append("\n  unsupported physical classifications (not proven here):");
  for (const std::string& name : unsupported_classifications) {
    out.append("\n    ");
    out.append(name);
  }
  return out;
}

} // namespace failure_domain_registry
