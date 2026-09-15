// Failure Domain Registry — domain class taxonomy.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/domain_class.hpp"

#include <array>

namespace failure_domain_registry {
namespace {

struct ClassName {
  DomainClass value;
  std::string_view name;
};

constexpr ClassName kClassNames[] = {
    {DomainClass::Device, "device"},
    {DomainClass::Chassis, "chassis"},
    {DomainClass::LineCard, "line-card"},
    {DomainClass::Asic, "asic"},
    {DomainClass::PortGroup, "port-group"},
    {DomainClass::Link, "link"},
    {DomainClass::Cable, "cable"},
    {DomainClass::Conduit, "conduit"},
    {DomainClass::TransceiverGroup, "transceiver-group"},
    {DomainClass::OpticalComponent, "optical-component"},
    {DomainClass::Rack, "rack"},
    {DomainClass::Row, "row"},
    {DomainClass::Pod, "pod"},
    {DomainClass::Fabric, "fabric"},
    {DomainClass::Site, "site"},
    {DomainClass::Building, "building"},
    {DomainClass::PowerFeed, "power-feed"},
    {DomainClass::PowerBus, "power-bus"},
    {DomainClass::Pdu, "pdu"},
    {DomainClass::Ups, "ups"},
    {DomainClass::Generator, "generator"},
    {DomainClass::CoolingZone, "cooling-zone"},
    {DomainClass::NetworkProvider, "network-provider"},
    {DomainClass::WanCircuit, "wan-circuit"},
    {DomainClass::ControlPlane, "control-plane"},
    {DomainClass::FirmwareGroup, "firmware-group"},
    {DomainClass::SoftwareControlGroup, "software-control-group"},
    {DomainClass::Administrative, "administrative"},
    {DomainClass::Custom, "custom"},
};

constexpr std::string_view kNamespaceVendor = "vendor";
constexpr std::string_view kNamespaceAdmin = "admin";

bool is_extension_char(char c) noexcept {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

bool is_valid_segment(std::string_view text, std::size_t max_bytes) noexcept {
  if (text.empty() || text.size() > max_bytes) {
    return false;
  }
  bool has_non_dot = false;
  for (char c : text) {
    if (!is_extension_char(c)) {
      return false;
    }
    if (c != '.') {
      has_non_dot = true;
    }
  }
  // "." and ".." are path components, not namespace or name components, and a
  // segment made only of dots is never a meaningful extension.
  return has_non_dot;
}

} // namespace

std::string_view to_string(DomainClass value) noexcept {
  for (const ClassName& entry : kClassNames) {
    if (entry.value == value) {
      return entry.name;
    }
  }
  return "unknown";
}

std::optional<DomainClass> domain_class_from_string(std::string_view text) noexcept {
  for (const ClassName& entry : kClassNames) {
    if (entry.name == text) {
      return entry.value;
    }
  }
  return std::nullopt;
}

bool is_valid_domain_class(DomainClass value) noexcept {
  return value != DomainClass::Unknown && static_cast<std::uint8_t>(value) <= kDomainClassCount;
}

bool is_exclusive_class(DomainClass value) noexcept {
  switch (value) {
    case DomainClass::Chassis:
    case DomainClass::LineCard:
    case DomainClass::Asic:
    case DomainClass::PortGroup:
    case DomainClass::Rack:
    case DomainClass::Row:
    case DomainClass::Pod:
    case DomainClass::Building:
    case DomainClass::Site:
    case DomainClass::Fabric:
      return true;
    default:
      return false;
  }
}

bool is_containment_class(DomainClass value) noexcept {
  switch (value) {
    case DomainClass::Chassis:
    case DomainClass::LineCard:
    case DomainClass::Asic:
    case DomainClass::PortGroup:
    case DomainClass::Rack:
    case DomainClass::Row:
    case DomainClass::Pod:
    case DomainClass::Building:
    case DomainClass::Site:
    case DomainClass::Fabric:
    case DomainClass::Conduit:
    case DomainClass::PowerBus:
    case DomainClass::PowerFeed:
    case DomainClass::Pdu:
    case DomainClass::Ups:
    case DomainClass::CoolingZone:
      return true;
    default:
      return false;
  }
}

std::optional<DomainClassRef> DomainClassRef::parse(std::string_view text) noexcept {
  if (text.empty()) {
    return std::nullopt;
  }
  const std::size_t colon = text.find(':');
  if (colon == std::string_view::npos) {
    const std::optional<DomainClass> klass = domain_class_from_string(text);
    if (!klass.has_value()) {
      return std::nullopt;
    }
    return DomainClassRef(*klass);
  }

  const std::string_view namespace_kind = text.substr(0, colon);
  if (namespace_kind != kNamespaceVendor && namespace_kind != kNamespaceAdmin) {
    return std::nullopt;
  }
  const std::string_view rest = text.substr(colon + 1);
  const std::size_t slash = rest.find('/');
  if (slash == std::string_view::npos) {
    return std::nullopt;
  }
  return DomainClassRef::extension(namespace_kind, rest.substr(0, slash), rest.substr(slash + 1));
}

std::optional<DomainClassRef> DomainClassRef::extension(std::string_view namespace_kind,
                                                        std::string_view ns,
                                                        std::string_view name) noexcept {
  if (namespace_kind != kNamespaceVendor && namespace_kind != kNamespaceAdmin) {
    return std::nullopt;
  }
  if (!is_valid_segment(ns, max_namespace_bytes) || !is_valid_segment(name, max_name_bytes)) {
    return std::nullopt;
  }
  DomainClassRef result;
  result.canonical_ = DomainClass::Unknown;
  result.extension_.assign(namespace_kind);
  result.extension_.push_back(':');
  result.extension_.append(ns);
  result.extension_.push_back('/');
  result.extension_.append(name);
  return result;
}

std::string DomainClassRef::to_string() const {
  if (is_canonical()) {
    return std::string(failure_domain_registry::to_string(canonical_));
  }
  if (!extension_.empty()) {
    return extension_;
  }
  return "unknown";
}

} // namespace failure_domain_registry
