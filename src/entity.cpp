// Failure Domain Registry — entity identity codec.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/entity.hpp"

#include <array>

namespace failure_domain_registry {
namespace {

struct EntityClassName {
  EntityClass value;
  std::string_view name;
};

constexpr EntityClassName kEntityClassNames[] = {
    {EntityClass::Fabric, "fabric"},
    {EntityClass::Site, "site"},
    {EntityClass::ControlDomain, "control-domain"},
    {EntityClass::Switch, "switch"},
    {EntityClass::Router, "router"},
    {EntityClass::Nic, "nic"},
    {EntityClass::SmartNic, "smartnic"},
    {EntityClass::Dpu, "dpu"},
    {EntityClass::Host, "host"},
    {EntityClass::Port, "port"},
    {EntityClass::Link, "link"},
    {EntityClass::Endpoint, "endpoint"},
    {EntityClass::ControlParticipant, "control-participant"},
    {EntityClass::VendorDevice, "vendor-device"},
    {EntityClass::SubFabric, "sub-fabric"},
};

} // namespace

std::string_view to_string(EntityClass value) noexcept {
  for (const EntityClassName& entry : kEntityClassNames) {
    if (entry.value == value) {
      return entry.name;
    }
  }
  return "unknown";
}

std::optional<EntityClass> entity_class_from_string(std::string_view text) noexcept {
  for (const EntityClassName& entry : kEntityClassNames) {
    if (entry.name == text) {
      return entry.value;
    }
  }
  return std::nullopt;
}

bool is_valid_entity_class(EntityClass value) noexcept {
  return value != EntityClass::Unknown &&
         static_cast<std::uint8_t>(value) <= kEntityClassCount;
}

bool is_device_class(EntityClass value) noexcept {
  switch (value) {
    case EntityClass::Switch:
    case EntityClass::Router:
    case EntityClass::Nic:
    case EntityClass::SmartNic:
    case EntityClass::Dpu:
    case EntityClass::Host:
    case EntityClass::VendorDevice:
      return true;
    default:
      return false;
  }
}

bool is_administrative_scope_class(EntityClass value) noexcept {
  switch (value) {
    case EntityClass::Fabric:
    case EntityClass::Site:
    case EntityClass::ControlDomain:
    case EntityClass::SubFabric:
      return true;
    default:
      return false;
  }
}

std::optional<EntityId> EntityId::parse(std::string_view entity_class, std::string_view hex) noexcept {
  const std::optional<EntityClass> klass = entity_class_from_string(entity_class);
  if (!klass.has_value()) {
    return std::nullopt;
  }
  if (hex.size() != kOpaqueIdTextLength) {
    return std::nullopt;
  }
  IdBytes bytes{};
  if (!parse_hex(hex.data(), hex.size(), bytes.data())) {
    return std::nullopt;
  }
  return EntityId(*klass, bytes);
}

std::optional<EntityId> EntityId::parse(std::string_view text) noexcept {
  const std::size_t colon = text.find(':');
  if (colon == std::string_view::npos) {
    return std::nullopt;
  }
  return EntityId::parse(text.substr(0, colon), text.substr(colon + 1));
}

std::string EntityId::to_string() const {
  if (is_null()) {
    return "null";
  }
  std::string out(failure_domain_registry::to_string(entity_class_));
  out.push_back(':');
  const std::size_t offset = out.size();
  out.resize(offset + kOpaqueIdTextLength);
  render_hex(bytes_.data(), bytes_.size(), out.data() + offset);
  return out;
}

std::optional<EntityRef> EntityRef::parse(std::string_view text) noexcept {
  const std::size_t at = text.rfind('@');
  if (at == std::string_view::npos || at + 1 >= text.size()) {
    return std::nullopt;
  }
  const std::optional<EntityGeneration> generation =
      EntityGeneration::parse(text.substr(at + 1));
  if (!generation.has_value() || generation->is_zero()) {
    return std::nullopt;
  }
  const std::optional<EntityId> id = EntityId::parse(text.substr(0, at));
  if (!id.has_value() || id->is_null()) {
    return std::nullopt;
  }
  return EntityRef(*id, *generation);
}

std::optional<EntityRef> EntityRef::parse(std::string_view text,
                                          EntityGeneration generation) noexcept {
  if (generation.is_zero()) {
    return std::nullopt;
  }
  const std::optional<EntityId> id = EntityId::parse(text);
  if (!id.has_value() || id->is_null()) {
    return std::nullopt;
  }
  return EntityRef(*id, generation);
}

std::string EntityRef::to_string() const {
  if (is_null()) {
    return "null";
  }
  std::string out = id_.to_string();
  out.push_back('@');
  out.append(generation_.to_string());
  return out;
}

} // namespace failure_domain_registry
