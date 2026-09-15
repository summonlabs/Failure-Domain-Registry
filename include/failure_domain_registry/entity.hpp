// Failure Domain Registry — canonical entity references.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Failure Domain Registry does not own canonical infrastructure identity: that
// belongs to Fabric Registry. This header declares the exact representation
// this runtime stores for a Fabric Registry canonical identity, so that a
// membership can bind an entity class, an entity id and - where the distinction
// matters - the exact entity generation the membership was established against.
//
// EntityClass enumerator values are byte-identical to the Fabric Registry
// entity taxonomy; they are part of the persisted format and the wire protocol
// and must never be renumbered.

#ifndef FAILURE_DOMAIN_REGISTRY_ENTITY_HPP
#define FAILURE_DOMAIN_REGISTRY_ENTITY_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"

namespace failure_domain_registry {

/// Classes of infrastructure entity that may be a failure-domain member.
enum class EntityClass : std::uint8_t {
  /// Sentinel meaning "no class". Never valid in a request or a record.
  Unknown = 0,
  Fabric = 1,
  Site = 2,
  ControlDomain = 3,
  Switch = 4,
  Router = 5,
  Nic = 6,
  SmartNic = 7,
  Dpu = 8,
  Host = 9,
  Port = 10,
  Link = 11,
  Endpoint = 12,
  ControlParticipant = 13,
  VendorDevice = 14,
  SubFabric = 15,
};

/// Number of enumerators in EntityClass that denote a real class.
inline constexpr std::uint8_t kEntityClassCount = 15;

FDR_API std::string_view to_string(EntityClass value) noexcept;
FDR_API std::optional<EntityClass> entity_class_from_string(std::string_view text) noexcept;

/// True when the class denotes a device-bearing element.
FDR_API bool is_device_class(EntityClass value) noexcept;
/// True when the class denotes an administrative scope rather than a physical
/// element.
FDR_API bool is_administrative_scope_class(EntityClass value) noexcept;
FDR_API bool is_valid_entity_class(EntityClass value) noexcept;

/// A canonical identity without a generation: the exact pair Fabric Registry
/// calls a canonical id. Used for presence queries and as an index key.
class FDR_API EntityId {
public:
  constexpr EntityId() noexcept = default;
  constexpr EntityId(EntityClass entity_class, const IdBytes& value) noexcept
      : entity_class_(entity_class), bytes_(value) {}

  /// Builds an entity id from a 32-character hexadecimal rendering and a class.
  static std::optional<EntityId> parse(std::string_view entity_class, std::string_view hex) noexcept;

  /// Parses "switch:00112233445566778899aabbccddeeff".
  static std::optional<EntityId> parse(std::string_view text) noexcept;

  constexpr EntityClass entity_class() const noexcept { return entity_class_; }
  constexpr const IdBytes& bytes() const noexcept { return bytes_; }

  constexpr bool is_null() const noexcept {
    if (entity_class_ == EntityClass::Unknown) {
      return true;
    }
    for (std::size_t i = 0; i < kOpaqueIdBytes; ++i) {
      if (bytes_[i] != 0) {
        return false;
      }
    }
    return true;
  }

  /// Renders as "<class>:<32 hex>".
  std::string to_string() const;

  friend constexpr bool operator==(const EntityId&, const EntityId&) noexcept = default;
  friend constexpr auto operator<=>(const EntityId&, const EntityId&) noexcept = default;

private:
  EntityClass entity_class_{EntityClass::Unknown};
  IdBytes bytes_{};
};

/// A canonical identity bound to one entity generation.
class FDR_API EntityRef {
public:
  constexpr EntityRef() noexcept = default;
  constexpr EntityRef(EntityId id, EntityGeneration generation) noexcept
      : id_(id), generation_(generation) {}
  constexpr EntityRef(EntityClass entity_class, const IdBytes& value, EntityGeneration generation) noexcept
      : id_(entity_class, value), generation_(generation) {}

  /// Parses "<class>:<32 hex>@<generation>". The generation is mandatory here:
  /// a membership binds an exact entity generation.
  static std::optional<EntityRef> parse(std::string_view text) noexcept;

  /// Parses a generation-free entity id and applies an explicit generation.
  static std::optional<EntityRef> parse(std::string_view text, EntityGeneration generation) noexcept;

  constexpr const EntityId& id() const noexcept { return id_; }
  constexpr EntityClass entity_class() const noexcept { return id_.entity_class(); }
  constexpr const IdBytes& bytes() const noexcept { return id_.bytes(); }
  constexpr EntityGeneration generation() const noexcept { return generation_; }
  constexpr bool is_null() const noexcept { return id_.is_null() || generation_.is_zero(); }

  std::string to_string() const;

  friend constexpr bool operator==(const EntityRef&, const EntityRef&) noexcept = default;
  friend constexpr auto operator<=>(const EntityRef&, const EntityRef&) noexcept = default;

private:
  EntityId id_{};
  EntityGeneration generation_{};
};

} // namespace failure_domain_registry

namespace std {

template <>
struct hash<failure_domain_registry::EntityId> {
  std::size_t operator()(const failure_domain_registry::EntityId& value) const noexcept {
    std::size_t accumulator = std::hash<std::uint8_t>{}(static_cast<std::uint8_t>(value.entity_class()));
    for (std::uint8_t byte : value.bytes()) {
      accumulator ^= static_cast<std::size_t>(byte);
      accumulator *= 1099511628211ull;
    }
    return accumulator;
  }
};

template <>
struct hash<failure_domain_registry::EntityRef> {
  std::size_t operator()(const failure_domain_registry::EntityRef& value) const noexcept {
    std::size_t accumulator = std::hash<failure_domain_registry::EntityId>{}(value.id());
    accumulator ^= std::hash<std::uint64_t>{}(value.generation().value());
    accumulator *= 1099511628211ull;
    return accumulator;
  }
};

} // namespace std

#endif // FAILURE_DOMAIN_REGISTRY_ENTITY_HPP
