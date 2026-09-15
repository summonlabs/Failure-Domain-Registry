// Failure Domain Registry — canonical failure-domain classes.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A domain class states what kind of common factor a failure domain
// represents. There is no free-form "type" string: a classification is either
// one of the canonical classes below or it lives in an explicit vendor or
// administrative extension namespace with its own bounded name.
//
// The enumerator values are part of the persisted format and the wire protocol
// and must never be renumbered. New classes are appended.

#ifndef FAILURE_DOMAIN_REGISTRY_DOMAIN_CLASS_HPP
#define FAILURE_DOMAIN_REGISTRY_DOMAIN_CLASS_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "failure_domain_registry/export.hpp"

namespace failure_domain_registry {

enum class DomainClass : std::uint8_t {
  Unknown = 0,
  /// A device-level common factor (one physical device failing as a unit).
  Device = 1,
  Chassis = 2,
  LineCard = 3,
  Asic = 4,
  PortGroup = 5,
  Link = 6,
  Cable = 7,
  Conduit = 8,
  TransceiverGroup = 9,
  OpticalComponent = 10,
  Rack = 11,
  Row = 12,
  Pod = 13,
  Fabric = 14,
  Site = 15,
  Building = 16,
  PowerFeed = 17,
  PowerBus = 18,
  Pdu = 19,
  Ups = 20,
  Generator = 21,
  CoolingZone = 22,
  NetworkProvider = 23,
  WanCircuit = 24,
  ControlPlane = 25,
  FirmwareGroup = 26,
  SoftwareControlGroup = 27,
  Administrative = 28,
  Custom = 29,
};

/// Number of canonical classes, excluding Unknown.
inline constexpr std::uint8_t kDomainClassCount = 29;

FDR_API std::string_view to_string(DomainClass value) noexcept;
FDR_API std::optional<DomainClass> domain_class_from_string(std::string_view text) noexcept;

/// True for the canonical classes. Returns false for Unknown and for anything
/// outside the enumeration, which the decoder can never produce.
FDR_API bool is_valid_domain_class(DomainClass value) noexcept;

/// True when a member may belong to at most one *current* domain of this class.
///
/// Exclusivity is a typed property of the class, never a global rule. It holds
/// for classes that describe a single physical position or a single containing
/// element: an entity occupies one rack, one row, one pod, one site, one
/// building, one chassis, one line-card slot, one ASIC, one port group. It does
/// not hold for power, cooling, conduit, carrier or control-plane classes,
/// where multiple simultaneous membership is the normal, correct case.
FDR_API bool is_exclusive_class(DomainClass value) noexcept;

/// True when a domain of the class is expected to be an element of the
/// containment hierarchy and may therefore carry CONTAINED_BY relations.
FDR_API bool is_containment_class(DomainClass value) noexcept;

/// A canonical class or an explicit extension class.
///
/// "vendor:<namespace>/<name>" and "admin:<namespace>/<name>" are the only
/// accepted extension forms. Both components are bounded, restricted to
/// [a-z0-9._-] and must be non-empty, so an extension can never be used to
/// smuggle an arbitrary string into the classification space.
class FDR_API DomainClassRef {
public:
  static constexpr std::size_t max_namespace_bytes = 64;
  static constexpr std::size_t max_name_bytes = 96;

  constexpr DomainClassRef() noexcept = default;
  constexpr explicit DomainClassRef(DomainClass value) noexcept : canonical_(value) {}

  static std::optional<DomainClassRef> parse(std::string_view text) noexcept;
  static std::optional<DomainClassRef> extension(std::string_view namespace_kind,
                                                 std::string_view ns,
                                                 std::string_view name) noexcept;

  constexpr bool is_canonical() const noexcept { return canonical_ != DomainClass::Unknown; }
  constexpr DomainClass canonical() const noexcept { return canonical_; }
  constexpr bool is_extension() const noexcept { return !extension_.empty(); }
  const std::string& extension() const noexcept { return extension_; }

  /// Extension namespaces are never exclusive: this runtime cannot prove the
  /// physical semantics of a vendor-defined class.
  constexpr bool is_exclusive() const noexcept {
    return is_canonical() && is_exclusive_class(canonical_);
  }

  /// The canonical class when there is one, otherwise Custom. Extension
  /// semantics are carried by extension().
  constexpr DomainClass classification() const noexcept {
    return is_canonical() ? canonical_ : DomainClass::Custom;
  }

  std::string to_string() const;

  friend bool operator==(const DomainClassRef&, const DomainClassRef&) noexcept = default;
  friend auto operator<=>(const DomainClassRef&, const DomainClassRef&) noexcept = default;

private:
  DomainClass canonical_{DomainClass::Unknown};
  std::string extension_;
};

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_DOMAIN_CLASS_HPP
