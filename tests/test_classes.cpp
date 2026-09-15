// Failure Domain Registry — domain class, entity and provenance taxonomy proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The classifications this runtime stores are part of the persisted format and the wire
// protocol: a class either has a stable name and a fixed set of typed properties, or it is
// rejected. Every enumerator is enumerated here, the exact name of each one is pinned, and
// the boolean properties of the taxonomy are compared against an expectation table written
// out in full in this file, so a taxonomy change cannot pass unnoticed.
//
// Where the header prose and the implementation disagree, the implemented behaviour is
// asserted and the disagreement is named in the comment above the assertion instead of being
// smoothed over.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>

#include "failure_domain_registry/domain_class.hpp"
#include "failure_domain_registry/entity.hpp"
#include "failure_domain_registry/provenance.hpp"
#include "support/test_harness.hpp"

namespace {

using failure_domain_registry::DomainClass;
using failure_domain_registry::DomainClassRef;
using failure_domain_registry::EntityClass;
using failure_domain_registry::EvidenceClass;
using failure_domain_registry::IdBytes;
using failure_domain_registry::kDomainClassCount;
using failure_domain_registry::kEntityClassCount;
using failure_domain_registry::Provenance;
using failure_domain_registry::ProvenanceSource;
using failure_domain_registry::PublisherId;
using failure_domain_registry::TruthClass;
using failure_domain_registry::WorkerBootId;

/// Number of enumerators that denote a real provenance source, evidence class
/// and truth class, derived from the enumerations themselves.
constexpr std::uint8_t kProvenanceSourceCount =
    static_cast<std::uint8_t>(ProvenanceSource::AdministrativeDeclaration);
constexpr std::uint8_t kEvidenceClassCount = static_cast<std::uint8_t>(EvidenceClass::Synthetic);
/// Number of enumerators of EvidenceClass including the Unknown sentinel. The
/// property tables are indexed by the enumerator, not by the rank, so they are
/// one slot longer than the count of valid classes.
constexpr std::uint8_t kEvidenceClassValues =
    static_cast<std::uint8_t>(static_cast<std::uint8_t>(EvidenceClass::Synthetic) + 1u);
constexpr std::uint8_t kTruthClassCount = static_cast<std::uint8_t>(TruthClass::Unsupported);

/// The stable wire names of every canonical domain class, in enumerator order.
/// The first entry is Device (1), the last is Custom (29).
constexpr std::string_view kDomainClassNames[kDomainClassCount] = {
    "device", "chassis", "line-card", "asic", "port-group", "link", "cable", "conduit",
    "transceiver-group", "optical-component", "rack", "row", "pod", "fabric", "site",
    "building", "power-feed", "power-bus", "pdu", "ups", "generator", "cooling-zone",
    "network-provider", "wan-circuit", "control-plane", "firmware-group",
    "software-control-group", "administrative", "custom"};

/// The exact exclusivity answer of every canonical class, in enumerator order.
constexpr bool kExclusiveClasses[kDomainClassCount] = {
    /* device */ false,
    /* chassis */ true,
    /* line-card */ true,
    /* asic */ true,
    /* port-group */ true,
    /* link */ false,
    /* cable */ false,
    /* conduit */ false,
    /* transceiver-group */ false,
    /* optical-component */ false,
    /* rack */ true,
    /* row */ true,
    /* pod */ true,
    /* fabric */ true,
    /* site */ true,
    /* building */ true,
    /* power-feed */ false,
    /* power-bus */ false,
    /* pdu */ false,
    /* ups */ false,
    /* generator */ false,
    /* cooling-zone */ false,
    /* network-provider */ false,
    /* wan-circuit */ false,
    /* control-plane */ false,
    /* firmware-group */ false,
    /* software-control-group */ false,
    /* administrative */ false,
    /* custom */ false};

/// The exact containment answer of every canonical class, in enumerator order.
constexpr bool kContainmentClasses[kDomainClassCount] = {
    /* device */ false,
    /* chassis */ true,
    /* line-card */ true,
    /* asic */ true,
    /* port-group */ true,
    /* link */ false,
    /* cable */ false,
    /* conduit */ true,
    /* transceiver-group */ false,
    /* optical-component */ false,
    /* rack */ true,
    /* row */ true,
    /* pod */ true,
    /* fabric */ true,
    /* site */ true,
    /* building */ true,
    /* power-feed */ true,
    /* power-bus */ true,
    /* pdu */ true,
    /* ups */ true,
    /* generator */ false,
    /* cooling-zone */ true,
    /* network-provider */ false,
    /* wan-circuit */ false,
    /* control-plane */ false,
    /* firmware-group */ false,
    /* software-control-group */ false,
    /* administrative */ false,
    /* custom */ false};

/// The stable wire names of every entity class, in enumerator order. The first
/// entry is Fabric (1), the last is SubFabric (15).
constexpr std::string_view kEntityClassNames[kEntityClassCount] = {
    "fabric",   "site",     "control-domain", "switch",           "router",
    "nic",      "smartnic", "dpu",            "host",             "port",
    "link",     "endpoint", "control-participant", "vendor-device", "sub-fabric"};

/// The exact device-class answer of every entity class, in enumerator order.
constexpr bool kDeviceClasses[kEntityClassCount] = {
    /* fabric */ false,     /* site */ false,      /* control-domain */ false,
    /* switch */ true,      /* router */ true,     /* nic */ true,
    /* smartnic */ true,    /* dpu */ true,        /* host */ true,
    /* port */ false,       /* link */ false,      /* endpoint */ false,
    /* control-participant */ false, /* vendor-device */ true, /* sub-fabric */ false};

/// The exact administrative-scope answer of every entity class, in enumerator
/// order.
constexpr bool kAdministrativeScopeClasses[kEntityClassCount] = {
    /* fabric */ true,      /* site */ true,       /* control-domain */ true,
    /* switch */ false,     /* router */ false,    /* nic */ false,
    /* smartnic */ false,   /* dpu */ false,       /* host */ false,
    /* port */ false,       /* link */ false,      /* endpoint */ false,
    /* control-participant */ false, /* vendor-device */ false, /* sub-fabric */ true};

constexpr std::string_view kProvenanceSourceNames[kProvenanceSourceCount] = {
    "operator-inventory", "cmdb", "physical-infrastructure", "topology-derivation",
    "power-management", "cable-inventory", "vendor-controller", "discovery-agent",
    "imported-manifest", "synthetic-test-source", "derivation-rule",
    "administrative-declaration"};

constexpr std::string_view kEvidenceClassNames[kEvidenceClassCount] = {
    "direct-authoritative-infrastructure", "direct-hardware-controller",
    "administrative-declaration", "derived-topology", "imported-static-inventory",
    "inferred", "synthetic"};

/// Rank of every valid evidence class, in enumerator order. Rank 0 is reserved
/// for the absence of evidence, so the weakest real class is rank 1.
constexpr std::uint8_t kEvidenceRanks[kEvidenceClassCount] = {1, 2, 3, 4, 5, 6, 7};

constexpr bool kProcessBoundEvidence[kEvidenceClassValues] = {
    /* unknown */ false,
    /* direct-authoritative-infrastructure */ false,
    /* direct-hardware-controller */ true,
    /* administrative-declaration */ false,
    /* derived-topology */ true,
    /* imported-static-inventory */ false,
    /* inferred */ true,
    /* synthetic */ false};

constexpr bool kAuthoritativeEvidence[kEvidenceClassValues] = {
    /* unknown */ false,
    /* direct-authoritative-infrastructure */ true,
    /* direct-hardware-controller */ true,
    /* administrative-declaration */ true,
    /* derived-topology */ false,
    /* imported-static-inventory */ false,
    /* inferred */ false,
    /* synthetic */ false};

constexpr std::string_view kTruthClassNames[kTruthClassCount] = {"REAL", "SYNTHETIC", "UNSUPPORTED"};

/// A non-null, distinguishable identifier for the fixture of one case.
PublisherId publisher_from(std::uint8_t salt) {
  IdBytes bytes{};
  bytes[0] = 0xC1u;
  bytes[failure_domain_registry::kOpaqueIdBytes - 1u] = salt;
  return PublisherId::from_bytes(bytes);
}

WorkerBootId boot_from(std::uint8_t salt) {
  IdBytes bytes{};
  bytes[0] = 0xC2u;
  bytes[failure_domain_registry::kOpaqueIdBytes - 1u] = salt;
  return WorkerBootId::from_bytes(bytes);
}

FDR_TEST_CASE(classes, domain_class_names_are_complete_and_round_trip) {
  std::set<std::string_view> names;
  std::size_t valid_count = 0;
  for (std::uint8_t raw = 1; raw <= kDomainClassCount; ++raw) {
    const DomainClass value = static_cast<DomainClass>(raw);
    const std::string_view name = failure_domain_registry::to_string(value);
    const std::string label = "domain class " + std::to_string(raw);
    FDR_CHECK_MSG(!name.empty(), label + " has no name");
    FDR_CHECK_MSG(name != std::string_view("unknown"), label + " has no stable name");
    FDR_CHECK_EQ(name, kDomainClassNames[static_cast<std::size_t>(raw) - 1u]);
    FDR_CHECK(failure_domain_registry::is_valid_domain_class(value));

    const std::optional<DomainClass> parsed = failure_domain_registry::domain_class_from_string(name);
    FDR_CHECK(parsed.has_value());
    FDR_CHECK_EQ(*parsed, value);
    // Every canonical class renders exactly once.
    FDR_CHECK_MSG(names.insert(name).second, "duplicate domain class name: " + std::string(name));
    ++valid_count;
  }
  FDR_CHECK_EQ(valid_count, static_cast<std::size_t>(kDomainClassCount));
  FDR_CHECK_EQ(names.size(), static_cast<std::size_t>(kDomainClassCount));

  // Unknown is a sentinel, not a class: it has no valid status and no parseable
  // name, so a caller cannot ask for "the unknown class" by accident.
  FDR_CHECK(!failure_domain_registry::is_valid_domain_class(DomainClass::Unknown));
  FDR_CHECK_EQ(failure_domain_registry::to_string(DomainClass::Unknown), std::string_view("unknown"));
  FDR_CHECK(!failure_domain_registry::domain_class_from_string("unknown").has_value());
  FDR_CHECK(!failure_domain_registry::domain_class_from_string(std::string()).has_value());
  FDR_CHECK(!failure_domain_registry::domain_class_from_string("Rack").has_value());
  FDR_CHECK(!failure_domain_registry::domain_class_from_string("rack ").has_value());
  FDR_CHECK(!failure_domain_registry::domain_class_from_string(" rack").has_value());
  FDR_CHECK(!failure_domain_registry::domain_class_from_string("line_card").has_value());

  // Values past the enumeration are never valid and never named.
  for (std::uint16_t raw = static_cast<std::uint16_t>(kDomainClassCount) + 1u; raw <= 255u; ++raw) {
    const DomainClass value = static_cast<DomainClass>(raw);
    FDR_CHECK(!failure_domain_registry::is_valid_domain_class(value));
    FDR_CHECK_EQ(failure_domain_registry::to_string(value), std::string_view("unknown"));
  }
}

FDR_TEST_CASE(classes, domain_class_names_are_stable) {
  // A name is a constant, not a computed rendering: repeated calls agree, and
  // the value does not depend on any state.
  for (std::uint8_t raw = 1; raw <= kDomainClassCount; ++raw) {
    const DomainClass value = static_cast<DomainClass>(raw);
    const std::string_view first = failure_domain_registry::to_string(value);
    const std::string_view second = failure_domain_registry::to_string(value);
    FDR_CHECK_EQ(first, second);
    FDR_CHECK_EQ(std::string(first), std::string(kDomainClassNames[static_cast<std::size_t>(raw) - 1u]));
    // The classification is unchanged by a round trip.
    const std::optional<DomainClass> parsed = failure_domain_registry::domain_class_from_string(first);
    FDR_CHECK(parsed.has_value());
    FDR_CHECK_EQ(failure_domain_registry::to_string(*parsed), first);
  }
}

FDR_TEST_CASE(classes, is_exclusive_class_matches_the_implemented_set) {
  std::size_t exclusive_count = 0;
  for (std::uint8_t raw = 1; raw <= kDomainClassCount; ++raw) {
    const DomainClass value = static_cast<DomainClass>(raw);
    const std::size_t index = static_cast<std::size_t>(raw) - 1u;
    FDR_CHECK_EQ(failure_domain_registry::is_exclusive_class(value), kExclusiveClasses[index]);
    // Exclusivity is a typed property of a class, never a global rule: a class
    // that is exclusive is also a containment element.
    FDR_CHECK(!kExclusiveClasses[index] || kContainmentClasses[index]);
    if (kExclusiveClasses[index]) {
      ++exclusive_count;
    }
  }
  FDR_CHECK_EQ(exclusive_count, std::size_t{10});
  FDR_CHECK(!failure_domain_registry::is_exclusive_class(DomainClass::Unknown));
  FDR_CHECK(!failure_domain_registry::is_exclusive_class(static_cast<DomainClass>(200)));

  // What the header documents: an entity occupies exactly one rack, row, pod,
  // site, building, chassis, line-card slot, ASIC and port group.
  const DomainClass positional[] = {DomainClass::Rack,      DomainClass::Row,
                                    DomainClass::Pod,       DomainClass::Site,
                                    DomainClass::Building,  DomainClass::Chassis,
                                    DomainClass::LineCard,  DomainClass::Asic,
                                    DomainClass::PortGroup};
  for (DomainClass value : positional) {
    FDR_CHECK_MSG(failure_domain_registry::is_exclusive_class(value),
                 "positional class is not exclusive: " +
                     std::string(failure_domain_registry::to_string(value)));
  }

  // What the header documents as additive: power, cooling, conduit, carrier and
  // control-plane membership is the normal case for several simultaneous
  // domains, so none of these classes is exclusive.
  const DomainClass additive[] = {DomainClass::PowerFeed,
                                  DomainClass::PowerBus,
                                  DomainClass::Pdu,
                                  DomainClass::Ups,
                                  DomainClass::Generator,
                                  DomainClass::CoolingZone,
                                  DomainClass::Conduit,
                                  DomainClass::NetworkProvider,
                                  DomainClass::WanCircuit,
                                  DomainClass::ControlPlane,
                                  DomainClass::FirmwareGroup,
                                  DomainClass::SoftwareControlGroup,
                                  DomainClass::Administrative,
                                  DomainClass::Link,
                                  DomainClass::Cable,
                                  DomainClass::TransceiverGroup,
                                  DomainClass::OpticalComponent,
                                  DomainClass::Custom};
  for (DomainClass value : additive) {
    FDR_CHECK_MSG(!failure_domain_registry::is_exclusive_class(value),
                 "additive class is exclusive: " +
                     std::string(failure_domain_registry::to_string(value)));
  }

  // Device is not exclusive here: a device-level common factor is not a position
  // and not a container, so a member may belong to more than one device domain.
  FDR_CHECK(!failure_domain_registry::is_exclusive_class(DomainClass::Device));
  // Fabric is exclusive although the header prose names only the positional
  // classes above; a fabric is a single containing element, which is the rule
  // the prose states.
  FDR_CHECK(failure_domain_registry::is_exclusive_class(DomainClass::Fabric));
}

FDR_TEST_CASE(classes, is_containment_class_matches_the_implemented_set) {
  std::size_t containment_count = 0;
  for (std::uint8_t raw = 1; raw <= kDomainClassCount; ++raw) {
    const DomainClass value = static_cast<DomainClass>(raw);
    const std::size_t index = static_cast<std::size_t>(raw) - 1u;
    FDR_CHECK_EQ(failure_domain_registry::is_containment_class(value), kContainmentClasses[index]);
    if (kContainmentClasses[index]) {
      ++containment_count;
    }
  }
  FDR_CHECK_EQ(containment_count, std::size_t{16});
  FDR_CHECK(!failure_domain_registry::is_containment_class(DomainClass::Unknown));
  FDR_CHECK(!failure_domain_registry::is_containment_class(static_cast<DomainClass>(200)));

  // A containment class is one that may carry CONTAINED_BY relations; the
  // positional classes and the utility classes that are physically laid out
  // (conduit, power feed, bus, PDU, UPS, cooling zone) qualify.
  const DomainClass contained[] = {DomainClass::Chassis, DomainClass::LineCard,
                                   DomainClass::Asic,    DomainClass::PortGroup,
                                   DomainClass::Rack,    DomainClass::Row,
                                   DomainClass::Pod,     DomainClass::Fabric,
                                   DomainClass::Site,    DomainClass::Building,
                                   DomainClass::Conduit, DomainClass::PowerFeed,
                                   DomainClass::PowerBus, DomainClass::Pdu,
                                   DomainClass::Ups,     DomainClass::CoolingZone};
  for (DomainClass value : contained) {
    FDR_CHECK_MSG(failure_domain_registry::is_containment_class(value),
                 "containment class is not a containment class: " +
                     std::string(failure_domain_registry::to_string(value)));
  }
  const DomainClass not_contained[] = {DomainClass::Device, DomainClass::Link, DomainClass::Cable,
                                       DomainClass::TransceiverGroup, DomainClass::OpticalComponent,
                                       DomainClass::Generator, DomainClass::NetworkProvider,
                                       DomainClass::WanCircuit, DomainClass::ControlPlane,
                                       DomainClass::FirmwareGroup, DomainClass::SoftwareControlGroup,
                                       DomainClass::Administrative, DomainClass::Custom};
  for (DomainClass value : not_contained) {
    FDR_CHECK_MSG(!failure_domain_registry::is_containment_class(value),
                 "non-containment class is a containment class: " +
                     std::string(failure_domain_registry::to_string(value)));
  }
}

FDR_TEST_CASE(classes, domain_class_ref_has_a_canonical_form) {
  const DomainClassRef absent;
  FDR_CHECK(!absent.is_canonical());
  FDR_CHECK(!absent.is_extension());
  FDR_CHECK_EQ(absent.canonical(), DomainClass::Unknown);
  FDR_CHECK_EQ(absent.classification(), DomainClass::Custom);
  FDR_CHECK(!absent.is_exclusive());
  FDR_CHECK_EQ(absent.to_string(), std::string("unknown"));
  // The Unknown enumerator and the default-constructed reference are the same
  // value: neither of them is a classification.
  FDR_CHECK(absent == DomainClassRef(DomainClass::Unknown));

  const DomainClassRef rack(DomainClass::Rack);
  FDR_CHECK(rack.is_canonical());
  FDR_CHECK(!rack.is_extension());
  FDR_CHECK_EQ(rack.canonical(), DomainClass::Rack);
  FDR_CHECK_EQ(rack.classification(), DomainClass::Rack);
  FDR_CHECK(rack.is_exclusive());
  FDR_CHECK_EQ(rack.to_string(), std::string("rack"));
  FDR_CHECK_EQ(rack.extension(), std::string());
  FDR_CHECK(rack == DomainClassRef(DomainClass::Rack));
  FDR_CHECK(!(rack == absent));

  const DomainClassRef pdu(DomainClass::Pdu);
  FDR_CHECK(pdu.is_canonical());
  FDR_CHECK(!pdu.is_exclusive());
  FDR_CHECK_EQ(pdu.classification(), DomainClass::Pdu);
  FDR_CHECK_EQ(pdu.canonical(), DomainClass::Pdu);
  FDR_CHECK(!(pdu == rack));
}

FDR_TEST_CASE(classes, domain_class_ref_parses_every_canonical_name) {
  for (std::uint8_t raw = 1; raw <= kDomainClassCount; ++raw) {
    const DomainClass value = static_cast<DomainClass>(raw);
    const std::string_view name = failure_domain_registry::to_string(value);
    const std::optional<DomainClassRef> parsed = DomainClassRef::parse(name);
    FDR_CHECK(parsed.has_value());
    FDR_CHECK(parsed->is_canonical());
    FDR_CHECK(!parsed->is_extension());
    FDR_CHECK_EQ(parsed->canonical(), value);
    FDR_CHECK_EQ(*parsed, DomainClassRef(value));
    FDR_CHECK_EQ(parsed->to_string(), std::string(name));
    FDR_CHECK_EQ(parsed->is_exclusive(), failure_domain_registry::is_exclusive_class(value));
  }

  // Anything that is not exactly a canonical name or a valid extension is
  // refused rather than guessed at.
  FDR_CHECK(!DomainClassRef::parse(std::string()).has_value());
  FDR_CHECK(!DomainClassRef::parse("unknown").has_value());
  FDR_CHECK(!DomainClassRef::parse("Rack").has_value());
  FDR_CHECK(!DomainClassRef::parse("rack ").has_value());
  FDR_CHECK(!DomainClassRef::parse(" rack").has_value());
  FDR_CHECK(!DomainClassRef::parse("rack\n").has_value());
  FDR_CHECK(!DomainClassRef::parse("rack:pdu").has_value());
  FDR_CHECK(!DomainClassRef::parse("rack/row").has_value());
  FDR_CHECK(!DomainClassRef::parse("line_card").has_value());
  FDR_CHECK(!DomainClassRef::parse("custom-x").has_value());
}

FDR_TEST_CASE(classes, domain_class_ref_extension_namespaces) {
  const std::optional<DomainClassRef> vendor = DomainClassRef::extension("vendor", "acme", "cooling-unit");
  FDR_CHECK(vendor.has_value());
  FDR_CHECK(!vendor->is_canonical());
  FDR_CHECK(vendor->is_extension());
  FDR_CHECK_EQ(vendor->canonical(), DomainClass::Unknown);
  FDR_CHECK_EQ(vendor->classification(), DomainClass::Custom);
  FDR_CHECK_EQ(vendor->to_string(), std::string("vendor:acme/cooling-unit"));
  FDR_CHECK_EQ(vendor->extension(), std::string("vendor:acme/cooling-unit"));
  // An extension is never exclusive: this runtime cannot prove the physical
  // semantics of a vendor-defined class.
  FDR_CHECK(!vendor->is_exclusive());

  const std::optional<DomainClassRef> admin = DomainClassRef::extension("admin", "dc1", "hall.2_a-1");
  FDR_CHECK(admin.has_value());
  FDR_CHECK(!admin->is_canonical());
  FDR_CHECK_EQ(admin->classification(), DomainClass::Custom);
  FDR_CHECK_EQ(admin->to_string(), std::string("admin:dc1/hall.2_a-1"));
  FDR_CHECK(!admin->is_exclusive());
  FDR_CHECK(!(*admin == *vendor));

  // Parse and extension() agree exactly, including for a name that collides
  // with a canonical class name.
  const std::optional<DomainClassRef> parsed = DomainClassRef::parse(vendor->to_string());
  FDR_CHECK(parsed.has_value());
  FDR_CHECK_EQ(*parsed, *vendor);
  FDR_CHECK_EQ(parsed->extension(), vendor->extension());

  const std::optional<DomainClassRef> named_like_canonical =
      DomainClassRef::extension("vendor", "acme", "rack");
  FDR_CHECK(named_like_canonical.has_value());
  FDR_CHECK(!named_like_canonical->is_canonical());
  FDR_CHECK(!named_like_canonical->is_exclusive());
  FDR_CHECK_EQ(named_like_canonical->classification(), DomainClass::Custom);
  FDR_CHECK_EQ(named_like_canonical->to_string(), std::string("vendor:acme/rack"));
  FDR_CHECK(!(*named_like_canonical == DomainClassRef(DomainClass::Rack)));

  // Only the two documented namespaces exist.
  const std::string_view accepted[] = {"vendor", "admin"};
  for (std::string_view kind : accepted) {
    FDR_CHECK(DomainClassRef::extension(kind, "ns", "name").has_value());
  }
  const std::string_view refused[] = {"",
                                      "vendo",
                                      "vendorx",
                                      "Vendor",
                                      "VENDOR",
                                      " admin",
                                      "admin ",
                                      "vendor:",
                                      "ext",
                                      "custom"};
  for (std::string_view kind : refused) {
    FDR_CHECK_MSG(!DomainClassRef::extension(kind, "ns", "name").has_value(),
                 "namespace kind accepted: " + std::string(kind));
  }
}

FDR_TEST_CASE(classes, domain_class_ref_extension_bounds) {
  const std::string max_namespace(DomainClassRef::max_namespace_bytes, 'a');
  const std::string max_name(DomainClassRef::max_name_bytes, 'b');
  // The bounds are part of the contract and are checked where they belong: at
  // compile time, because widening either component changes what can be stored.
  static_assert(DomainClassRef::max_namespace_bytes == 64);
  static_assert(DomainClassRef::max_name_bytes == 96);

  const std::optional<DomainClassRef> limit = DomainClassRef::extension("vendor", max_namespace, max_name);
  FDR_CHECK(limit.has_value());
  FDR_CHECK_EQ(limit->extension(), std::string("vendor:") + max_namespace + "/" + max_name);
  FDR_CHECK_EQ(limit->extension().size(), std::size_t{7} + std::size_t{64} + std::size_t{1} + std::size_t{96});
  const std::optional<DomainClassRef> parsed_limit = DomainClassRef::parse(limit->to_string());
  FDR_CHECK(parsed_limit.has_value());
  FDR_CHECK_EQ(*parsed_limit, *limit);

  // One byte over either bound is refused, on both the construction and the
  // parsing path.
  FDR_CHECK(!DomainClassRef::extension("vendor", max_namespace + "a", "name").has_value());
  FDR_CHECK(!DomainClassRef::extension("vendor", "ns", max_name + "b").has_value());
  FDR_CHECK(!DomainClassRef::parse(std::string("vendor:") + max_namespace + "a/name").has_value());
  FDR_CHECK(!DomainClassRef::parse(std::string("vendor:ns/") + max_name + "b").has_value());

  // Both components must be present.
  FDR_CHECK(!DomainClassRef::extension("vendor", std::string(), "name").has_value());
  FDR_CHECK(!DomainClassRef::extension("vendor", "ns", std::string()).has_value());
  FDR_CHECK(!DomainClassRef::extension("vendor", std::string(), std::string()).has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:/name").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:ns/").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:/").has_value());
  // The extension form requires exactly one slash.
  FDR_CHECK(!DomainClassRef::parse("vendor:ns").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:ns/name/extra").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:ns/na me").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:ns/name ").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:NS/name").has_value());

  // The component alphabet is [a-z0-9._-] and nothing else.
  FDR_CHECK(DomainClassRef::extension("vendor", "acme.corp_1-2", "unit.3_x-4").has_value());
  const std::string illegal[] = {std::string(1, static_cast<char>(0x09)),
                                 std::string(1, static_cast<char>(0x0A)),
                                 std::string(1, static_cast<char>(0x7F)),
                                 std::string(1, static_cast<char>(0x80)),
                                 std::string(1, 'A'),
                                 std::string(1, 'Z'),
                                 std::string(1, '/'),
                                 std::string(1, ':'),
                                 std::string(1, ' '),
                                 std::string(1, '+'),
                                 std::string(1, '!'),
                                 std::string(1, '@'),
                                 std::string(1, '*'),
                                 std::string(1, ','),
                                 std::string(1, '=')};
  for (const std::string& segment : illegal) {
    FDR_CHECK_MSG(!DomainClassRef::extension("vendor", segment, "name").has_value(),
                 "the namespace accepted an illegal character");
    FDR_CHECK_MSG(!DomainClassRef::extension("vendor", "ns", segment).has_value(),
                 "the name accepted an illegal character");
    FDR_CHECK_MSG(!DomainClassRef::parse(std::string("vendor:") + segment + "/name").has_value(),
                 "the parser accepted an illegal namespace character");
    FDR_CHECK_MSG(!DomainClassRef::parse(std::string("vendor:ns/") + segment).has_value(),
                 "the parser accepted an illegal name character");
  }
}

FDR_TEST_CASE(classes, domain_class_ref_ordering_and_equality) {
  const DomainClassRef device(DomainClass::Device);
  const DomainClassRef rack(DomainClass::Rack);
  FDR_CHECK(device == DomainClassRef(DomainClass::Device));
  FDR_CHECK(!(device == rack));
  FDR_CHECK(device < rack);
  FDR_CHECK(!(rack < device));

  const std::optional<DomainClassRef> acme = DomainClassRef::extension("vendor", "acme", "unit");
  const std::optional<DomainClassRef> beta = DomainClassRef::extension("vendor", "beta", "unit");
  const std::optional<DomainClassRef> admin = DomainClassRef::extension("admin", "acme", "unit");
  FDR_CHECK(acme.has_value());
  FDR_CHECK(beta.has_value());
  FDR_CHECK(admin.has_value());
  FDR_CHECK_EQ(acme->to_string(), std::string("vendor:acme/unit"));
  FDR_CHECK_EQ(beta->to_string(), std::string("vendor:beta/unit"));
  FDR_CHECK_EQ(admin->to_string(), std::string("admin:acme/unit"));

  // An extension carries no canonical class, so it orders before every
  // canonical reference and among extensions by its rendered text.
  FDR_CHECK(*acme < device);
  FDR_CHECK(*admin < *acme);
  FDR_CHECK(*acme < *beta);
  FDR_CHECK(!(*beta < *acme));
  FDR_CHECK(!(*acme == *beta));
  FDR_CHECK_EQ(admin < beta, true);
  const std::optional<DomainClassRef> acme_again = DomainClassRef::extension("vendor", "acme", "unit");
  FDR_CHECK(acme_again.has_value());
  FDR_CHECK_EQ(*acme_again, *acme);
  FDR_CHECK_EQ(DomainClassRef::parse(acme->to_string()), acme);
}

FDR_TEST_CASE(classes, entity_class_names_round_trip) {
  std::set<std::string_view> names;
  std::size_t valid_count = 0;
  for (std::uint8_t raw = 1; raw <= kEntityClassCount; ++raw) {
    const EntityClass value = static_cast<EntityClass>(raw);
    const std::string_view name = failure_domain_registry::to_string(value);
    const std::string label = "entity class " + std::to_string(raw);
    FDR_CHECK_MSG(!name.empty(), label + " has no name");
    FDR_CHECK_MSG(name != std::string_view("unknown"), label + " has no stable name");
    FDR_CHECK_EQ(name, kEntityClassNames[static_cast<std::size_t>(raw) - 1u]);
    FDR_CHECK(failure_domain_registry::is_valid_entity_class(value));
    const std::optional<EntityClass> parsed = failure_domain_registry::entity_class_from_string(name);
    FDR_CHECK(parsed.has_value());
    FDR_CHECK_EQ(*parsed, value);
    FDR_CHECK_MSG(names.insert(name).second, "duplicate entity class name: " + std::string(name));
    ++valid_count;
  }
  FDR_CHECK_EQ(valid_count, static_cast<std::size_t>(kEntityClassCount));
  FDR_CHECK_EQ(names.size(), static_cast<std::size_t>(kEntityClassCount));

  FDR_CHECK(!failure_domain_registry::is_valid_entity_class(EntityClass::Unknown));
  FDR_CHECK_EQ(failure_domain_registry::to_string(EntityClass::Unknown), std::string_view("unknown"));
  FDR_CHECK(!failure_domain_registry::entity_class_from_string("unknown").has_value());
  FDR_CHECK(!failure_domain_registry::entity_class_from_string(std::string()).has_value());
  FDR_CHECK(!failure_domain_registry::entity_class_from_string("Switch").has_value());
  FDR_CHECK(!failure_domain_registry::entity_class_from_string("smart-nic").has_value());
  FDR_CHECK(!failure_domain_registry::entity_class_from_string("switch ").has_value());
  for (std::uint16_t raw = static_cast<std::uint16_t>(kEntityClassCount) + 1u; raw <= 255u; ++raw) {
    const EntityClass value = static_cast<EntityClass>(raw);
    FDR_CHECK(!failure_domain_registry::is_valid_entity_class(value));
    FDR_CHECK_EQ(failure_domain_registry::to_string(value), std::string_view("unknown"));
  }
}

FDR_TEST_CASE(classes, entity_class_predicates_are_exact) {
  std::size_t device_count = 0;
  std::size_t scope_count = 0;
  for (std::uint8_t raw = 1; raw <= kEntityClassCount; ++raw) {
    const EntityClass value = static_cast<EntityClass>(raw);
    const std::size_t index = static_cast<std::size_t>(raw) - 1u;
    FDR_CHECK_EQ(failure_domain_registry::is_device_class(value), kDeviceClasses[index]);
    FDR_CHECK_EQ(failure_domain_registry::is_administrative_scope_class(value), kAdministrativeScopeClasses[index]);
    // A class is never both: an administrative scope is not a device and a
    // device is not a scope.
    FDR_CHECK(!(kDeviceClasses[index] && kAdministrativeScopeClasses[index]));
    if (kDeviceClasses[index]) {
      ++device_count;
    }
    if (kAdministrativeScopeClasses[index]) {
      ++scope_count;
    }
  }
  FDR_CHECK_EQ(device_count, std::size_t{7});
  FDR_CHECK_EQ(scope_count, std::size_t{4});
  FDR_CHECK(!failure_domain_registry::is_device_class(EntityClass::Unknown));
  FDR_CHECK(!failure_domain_registry::is_administrative_scope_class(EntityClass::Unknown));
  FDR_CHECK(!failure_domain_registry::is_device_class(static_cast<EntityClass>(200)));
  FDR_CHECK(!failure_domain_registry::is_administrative_scope_class(static_cast<EntityClass>(200)));

  // The device classes are exactly the element-bearing ones.
  const EntityClass devices[] = {EntityClass::Switch, EntityClass::Router, EntityClass::Nic,
                                 EntityClass::SmartNic, EntityClass::Dpu, EntityClass::Host,
                                 EntityClass::VendorDevice};
  for (EntityClass value : devices) {
    FDR_CHECK_MSG(failure_domain_registry::is_device_class(value),
                 "device class is not a device class: " +
                     std::string(failure_domain_registry::to_string(value)));
  }
  // The administrative scopes are exactly the four scoping classes.
  const EntityClass scopes[] = {EntityClass::Fabric, EntityClass::Site, EntityClass::ControlDomain,
                                EntityClass::SubFabric};
  for (EntityClass value : scopes) {
    FDR_CHECK(failure_domain_registry::is_administrative_scope_class(value));
    FDR_CHECK(!failure_domain_registry::is_device_class(value));
  }
}

FDR_TEST_CASE(classes, provenance_sources_round_trip) {
  std::set<std::string_view> names;
  for (std::uint8_t raw = 1; raw <= kProvenanceSourceCount; ++raw) {
    const ProvenanceSource value = static_cast<ProvenanceSource>(raw);
    const std::string_view name = failure_domain_registry::to_string(value);
    FDR_CHECK(!name.empty());
    FDR_CHECK_MSG(name != std::string_view("unknown"), "source " + std::to_string(raw) + " has no name");
    FDR_CHECK_EQ(name, kProvenanceSourceNames[static_cast<std::size_t>(raw) - 1u]);
    FDR_CHECK(failure_domain_registry::is_valid_provenance_source(value));
    const std::optional<ProvenanceSource> parsed = failure_domain_registry::provenance_source_from_string(name);
    FDR_CHECK(parsed.has_value());
    FDR_CHECK_EQ(*parsed, value);
    FDR_CHECK(names.insert(name).second);
  }
  FDR_CHECK_EQ(names.size(), static_cast<std::size_t>(kProvenanceSourceCount));

  FDR_CHECK(!failure_domain_registry::is_valid_provenance_source(ProvenanceSource::Unknown));
  FDR_CHECK_EQ(failure_domain_registry::to_string(ProvenanceSource::Unknown), std::string_view("unknown"));
  FDR_CHECK(!failure_domain_registry::provenance_source_from_string("unknown").has_value());
  FDR_CHECK(!failure_domain_registry::provenance_source_from_string(std::string()).has_value());
  FDR_CHECK(!failure_domain_registry::provenance_source_from_string("Cmdb").has_value());
  FDR_CHECK(!failure_domain_registry::provenance_source_from_string("cmdb ").has_value());
  for (std::uint16_t raw = static_cast<std::uint16_t>(kProvenanceSourceCount) + 1u; raw <= 255u; ++raw) {
    FDR_CHECK(!failure_domain_registry::is_valid_provenance_source(static_cast<ProvenanceSource>(raw)));
    FDR_CHECK_EQ(failure_domain_registry::to_string(static_cast<ProvenanceSource>(raw)),
                std::string_view("unknown"));
  }
}

FDR_TEST_CASE(classes, evidence_classes_rank_is_a_total_order) {
  std::set<std::string_view> names;
  std::set<std::uint8_t> ranks;
  for (std::uint8_t raw = 1; raw <= kEvidenceClassCount; ++raw) {
    const EvidenceClass value = static_cast<EvidenceClass>(raw);
    const std::string_view name = failure_domain_registry::to_string(value);
    FDR_CHECK(!name.empty());
    FDR_CHECK_MSG(name != std::string_view("unknown"), "evidence class " + std::to_string(raw) + " has no name");
    FDR_CHECK_EQ(name, kEvidenceClassNames[static_cast<std::size_t>(raw) - 1u]);
    FDR_CHECK(failure_domain_registry::is_valid_evidence_class(value));
    const std::optional<EvidenceClass> parsed = failure_domain_registry::evidence_class_from_string(name);
    FDR_CHECK(parsed.has_value());
    FDR_CHECK_EQ(*parsed, value);
    FDR_CHECK(names.insert(name).second);
    // The rank is the enumerator value, it is total, and no two classes share a
    // rank.
    FDR_CHECK_EQ(failure_domain_registry::evidence_rank(value), kEvidenceRanks[static_cast<std::size_t>(raw) - 1u]);
    FDR_CHECK(ranks.insert(failure_domain_registry::evidence_rank(value)).second);
  }
  FDR_CHECK_EQ(names.size(), static_cast<std::size_t>(kEvidenceClassCount));
  FDR_CHECK_EQ(ranks.size(), static_cast<std::size_t>(kEvidenceClassCount));
  FDR_CHECK_EQ(*ranks.begin(), std::uint8_t{1});
  FDR_CHECK_EQ(*ranks.rbegin(), std::uint8_t{7});

  // Zero means "no evidence": Unknown is not a weaker class, it is the absence
  // of one.
  FDR_CHECK_EQ(failure_domain_registry::evidence_rank(EvidenceClass::Unknown), std::uint8_t{0});
  FDR_CHECK(!failure_domain_registry::is_valid_evidence_class(EvidenceClass::Unknown));
  FDR_CHECK_EQ(failure_domain_registry::to_string(EvidenceClass::Unknown), std::string_view("unknown"));
  FDR_CHECK(!failure_domain_registry::evidence_class_from_string("unknown").has_value());
  FDR_CHECK(!failure_domain_registry::evidence_class_from_string(std::string()).has_value());
  FDR_CHECK(!failure_domain_registry::evidence_class_from_string("Synthetic").has_value());

  // Outranking is strict and total over the valid classes: exactly one
  // direction holds for every unequal pair, and equal ranks never outrank.
  for (std::uint8_t left = 1; left <= kEvidenceClassCount; ++left) {
    const EvidenceClass left_class = static_cast<EvidenceClass>(left);
    FDR_CHECK(!failure_domain_registry::evidence_outranks(left_class, left_class));
    for (std::uint8_t right = 1; right <= kEvidenceClassCount; ++right) {
      const EvidenceClass right_class = static_cast<EvidenceClass>(right);
      const bool expected =
          failure_domain_registry::evidence_rank(left_class) < failure_domain_registry::evidence_rank(right_class);
      FDR_CHECK_EQ(failure_domain_registry::evidence_outranks(left_class, right_class), expected);
      if (left != right) {
        // Asymmetry: two distinct classes cannot both outrank each other.
        FDR_CHECK(failure_domain_registry::evidence_outranks(left_class, right_class) !=
                 failure_domain_registry::evidence_outranks(right_class, left_class));
      }
    }
  }

  // Unknown never outranks anything and is never outranked: it is not a rank.
  for (std::uint8_t raw = 0; raw <= kEvidenceClassCount; ++raw) {
    const EvidenceClass value = static_cast<EvidenceClass>(raw);
    FDR_CHECK(!failure_domain_registry::evidence_outranks(EvidenceClass::Unknown, value));
    FDR_CHECK(!failure_domain_registry::evidence_outranks(value, EvidenceClass::Unknown));
  }
  for (std::uint16_t raw = static_cast<std::uint16_t>(kEvidenceClassCount) + 1u; raw <= 255u; ++raw) {
    const EvidenceClass value = static_cast<EvidenceClass>(raw);
    FDR_CHECK(!failure_domain_registry::is_valid_evidence_class(value));
    FDR_CHECK_EQ(failure_domain_registry::to_string(value), std::string_view("unknown"));
    // An invalid class is not a rank either: it neither outranks nor is
    // outranked by the absence of evidence.
    FDR_CHECK(!failure_domain_registry::evidence_outranks(value, EvidenceClass::Unknown));
    FDR_CHECK(!failure_domain_registry::evidence_outranks(EvidenceClass::Unknown, value));
  }
}

FDR_TEST_CASE(classes, process_bound_and_authoritative_evidence_are_exact) {
  std::size_t process_bound_count = 0;
  std::size_t authoritative_count = 0;
  for (std::uint16_t raw = 0; raw <= 255u; ++raw) {
    const EvidenceClass value = static_cast<EvidenceClass>(raw);
    const bool process_bound = failure_domain_registry::is_process_bound_evidence(value);
    const bool authoritative = failure_domain_registry::is_authoritative_evidence(value);
    if (raw <= kEvidenceClassCount) {
      const std::size_t index = static_cast<std::size_t>(raw);
      FDR_CHECK_EQ(process_bound, kProcessBoundEvidence[index]);
      FDR_CHECK_EQ(authoritative, kAuthoritativeEvidence[index]);
    } else {
      // Values the decoder can never produce are not evidence of any kind.
      FDR_CHECK(!process_bound);
      FDR_CHECK(!authoritative);
    }
    if (process_bound) {
      ++process_bound_count;
    }
    if (authoritative) {
      ++authoritative_count;
    }
  }
  FDR_CHECK_EQ(process_bound_count, std::size_t{3});
  FDR_CHECK_EQ(authoritative_count, std::size_t{3});

  // Exactly the classes that need a live incarnation: a hardware reading, a
  // derivation and an inference all describe who observed them.
  const EvidenceClass process_bound[] = {EvidenceClass::DirectHardwareController,
                                         EvidenceClass::DerivedTopology,
                                         EvidenceClass::Inferred};
  for (EvidenceClass value : process_bound) {
    FDR_CHECK_MSG(failure_domain_registry::is_process_bound_evidence(value),
                 "class should need a live incarnation: " +
                     std::string(failure_domain_registry::to_string(value)));
  }
  // Durable classes survive the loss of their publisher as classification.
  const EvidenceClass durable[] = {EvidenceClass::DirectAuthoritativeInfrastructure,
                                   EvidenceClass::AdministrativeDeclaration,
                                   EvidenceClass::ImportedStaticInventory,
                                   EvidenceClass::Synthetic};
  for (EvidenceClass value : durable) {
    FDR_CHECK_MSG(!failure_domain_registry::is_process_bound_evidence(value),
                 "class should survive a publisher loss: " +
                     std::string(failure_domain_registry::to_string(value)));
  }

  // Authoritative classes are the three that may break a tie, and they are
  // exactly the three strongest ranks.
  const EvidenceClass authoritative[] = {EvidenceClass::DirectAuthoritativeInfrastructure,
                                         EvidenceClass::DirectHardwareController,
                                         EvidenceClass::AdministrativeDeclaration};
  for (EvidenceClass value : authoritative) {
    FDR_CHECK(failure_domain_registry::is_authoritative_evidence(value));
    FDR_CHECK(failure_domain_registry::is_valid_evidence_class(value));
  }
  FDR_CHECK(!failure_domain_registry::is_authoritative_evidence(EvidenceClass::DerivedTopology));
  FDR_CHECK(!failure_domain_registry::is_authoritative_evidence(EvidenceClass::Synthetic));
  FDR_CHECK(!failure_domain_registry::is_authoritative_evidence(EvidenceClass::Unknown));
}

FDR_TEST_CASE(classes, truth_classes_round_trip) {
  std::set<std::string_view> names;
  for (std::uint8_t raw = 1; raw <= kTruthClassCount; ++raw) {
    const TruthClass value = static_cast<TruthClass>(raw);
    const std::string_view name = failure_domain_registry::to_string(value);
    FDR_CHECK(!name.empty());
    FDR_CHECK_MSG(name != std::string_view("UNKNOWN"), "truth class " + std::to_string(raw) + " has no name");
    FDR_CHECK_EQ(name, kTruthClassNames[static_cast<std::size_t>(raw) - 1u]);
    FDR_CHECK(failure_domain_registry::is_valid_truth_class(value));
    const std::optional<TruthClass> parsed = failure_domain_registry::truth_class_from_string(name);
    FDR_CHECK(parsed.has_value());
    FDR_CHECK_EQ(*parsed, value);
    FDR_CHECK(names.insert(name).second);
  }
  FDR_CHECK_EQ(names.size(), static_cast<std::size_t>(kTruthClassCount));

  FDR_CHECK(!failure_domain_registry::is_valid_truth_class(TruthClass::Unknown));
  FDR_CHECK_EQ(failure_domain_registry::to_string(TruthClass::Unknown), std::string_view("UNKNOWN"));
  FDR_CHECK(!failure_domain_registry::truth_class_from_string("UNKNOWN").has_value());
  FDR_CHECK(!failure_domain_registry::truth_class_from_string(std::string()).has_value());
  // The names are case sensitive and there is no "probably real" category.
  FDR_CHECK(!failure_domain_registry::truth_class_from_string("real").has_value());
  FDR_CHECK(!failure_domain_registry::truth_class_from_string("Probable").has_value());
  for (std::uint16_t raw = static_cast<std::uint16_t>(kTruthClassCount) + 1u; raw <= 255u; ++raw) {
    const TruthClass value = static_cast<TruthClass>(raw);
    FDR_CHECK(!failure_domain_registry::is_valid_truth_class(value));
    FDR_CHECK_EQ(failure_domain_registry::to_string(value), std::string_view("UNKNOWN"));
  }
}

FDR_TEST_CASE(classes, provenance_durability_follows_the_evidence_class) {
  Provenance durable;
  durable.source = ProvenanceSource::PhysicalInfrastructure;
  durable.evidence = EvidenceClass::DirectAuthoritativeInfrastructure;
  durable.truth = TruthClass::Real;
  FDR_CHECK(!durable.has_publisher());
  FDR_CHECK(durable.is_durable());

  Provenance process;
  process.source = ProvenanceSource::VendorController;
  process.evidence = EvidenceClass::DirectHardwareController;
  process.truth = TruthClass::Real;
  process.publisher = publisher_from(1u);
  process.worker_boot = boot_from(1u);
  FDR_CHECK(process.has_publisher());
  FDR_CHECK(!process.is_durable());

  // is_durable is exactly the negation of the process-bound predicate, for every
  // byte value and not only for the enumerators.
  for (std::uint16_t raw = 0; raw <= 255u; ++raw) {
    Provenance value;
    value.evidence = static_cast<EvidenceClass>(raw);
    FDR_CHECK_EQ(value.is_durable(), !failure_domain_registry::is_process_bound_evidence(value.evidence));
  }

  // Holding a publisher is not the same as being process bound: durable evidence
  // may name the publisher that supplied it and still survive that publisher.
  Provenance durable_with_publisher = durable;
  durable_with_publisher.publisher = publisher_from(2u);
  durable_with_publisher.worker_boot = boot_from(2u);
  FDR_CHECK(durable_with_publisher.has_publisher());
  FDR_CHECK(durable_with_publisher.is_durable());
}

} // namespace

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
