// Failure Domain Registry — relation type semantics.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/relation.hpp"

namespace failure_domain_registry {

std::string_view to_string(DomainRelationType value) noexcept {
  switch (value) {
    case DomainRelationType::ContainedBy: return "CONTAINED_BY";
    case DomainRelationType::DependsOn: return "DEPENDS_ON";
    case DomainRelationType::SharesRiskWith: return "SHARES_RISK_WITH";
    case DomainRelationType::PoweredBy: return "POWERED_BY";
    case DomainRelationType::CooledBy: return "COOLED_BY";
    case DomainRelationType::ControlledBy: return "CONTROLLED_BY";
    case DomainRelationType::BackedBy: return "BACKED_BY";
    case DomainRelationType::CorrelatedWith: return "CORRELATED_WITH";
    default: return "UNKNOWN";
  }
}

std::optional<DomainRelationType> domain_relation_type_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= kDomainRelationTypeCount; ++raw) {
    const auto value = static_cast<DomainRelationType>(raw);
    if (to_string(value) == text) {
      return value;
    }
  }
  return std::nullopt;
}

bool is_valid_domain_relation_type(DomainRelationType value) noexcept {
  return value != DomainRelationType::Unknown &&
         static_cast<std::uint8_t>(value) <= kDomainRelationTypeCount;
}

bool is_symmetric_relation(DomainRelationType value) noexcept {
  return value == DomainRelationType::SharesRiskWith || value == DomainRelationType::CorrelatedWith;
}

bool is_acyclic_relation(DomainRelationType value) noexcept {
  switch (value) {
    case DomainRelationType::ContainedBy:
    case DomainRelationType::DependsOn:
    case DomainRelationType::PoweredBy:
    case DomainRelationType::CooledBy:
    case DomainRelationType::ControlledBy:
    case DomainRelationType::BackedBy:
      return true;
    default:
      return false;
  }
}

std::string_view inverse_text(DomainRelationType value) noexcept {
  switch (value) {
    case DomainRelationType::ContainedBy: return "CONTAINS";
    case DomainRelationType::DependsOn: return "IS-DEPENDED-ON-BY";
    case DomainRelationType::SharesRiskWith: return "SHARES_RISK_WITH";
    case DomainRelationType::PoweredBy: return "POWERS";
    case DomainRelationType::CooledBy: return "COOLS";
    case DomainRelationType::ControlledBy: return "CONTROLS";
    case DomainRelationType::BackedBy: return "BACKS";
    case DomainRelationType::CorrelatedWith: return "CORRELATED_WITH";
    default: return "UNKNOWN";
  }
}

} // namespace failure_domain_registry
