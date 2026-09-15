// Failure Domain Registry — derivation rule definitions.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/derivation.hpp"

#include "failure_domain_registry/digest.hpp"

namespace failure_domain_registry {

std::string_view to_string(DerivationOperator value) noexcept {
  switch (value) {
    case DerivationOperator::MembersShareContainingClass: return "members-share-containing-class";
    case DerivationOperator::SameDomainMemberRelationship: return "same-domain-member-relationship";
    default: return "unknown";
  }
}

bool is_valid_derivation_operator(DerivationOperator value) noexcept {
  return value != DerivationOperator::Unknown &&
         static_cast<std::uint8_t>(value) <=
             static_cast<std::uint8_t>(DerivationOperator::SameDomainMemberRelationship);
}

std::string DerivationRule::canonical_form() const {
  std::string out;
  append_bytes(out, "fdr/derivation-rule/v1");
  append_bytes(out, name);
  append_u8(out, static_cast<std::uint8_t>(op));
  append_bytes(out, source_class.to_string());
  append_bytes(out, target_class.to_string());
  append_u8(out, static_cast<std::uint8_t>(member_class));
  append_u8(out, static_cast<std::uint8_t>(derived_role));
  append_u8(out, static_cast<std::uint8_t>(dependency));
  append_u32(out, rule_version);
  return out;
}

DerivationRuleId derivation_rule_id_for(const DerivationRule& rule) {
  return DerivationRuleId::from_digest(sha256(rule.canonical_form()));
}

} // namespace failure_domain_registry
