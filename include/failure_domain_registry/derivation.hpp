// Failure Domain Registry — the bounded derivation rule engine.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Derived membership exists so that a link can inherit the failure domains of
// its endpoints, or an endpoint can inherit the domains of its host, without a
// publisher restating the same facts. Derivation is never implicit and never
// arbitrary: a rule must be named, versioned, published by an authorized
// publisher and carried out by one of the deterministic evaluators below.
//
// Every derived membership records the rule identity, the source memberships,
// the exact source generations and a derivation generation. When a source
// generation moves on, the derived membership is recomputed or withdrawn - it
// is never quietly left standing.

#ifndef FAILURE_DOMAIN_REGISTRY_DERIVATION_HPP
#define FAILURE_DOMAIN_REGISTRY_DERIVATION_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "failure_domain_registry/domain_class.hpp"
#include "failure_domain_registry/entity.hpp"
#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"
#include "failure_domain_registry/membership.hpp"

namespace failure_domain_registry {

/// The deterministic evaluators this build implements. There is no scripting
/// hook and no pluggable callback: a rule that is not one of these cannot be
/// published.
enum class DerivationOperator : std::uint8_t {
  Unknown = 0,
  /// Every member of a domain of class S derives membership in the domains of
  /// class T that its own current members belong to.
  ///
  /// Concretely: for each current direct member M of S, and each current
  /// T-domain D that M belongs to, every current direct member of S becomes a
  /// derived member of D. This is the "shared chassis implies shared rack"
  /// shape.
  MembersShareContainingClass = 1,
  /// A member inherits the target-class domains of a co-member of a specific
  /// entity class.
  ///
  /// Concretely: for each current domain DS of class S, for each pair of
  /// distinct current members (M, C) of DS where C has the rule's member class,
  /// M receives derived membership in every current domain of class T that C
  /// belongs to. This is the "a link inherits the failure domains of the
  /// endpoint device it shares a device domain with" shape, restricted to the
  /// co-member class the rule names.
  SameDomainMemberRelationship = 2,
};

FDR_API std::string_view to_string(DerivationOperator value) noexcept;
FDR_API bool is_valid_derivation_operator(DerivationOperator value) noexcept;

/// A published derivation rule.
struct FDR_API DerivationRule {
  DerivationRuleId id{};
  /// Bounded stable rule name, e.g. "link-inherits-endpoint-domains".
  std::string name;
  DerivationOperator op{DerivationOperator::Unknown};
  /// Class the rule reads membership from.
  DomainClassRef source_class{};
  /// Class the rule writes membership into.
  DomainClassRef target_class{};
  /// Entity class the rule is restricted to. For
  /// MembersShareContainingClass it restricts which members receive the
  /// derived membership. For SameDomainMemberRelationship it restricts which
  /// co-members may act as the source of the inherited fact. Unknown means
  /// "any class".
  EntityClass member_class{EntityClass::Unknown};
  /// Role written onto derived memberships.
  MembershipRole derived_role{MembershipRole::Derived};
  /// Dependency semantics written onto derived memberships.
  DependencySemantics dependency{DependencySemantics::Unspecified};
  /// Version of the rule definition itself. A change produces a new version and
  /// a fresh derivation generation.
  std::uint32_t rule_version{1};
  /// Publisher that published the rule.
  PublisherId publisher{};
  RegistryGeneration published_at{};
  bool enabled{true};

  /// Deterministic identity of the rule definition.
  std::string canonical_form() const;
  friend bool operator==(const DerivationRule&, const DerivationRule&) = default;
};

/// Computes the deterministic rule id from the rule's definition.
FDR_API DerivationRuleId derivation_rule_id_for(const DerivationRule& rule);

/// The result of one derivation pass.
struct DerivationReport {
  std::size_t rules_evaluated{0};
  std::size_t memberships_created{0};
  std::size_t memberships_updated{0};
  std::size_t memberships_withdrawn{0};
  std::size_t memberships_unchanged{0};
  std::size_t bounded_out{0};
  RegistryGeneration generation{};
};

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_DERIVATION_HPP
