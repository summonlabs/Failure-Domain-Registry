// Failure Domain Registry — deterministic explanations.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef FAILURE_DOMAIN_REGISTRY_EXPLANATION_HPP
#define FAILURE_DOMAIN_REGISTRY_EXPLANATION_HPP

#include <string>
#include <vector>

#include "failure_domain_registry/errors.hpp"
#include "failure_domain_registry/export.hpp"

namespace failure_domain_registry {

/// A structured answer to a "why" question, plus a deterministic rendering.
struct FDR_API Explanation {
  /// What was asked, rendered canonically.
  std::string subject;
  /// Ordered steps. Stage names are stable and machine-matchable.
  std::vector<ExplanationStep> steps;
  /// True when the explanation is complete. A truncated explanation says so
  /// rather than silently stopping.
  bool complete{true};

  Explanation() = default;
  explicit Explanation(std::string subject_in) : subject(std::move(subject_in)) {}

  Explanation& step(std::string stage, std::string detail);
  Explanation& field_step(std::string stage, std::string field, std::string value, std::string detail);

  /// Multi-line rendering: "subject", then one indented line per step.
  std::string render() const;
};

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_EXPLANATION_HPP
