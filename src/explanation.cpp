// Failure Domain Registry — explanation values.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/explanation.hpp"

namespace failure_domain_registry {

Explanation& Explanation::step(std::string stage, std::string detail) {
  steps.push_back(ExplanationStep{std::move(stage), std::string(), std::string(), std::move(detail)});
  return *this;
}

Explanation& Explanation::field_step(std::string stage, std::string field, std::string value,
                                     std::string detail) {
  steps.push_back(ExplanationStep{std::move(stage), std::move(field), std::move(value),
                                  std::move(detail)});
  return *this;
}

std::string Explanation::render() const {
  std::string out = subject;
  if (!complete) {
    out.append(" (incomplete)");
  }
  for (const ExplanationStep& entry : steps) {
    out.append("\n  [");
    out.append(entry.stage);
    out.append("]");
    if (!entry.field.empty()) {
      out.append(" ");
      out.append(entry.field);
      out.append("=");
      out.append(entry.value);
    }
    out.append(" ");
    out.append(entry.detail);
  }
  return out;
}

} // namespace failure_domain_registry
