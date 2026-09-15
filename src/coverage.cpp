// Failure Domain Registry - coverage states.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/coverage.hpp"

namespace failure_domain_registry {

std::string_view to_string(CoverageState value) noexcept {
  switch (value) {
    case CoverageState::Complete: return "COMPLETE";
    case CoverageState::Partial: return "PARTIAL";
    case CoverageState::UnknownCoverage: return "UNKNOWN";
    default: return "UNKNOWN";
  }
}

bool is_valid_coverage_state(CoverageState value) noexcept {
  return value != CoverageState::Unknown &&
         static_cast<std::uint8_t>(value) <=
             static_cast<std::uint8_t>(CoverageState::UnknownCoverage);
}

} // namespace failure_domain_registry
