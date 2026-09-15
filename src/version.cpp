// Failure Domain Registry — version reporting.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/version.hpp"

#include <string>

namespace failure_domain_registry {

std::string_view version_string() noexcept {
  return "1.0.0";
}

} // namespace failure_domain_registry
