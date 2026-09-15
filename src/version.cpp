// Failure Domain Registry — version reporting.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/version.hpp"

#include <string>

namespace failure_domain_registry {

std::string_view version_string() noexcept {
  // Composed once from the published constants, so the reported version can
  // never claim a release other than the one this build was configured with.
  static const std::string text = std::to_string(kVersionMajor) + "." +
                                  std::to_string(kVersionMinor) + "." +
                                  std::to_string(kVersionPatch);
  return text;
}

} // namespace failure_domain_registry
