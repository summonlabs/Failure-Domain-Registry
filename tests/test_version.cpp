// Failure Domain Registry — version reporting.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The reported version has to be the version the build was configured with. The
// string is derived from the published constants, so a release bump can never
// leave the library claiming an earlier release than the one that was tagged.

#include <cstdint>
#include <string>

#include "failure_domain_registry/version.hpp"
#include "support/test_harness.hpp"

namespace {

using failure_domain_registry::kDerivationRuleSetVersion;
using failure_domain_registry::kDigestVersion;
using failure_domain_registry::kStateFormatVersion;
using failure_domain_registry::kVersionMajor;
using failure_domain_registry::kVersionMinor;
using failure_domain_registry::kVersionPatch;
using failure_domain_registry::kWireProtocolVersion;
using failure_domain_registry::version_string;

/// The version the constants describe, composed the same way a consumer would.
std::string composed_version() {
  return std::to_string(kVersionMajor) + "." + std::to_string(kVersionMinor) + "." +
         std::to_string(kVersionPatch);
}

} // namespace

FDR_TEST_CASE(version, the_reported_version_is_the_configured_version) {
  // The release numbers are compile-time constants and the reported string is
  // derived from them, so the two halves of the version identity cannot drift.
  static_assert(kVersionMajor == 1, "the major version of this release is one");
  static_assert(kVersionMinor == 0, "the minor version of this release is zero");
  static_assert(kVersionPatch == 1, "the patch version of this release is one");
  // A change to any of these would invalidate every persisted image, every
  // framed message and every digest a consumer has already recorded.
  static_assert(kStateFormatVersion == 1, "the persisted container format is version one");
  static_assert(kWireProtocolVersion == 1, "the wire protocol is version one");
  static_assert(kDigestVersion == 1, "the canonical digest input is version one");
  static_assert(kDerivationRuleSetVersion == 1, "the derivation rule set is version one");

  const std::string reported(version_string());
  FDR_CHECK_EQ(reported, composed_version());
  FDR_CHECK_MSG(reported == std::string("1.0.1"),
                "the library reports " + reported + ", which is not the tagged release");
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
