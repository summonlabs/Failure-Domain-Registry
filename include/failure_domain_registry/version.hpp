// Failure Domain Registry — version and format constants.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef FAILURE_DOMAIN_REGISTRY_VERSION_HPP
#define FAILURE_DOMAIN_REGISTRY_VERSION_HPP

#include <cstdint>
#include <string_view>

#include "failure_domain_registry/export.hpp"

namespace failure_domain_registry {

/// Semantic version of the library itself.
inline constexpr std::uint32_t kVersionMajor = 1;
inline constexpr std::uint32_t kVersionMinor = 0;
inline constexpr std::uint32_t kVersionPatch = 0;

/// Version of the persisted state container written by save().
inline constexpr std::uint32_t kStateFormatVersion = 1;

/// Version of the framed control transport.
inline constexpr std::uint32_t kWireProtocolVersion = 1;

/// Version of the canonical semantic digest input.
inline constexpr std::uint32_t kDigestVersion = 1;

/// Version of the derivation rule set understood by this build.
inline constexpr std::uint32_t kDerivationRuleSetVersion = 1;

FDR_API std::string_view version_string() noexcept;

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_VERSION_HPP
