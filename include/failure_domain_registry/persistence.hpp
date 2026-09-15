// Failure Domain Registry — versioned, integrity-checked persistence.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The persisted container is a single file:
//
//   magic       8 bytes  "FDRSTATE"
//   version     4 bytes  little endian, currently 1
//   flags       4 bytes  reserved, must be zero
//   payload     u64      length of the payload in bytes
//   payload sha 32 bytes SHA-256 over the payload
//   header sha  32 bytes SHA-256 over the preceding 56 bytes
//   payload     N bytes  deterministic record encoding
//   trailer     6 bytes  "FDREND"
//
// The file size must equal 88 + payload + 6 exactly, and the trailer must be
// present at that offset, so a truncation at any byte position is rejected by
// construction. Replacement is atomic: the image is written to a sibling
// temporary file, flushed, and renamed over the destination.

#ifndef FAILURE_DOMAIN_REGISTRY_PERSISTENCE_HPP
#define FAILURE_DOMAIN_REGISTRY_PERSISTENCE_HPP

#include <cstddef>
#include <cstdint>
#include <string>

#include "failure_domain_registry/errors.hpp"
#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"

namespace failure_domain_registry {

/// Bytes of fixed header before the payload.
inline constexpr std::size_t kStateHeaderBytes = 88;
inline constexpr std::size_t kStateTrailerBytes = 6;

struct PersistenceConfig {
  std::string path;
  /// Flush file contents to the device before renaming. Measured durability is
  /// platform dependent; the flag states the intent, not a guarantee.
  bool durable{true};
  /// Write to a sibling temporary file and rename over the destination. Turning
  /// this off is only meaningful for read-only media.
  bool atomic{true};
  friend bool operator==(const PersistenceConfig&, const PersistenceConfig&) = default;
};

/// What one save() wrote, or what one load() found.
struct PersistenceReport {
  std::size_t bytes{0};
  std::size_t domains{0};
  std::size_t memberships{0};
  std::size_t relations{0};
  std::size_t coverage_declarations{0};
  std::size_t publishers{0};
  std::size_t fences{0};
  std::size_t derivation_rules{0};
  RegistryGeneration generation{};
  CoordinatorEpoch epoch{};
  StateDigest digest{};
  std::uint32_t format_version{0};
};

/// Reads the header and trailer of a persisted image without decoding its
/// records. Used by the CLI to inspect an image and to detect corruption
/// without trusting it.
FDR_API Outcome inspect_persistence(const PersistenceConfig& config, PersistenceReport* report);

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_PERSISTENCE_HPP
