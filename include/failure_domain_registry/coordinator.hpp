// Failure Domain Registry — the coordinating process.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The coordinator owns the registry, the durable image and the listening
// control socket. Publishers are separate operating-system processes. Session
// loss is detected through the real socket, and a lost session fences exactly
// the worker incarnation that owned it.
//
// Coordinator::stop() must not be called from a session thread: it joins them.

#ifndef FAILURE_DOMAIN_REGISTRY_COORDINATOR_HPP
#define FAILURE_DOMAIN_REGISTRY_COORDINATOR_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "failure_domain_registry/authority.hpp"
#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/limits.hpp"
#include "failure_domain_registry/persistence.hpp"
#include "failure_domain_registry/registry.hpp"

namespace failure_domain_registry {

struct CoordinatorConfig {
  std::string bind_address{"127.0.0.1"};
  /// Zero selects an ephemeral port; read the chosen one from bound_port().
  std::uint16_t port{0};
  PersistenceConfig persistence{};
  /// Load the durable image at start. A missing file is not an error.
  bool load_on_start{true};
  /// Save after every committed mutation.
  bool save_on_commit{true};
  /// Authority grants installed before the first client is accepted.
  std::vector<PublisherRegistration> grants;
  RegistryLimits registry{};
  FrameLimits frames{};
  /// How long accept() waits before re-checking the stop flag.
  std::uint32_t accept_poll_ms{25};
};

/// Counters reported by the coordinator for diagnostics.
struct CoordinatorStats {
  std::size_t sessions_accepted{0};
  std::size_t sessions_completed{0};
  std::size_t sessions_rejected{0};
  std::size_t frames_received{0};
  std::size_t frames_rejected{0};
  std::size_t mutations_committed{0};
  std::size_t mutations_rejected{0};
  std::size_t queries_served{0};
  std::size_t workers_fenced{0};
  std::size_t saves{0};
  std::size_t save_failures{0};
  CoordinatorEpoch epoch{};
  RegistryGeneration generation{};
  std::string render() const;
};

class FDR_API Coordinator {
public:
  explicit Coordinator(CoordinatorConfig config);
  ~Coordinator();

  Coordinator(const Coordinator&) = delete;
  Coordinator& operator=(const Coordinator&) = delete;
  Coordinator(Coordinator&&) = delete;
  Coordinator& operator=(Coordinator&&) = delete;

  /// Binds, loads durable state, advances the coordinator epoch and starts the
  /// accept thread. `endpoint` receives "host:port".
  Outcome start(std::string* endpoint);
  /// Stops accepting, fences every live incarnation with CoordinatorRestart,
  /// saves and joins every thread. Idempotent.
  Outcome stop();

  bool running() const noexcept;
  std::uint16_t bound_port() const noexcept;
  CoordinatorEpoch epoch() const;
  RegistryGeneration generation() const;
  CoordinatorStats stats() const;
  /// Read-only access for local inspection. Never used by a session thread for
  /// mutation: sessions mutate through the registry's public operations.
  const Registry& registry() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_COORDINATOR_HPP
