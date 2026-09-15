// Failure Domain Registry — mutation authority.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A publisher may mutate only what it is explicitly authorized to mutate, under
// the current coordinator epoch, with a live process incarnation. Connecting is
// not authority: authority is a durable grant with a scope, and it is checked
// before any mutation reaches the state.

#ifndef FAILURE_DOMAIN_REGISTRY_AUTHORITY_HPP
#define FAILURE_DOMAIN_REGISTRY_AUTHORITY_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "failure_domain_registry/domain_class.hpp"
#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/ids.hpp"
#include "failure_domain_registry/provenance.hpp"

namespace failure_domain_registry {

/// What a publisher is allowed to change.
///
/// An empty class list means "no class is authorized", never "all classes". A
/// publisher that must be able to do anything says so explicitly with
/// AuthorityScope::unrestricted().
struct FDR_API AuthorityScope {
  /// Domain classes the publisher may create, supersede, retire or populate.
  std::vector<DomainClass> classes;
  /// Administrative scope name the publisher is confined to. Empty means the
  /// publisher is not confined to an administrative scope. When it is set, the
  /// publisher may only mutate domains whose administrative_scope matches.
  std::string administrative_scope;
  /// Highest evidence class the publisher may assert. Weaker evidence is always
  /// allowed; stronger is not.
  EvidenceClass max_evidence{EvidenceClass::Synthetic};

  static AuthorityScope none() noexcept { return AuthorityScope{}; }
  static AuthorityScope unrestricted() noexcept;
  static AuthorityScope for_classes(std::vector<DomainClass> classes,
                                   EvidenceClass max_evidence) noexcept;

  bool allows_class(DomainClass value) const noexcept;
  bool allows_scope(const std::string& scope_name) const noexcept;
  bool allows_evidence(EvidenceClass value) const noexcept;
  bool is_empty() const noexcept { return classes.empty(); }

  /// Canonical rendering: "classes=rack,pdu;scope=dc1;max-evidence=2".
  std::string render() const;
  friend bool operator==(const AuthorityScope&, const AuthorityScope&) = default;
};

/// A durable authority grant for one publisher identity.
struct FDR_API PublisherRegistration {
  PublisherId publisher{};
  /// Administrative label. Bounded and free of control characters.
  std::string name;
  AuthorityScope scope;
  PublisherGeneration generation{};
};

/// The authority context attached to one mutation attempt.
struct FDR_API AuthorityContext {
  /// Publisher claiming the mutation. Required.
  PublisherId publisher{};
  /// Process incarnation. Required: a restarted publisher is a new incarnation
  /// and the old one is fenced.
  WorkerBootId worker_boot{};
  /// Coordinator epoch the caller believes is current.
  CoordinatorEpoch epoch{};
  /// Evidence class the publisher asserts for this attempt.
  EvidenceClass evidence{EvidenceClass::Unknown};

  bool is_complete() const noexcept {
    return !publisher.is_null() && !worker_boot.is_null() && !epoch.is_zero();
  }
};

/// Why a worker incarnation stopped being live.
enum class FenceReason : std::uint8_t {
  Unknown = 0,
  /// The publisher process exited or was killed.
  SessionLost = 1,
  /// The publisher reattached with a fresh incarnation.
  Reincarnated = 2,
  /// The coordinator restarted and cannot vouch for the old incarnation.
  CoordinatorRestart = 3,
  /// An operator fenced the incarnation explicitly.
  Administrative = 4,
  /// The incarnation was retired because its authority grant was revoked.
  Revoked = 5,
};

FDR_API std::string_view to_string(FenceReason value) noexcept;

/// A recorded fence. Durable: it survives restart.
struct FDR_API FenceRecord {
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  FenceReason reason{FenceReason::Unknown};
  CoordinatorEpoch epoch{};
  RegistryGeneration at_generation{};
  friend bool operator==(const FenceRecord&, const FenceRecord&) = default;
};

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_AUTHORITY_HPP
