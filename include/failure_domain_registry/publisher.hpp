// Failure Domain Registry — the publisher client.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A publisher is a real process with its own publisher identity, its own worker
// boot id and its own connection. It never mutates coordinator state directly:
// every operation is a framed request. A restarted publisher has a fresh worker
// boot id and must reattach before it can mutate anything again.

#ifndef FAILURE_DOMAIN_REGISTRY_PUBLISHER_HPP
#define FAILURE_DOMAIN_REGISTRY_PUBLISHER_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "failure_domain_registry/authority.hpp"
#include "failure_domain_registry/errors.hpp"
#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/frame.hpp"
#include "failure_domain_registry/limits.hpp"
#include "failure_domain_registry/requests.hpp"
#include "failure_domain_registry/transport.hpp"

namespace failure_domain_registry {

struct PublisherClientConfig {
  Endpoint endpoint{};
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  /// Epoch the client believes is current. Zero means "unknown".
  CoordinatorEpoch epoch{};
  /// When true, a Hello answered with STALE_EPOCH is retried exactly once at
  /// the epoch the coordinator reported. When false, the configured epoch is
  /// presented as-is and the rejection is surfaced to the caller.
  bool learn_epoch{true};
  std::string label;
  EvidenceClass max_evidence{EvidenceClass::Unknown};
  FrameLimits frames{};
  std::uint32_t connect_timeout_ms{5000};
  std::uint32_t io_timeout_ms{10000};
};

class FDR_API PublisherClient {
public:
  explicit PublisherClient(PublisherClientConfig config);
  ~PublisherClient();

  PublisherClient(const PublisherClient&) = delete;
  PublisherClient& operator=(const PublisherClient&) = delete;
  PublisherClient(PublisherClient&&) = delete;
  PublisherClient& operator=(PublisherClient&&) = delete;

  /// Connects and performs the Hello/HelloAck exchange.
  Outcome connect();
  /// Sends Bye and shuts the connection down. Idempotent.
  Outcome close();
  bool connected() const noexcept;

  CoordinatorEpoch epoch() const;
  RegistryGeneration generation() const;
  const PublisherClientConfig& config() const noexcept;

  Outcome create_domain(const CreateDomainRequest& request);
  /// Re-attest a domain: restore authority after a revalidation demand, update
  /// its name or metadata, or move its lifecycle along a legal transition.
  Outcome update_domain(const UpdateDomainRequest& request);
  Outcome supersede_domain(const SupersedeDomainRequest& request);
  Outcome retire_domain(const RetireDomainRequest& request);
  Outcome attach_member(const AttachMemberRequest& request);
  Outcome publish_memberships(const MembershipBatchRequest& request);
  Outcome withdraw_evidence(const WithdrawEvidenceRequest& request);
  Outcome declare_coverage(const DeclareCoverageRequest& request);
  Outcome invalidate_entity(const EntityInvalidationRequest& request);
  Outcome run_derivation(const DerivationRunRequest& request, std::string* rendered);

  /// Read-only queries. The rendering is the same deterministic text the CLI
  /// prints, so a script can compare it byte for byte.
  Outcome query_status(std::string* rendered);
  Outcome query_domain(const FailureDomainId& id, std::string* rendered);
  Outcome query_domain_members(const FailureDomainId& id, std::string* rendered);
  Outcome query_entity_domains(const EntityId& entity, std::string* rendered);
  Outcome query_overlap(const std::vector<EntityId>& entities, std::string* rendered);
  Outcome query_coverage(std::string_view scope,
                         const std::vector<DomainClassRef>& classes,
                         std::string* rendered);
  Outcome query_independence(const std::vector<EntityId>& entities,
                             const std::vector<DomainClassRef>& classes,
                             std::string* rendered);
  Outcome query_snapshot(std::string_view scope, std::string* rendered);
  Outcome query_explain_membership(const FailureDomainId& domain,
                                   const EntityId& entity,
                                   std::string* rendered);

private:
  Outcome send_request(MessageType request_type, std::string_view payload, std::string* response_payload);
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_PUBLISHER_HPP
