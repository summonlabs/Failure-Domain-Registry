// Failure Domain Registry - control protocol payloads.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The frame carries an operation tag and a field-by-field encoded body. No
// structure is ever memcpy'd onto the wire, and every decode ends with an
// exhaustion check.

#ifndef FAILURE_DOMAIN_REGISTRY_SRC_MESSAGE_CODEC_HPP
#define FAILURE_DOMAIN_REGISTRY_SRC_MESSAGE_CODEC_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "failure_domain_registry/errors.hpp"
#include "failure_domain_registry/registry.hpp"
#include "failure_domain_registry/transport.hpp"

namespace failure_domain_registry {

enum class Operation : std::uint16_t {
  Unknown = 0,
  Hello = 1,
  HelloAck = 2,
  Bye = 3,
  Heartbeat = 4,
  CreateDomain = 10,
  SupersedeDomain = 11,
  RetireDomain = 12,
  AttachMember = 13,
  /// Re-attest a domain: name, metadata, evidence and lifecycle transition.
  UpdateDomain = 14,
  PublishMemberships = 20,
  WithdrawEvidence = 21,
  DeclareCoverage = 22,
  InvalidateEntity = 23,
  RunDerivation = 24,
  QueryStatus = 40,
  QueryDomain = 41,
  QueryDomainMembers = 42,
  QueryEntityDomains = 43,
  QueryOverlap = 44,
  QueryCoverage = 45,
  QueryIndependence = 46,
  QuerySnapshot = 47,
  QueryExplainMembership = 48,
  Response = 60,
};

FDR_API std::string_view to_string(Operation value) noexcept;
FDR_API bool is_valid_operation(Operation value) noexcept;
FDR_API bool is_mutation_operation(Operation value) noexcept;

struct WireAuthority {
  MutationAttemptId attempt{};
  CoordinatorEpoch epoch{};
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  EvidenceClass evidence{EvidenceClass::Unknown};
};

struct WireRequest {
  Operation op{Operation::Unknown};
  WireAuthority authority{};
  std::string label;
  CreateDomainRequest create_domain{};
  AttachMemberRequest attach_member{};
  UpdateDomainRequest update_domain{};
  MembershipBatchRequest publish{};
  WithdrawEvidenceRequest withdraw{};
  SupersedeDomainRequest supersede{};
  RetireDomainRequest retire{};
  DeclareCoverageRequest coverage{};
  EntityInvalidationRequest invalidate{};
  DerivationRunRequest derivation{};
  FailureDomainId domain{};
  EntityId entity{};
  std::vector<EntityId> entities;
  std::vector<DomainClassRef> classes;
  std::string scope;
};

struct WireResponse {
  OutcomeCode code{OutcomeCode::InternalFailure};
  std::string message;
  std::string rendered;
  CoordinatorEpoch epoch{};
  RegistryGeneration generation{};
  FailureDomainId domain{};
  MembershipId membership{};
  RequestDigest request_digest{};
};

FDR_API Outcome encode_wire_request(const WireRequest& request, std::string* payload);
FDR_API Outcome decode_wire_request(std::string_view payload, WireRequest* request);
FDR_API Outcome encode_wire_response(const WireResponse& response, std::string* payload);
FDR_API Outcome decode_wire_response(std::string_view payload, WireResponse* response);

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_SRC_MESSAGE_CODEC_HPP
