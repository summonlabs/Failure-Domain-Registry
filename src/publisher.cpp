// Failure Domain Registry - the publisher client.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/publisher.hpp"

#include <mutex>

#include "failure_domain_registry/frame.hpp"
#include "message_codec.hpp"

namespace failure_domain_registry {

struct PublisherClient::Impl {
  explicit Impl(PublisherClientConfig config_in) : config(std::move(config_in)) {}

  PublisherClientConfig config;
  TcpSocket socket;
  bool connected{false};
  std::mutex mutex;
  std::uint64_t sequence{1};
  CoordinatorEpoch epoch;
  RegistryGeneration generation;
};

PublisherClient::PublisherClient(PublisherClientConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

PublisherClient::~PublisherClient() {
  if (impl_ && impl_->connected) {
    static_cast<void>(close());
  }
}

bool PublisherClient::connected() const noexcept { return impl_->connected; }

CoordinatorEpoch PublisherClient::epoch() const { return impl_->epoch; }

RegistryGeneration PublisherClient::generation() const { return impl_->generation; }

const PublisherClientConfig& PublisherClient::config() const noexcept { return impl_->config; }

Outcome PublisherClient::send_request(MessageType request_type, std::string_view payload,
                                      std::string* response_payload) {
  std::string frame;
  const Outcome encoded = encode_frame(request_type, impl_->sequence++, payload,
                                       impl_->config.frames.max_payload_bytes, frame);
  if (!encoded.committed()) {
    return encoded;
  }
  const Outcome sent = impl_->socket.send_all(frame);
  if (!sent.committed()) {
    impl_->connected = false;
    return sent;
  }
  for (;;) {
    std::string header_bytes;
    const Outcome header_read = impl_->socket.recv_exact(kFrameHeaderBytes, &header_bytes);
    if (!header_read.committed()) {
      impl_->connected = false;
      return header_read;
    }
    FrameHeader header;
    const Outcome header_result =
        decode_frame_header(header_bytes, impl_->config.frames, &header);
    if (!header_result.committed()) {
      impl_->connected = false;
      return header_result;
    }
    std::string body;
    if (header.payload_bytes > 0) {
      const Outcome body_read = impl_->socket.recv_exact(header.payload_bytes, &body);
      if (!body_read.committed()) {
        impl_->connected = false;
        return body_read;
      }
    }
    std::string complete = header_bytes;
    complete.append(body);
    FrameHeader decoded_header;
    std::string_view decoded_payload;
    std::size_t consumed = 0;
    const Outcome decoded = decode_frame(complete, impl_->config.frames, &decoded_header,
                                         &decoded_payload, &consumed);
    if (!decoded.committed()) {
      impl_->connected = false;
      return decoded;
    }
    if (decoded_header.type == MessageType::Heartbeat) {
      continue;
    }
    if (decoded_header.type != MessageType::Response) {
      impl_->connected = false;
      return Outcome::make(OutcomeCode::ProtocolViolation,
                           "the coordinator sent an unexpected frame type");
    }
    response_payload->assign(decoded_payload.data(), decoded_payload.size());
    return Outcome::make(OutcomeCode::Committed, "response received");
  }
}

namespace {

Outcome response_to_outcome(const WireResponse& response, std::string* rendered) {
  Outcome outcome = Outcome::make(response.code, response.message);
  outcome.epoch = response.epoch;
  outcome.state_generation = response.generation;
  outcome.request_digest = response.request_digest;
  if (!response.domain.is_null()) {
    outcome.domain = response.domain;
  }
  if (!response.membership.is_null()) {
    outcome.membership = response.membership;
  }
  if (rendered != nullptr) {
    *rendered = response.rendered;
  } else if (!response.rendered.empty()) {
    outcome.steps.push_back(
        ExplanationStep{"response", "rendered", std::string(), response.rendered});
  }
  return outcome;
}

} // namespace

Outcome PublisherClient::connect() {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  if (impl_->connected) {
    return Outcome::make(OutcomeCode::Idempotent, "already connected");
  }
  const Outcome connected_result =
      connect_to(impl_->config.endpoint, impl_->config.connect_timeout_ms, &impl_->socket);
  if (!connected_result.committed()) {
    return connected_result;
  }
  // A fresh publisher does not know the coordinator epoch, so a Hello answered
  // with STALE_EPOCH is retried exactly once at the epoch the coordinator
  // reported. Configurations that pin the epoch get the rejection instead.
  WireResponse response;
  const int attempts = impl_->config.learn_epoch ? 2 : 1;
  for (int attempt = 0; attempt < attempts; ++attempt) {
    WireRequest hello;
    hello.op = Operation::Hello;
    hello.authority.publisher = impl_->config.publisher;
    hello.authority.worker_boot = impl_->config.worker_boot;
    hello.authority.epoch = impl_->epoch.is_zero() ? impl_->config.epoch : impl_->epoch;
    hello.authority.evidence = impl_->config.max_evidence;
    hello.label = impl_->config.label;
    std::string payload;
    Outcome result = encode_wire_request(hello, &payload);
    if (!result.committed()) {
      impl_->socket.close();
      return result;
    }
    std::string response_payload;
    result = send_request(MessageType::Hello, payload, &response_payload);
    if (!result.committed()) {
      impl_->socket.shutdown_both();
      impl_->socket.close();
      return result;
    }
    result = decode_wire_response(response_payload, &response);
    if (!result.committed()) {
      impl_->socket.shutdown_both();
      impl_->socket.close();
      return result;
    }
    impl_->epoch = response.epoch;
    impl_->generation = response.generation;
    if (response.code == OutcomeCode::StaleEpoch && attempt + 1 < attempts) {
      continue;
    }
    if (response.code != OutcomeCode::Committed && response.code != OutcomeCode::Idempotent) {
      impl_->socket.shutdown_both();
      impl_->socket.close();
      return response_to_outcome(response, nullptr);
    }
    impl_->connected = true;
    Outcome outcome = Outcome::make(OutcomeCode::Committed, "attached to the coordinator");
    outcome.epoch = response.epoch;
    outcome.state_generation = response.generation;
    return outcome;
  }
  impl_->socket.shutdown_both();
  impl_->socket.close();
  return response_to_outcome(response, nullptr);
}

Outcome PublisherClient::close() {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  if (!impl_->connected && !impl_->socket.valid()) {
    return Outcome::make(OutcomeCode::Idempotent, "already detached");
  }
  if (impl_->connected) {
    WireRequest bye;
    bye.op = Operation::Bye;
    bye.authority.publisher = impl_->config.publisher;
    bye.authority.worker_boot = impl_->config.worker_boot;
    bye.authority.epoch = impl_->epoch;
    bye.label = impl_->config.label;
    std::string payload;
    if (encode_wire_request(bye, &payload).committed()) {
      std::string response_payload;
      static_cast<void>(send_request(MessageType::Bye, payload, &response_payload));
    }
  }
  impl_->socket.shutdown_both();
  impl_->socket.close();
  impl_->connected = false;
  return Outcome::make(OutcomeCode::Committed, "detached");
}

namespace {

WireAuthority authority_of(const PublisherClientConfig& config, CoordinatorEpoch epoch,
                           const MutationAttempt& attempt, EvidenceClass evidence) {
  WireAuthority authority;
  authority.attempt = attempt.id();
  authority.epoch = epoch;
  authority.publisher = config.publisher;
  authority.worker_boot = config.worker_boot;
  authority.evidence = is_valid_evidence_class(evidence) ? evidence : config.max_evidence;
  return authority;
}

} // namespace

Outcome PublisherClient::create_domain(const CreateDomainRequest& request) {
  WireRequest wire;
  wire.op = Operation::CreateDomain;
  wire.create_domain = request;
  wire.authority = authority_of(impl_->config, impl_->epoch, request.attempt,
                                request.provenance.evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Mutate, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  impl_->generation = response.generation;
  return response_to_outcome(response, nullptr);
}

Outcome PublisherClient::update_domain(const UpdateDomainRequest& request) {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  WireRequest wire;
  wire.op = Operation::UpdateDomain;
  wire.update_domain = request;
  wire.authority = authority_of(impl_->config, impl_->epoch, request.attempt,
                                request.provenance.evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Mutate, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  impl_->generation = response.generation;
  return response_to_outcome(response, nullptr);
}

Outcome PublisherClient::attach_member(const AttachMemberRequest& request) {
  WireRequest wire;
  wire.op = Operation::AttachMember;
  wire.attach_member = request;
  wire.authority = authority_of(impl_->config, impl_->epoch, request.attempt,
                                request.provenance.evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Mutate, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  impl_->generation = response.generation;
  return response_to_outcome(response, nullptr);
}

Outcome PublisherClient::publish_memberships(const MembershipBatchRequest& request) {
  WireRequest wire;
  wire.op = Operation::PublishMemberships;
  wire.publish = request;
  EvidenceClass evidence = EvidenceClass::Unknown;
  if (!request.entries.empty()) {
    evidence = request.entries.front().provenance.evidence;
  }
  wire.authority = authority_of(impl_->config, impl_->epoch, request.attempt, evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Mutate, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  impl_->generation = response.generation;
  return response_to_outcome(response, nullptr);
}

Outcome PublisherClient::withdraw_evidence(const WithdrawEvidenceRequest& request) {
  WireRequest wire;
  wire.op = Operation::WithdrawEvidence;
  wire.withdraw = request;
  wire.authority = authority_of(impl_->config, impl_->epoch, request.attempt,
                                request.authority.evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Mutate, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  impl_->generation = response.generation;
  return response_to_outcome(response, nullptr);
}

Outcome PublisherClient::declare_coverage(const DeclareCoverageRequest& request) {
  WireRequest wire;
  wire.op = Operation::DeclareCoverage;
  wire.coverage = request;
  wire.authority = authority_of(impl_->config, impl_->epoch, request.attempt,
                                request.provenance.evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Mutate, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  impl_->generation = response.generation;
  return response_to_outcome(response, nullptr);
}

Outcome PublisherClient::invalidate_entity(const EntityInvalidationRequest& request) {
  WireRequest wire;
  wire.op = Operation::InvalidateEntity;
  wire.invalidate = request;
  wire.authority = authority_of(impl_->config, impl_->epoch, request.attempt,
                                impl_->config.max_evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Mutate, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  impl_->generation = response.generation;
  return response_to_outcome(response, nullptr);
}

Outcome PublisherClient::run_derivation(const DerivationRunRequest& request, std::string* rendered) {
  WireRequest wire;
  wire.op = Operation::RunDerivation;
  wire.derivation = request;
  wire.authority = authority_of(impl_->config, impl_->epoch, request.attempt,
                                impl_->config.max_evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Mutate, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  impl_->generation = response.generation;
  return response_to_outcome(response, rendered);
}

Outcome PublisherClient::supersede_domain(const SupersedeDomainRequest& request) {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  WireRequest wire;
  wire.op = Operation::SupersedeDomain;
  wire.supersede = request;
  wire.authority = authority_of(impl_->config, impl_->epoch, request.attempt,
                                impl_->config.max_evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Mutate, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  impl_->generation = response.generation;
  return response_to_outcome(response, nullptr);
}

Outcome PublisherClient::retire_domain(const RetireDomainRequest& request) {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  WireRequest wire;
  wire.op = Operation::RetireDomain;
  wire.retire = request;
  wire.authority = authority_of(impl_->config, impl_->epoch, request.attempt,
                                impl_->config.max_evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Mutate, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  impl_->generation = response.generation;
  return response_to_outcome(response, nullptr);
}

Outcome PublisherClient::query_status(std::string* rendered) {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  WireRequest wire;
  wire.op = Operation::QueryStatus;
  wire.authority = authority_of(impl_->config, impl_->epoch, MutationAttempt{},
                                impl_->config.max_evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Query, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  impl_->generation = response.generation;
  return response_to_outcome(response, rendered);
}

Outcome PublisherClient::query_domain(const FailureDomainId& id, std::string* rendered) {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  WireRequest wire;
  wire.op = Operation::QueryDomain;
  wire.domain = id;
  wire.authority = authority_of(impl_->config, impl_->epoch, MutationAttempt{},
                                impl_->config.max_evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Query, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  return response_to_outcome(response, rendered);
}

Outcome PublisherClient::query_domain_members(const FailureDomainId& id, std::string* rendered) {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  WireRequest wire;
  wire.op = Operation::QueryDomainMembers;
  wire.domain = id;
  wire.authority = authority_of(impl_->config, impl_->epoch, MutationAttempt{},
                                impl_->config.max_evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Query, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  return response_to_outcome(response, rendered);
}

Outcome PublisherClient::query_entity_domains(const EntityId& entity, std::string* rendered) {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  WireRequest wire;
  wire.op = Operation::QueryEntityDomains;
  wire.entity = entity;
  wire.authority = authority_of(impl_->config, impl_->epoch, MutationAttempt{},
                                impl_->config.max_evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Query, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  return response_to_outcome(response, rendered);
}

Outcome PublisherClient::query_overlap(const std::vector<EntityId>& entities, std::string* rendered) {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  WireRequest wire;
  wire.op = Operation::QueryOverlap;
  wire.entities = entities;
  wire.authority = authority_of(impl_->config, impl_->epoch, MutationAttempt{},
                                impl_->config.max_evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Query, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  return response_to_outcome(response, rendered);
}

Outcome PublisherClient::query_coverage(std::string_view scope,
                                        const std::vector<DomainClassRef>& classes,
                                        std::string* rendered) {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  WireRequest wire;
  wire.op = Operation::QueryCoverage;
  wire.scope = std::string(scope);
  wire.classes = classes;
  wire.authority = authority_of(impl_->config, impl_->epoch, MutationAttempt{},
                                impl_->config.max_evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Query, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  return response_to_outcome(response, rendered);
}

Outcome PublisherClient::query_independence(const std::vector<EntityId>& entities,
                                            const std::vector<DomainClassRef>& classes,
                                            std::string* rendered) {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  WireRequest wire;
  wire.op = Operation::QueryIndependence;
  wire.entities = entities;
  wire.classes = classes;
  wire.authority = authority_of(impl_->config, impl_->epoch, MutationAttempt{},
                                impl_->config.max_evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Query, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  return response_to_outcome(response, rendered);
}

Outcome PublisherClient::query_snapshot(std::string_view scope, std::string* rendered) {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  WireRequest wire;
  wire.op = Operation::QuerySnapshot;
  wire.scope = std::string(scope);
  wire.authority = authority_of(impl_->config, impl_->epoch, MutationAttempt{},
                                impl_->config.max_evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Query, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  return response_to_outcome(response, rendered);
}

Outcome PublisherClient::query_explain_membership(const FailureDomainId& domain,
                                                  const EntityId& entity,
                                                  std::string* rendered) {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  WireRequest wire;
  wire.op = Operation::QueryExplainMembership;
  wire.domain = domain;
  wire.entity = entity;
  wire.authority = authority_of(impl_->config, impl_->epoch, MutationAttempt{},
                                impl_->config.max_evidence);
  std::string payload;
  Outcome result = encode_wire_request(wire, &payload);
  if (!result.committed()) {
    return result;
  }
  std::string response_payload;
  result = send_request(MessageType::Query, payload, &response_payload);
  if (!result.committed()) {
    return result;
  }
  WireResponse response;
  result = decode_wire_response(response_payload, &response);
  if (!result.committed()) {
    return result;
  }
  return response_to_outcome(response, rendered);
}

} // namespace failure_domain_registry
