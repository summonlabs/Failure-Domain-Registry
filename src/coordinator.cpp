// Failure Domain Registry - the coordinating process.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Lock ordering, stated once: the registry lock is the outer lock and a
// session lock is only ever taken while it is not held. Session threads never
// hold a session lock while calling into the registry, and Coordinator::stop
// never calls into a session thread.

#include "failure_domain_registry/coordinator.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <thread>

#include "failure_domain_registry/frame.hpp"
#include "failure_domain_registry/version.hpp"
#include "message_codec.hpp"

namespace failure_domain_registry {

namespace {

std::string render_status(const Registry& registry) {
  std::string out = "status\n";
  out.append("  epoch            = ");
  out.append(registry.epoch().to_string());
  out.append("\n  registry-gen     = ");
  out.append(registry.generation().to_string());
  out.append("\n  domains          = ");
  out.append(std::to_string(registry.domain_count()));
  out.append("\n  memberships      = ");
  out.append(std::to_string(registry.membership_count()));
  out.append("\n  live-sessions    = ");
  out.append(std::to_string(registry.live_sessions().size()));
  out.append("\n  fences           = ");
  out.append(std::to_string(registry.fences().size()));
  return out;
}

} // namespace

struct Coordinator::Impl {
  CoordinatorConfig config;
  Registry registry{config.registry};
  TcpListener listener;
  std::atomic<bool> running{false};
  std::atomic<bool> stopping{false};
  std::thread accept_thread;

  struct SessionHandle {
    std::thread thread;
    std::shared_ptr<std::atomic<bool>> finished;
  };
  std::mutex sessions_mutex;
  std::vector<SessionHandle> sessions;

  std::mutex live_sockets_mutex;
  std::vector<std::shared_ptr<TcpSocket>> live_sockets;

  mutable std::mutex stats_mutex;
  CoordinatorStats stats;

  void add_session(SessionHandle handle) {
    const std::lock_guard<std::mutex> guard(sessions_mutex);
    sessions.push_back(std::move(handle));
  }

  void reap_finished() {
    const std::lock_guard<std::mutex> guard(sessions_mutex);
    for (auto it = sessions.begin(); it != sessions.end();) {
      if (it->finished->load()) {
        if (it->thread.joinable()) {
          it->thread.join();
        }
        it = sessions.erase(it);
      } else {
        ++it;
      }
    }
  }

  void join_all() {
    std::vector<SessionHandle> handles;
    {
      const std::lock_guard<std::mutex> guard(sessions_mutex);
      handles.swap(sessions);
    }
    for (SessionHandle& handle : handles) {
      if (handle.thread.joinable()) {
        handle.thread.join();
      }
    }
  }

  void register_socket(const std::shared_ptr<TcpSocket>& socket) {
    const std::lock_guard<std::mutex> guard(live_sockets_mutex);
    live_sockets.push_back(socket);
  }

  void unregister_socket(const std::shared_ptr<TcpSocket>& socket) {
    const std::lock_guard<std::mutex> guard(live_sockets_mutex);
    live_sockets.erase(std::remove(live_sockets.begin(), live_sockets.end(), socket),
                       live_sockets.end());
  }

  void shutdown_live_sockets() {
    std::vector<std::shared_ptr<TcpSocket>> sockets;
    {
      const std::lock_guard<std::mutex> guard(live_sockets_mutex);
      sockets = live_sockets;
    }
    for (const std::shared_ptr<TcpSocket>& socket : sockets) {
      socket->shutdown_both();
    }
  }

  Outcome save_if_configured() {
    if (!config.save_on_commit || config.persistence.path.empty()) {
      return Outcome::make(OutcomeCode::Committed, "persistence is disabled");
    }
    const Outcome saved = registry.save(config.persistence);
    const std::lock_guard<std::mutex> guard(stats_mutex);
    if (saved.committed()) {
      ++stats.saves;
    } else {
      ++stats.save_failures;
    }
    return saved;
  }

  Outcome dispatch(std::string_view payload, std::string* rendered, bool* is_mutation,
                  bool* attached, PublisherId* attached_publisher,
                  WorkerBootId* attached_boot);
  void serve(std::shared_ptr<TcpSocket> socket, std::shared_ptr<std::atomic<bool>> finished);
  void accept_loop();
};

Outcome Coordinator::Impl::dispatch(std::string_view payload, std::string* rendered,
                                    bool* is_mutation, bool* attached,
                                    PublisherId* attached_publisher,
                                    WorkerBootId* attached_boot) {
  WireRequest request;
  const Outcome decoded = decode_wire_request(payload, &request);
  if (!decoded.committed()) {
    const std::lock_guard<std::mutex> guard(stats_mutex);
    ++stats.frames_rejected;
    return decoded;
  }
  *is_mutation = is_mutation_operation(request.op);

  const auto authority_for = [&request](const Provenance& provenance) {
    AuthorityContext authority;
    authority.publisher = request.authority.publisher;
    authority.worker_boot = request.authority.worker_boot;
    authority.epoch = request.authority.epoch;
    authority.evidence = is_valid_evidence_class(provenance.evidence)
                             ? provenance.evidence
                             : request.authority.evidence;
    return authority;
  };
  const auto base_authority = [&request]() {
    AuthorityContext authority;
    authority.publisher = request.authority.publisher;
    authority.worker_boot = request.authority.worker_boot;
    authority.epoch = request.authority.epoch;
    authority.evidence = request.authority.evidence;
    return authority;
  };
  const MutationAttempt attempt{request.authority.attempt, RequestDigest{}};

  switch (request.op) {
    case Operation::Hello: {
      const Outcome attached_out = registry.attach_worker(
          request.authority.publisher, request.authority.worker_boot, request.authority.epoch,
          request.label, request.authority.evidence);
      if (attached_out.committed() || attached_out.code == OutcomeCode::Idempotent) {
        *attached = true;
        *attached_publisher = request.authority.publisher;
        *attached_boot = request.authority.worker_boot;
      }
      rendered->assign("epoch ");
      rendered->append(registry.epoch().to_string());
      return attached_out;
    }
    case Operation::Bye:
      return Outcome::make(OutcomeCode::Committed, "detached");
    case Operation::Heartbeat:
      return Outcome::make(OutcomeCode::Committed, "alive");
    case Operation::QueryStatus:
      *rendered = render_status(registry);
      return Outcome::make(OutcomeCode::Committed, "status");
    case Operation::QueryDomain: {
      const std::optional<FailureDomain> domain = registry.domain(request.domain);
      if (!domain.has_value()) {
        return Outcome::make(OutcomeCode::NotFound, "no such domain");
      }
      *rendered = domain->render();
      return Outcome::make(OutcomeCode::Committed, "domain");
    }
    case Operation::QueryDomainMembers: {
      const std::vector<Membership> members = registry.members_of(request.domain);
      std::string out = "members of ";
      out.append(request.domain.to_string());
      for (const Membership& record : members) {
        out.append("\n  ");
        out.append(record.member.to_string());
        out.append(" kind=");
        out.append(failure_domain_registry::to_string(record.kind));
        out.append(" lifecycle=");
        out.append(failure_domain_registry::to_string(record.lifecycle));
      }
      *rendered = out;
      return Outcome::make(OutcomeCode::Committed, "members");
    }
    case Operation::QueryEntityDomains: {
      const std::vector<Membership> memberships = registry.memberships_of(request.entity);
      std::string out = "domains of ";
      out.append(request.entity.to_string());
      for (const Membership& record : memberships) {
        out.append("\n  ");
        out.append(record.domain.to_string());
        out.append(" kind=");
        out.append(failure_domain_registry::to_string(record.kind));
        out.append(" lifecycle=");
        out.append(failure_domain_registry::to_string(record.lifecycle));
      }
      *rendered = out;
      return Outcome::make(OutcomeCode::Committed, "entity domains");
    }
    case Operation::QueryOverlap: {
      const OverlapResult overlap = registry.overlap(request.entities);
      std::string out = "overlap ";
      out.append(failure_domain_registry::to_string(overlap.state));
      for (const SharedDomain& shared : overlap.shared) {
        out.append("\n  shared ");
        out.append(shared.domain.to_string());
        out.append(" class=");
        out.append(shared.domain_class.to_string());
      }
      *rendered = out;
      return Outcome::make(OutcomeCode::Committed, "overlap");
    }
    case Operation::QueryIndependence: {
      const IndependenceResult result =
          registry.independence(request.entities, request.classes, request.scope);
      std::string out = "independence ";
      out.append(failure_domain_registry::to_string(result.state));
      *rendered = out;
      return Outcome::make(OutcomeCode::Committed, "independence");
    }
    case Operation::QueryCoverage: {
      const CoverageReport report = registry.coverage(request.scope, request.classes);
      std::string out = "coverage ";
      out.append(request.scope);
      for (const CoverageEntry& entry : report.entries) {
        out.append("\n  ");
        out.append(entry.domain_class.to_string());
        out.append(" ");
        out.append(failure_domain_registry::to_string(entry.state));
      }
      *rendered = out;
      return Outcome::make(OutcomeCode::Committed, "coverage");
    }
    case Operation::QuerySnapshot: {
      const Snapshot snapshot = registry.snapshot(request.scope);
      *rendered = snapshot.render();
      return Outcome::make(OutcomeCode::Committed, "snapshot");
    }
    case Operation::QueryExplainMembership: {
      const Explanation explanation =
          registry.explain_membership(request.domain, request.entity);
      *rendered = explanation.render();
      return Outcome::make(OutcomeCode::Committed, "explanation");
    }
    case Operation::CreateDomain: {
      CreateDomainRequest body = request.create_domain;
      body.attempt = attempt;
      body.authority = authority_for(body.provenance);
      const Outcome outcome = registry.create_domain(body);
      if (outcome.committed()) {
        static_cast<void>(save_if_configured());
      }
      return outcome;
    }
    case Operation::UpdateDomain: {
      UpdateDomainRequest body = request.update_domain;
      body.attempt = attempt;
      body.authority = authority_for(body.provenance);
      const Outcome outcome = registry.update_domain(body);
      if (outcome.committed()) {
        static_cast<void>(save_if_configured());
      }
      return outcome;
    }
    case Operation::AttachMember: {
      AttachMemberRequest body = request.attach_member;
      body.attempt = attempt;
      body.authority = authority_for(body.provenance);
      const Outcome outcome = registry.attach_member(body);
      if (outcome.committed()) {
        static_cast<void>(save_if_configured());
      }
      return outcome;
    }
    case Operation::PublishMemberships: {
      MembershipBatchRequest body = request.publish;
      body.attempt = attempt;
      body.authority = base_authority();
      if (!body.entries.empty()) {
        body.authority = authority_for(body.entries.front().provenance);
      }
      const Outcome outcome = registry.publish_memberships(body);
      if (outcome.committed()) {
        static_cast<void>(save_if_configured());
      }
      return outcome;
    }
    case Operation::WithdrawEvidence: {
      WithdrawEvidenceRequest body = request.withdraw;
      body.attempt = attempt;
      body.authority = base_authority();
      const Outcome outcome = registry.withdraw_evidence(body);
      if (outcome.committed()) {
        static_cast<void>(save_if_configured());
      }
      return outcome;
    }
    case Operation::SupersedeDomain: {
      SupersedeDomainRequest body = request.supersede;
      body.attempt = attempt;
      body.authority = base_authority();
      const Outcome outcome = registry.supersede_domain(body);
      if (outcome.committed()) {
        static_cast<void>(save_if_configured());
      }
      return outcome;
    }
    case Operation::RetireDomain: {
      RetireDomainRequest body = request.retire;
      body.attempt = attempt;
      body.authority = base_authority();
      const Outcome outcome = registry.retire_domain(body);
      if (outcome.committed()) {
        static_cast<void>(save_if_configured());
      }
      return outcome;
    }
    case Operation::DeclareCoverage: {
      DeclareCoverageRequest body = request.coverage;
      body.attempt = attempt;
      body.authority = authority_for(body.provenance);
      const Outcome outcome = registry.declare_coverage(body);
      if (outcome.committed()) {
        static_cast<void>(save_if_configured());
      }
      return outcome;
    }
    case Operation::InvalidateEntity: {
      EntityInvalidationRequest body = request.invalidate;
      body.attempt = attempt;
      body.authority = base_authority();
      const Outcome outcome = registry.invalidate_entity(body);
      if (outcome.committed()) {
        static_cast<void>(save_if_configured());
      }
      return outcome;
    }
    case Operation::RunDerivation: {
      DerivationRunRequest body = request.derivation;
      body.attempt = attempt;
      body.authority = base_authority();
      DerivationReport report;
      const Outcome outcome = registry.run_derivation(body, &report);
      rendered->assign(
          std::to_string(report.memberships_created) + " created, " +
          std::to_string(report.memberships_updated) + " updated, " +
          std::to_string(report.memberships_withdrawn) + " withdrawn");
      if (outcome.committed()) {
        static_cast<void>(save_if_configured());
      }
      return outcome;
    }
    default:
      return Outcome::make(OutcomeCode::ProtocolViolation,
                           "this coordinator does not handle that operation");
  }
}

void Coordinator::Impl::serve(std::shared_ptr<TcpSocket> socket,
                              std::shared_ptr<std::atomic<bool>> finished) {
  register_socket(socket);
  // shutdown(both) is the fast path but is not a guarantee on every stack that
  // a pending blocking receive returns, so the session socket also carries a
  // receive timeout. An expired receive is reported as "no data yet" and the
  // loop re-checks stopping, which bounds shutdown unconditionally.
  static_cast<void>(socket->set_receive_timeout(200));
  PublisherId attached_publisher;
  WorkerBootId attached_boot;
  bool attached = false;
  std::string buffer;
  std::string pending_out;
  std::uint64_t sequence = 1;
  while (!stopping.load()) {
    std::string chunk;
    bool closed = false;
    const Outcome received = socket->recv_some(65536, &chunk, &closed);
    if (closed) {
      break;
    }
    if (!received.committed()) {
      break;
    }
    buffer.append(chunk);
    bool protocol_error = false;
    for (;;) {
      if (buffer.size() < kFrameHeaderBytes) {
        break;
      }
      FrameHeader header;
      const Outcome header_result = decode_frame_header(buffer, config.frames, &header);
      if (!header_result.committed()) {
        const std::lock_guard<std::mutex> guard(stats_mutex);
        ++stats.frames_rejected;
        protocol_error = true;
        break;
      }
      const std::size_t total = kFrameHeaderBytes + header.payload_bytes;
      if (buffer.size() < total) {
        break;
      }
      std::string_view payload;
      std::size_t consumed = 0;
      const Outcome frame_result =
          decode_frame(std::string_view(buffer).substr(0, total), config.frames, &header,
                       &payload, &consumed);
      buffer.erase(0, total);
      if (!frame_result.committed()) {
        const std::lock_guard<std::mutex> guard(stats_mutex);
        ++stats.frames_rejected;
        protocol_error = true;
        break;
      }
      {
        const std::lock_guard<std::mutex> guard(stats_mutex);
        ++stats.frames_received;
      }
      std::string rendered;
      bool is_mutation = false;
      const Outcome outcome =
          dispatch(payload, &rendered, &is_mutation, &attached, &attached_publisher, &attached_boot);
      if (is_mutation) {
        const std::lock_guard<std::mutex> guard(stats_mutex);
        if (outcome.committed() || outcome.code == OutcomeCode::Idempotent) {
          ++stats.mutations_committed;
        } else {
          ++stats.mutations_rejected;
        }
      } else {
        const std::lock_guard<std::mutex> guard(stats_mutex);
        ++stats.queries_served;
      }
      WireResponse response;
      response.code = outcome.code;
      response.message = outcome.message;
      response.rendered = std::move(rendered);
      response.epoch = registry.epoch();
      response.generation = registry.generation();
      response.request_digest = outcome.request_digest;
      if (outcome.domain.has_value()) {
        response.domain = *outcome.domain;
      }
      if (outcome.membership.has_value()) {
        response.membership = *outcome.membership;
      }
      std::string body;
      if (!encode_wire_response(response, &body).committed()) {
        protocol_error = true;
        break;
      }
      pending_out.clear();
      if (!encode_frame(MessageType::Response, sequence++, body, config.frames.max_payload_bytes,
                        pending_out)
               .committed()) {
        protocol_error = true;
        break;
      }
      if (!socket->send_all(pending_out).committed()) {
        protocol_error = true;
        break;
      }
    }
    if (protocol_error) {
      break;
    }
    if (buffer.size() > hard_limits::kMaxFramePayloadBytes + kFrameHeaderBytes) {
      const std::lock_guard<std::mutex> guard(stats_mutex);
      ++stats.frames_rejected;
      break;
    }
  }

  // Session loss is detected here, through the real socket, and fences exactly
  // the incarnation that owned this connection.
  if (attached) {
    // Fencing is a committed state change, so it is persisted before the
    // session is torn down: a coordinator that dies after a publisher is lost
    // must not come back believing the lost incarnation is still authoritative.
    static_cast<void>(registry.fence_worker(attached_publisher, attached_boot,
                                            FenceReason::SessionLost, registry.epoch()));
    static_cast<void>(save_if_configured());
    const std::lock_guard<std::mutex> guard(stats_mutex);
    ++stats.workers_fenced;
  }
  socket->shutdown_both();
  unregister_socket(socket);
  socket->close();
  {
    const std::lock_guard<std::mutex> guard(stats_mutex);
    ++stats.sessions_completed;
  }
  finished->store(true);
}

void Coordinator::Impl::accept_loop() {
  while (!stopping.load()) {
    auto accepted = std::make_shared<TcpSocket>();
    bool got_connection = false;
    const Outcome result =
        listener.accept(accepted.get(), &got_connection, config.accept_poll_ms);
    reap_finished();
    if (!result.committed()) {
      if (stopping.load()) {
        break;
      }
      continue;
    }
    if (!got_connection) {
      continue;
    }
    {
      const std::lock_guard<std::mutex> guard(stats_mutex);
      if (++stats.sessions_accepted > config.frames.max_sessions) {
        ++stats.sessions_rejected;
        continue;
      }
    }
    auto finished = std::make_shared<std::atomic<bool>>(false);
    SessionHandle handle;
    handle.finished = finished;
    handle.thread = std::thread([this, accepted, finished]() {
      serve(accepted, finished);
    });
    add_session(std::move(handle));
  }
  reap_finished();
}

Coordinator::Coordinator(CoordinatorConfig config) : impl_(std::make_unique<Impl>()) {
  impl_->config = std::move(config);
}

Coordinator::~Coordinator() {
  if (impl_ && impl_->running.load()) {
    static_cast<void>(stop());
  }
}

Outcome Coordinator::start(std::string* endpoint) {
  if (impl_->running.load()) {
    return Outcome::make(OutcomeCode::PolicyRejected, "the coordinator is already running");
  }
  const ValidationResult registry_limits = impl_->config.registry.validate();
  if (!registry_limits) {
    return Outcome::make(OutcomeCode::MalformedRequest, registry_limits.message);
  }
  const ValidationResult frame_limits = impl_->config.frames.validate();
  if (!frame_limits) {
    return Outcome::make(OutcomeCode::MalformedRequest, frame_limits.message);
  }

  CoordinatorEpoch loaded_epoch;
  if (impl_->config.load_on_start && !impl_->config.persistence.path.empty()) {
    const Outcome loaded = impl_->registry.load(impl_->config.persistence);
    if (loaded.committed()) {
      loaded_epoch = impl_->registry.epoch();
    } else if (loaded.code != OutcomeCode::NotFound) {
      return Outcome::make(loaded.code, "cannot recover durable state: " + loaded.message);
    }
  }

  for (const PublisherRegistration& grant : impl_->config.grants) {
    const Outcome granted = impl_->registry.grant_publisher(grant, AuthorityContext{});
    if (!granted.committed() && granted.code != OutcomeCode::Idempotent) {
      return Outcome::make(granted.code, "cannot install a publisher grant: " + granted.message);
    }
  }

  // Conservative recovery: process-bound evidence never becomes fresh merely
  // because it survived on disk.
  for (const auto& incarnation : impl_->registry.process_bound_incarnations()) {
    static_cast<void>(impl_->registry.fence_worker(incarnation.first, incarnation.second,
                                                    FenceReason::CoordinatorRestart,
                                                    impl_->registry.epoch()));
  }

  CoordinatorEpoch next_epoch = loaded_epoch;
  const Outcome advanced = impl_->registry.advance_epoch(loaded_epoch, &next_epoch);
  if (!advanced.committed()) {
    return Outcome::make(advanced.code, "cannot advance the coordinator epoch: " + advanced.message);
  }

  const Outcome bound =
      listen_on(impl_->config.bind_address, impl_->config.port, 64, &impl_->listener);
  if (!bound.committed()) {
    return bound;
  }
  impl_->stopping.store(false);
  impl_->running.store(true);
  {
    const std::lock_guard<std::mutex> guard(impl_->stats_mutex);
    impl_->stats.epoch = next_epoch;
  }
  impl_->accept_thread = std::thread([this]() { impl_->accept_loop(); });
  if (endpoint != nullptr) {
    *endpoint = impl_->config.bind_address + ":" + std::to_string(impl_->listener.bound_port());
  }
  static_cast<void>(impl_->save_if_configured());
  Outcome outcome = Outcome::make(OutcomeCode::Committed, "coordinator started");
  outcome.steps.push_back(ExplanationStep{"start", "epoch", next_epoch.to_string(),
                                          "epoch advanced on start"});
  return outcome;
}

Outcome Coordinator::stop() {
  if (!impl_->running.load()) {
    return Outcome::make(OutcomeCode::Idempotent, "the coordinator is not running");
  }
  impl_->stopping.store(true);
  impl_->listener.shutdown_listen();
  if (impl_->accept_thread.joinable()) {
    impl_->accept_thread.join();
  }
  impl_->listener.close();
  impl_->shutdown_live_sockets();
  impl_->join_all();
  impl_->running.store(false);
  static_cast<void>(impl_->save_if_configured());
  return Outcome::make(OutcomeCode::Committed, "coordinator stopped");
}

bool Coordinator::running() const noexcept { return impl_->running.load(); }

std::uint16_t Coordinator::bound_port() const noexcept { return impl_->listener.bound_port(); }

CoordinatorEpoch Coordinator::epoch() const { return impl_->registry.epoch(); }

RegistryGeneration Coordinator::generation() const { return impl_->registry.generation(); }

CoordinatorStats Coordinator::stats() const {
  const std::lock_guard<std::mutex> guard(impl_->stats_mutex);
  CoordinatorStats snapshot = impl_->stats;
  snapshot.epoch = impl_->registry.epoch();
  snapshot.generation = impl_->registry.generation();
  return snapshot;
}

const Registry& Coordinator::registry() const { return impl_->registry; }

std::string CoordinatorStats::render() const {
  std::string out = "coordinator-stats\n";
  const auto line = [&out](const char* name, std::size_t value) {
    out.append("  ");
    out.append(name);
    out.append(" = ");
    out.append(std::to_string(value));
    out.push_back('\n');
  };
  line("sessions-accepted", sessions_accepted);
  line("sessions-completed", sessions_completed);
  line("sessions-rejected", sessions_rejected);
  line("frames-received", frames_received);
  line("frames-rejected", frames_rejected);
  line("mutations-committed", mutations_committed);
  line("mutations-rejected", mutations_rejected);
  line("queries-served", queries_served);
  line("workers-fenced", workers_fenced);
  line("saves", saves);
  line("save-failures", save_failures);
  out.append("  epoch = ");
  out.append(epoch.to_string());
  out.append("\n  registry-generation = ");
  out.append(generation.to_string());
  out.push_back('\n');
  return out;
}

} // namespace failure_domain_registry
