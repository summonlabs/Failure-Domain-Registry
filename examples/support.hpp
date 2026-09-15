// Failure Domain Registry - shared helpers for the example programs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every example is a self-contained program that uses nothing but the installed
// public API. This header carries the small amount of scaffolding they have in
// common: deterministic identifier minting, the authority handshake a local
// registry needs before it accepts any mutation, and uniform reporting. It
// deliberately contains no example-specific logic - each example builds its own
// domains, members and queries.

#ifndef FAILURE_DOMAIN_REGISTRY_EXAMPLES_SUPPORT_HPP
#define FAILURE_DOMAIN_REGISTRY_EXAMPLES_SUPPORT_HPP

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

#include "failure_domain_registry/failure_domain_registry.hpp"

namespace example {

/// Raised when an example's own precondition does not hold. main() turns it
/// into a non-zero exit status, so a broken example can never look like a
/// passing one.
class failure : public std::runtime_error {
public:
  explicit failure(const std::string& message) : std::runtime_error(message) {}
};

inline void require(bool condition, const std::string& message) {
  if (!condition) {
    throw failure(message);
  }
}

// ---------------------------------------------------------------------------
// Deterministic identities
// ---------------------------------------------------------------------------

/// Mints a deterministic, non-null 128-bit value from a label. Nothing here
/// depends on time, process state or the order the example runs in, so every
/// run of an example produces exactly the same identifiers.
inline failure_domain_registry::IdBytes bytes_from(std::string_view label) {
  const std::string framed = std::string("fdr/example/identity/v1/") + std::string(label);
  const failure_domain_registry::DigestBytes digest = failure_domain_registry::sha256(framed);
  failure_domain_registry::IdBytes bytes{};
  bool all_zero = true;
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    bytes[index] = digest[index];
    if (bytes[index] != 0) {
      all_zero = false;
    }
  }
  if (all_zero) {
    bytes[0] = 0xE1u;
  }
  return bytes;
}

template <class Id>
inline Id id_from(std::string_view label) {
  return Id::from_bytes(bytes_from(label));
}

inline failure_domain_registry::MutationAttemptId attempt_from(std::string_view label) {
  return id_from<failure_domain_registry::MutationAttemptId>(std::string("attempt/") + std::string(label));
}

inline failure_domain_registry::PublisherId publisher_from(std::string_view label) {
  return id_from<failure_domain_registry::PublisherId>(std::string("publisher/") + std::string(label));
}

inline failure_domain_registry::WorkerBootId worker_boot_from(std::string_view label) {
  return id_from<failure_domain_registry::WorkerBootId>(std::string("boot/") + std::string(label));
}

inline failure_domain_registry::EntityId entity_from(failure_domain_registry::EntityClass entity_class,
                                                     std::string_view label) {
  return failure_domain_registry::EntityId(entity_class, bytes_from(std::string("entity/") + std::string(label)));
}

inline failure_domain_registry::EntityRef entity_ref_from(failure_domain_registry::EntityClass entity_class,
                                                          std::string_view label,
                                                          std::uint64_t generation) {
  return failure_domain_registry::EntityRef(
      entity_from(entity_class, label), failure_domain_registry::EntityGeneration(generation));
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

inline failure_domain_registry::Provenance provenance_of(failure_domain_registry::ProvenanceSource source,
                                                         failure_domain_registry::EvidenceClass evidence,
                                                         failure_domain_registry::TruthClass truth,
                                                         std::string_view source_identity) {
  failure_domain_registry::Provenance provenance;
  provenance.source = source;
  provenance.evidence = evidence;
  provenance.truth = truth;
  provenance.source_identity = std::string(source_identity);
  return provenance;
}

/// Durable, operator-owned evidence: it does not depend on the process that
/// published it, so losing that process never demotes it.
inline failure_domain_registry::Provenance durable_provenance(std::string_view source_identity) {
  return provenance_of(failure_domain_registry::ProvenanceSource::OperatorInventory,
                       failure_domain_registry::EvidenceClass::DirectAuthoritativeInfrastructure,
                       failure_domain_registry::TruthClass::Real, source_identity);
}

/// Process-bound evidence: a direct reading from a live discovery process, which
/// is exactly what fencing has to demote.
inline failure_domain_registry::Provenance process_bound_provenance(std::string_view source_identity) {
  return provenance_of(failure_domain_registry::ProvenanceSource::DiscoveryAgent,
                       failure_domain_registry::EvidenceClass::DirectHardwareController,
                       failure_domain_registry::TruthClass::Real, source_identity);
}

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

/// One attached publisher incarnation: the identity every mutation is made
/// under. An unattached publisher has no authority at all, which is why the
/// examples go through this handshake instead of calling mutations directly.
struct Session {
  failure_domain_registry::PublisherId publisher{};
  failure_domain_registry::WorkerBootId worker_boot{};
  failure_domain_registry::CoordinatorEpoch epoch{};

  failure_domain_registry::AuthorityContext authority(
      failure_domain_registry::EvidenceClass evidence =
          failure_domain_registry::EvidenceClass::DirectAuthoritativeInfrastructure) const {
    failure_domain_registry::AuthorityContext context;
    context.publisher = publisher;
    context.worker_boot = worker_boot;
    context.epoch = epoch;
    context.evidence = evidence;
    return context;
  }
};

/// Establishes the coordinator epoch and installs the first publisher through
/// the documented bootstrap path: with no live session, an incomplete authority
/// context is accepted for the grant that creates authority in the first place.
inline Session open_registry(failure_domain_registry::Registry& registry, std::string_view label,
                             failure_domain_registry::AuthorityScope scope =
                                 failure_domain_registry::AuthorityScope::unrestricted(),
                             failure_domain_registry::EvidenceClass max_evidence =
                                 failure_domain_registry::EvidenceClass::DirectAuthoritativeInfrastructure) {
  Session session;
  session.publisher = publisher_from(label);
  session.worker_boot = worker_boot_from(label);

  failure_domain_registry::CoordinatorEpoch epoch;
  const failure_domain_registry::Outcome advanced = registry.advance_epoch(registry.epoch(), &epoch);
  require(advanced.committed(), "could not establish the coordinator epoch: " + advanced.render());
  session.epoch = epoch;

  failure_domain_registry::PublisherRegistration registration;
  registration.publisher = session.publisher;
  registration.name = std::string(label);
  registration.scope = scope;
  const failure_domain_registry::Outcome granted =
      registry.grant_publisher(registration, failure_domain_registry::AuthorityContext{});
  require(granted.committed(), "bootstrap publisher grant failed: " + granted.render());

  const failure_domain_registry::Outcome attached = registry.attach_worker(
      session.publisher, session.worker_boot, session.epoch, std::string(label), max_evidence);
  require(attached.committed(), "attaching the publisher incarnation failed: " + attached.render());
  return session;
}

/// Grants and attaches one further publisher. Only an unrestricted publisher may
/// grant authority, so the granter is named explicitly.
inline Session add_publisher(failure_domain_registry::Registry& registry, const Session& granter,
                             std::string_view label,
                             failure_domain_registry::AuthorityScope scope =
                                 failure_domain_registry::AuthorityScope::unrestricted(),
                             failure_domain_registry::EvidenceClass max_evidence =
                                 failure_domain_registry::EvidenceClass::DirectAuthoritativeInfrastructure) {
  Session session;
  session.publisher = publisher_from(label);
  session.worker_boot = worker_boot_from(label);
  session.epoch = granter.epoch;

  failure_domain_registry::PublisherRegistration registration;
  registration.publisher = session.publisher;
  registration.name = std::string(label);
  registration.scope = scope;
  const failure_domain_registry::Outcome granted = registry.grant_publisher(registration, granter.authority());
  require(granted.committed(), "publisher grant failed: " + granted.render());

  const failure_domain_registry::Outcome attached = registry.attach_worker(
      session.publisher, session.worker_boot, session.epoch, std::string(label), max_evidence);
  require(attached.committed(), "attaching the publisher incarnation failed: " + attached.render());
  return session;
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

inline failure_domain_registry::FailureDomainId declare_domain(
    failure_domain_registry::Registry& registry, const Session& session,
    const failure_domain_registry::DomainClassRef& domain_class, std::string_view administrative_scope,
    std::string_view identity_key, std::string_view name, std::string_view attempt_label,
    const failure_domain_registry::Provenance& provenance) {
  failure_domain_registry::CreateDomainRequest request;
  request.attempt = failure_domain_registry::MutationAttempt{attempt_from(attempt_label),
                                                             failure_domain_registry::RequestDigest{}};
  request.authority = session.authority(provenance.evidence);
  request.domain_class = domain_class;
  request.administrative_scope = std::string(administrative_scope);
  request.identity_key = std::string(identity_key);
  request.name = std::string(name);
  request.provenance = provenance;
  const failure_domain_registry::Outcome outcome = registry.create_domain(request);
  require(outcome.succeeded(), "creating domain '" + std::string(identity_key) + "' failed: " + outcome.render());
  return failure_domain_registry::domain_id_for(administrative_scope, domain_class, identity_key);
}

inline failure_domain_registry::Outcome attach_member(
    failure_domain_registry::Registry& registry, const Session& session,
    const failure_domain_registry::FailureDomainId& domain, const failure_domain_registry::EntityRef& member,
    std::string_view attempt_label, const failure_domain_registry::Provenance& provenance,
    failure_domain_registry::MembershipKind kind = failure_domain_registry::MembershipKind::Direct,
    failure_domain_registry::MembershipRole role = failure_domain_registry::MembershipRole::SharedRisk,
    failure_domain_registry::DependencySemantics dependency =
        failure_domain_registry::DependencySemantics::AnyDependencyFailureAffectsMember) {
  failure_domain_registry::AttachMemberRequest request;
  request.attempt = failure_domain_registry::MutationAttempt{attempt_from(attempt_label),
                                                             failure_domain_registry::RequestDigest{}};
  request.authority = session.authority(provenance.evidence);
  request.domain = domain;
  request.member = member;
  request.kind = kind;
  request.role = role;
  request.dependency = dependency;
  request.provenance = provenance;
  return registry.attach_member(request);
}

inline void attach_required(failure_domain_registry::Registry& registry, const Session& session,
                            const failure_domain_registry::FailureDomainId& domain,
                            const failure_domain_registry::EntityRef& member, std::string_view attempt_label,
                            const failure_domain_registry::Provenance& provenance,
                            failure_domain_registry::MembershipKind kind =
                                failure_domain_registry::MembershipKind::Direct,
                            failure_domain_registry::MembershipRole role =
                                failure_domain_registry::MembershipRole::SharedRisk) {
  const failure_domain_registry::Outcome outcome =
      attach_member(registry, session, domain, member, attempt_label, provenance, kind, role);
  require(outcome.succeeded(), "attaching " + member.to_string() + " failed: " + outcome.render());
}

inline failure_domain_registry::Outcome add_relation(
    failure_domain_registry::Registry& registry, const Session& session,
    const failure_domain_registry::FailureDomainId& source,
    const failure_domain_registry::FailureDomainId& target,
    failure_domain_registry::DomainRelationType type, std::string_view attempt_label,
    const failure_domain_registry::Provenance& provenance) {
  failure_domain_registry::AddRelationRequest request;
  request.attempt = failure_domain_registry::MutationAttempt{attempt_from(attempt_label),
                                                             failure_domain_registry::RequestDigest{}};
  request.authority = session.authority(provenance.evidence);
  request.source = source;
  request.target = target;
  request.type = type;
  request.provenance = provenance;
  return registry.add_relation(request);
}

inline failure_domain_registry::Outcome declare_coverage(
    failure_domain_registry::Registry& registry, const Session& session, std::string_view administrative_scope,
    const failure_domain_registry::DomainClassRef& domain_class,
    failure_domain_registry::CoverageState state, std::string_view attempt_label,
    const failure_domain_registry::Provenance& provenance) {
  failure_domain_registry::DeclareCoverageRequest request;
  request.attempt = failure_domain_registry::MutationAttempt{attempt_from(attempt_label),
                                                             failure_domain_registry::RequestDigest{}};
  request.authority = session.authority(provenance.evidence);
  request.administrative_scope = std::string(administrative_scope);
  request.domain_class = domain_class;
  request.state = state;
  request.provenance = provenance;
  return registry.declare_coverage(request);
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

inline void report(const failure_domain_registry::Outcome& outcome, std::string_view label) {
  std::cout << label << ": " << failure_domain_registry::to_string(outcome.code) << " - "
            << outcome.message << "\n";
}

inline std::string class_text(const failure_domain_registry::Registry& registry,
                              const failure_domain_registry::FailureDomainId& id) {
  const std::optional<failure_domain_registry::FailureDomain> record = registry.domain(id);
  return record.has_value() ? record->domain_class.to_string() : std::string("<unknown>");
}

/// One deterministic line per membership, used by several examples.
inline std::string membership_line(const failure_domain_registry::Registry& registry,
                                   const failure_domain_registry::Membership& membership) {
  std::string line = "class=";
  line.append(class_text(registry, membership.domain));
  line.append(" domain=");
  line.append(membership.domain.to_string());
  line.append(" member=");
  line.append(membership.member.to_string());
  line.append(" kind=");
  line.append(failure_domain_registry::to_string(membership.kind));
  line.append(" lifecycle=");
  line.append(failure_domain_registry::to_string(membership.lifecycle));
  return line;
}

} // namespace example

#endif // FAILURE_DOMAIN_REGISTRY_EXAMPLES_SUPPORT_HPP
