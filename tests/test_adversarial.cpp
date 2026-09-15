// Failure Domain Registry — hostile and malformed input.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every case here tries to make the registry accept something it must not, or
// to make it change state while refusing. Each refusal asserts the exact
// OutcomeCode and then asserts that the generation, the epoch, every published
// count and every membership lifecycle count are exactly where they were, and
// that validate_state still reconciles the record tables with the indexes.
// Where the registry deliberately changes state - a conflict demotes a record,
// a reset drops everything - the case asserts the change that really happens
// instead of the absence of one.
//
// Nothing is asserted through a renderer or a message alone: the enumerators
// are the contract, and the messages are only checked where the message is the
// behaviour being pinned.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "failure_domain_registry/digest.hpp"
#include "failure_domain_registry/failure_domain_registry.hpp"
#include "support/test_harness.hpp"

namespace {

using failure_domain_registry::AddRelationRequest;
using failure_domain_registry::AttachMemberRequest;
using failure_domain_registry::AuthorityContext;
using failure_domain_registry::AuthorityScope;
using failure_domain_registry::CoordinatorEpoch;
using failure_domain_registry::CoverageState;
using failure_domain_registry::CreateDomainRequest;
using failure_domain_registry::DeclareCoverageRequest;
using failure_domain_registry::DependencySemantics;
using failure_domain_registry::DerivationOperator;
using failure_domain_registry::DerivationReport;
using failure_domain_registry::DerivationRule;
using failure_domain_registry::DerivationRuleId;
using failure_domain_registry::DerivationRunRequest;
using failure_domain_registry::DetachMemberRequest;
using failure_domain_registry::DigestBytes;
using failure_domain_registry::DomainClass;
using failure_domain_registry::DomainClassRef;
using failure_domain_registry::DomainLifecycle;
using failure_domain_registry::DomainRelationType;
using failure_domain_registry::EntityClass;
using failure_domain_registry::EntityGeneration;
using failure_domain_registry::EntityId;
using failure_domain_registry::EntityInvalidationRequest;
using failure_domain_registry::EntityRef;
using failure_domain_registry::EvidenceClass;
using failure_domain_registry::FailureDomainGeneration;
using failure_domain_registry::FailureDomainId;
using failure_domain_registry::FenceReason;
using failure_domain_registry::IdBytes;
using failure_domain_registry::IndependenceState;
using failure_domain_registry::MarkRevalidationRequest;
using failure_domain_registry::Membership;
using failure_domain_registry::MembershipBatchEntry;
using failure_domain_registry::MembershipBatchRequest;
using failure_domain_registry::MembershipGeneration;
using failure_domain_registry::MembershipId;
using failure_domain_registry::MembershipKey;
using failure_domain_registry::MembershipKind;
using failure_domain_registry::MembershipLifecycle;
using failure_domain_registry::MembershipRole;
using failure_domain_registry::MetadataEntry;
using failure_domain_registry::MutationAttempt;
using failure_domain_registry::MutationAttemptId;
using failure_domain_registry::Outcome;
using failure_domain_registry::OutcomeCode;
using failure_domain_registry::Provenance;
using failure_domain_registry::ProvenanceSource;
using failure_domain_registry::PublicationMode;
using failure_domain_registry::PublisherId;
using failure_domain_registry::PublisherRegistration;
using failure_domain_registry::Registry;
using failure_domain_registry::RegistryGeneration;
using failure_domain_registry::RegistryLimits;
using failure_domain_registry::ReplaceMembershipRequest;
using failure_domain_registry::RequestDigest;
using failure_domain_registry::RetireDomainRequest;
using failure_domain_registry::TopologyChangeRequest;
using failure_domain_registry::TopologyGeneration;
using failure_domain_registry::TruthClass;
using failure_domain_registry::UpdateDomainRequest;
using failure_domain_registry::WithdrawEvidenceRequest;
using failure_domain_registry::WorkerBootId;

// ---------------------------------------------------------------------------
// Deterministic identities
// ---------------------------------------------------------------------------

IdBytes bytes_from(std::string_view label) {
  const std::string framed = std::string("fdr/test-adversarial/identity/v1/") + std::string(label);
  const DigestBytes digest = failure_domain_registry::sha256(framed);
  IdBytes bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    bytes[index] = digest[index];
  }
  bytes[0] = static_cast<std::uint8_t>(bytes[0] | 0x80u);
  return bytes;
}

template <class Id>
Id id_from(std::string_view label) {
  return Id::from_bytes(bytes_from(label));
}

PublisherId publisher_from(std::string_view label) {
  return id_from<PublisherId>(std::string("publisher/") + std::string(label));
}

WorkerBootId boot_from(std::string_view label) {
  return id_from<WorkerBootId>(std::string("boot/") + std::string(label));
}

MutationAttemptId attempt_from(std::string_view label) {
  return id_from<MutationAttemptId>(std::string("attempt/") + std::string(label));
}

EntityId entity_id(EntityClass entity_class, std::string_view label) {
  return EntityId(entity_class, bytes_from(std::string("entity/") + std::string(label)));
}

EntityRef entity_ref(EntityClass entity_class, std::string_view label, std::uint64_t generation) {
  return EntityRef(entity_id(entity_class, label), EntityGeneration(generation));
}

std::string text_of(std::size_t length, char value) { return std::string(length, value); }

Provenance provenance_of(ProvenanceSource source, EvidenceClass evidence, std::string_view identity) {
  Provenance provenance;
  provenance.source = source;
  provenance.evidence = evidence;
  provenance.truth = TruthClass::Real;
  provenance.source_identity = std::string(identity);
  return provenance;
}

/// Durable, operator-owned, strongest-class evidence.
Provenance authoritative(std::string_view identity) {
  return provenance_of(ProvenanceSource::OperatorInventory,
                       EvidenceClass::DirectAuthoritativeInfrastructure, identity);
}

/// Process-bound evidence: it dies with the incarnation that published it.
Provenance process_bound(std::string_view identity) {
  return provenance_of(ProvenanceSource::DiscoveryAgent,
                       EvidenceClass::DirectHardwareController, identity);
}

std::string describe(const Outcome& outcome) {
  std::string out = std::string(failure_domain_registry::to_string(outcome.code));
  out.append(": ");
  out.append(outcome.message);
  for (const failure_domain_registry::ExplanationStep& step : outcome.steps) {
    out.append(" | ");
    out.append(step.stage);
    out.append("/");
    out.append(step.field);
    out.append("=");
    out.append(step.value);
    out.append(" (");
    out.append(step.detail);
    out.append(")");
  }
  return out;
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

/// Everything a refused request must leave untouched. The generation alone
/// would miss an index updated without a commit, so every count the public API
/// publishes is compared and validate_state is asked to reconcile the tables.
struct Fingerprint {
  RegistryGeneration generation;
  CoordinatorEpoch epoch;
  std::size_t domains{0};
  std::size_t memberships{0};
  std::size_t sessions{0};
  std::size_t publishers{0};
  std::size_t fences{0};
  std::size_t current{0};
  std::size_t revalidation{0};
  std::size_t superseded{0};
  std::size_t retired{0};
  std::size_t conflicted{0};

  static Fingerprint capture(const Registry& registry) {
    Fingerprint out;
    out.generation = registry.generation();
    out.epoch = registry.epoch();
    out.domains = registry.domain_count();
    out.memberships = registry.membership_count();
    out.sessions = registry.live_sessions().size();
    out.publishers = registry.publishers().size();
    out.fences = registry.fences().size();
    out.current = registry.memberships_in_lifecycle(MembershipLifecycle::Current).size();
    out.revalidation =
        registry.memberships_in_lifecycle(MembershipLifecycle::RevalidationRequired).size();
    out.superseded = registry.memberships_in_lifecycle(MembershipLifecycle::Superseded).size();
    out.retired = registry.memberships_in_lifecycle(MembershipLifecycle::Retired).size();
    out.conflicted = registry.memberships_in_lifecycle(MembershipLifecycle::Conflicted).size();
    return out;
  }

  /// Empty when the registry still matches this fingerprint, otherwise the
  /// first difference found.
  std::string drift(const Registry& registry) const {
    std::string why;
    if (!registry.validate_state(&why)) {
      return "validate_state failed: " + why;
    }
    if (!(registry.generation() == generation)) {
      return "generation moved from " + generation.to_string() + " to " +
             registry.generation().to_string();
    }
    if (!(registry.epoch() == epoch)) {
      return "epoch moved from " + epoch.to_string() + " to " + registry.epoch().to_string();
    }
    if (registry.domain_count() != domains) {
      return "domain count moved from " + std::to_string(domains) + " to " +
             std::to_string(registry.domain_count());
    }
    if (registry.membership_count() != memberships) {
      return "membership count moved from " + std::to_string(memberships) + " to " +
             std::to_string(registry.membership_count());
    }
    if (registry.live_sessions().size() != sessions) {
      return "the live session set moved";
    }
    if (registry.publishers().size() != publishers) {
      return "the publisher set moved";
    }
    if (registry.fences().size() != fences) {
      return "the fence set moved";
    }
    if (registry.memberships_in_lifecycle(MembershipLifecycle::Current).size() != current ||
        registry.memberships_in_lifecycle(MembershipLifecycle::RevalidationRequired).size() !=
            revalidation ||
        registry.memberships_in_lifecycle(MembershipLifecycle::Superseded).size() != superseded ||
        registry.memberships_in_lifecycle(MembershipLifecycle::Retired).size() != retired ||
        registry.memberships_in_lifecycle(MembershipLifecycle::Conflicted).size() != conflicted) {
      return "a membership lifecycle count moved";
    }
    return std::string();
  }
};

// ---------------------------------------------------------------------------
// Sessions and fixtures
// ---------------------------------------------------------------------------

/// One publisher plus one live incarnation of it.
struct Session {
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  CoordinatorEpoch epoch{};
  Outcome granted;
  Outcome attached;

  AuthorityContext authority(
      EvidenceClass evidence = EvidenceClass::DirectAuthoritativeInfrastructure) const {
    AuthorityContext context;
    context.publisher = publisher;
    context.worker_boot = worker_boot;
    context.epoch = epoch;
    context.evidence = evidence;
    return context;
  }

  std::string problem() const {
    if (!granted.committed()) {
      return "grant: " + granted.message;
    }
    if (!attached.committed()) {
      return "attach: " + attached.message;
    }
    return std::string();
  }
};

/// A registry plus the bootstrap handshake: an epoch, the first durable grant
/// and one live incarnation of the first publisher.
struct Fixture {
  std::unique_ptr<Registry> registry;
  Outcome advanced;
  Outcome granted;
  Outcome attached;
  Session session;

  std::string problem() const {
    if (!advanced.committed()) {
      return "advance_epoch: " + advanced.message;
    }
    if (!granted.committed()) {
      return "grant_publisher: " + granted.message;
    }
    if (!attached.committed()) {
      return "attach_worker: " + attached.message;
    }
    return std::string();
  }
};

Fixture open(RegistryLimits limits = RegistryLimits::defaults()) {
  Fixture fixture;
  fixture.registry = std::make_unique<Registry>(limits);
  fixture.session.publisher = publisher_from("host");
  fixture.session.worker_boot = boot_from("host");
  fixture.advanced =
      fixture.registry->advance_epoch(CoordinatorEpoch(0), &fixture.session.epoch);
  PublisherRegistration registration;
  registration.publisher = fixture.session.publisher;
  registration.name = "host";
  registration.scope = AuthorityScope::unrestricted();
  fixture.granted = fixture.registry->grant_publisher(registration, AuthorityContext{});
  fixture.attached = fixture.registry->attach_worker(
      fixture.session.publisher, fixture.session.worker_boot, fixture.session.epoch, "host",
      EvidenceClass::DirectAuthoritativeInfrastructure);
  return fixture;
}

/// Every canonical class, with the evidence cap moved to the requested class.
/// AuthorityScope::unrestricted() names all classes but always caps evidence at
/// the strongest class, so a weaker cap is stated explicitly.
AuthorityScope unrestricted_at(EvidenceClass max_evidence) {
  AuthorityScope scope = AuthorityScope::unrestricted();
  scope.max_evidence = max_evidence;
  return scope;
}

/// Grants and attaches one further publisher. Only an unrestricted publisher
/// may grant authority, so the granter is passed explicitly.
Session add_session(Registry& registry, const AuthorityContext& granter, CoordinatorEpoch epoch,
                    std::string_view label, AuthorityScope scope, EvidenceClass max_evidence) {
  Session session;
  session.publisher = publisher_from(label);
  session.worker_boot = boot_from(label);
  session.epoch = epoch;
  PublisherRegistration registration;
  registration.publisher = session.publisher;
  registration.name = std::string(label);
  registration.scope = std::move(scope);
  session.granted = registry.grant_publisher(registration, granter);
  if (session.granted.committed()) {
    session.attached =
        registry.attach_worker(session.publisher, session.worker_boot, epoch, std::string(label),
                               max_evidence);
  } else {
    session.attached = Outcome::make(OutcomeCode::InternalFailure, "the grant did not commit");
  }
  return session;
}

// ---------------------------------------------------------------------------
// Mutation helpers
// ---------------------------------------------------------------------------

Outcome declare_domain(Registry& registry, const AuthorityContext& authority,
                       const DomainClassRef& domain_class, std::string_view scope,
                       std::string_view identity_key, std::string_view name,
                       std::string_view attempt_label, const Provenance& provenance,
                       std::vector<MetadataEntry> metadata = {}) {
  CreateDomainRequest request;
  request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
  request.authority = authority;
  request.domain_class = domain_class;
  request.administrative_scope = std::string(scope);
  request.identity_key = std::string(identity_key);
  request.name = std::string(name);
  request.provenance = provenance;
  request.metadata = std::move(metadata);
  return registry.create_domain(request);
}

Outcome attach_member(Registry& registry, const AuthorityContext& authority,
                      const FailureDomainId& domain, const EntityRef& member,
                      std::string_view attempt_label, const Provenance& provenance,
                      MembershipRole role = MembershipRole::SharedRisk,
                      MembershipKind kind = MembershipKind::Direct) {
  AttachMemberRequest request;
  request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
  request.authority = authority;
  request.domain = domain;
  request.member = member;
  request.kind = kind;
  request.role = role;
  request.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
  request.provenance = provenance;
  return registry.attach_member(request);
}

MembershipId membership_of(const FailureDomainId& domain, const EntityRef& member,
                           MembershipKind kind = MembershipKind::Direct) {
  MembershipKey key;
  key.domain = domain;
  key.member = member.id();
  key.member_generation = member.generation();
  key.kind = kind;
  return failure_domain_registry::membership_id_for(key);
}

Outcome retire_domain(Registry& registry, const AuthorityContext& authority,
                      const FailureDomainId& domain, std::string_view reason,
                      std::string_view attempt_label) {
  RetireDomainRequest request;
  request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
  request.authority = authority;
  request.domain = domain;
  request.reason = std::string(reason);
  return registry.retire_domain(request);
}

Outcome detach_member(Registry& registry, const AuthorityContext& authority,
                      const FailureDomainId& domain, const EntityRef& member,
                      MembershipGeneration expected, std::string_view attempt_label) {
  DetachMemberRequest request;
  request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
  request.authority = authority;
  request.domain = domain;
  request.member = member;
  request.expected_membership_generation = expected;
  return registry.detach_member(request);
}

Outcome replace_membership(Registry& registry, const AuthorityContext& authority,
                           const MembershipId& membership, MembershipGeneration expected,
                           std::string_view attempt_label, const Provenance& provenance) {
  ReplaceMembershipRequest request;
  request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
  request.authority = authority;
  request.membership = membership;
  request.expected_generation = expected;
  request.provenance = provenance;
  return registry.replace_membership(request);
}

Outcome withdraw_evidence(Registry& registry, const AuthorityContext& authority,
                          const MembershipId& membership, MembershipGeneration expected,
                          std::string_view attempt_label) {
  WithdrawEvidenceRequest request;
  request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
  request.authority = authority;
  request.membership = membership;
  request.expected_generation = expected;
  return registry.withdraw_evidence(request);
}

Outcome invalidate_entity(Registry& registry, const AuthorityContext& authority,
                          const EntityId& entity, std::uint64_t superseded_generation,
                          std::string_view attempt_label) {
  EntityInvalidationRequest request;
  request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
  request.authority = authority;
  request.entity = entity;
  request.superseded_generation = EntityGeneration(superseded_generation);
  return registry.invalidate_entity(request);
}

Outcome add_relation(Registry& registry, const AuthorityContext& authority,
                     const FailureDomainId& source, const FailureDomainId& target,
                     DomainRelationType type, std::string_view attempt_label,
                     const Provenance& provenance) {
  AddRelationRequest request;
  request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
  request.authority = authority;
  request.source = source;
  request.target = target;
  request.type = type;
  request.provenance = provenance;
  return registry.add_relation(request);
}

MembershipBatchRequest publication(const AuthorityContext& authority, const FailureDomainId& domain,
                                   const std::vector<EntityRef>& members,
                                   std::string_view attempt_label) {
  MembershipBatchRequest request;
  request.attempt = MutationAttempt{attempt_from(attempt_label), RequestDigest{}};
  request.authority = authority;
  request.mode = PublicationMode::Incremental;
  request.administrative_scope = "dc1";
  for (const EntityRef& member : members) {
    MembershipBatchEntry entry;
    entry.domain = domain;
    entry.member = member;
    entry.kind = MembershipKind::Direct;
    entry.role = MembershipRole::SharedRisk;
    entry.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
    entry.provenance = authoritative("inv");
    request.entries.push_back(std::move(entry));
  }
  return request;
}

FailureDomainId domain_of(std::string_view scope, const DomainClassRef& domain_class,
                          std::string_view identity_key) {
  return failure_domain_registry::domain_id_for(scope, domain_class, identity_key);
}

/// A declared domain plus the identity the caller must use to address it.
struct Declared {
  Outcome outcome;
  FailureDomainId id{};
};

Declared declare_named(Registry& registry, const AuthorityContext& authority,
                       const DomainClassRef& domain_class, std::string_view scope,
                       std::string_view identity_key, std::string_view name,
                       std::string_view attempt_label, const Provenance& provenance) {
  Declared declared;
  declared.id = domain_of(scope, domain_class, identity_key);
  declared.outcome = declare_domain(registry, authority, domain_class, scope, identity_key, name,
                                    attempt_label, provenance);
  return declared;
}

/// The common case: the canonical name of a declared domain is its identity
/// key, so the caller states the identity once.
Declared declare(Registry& registry, const AuthorityContext& authority,
                 const DomainClassRef& domain_class, std::string_view scope,
                 std::string_view identity_key, std::string_view attempt_label,
                 const Provenance& provenance) {
  return declare_named(registry, authority, domain_class, scope, identity_key, identity_key,
                       attempt_label, provenance);
}

} // namespace

// ---------------------------------------------------------------------------
// Malformed identities
// ---------------------------------------------------------------------------

FDR_TEST_CASE(adversarial, null_and_zero_identities_are_refused_with_the_exact_code) {
  Fixture fixture = open();
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::Conduit);
  const Declared domain = declare(registry, fixture.session.authority(), klass, "dc1", "conduit-1",
                                  "d1", authoritative("inv"));
  FDR_CHECK_EQ(domain.outcome.code, OutcomeCode::Committed);
  const FailureDomainId missing = domain_of("dc1", DomainClassRef(DomainClass::Device), "no-such-domain");
  const EntityRef member = entity_ref(EntityClass::Switch, "member-1", 1);
  const Provenance provenance = authoritative("inv");
  const Fingerprint before = Fingerprint::capture(registry);

  // A null attempt id is refused before anything else is examined, even though
  // the rest of the request is complete and legal.
  {
    AttachMemberRequest request;
    request.attempt = MutationAttempt{MutationAttemptId{}, RequestDigest{}};
    request.authority = fixture.session.authority();
    request.domain = domain.id;
    request.member = member;
    request.provenance = provenance;
    const Outcome refused = registry.attach_member(request);
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
    FDR_CHECK_MSG(refused.message.find("attempt id is null") != std::string::npos,
                 "a null attempt id was not the reported reason: " + describe(refused));
  }
  // Incomplete authority: each missing piece is one case, because the check is
  // on completeness and not on any single field.
  {
    AuthorityContext context = fixture.session.authority();
    context.publisher = PublisherId{};
    const Outcome refused = attach_member(registry, context, domain.id, member, "a-null-pub", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::NoAuthority);
    FDR_CHECK(!refused.message.empty());
  }
  {
    AuthorityContext context = fixture.session.authority();
    context.worker_boot = WorkerBootId{};
    const Outcome refused = attach_member(registry, context, domain.id, member, "a-null-boot", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::NoAuthority);
  }
  {
    AuthorityContext context = fixture.session.authority();
    context.epoch = CoordinatorEpoch(0);
    const Outcome refused = attach_member(registry, context, domain.id, member, "a-zero-epoch", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::NoAuthority);
    FDR_CHECK_EQ(registry.epoch(), fixture.session.epoch);
  }
  // A null FailureDomainId addresses nothing, and the registry says so: it is
  // not a malformed request, it is a request about a domain that cannot exist.
  {
    const Outcome refused =
        attach_member(registry, fixture.session.authority(), FailureDomainId{}, member, "a-null-domain",
                      provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::UnknownDomain);
  }
  // A member with no class, no bytes or no generation is not an entity at all.
  {
    const EntityRef empty_class(EntityClass::Unknown, bytes_from("member-1"), EntityGeneration(1));
    FDR_CHECK(empty_class.is_null());
    const Outcome refused = attach_member(registry, fixture.session.authority(), domain.id,
                                          empty_class, "a-unknown-class", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
  }
  {
    const EntityRef zero_bytes(EntityClass::Switch, IdBytes{}, EntityGeneration(1));
    FDR_CHECK(zero_bytes.is_null());
    const Outcome refused = attach_member(registry, fixture.session.authority(), domain.id,
                                          zero_bytes, "a-zero-bytes", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
  }
  {
    const EntityRef zero_generation(EntityClass::Switch, bytes_from("member-1"),
                                    EntityGeneration(0));
    FDR_CHECK(zero_generation.is_null());
    const Outcome refused = attach_member(registry, fixture.session.authority(), domain.id,
                                          zero_generation, "a-zero-generation", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
  }
  // The null member beats the unknown domain, so a request that is wrong twice
  // reports the fault it can prove first.
  {
    const Outcome refused = attach_member(registry, fixture.session.authority(), missing,
                                          EntityRef{}, "a-null-member", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
  }
  // A null class in a domain declaration is malformed rather than unknown.
  {
    const Outcome refused =
        declare_domain(registry, fixture.session.authority(), DomainClassRef{}, "dc1", "dc-null",
                       "dc-null", "d-null-class", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
  }
  // An unknown lifecycle value can never be a legal transition.
  {
    UpdateDomainRequest request;
    request.attempt = MutationAttempt{attempt_from("u-unknown"), RequestDigest{}};
    request.authority = fixture.session.authority();
    request.domain = domain.id;
    request.transition = static_cast<DomainLifecycle>(200);
    const Outcome refused = registry.update_domain(request);
    FDR_CHECK_EQ(refused.code, OutcomeCode::IllegalTransition);
  }
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{0});
  const std::string drift = before.drift(registry);
  FDR_CHECK_MSG(drift.empty(), "a malformed identity changed state: " + drift);
}

FDR_TEST_CASE(adversarial, unknown_enumerators_and_empty_selectors_are_malformed) {
  Fixture fixture = open();
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::Pdu);
  const Declared domain =
      declare(registry, fixture.session.authority(), klass, "dc1", "pdu-1", "d1", authoritative("inv"));
  FDR_CHECK_EQ(domain.outcome.code, OutcomeCode::Committed);
  const EntityRef member = entity_ref(EntityClass::Switch, "member-1", 1);
  const Provenance provenance = authoritative("inv");
  const Fingerprint before = Fingerprint::capture(registry);

  // An unknown membership kind would put a record in a lifecycle no reader can
  // interpret, so it is refused at validation time.
  {
    const Outcome refused = attach_member(registry, fixture.session.authority(), domain.id, member,
                                          "k-unknown", provenance, MembershipRole::SharedRisk,
                                          static_cast<MembershipKind>(200));
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
  }
  // Derived membership is never published directly: it is produced by a rule.
  {
    const Outcome refused = attach_member(registry, fixture.session.authority(), domain.id, member,
                                          "k-derived", provenance, MembershipRole::SharedRisk,
                                          MembershipKind::Derived);
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
  }
  {
    const Outcome refused = attach_member(registry, fixture.session.authority(), domain.id, member,
                                          "k-role", provenance, static_cast<MembershipRole>(200));
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
  }
  {
    AttachMemberRequest request;
    request.attempt = MutationAttempt{attempt_from("k-dependency"), RequestDigest{}};
    request.authority = fixture.session.authority();
    request.domain = domain.id;
    request.member = member;
    request.provenance = provenance;
    request.dependency = static_cast<DependencySemantics>(200);
    const Outcome refused = registry.attach_member(request);
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
  }
  // An unknown relation type has no acyclicity and no inverse, so it is not a
  // relation the graph can hold.
  {
    const Outcome refused = add_relation(registry, fixture.session.authority(), domain.id, domain.id,
                                         static_cast<DomainRelationType>(200), "r-unknown", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
  }
  // An unknown coverage state and an unknown domain class are both malformed.
  {
    DeclareCoverageRequest request;
    request.attempt = MutationAttempt{attempt_from("c-state"), RequestDigest{}};
    request.authority = fixture.session.authority();
    request.administrative_scope = "dc1";
    request.domain_class = klass;
    request.state = static_cast<CoverageState>(200);
    request.provenance = provenance;
    FDR_CHECK_EQ(registry.declare_coverage(request).code, OutcomeCode::MalformedRequest);
  }
  {
    DeclareCoverageRequest request;
    request.attempt = MutationAttempt{attempt_from("c-class"), RequestDigest{}};
    request.authority = fixture.session.authority();
    request.administrative_scope = "dc1";
    request.state = CoverageState::Complete;
    request.provenance = provenance;
    FDR_CHECK_EQ(registry.declare_coverage(request).code, OutcomeCode::MalformedRequest);
  }
  // An entity invalidation that names neither an entity nor a generation is not
  // an invalidation.
  {
    const Outcome refused =
        invalidate_entity(registry, fixture.session.authority(), entity_id(EntityClass::Switch, "x"), 0,
                          "i-zero");
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
    const Outcome refused_null =
        invalidate_entity(registry, fixture.session.authority(), EntityId{}, 1, "i-null");
    FDR_CHECK_EQ(refused_null.code, OutcomeCode::MalformedRequest);
  }
  // A topology change must name the new topology generation.
  {
    TopologyChangeRequest request;
    request.attempt = MutationAttempt{attempt_from("t-zero"), RequestDigest{}};
    request.authority = fixture.session.authority();
    request.topology_generation = TopologyGeneration(0);
    const Outcome refused = registry.notify_topology_change(request);
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
  }
  // A revalidation demand with no selector and no "everything in scope" flag
  // would have to guess what to demote, so it refuses instead.
  {
    MarkRevalidationRequest request;
    request.attempt = MutationAttempt{attempt_from("m-empty"), RequestDigest{}};
    request.authority = fixture.session.authority();
    const Outcome refused = registry.mark_revalidation_required(request);
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
    FDR_CHECK_MSG(refused.message.find("selector") != std::string::npos,
                 "an empty revalidation demand was not the reported reason: " + describe(refused));
  }
  // A membership id that was never minted is not found - including the id
  // derived from a completely null key, which is a real 128-bit value and not
  // the null id.
  {
    const MembershipId derived_from_null_key = membership_of(FailureDomainId{}, EntityRef{});
    FDR_CHECK(!derived_from_null_key.is_null());
    const Outcome refused = replace_membership(registry, fixture.session.authority(),
                                               derived_from_null_key, MembershipGeneration(1),
                                               "r-null", Provenance{});
    FDR_CHECK_EQ(refused.code, OutcomeCode::NotFound);
    const Outcome detached = detach_member(registry, fixture.session.authority(), FailureDomainId{},
                                           EntityRef{}, MembershipGeneration(0), "x-null");
    FDR_CHECK_EQ(detached.code, OutcomeCode::NotFound);
  }
  const std::string drift = before.drift(registry);
  FDR_CHECK_MSG(drift.empty(), "an unknown enumerator changed state: " + drift);
}

// ---------------------------------------------------------------------------
// Unknown entities and generations
// ---------------------------------------------------------------------------

FDR_TEST_CASE(adversarial, an_entity_nothing_has_mentioned_is_recorded_but_never_demoted) {
  Fixture fixture = open();
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::Conduit);
  const Declared domain =
      declare(registry, fixture.session.authority(), klass, "dc1", "conduit-1", "d1", authoritative("inv"));
  FDR_CHECK_EQ(domain.outcome.code, OutcomeCode::Committed);

  // Canonical entity identity belongs to Fabric Registry. A publisher telling
  // this registry about an entity nobody mentioned before is a normal
  // classification, not an error: the membership is recorded exactly as stated.
  const EntityRef stranger = entity_ref(EntityClass::Switch, "nobody-mentioned", 4);
  const Outcome attached =
      attach_member(registry, fixture.session.authority(), domain.id, stranger, "a1", authoritative("inv"));
  FDR_CHECK_EQ(attached.code, OutcomeCode::Committed);
  FDR_CHECK(attached.membership.has_value());
  const MembershipId membership_id = membership_of(domain.id, stranger);
  FDR_CHECK_EQ(*attached.membership, membership_id);
  const std::optional<Membership> recorded = registry.membership(membership_id);
  FDR_CHECK(recorded.has_value());
  FDR_CHECK_EQ(recorded->lifecycle, MembershipLifecycle::Current);
  FDR_CHECK(recorded->member == stranger);

  // Two entities with no memberships and no coverage produce no knowledge at
  // all rather than a confident answer in either direction.
  const failure_domain_registry::OverlapResult unknown = registry.overlap(
      {entity_id(EntityClass::Switch, "ghost-a"), entity_id(EntityClass::Switch, "ghost-b")});
  FDR_CHECK_EQ(unknown.state, IndependenceState::NoKnowledge);
  FDR_CHECK(unknown.shared.empty());

  // A generation that no membership carries demotes nothing: the invalidation
  // commits, reports that it re-evaluated derivations, and leaves the record
  // alone.
  {
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome outcome = invalidate_entity(registry, fixture.session.authority(),
                                              stranger.id(), stranger.generation().value() + 1, "i1");
    FDR_CHECK_EQ(outcome.code, OutcomeCode::Committed);
    FDR_CHECK_MSG(outcome.message.find("derivations were re-evaluated") != std::string::npos,
                 "a no-op invalidation did not say so: " + describe(outcome));
    FDR_CHECK_MSG(outcome.steps.size() == 1 && outcome.steps[0].stage == "invalidate",
                 "a no-op invalidation reported the wrong step: " + describe(outcome));
    FDR_CHECK_EQ(registry.generation(), RegistryGeneration(before.generation.value() + 1));
    Fingerprint expected = before;
    expected.generation = registry.generation();
    const std::string drift = expected.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "an unmatched generation changed more than the generation: " + drift);
    const std::optional<Membership> after = registry.membership(membership_id);
    FDR_CHECK(after.has_value());
    FDR_CHECK_EQ(after->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(after->generation, recorded->generation);
  }
  // The same for an entity that no record mentions at all.
  {
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome outcome = invalidate_entity(registry, fixture.session.authority(),
                                              entity_id(EntityClass::Router, "never-seen"), 1, "i2");
    FDR_CHECK_EQ(outcome.code, OutcomeCode::Committed);
    Fingerprint expected = before;
    expected.generation = registry.generation();
    const std::string drift = expected.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "invalidating an unknown entity changed state: " + drift);
  }
}

FDR_TEST_CASE(adversarial, entity_class_is_part_of_the_membership_identity) {
  Fixture fixture = open();
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::Conduit);
  const Declared domain =
      declare(registry, fixture.session.authority(), klass, "dc1", "conduit-1", "d1", authoritative("inv"));
  FDR_CHECK_EQ(domain.outcome.code, OutcomeCode::Committed);

  // The same sixteen bytes in two classes are two identities. The membership id
  // is derived from the class as well as the bytes, so it cannot collide.
  const EntityRef as_switch = entity_ref(EntityClass::Switch, "same-bytes", 1);
  const EntityRef as_port = entity_ref(EntityClass::Port, "same-bytes", 1);
  FDR_CHECK_EQ(as_switch.bytes(), as_port.bytes());
  FDR_CHECK(!(as_switch.id() == as_port.id()));
  FDR_CHECK(!(as_switch.id().to_string() == as_port.id().to_string()));
  const MembershipId switch_membership = membership_of(domain.id, as_switch);
  const MembershipId port_membership = membership_of(domain.id, as_port);
  FDR_CHECK_MSG(!(switch_membership == port_membership),
               "the same bytes in two entity classes produced one membership id");

  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), domain.id, as_switch, "a1",
                            authoritative("inv")).code,
              OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), domain.id, as_port, "a2",
                            authoritative("inv")).code,
              OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{2});

  // The overlap answer follows the identity: two class-distinct entities that
  // share a domain do share it, while the same identity addressed twice is one
  // entity and cannot overlap with itself.
  const failure_domain_registry::OverlapResult distinct = registry.overlap(as_switch.id(), as_port.id());
  FDR_CHECK_EQ(distinct.state, IndependenceState::SharedDomain);
  FDR_CHECK_EQ(distinct.shared.size(), std::size_t{1});
  FDR_CHECK_EQ(distinct.shared[0].members.size(), std::size_t{2});
  const failure_domain_registry::OverlapResult same = registry.overlap(as_switch.id(), as_switch.id());
  FDR_CHECK_EQ(same.state, IndependenceState::Unknown);
  FDR_CHECK(same.shared.empty());
  FDR_CHECK_MSG(!(distinct.state == same.state),
               "a class-contradicting entity produced the same overlap answer as the entity itself");

  // A membership whose member entity class is Unknown is malformed: there is no
  // class to derive an identity from.
  {
    const EntityRef unknown_class(EntityClass::Unknown, bytes_from("same-bytes"), EntityGeneration(1));
    const Outcome refused = attach_member(registry, fixture.session.authority(), domain.id,
                                          unknown_class, "a3", authoritative("inv"));
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
  }
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "class-distinct memberships broke the state: " + why);
}

FDR_TEST_CASE(adversarial, a_superseded_generation_demotes_only_the_memberships_that_carry_it) {
  Fixture fixture = open();
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::Conduit);
  const Declared domain =
      declare(registry, fixture.session.authority(), klass, "dc1", "conduit-1", "d1", authoritative("inv"));
  FDR_CHECK_EQ(domain.outcome.code, OutcomeCode::Committed);

  const EntityRef old_generation = entity_ref(EntityClass::Switch, "replaced", 1);
  const EntityRef new_generation = entity_ref(EntityClass::Switch, "replaced", 2);
  FDR_CHECK_EQ(old_generation.id(), new_generation.id());
  FDR_CHECK(!(old_generation == new_generation));
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), domain.id, old_generation, "a1",
                            authoritative("inv")).code,
              OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), domain.id, new_generation, "a2",
                            authoritative("inv")).code,
              OutcomeCode::Committed);
  const MembershipId old_id = membership_of(domain.id, old_generation);
  const MembershipId new_id = membership_of(domain.id, new_generation);
  FDR_CHECK(!(old_id == new_id));
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{2});
  const MembershipGeneration new_generation_before = registry.membership(new_id)->generation;

  const Outcome outcome = invalidate_entity(registry, fixture.session.authority(),
                                            old_generation.id(), 1, "i1");
  FDR_CHECK_EQ(outcome.code, OutcomeCode::Committed);
  FDR_CHECK_MSG(outcome.steps.size() == 1 && outcome.steps[0].value == "1",
               "the invalidation did not report exactly one demoted membership: " + describe(outcome));

  const std::optional<Membership> demoted = registry.membership(old_id);
  const std::optional<Membership> survivor = registry.membership(new_id);
  FDR_CHECK(demoted.has_value());
  FDR_CHECK(survivor.has_value());
  FDR_CHECK_EQ(demoted->lifecycle, MembershipLifecycle::RevalidationRequired);
  FDR_CHECK_EQ(survivor->lifecycle, MembershipLifecycle::Current);
  FDR_CHECK_EQ(survivor->generation, new_generation_before);
  FDR_CHECK(!(demoted->generation == new_generation_before));
  FDR_CHECK_EQ(registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(), std::size_t{1});
  FDR_CHECK_EQ(registry.memberships_in_lifecycle(MembershipLifecycle::RevalidationRequired).size(),
              std::size_t{1});

  // The same superseded generation again demotes nothing at all: the record is
  // already where the invalidation would put it.
  {
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome repeated = invalidate_entity(registry, fixture.session.authority(),
                                               old_generation.id(), 1, "i2");
    FDR_CHECK_EQ(repeated.code, OutcomeCode::Committed);
    FDR_CHECK_MSG(repeated.steps.size() == 1 &&
                     repeated.steps[0].detail.find("already revalidation-required") != std::string::npos,
                 "a repeated invalidation demoted something again: " + describe(repeated));
    Fingerprint expected = before;
    expected.generation = registry.generation();
    const std::string drift = expected.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a repeated invalidation changed state: " + drift);
  }
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "generation demotion broke the state: " + why);
}

// ---------------------------------------------------------------------------
// Stale generations, epochs and incarnations
// ---------------------------------------------------------------------------

FDR_TEST_CASE(adversarial, every_stale_binding_is_refused_with_its_own_code) {
  Fixture fixture = open();
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::Conduit);
  const Declared domain =
      declare(registry, fixture.session.authority(), klass, "dc1", "conduit-1", "d1", authoritative("inv"));
  FDR_CHECK_EQ(domain.outcome.code, OutcomeCode::Committed);
  const EntityRef member = entity_ref(EntityClass::Switch, "member-1", 1);
  const Provenance provenance = authoritative("inv");
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), domain.id, member, "a1", provenance).code,
              OutcomeCode::Committed);
  const MembershipId membership_id = membership_of(domain.id, member);
  const FailureDomainGeneration domain_generation = registry.domain(domain.id)->generation;
  const MembershipGeneration membership_generation = registry.membership(membership_id)->generation;

  // StaleDomain: the membership is bound to a domain generation that moved on.
  {
    AttachMemberRequest request;
    request.attempt = MutationAttempt{attempt_from("sd"), RequestDigest{}};
    request.authority = fixture.session.authority();
    request.domain = domain.id;
    request.expected_domain_generation =
        FailureDomainGeneration(domain_generation.value() + 1);
    request.member = entity_ref(EntityClass::Switch, "member-2", 1);
    request.provenance = provenance;
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = registry.attach_member(request);
    FDR_CHECK_EQ(refused.code, OutcomeCode::StaleDomain);
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a stale domain expectation changed state: " + drift);
  }
  // StaleGeneration: a domain update that names an older generation.
  {
    UpdateDomainRequest request;
    request.attempt = MutationAttempt{attempt_from("sg"), RequestDigest{}};
    request.authority = fixture.session.authority();
    request.domain = domain.id;
    request.expected_generation = FailureDomainGeneration(domain_generation.value() + 1);
    request.name = "renamed";
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = registry.update_domain(request);
    FDR_CHECK_EQ(refused.code, OutcomeCode::StaleGeneration);
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a stale generation changed state: " + drift);
    FDR_CHECK_EQ(registry.domain(domain.id)->name, std::string("conduit-1"));
  }
  // StaleGeneration on retire as well: the same field, a different path.
  {
    RetireDomainRequest request;
    request.attempt = MutationAttempt{attempt_from("sgr"), RequestDigest{}};
    request.authority = fixture.session.authority();
    request.domain = domain.id;
    request.expected_generation = FailureDomainGeneration(domain_generation.value() + 1);
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = registry.retire_domain(request);
    FDR_CHECK_EQ(refused.code, OutcomeCode::StaleGeneration);
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a stale retire changed state: " + drift);
  }
  // StaleMembership: on detach, on replace and on evidence withdrawal.
  {
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = detach_member(registry, fixture.session.authority(), domain.id, member,
                                          MembershipGeneration(membership_generation.value() + 1),
                                          "sm1");
    FDR_CHECK_EQ(refused.code, OutcomeCode::StaleMembership);
    const Outcome replaced = replace_membership(
        registry, fixture.session.authority(), membership_id,
        MembershipGeneration(membership_generation.value() + 1), "sm2", Provenance{});
    FDR_CHECK_EQ(replaced.code, OutcomeCode::StaleMembership);
    const Outcome withdrawn = withdraw_evidence(
        registry, fixture.session.authority(), membership_id,
        MembershipGeneration(membership_generation.value() + 1), "sm3");
    FDR_CHECK_EQ(withdrawn.code, OutcomeCode::StaleMembership);
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a stale membership expectation changed state: " + drift);
  }
  // StaleWorkerBoot: a fenced incarnation cannot mutate, even at the right
  // epoch and with the right scope.
  {
    FDR_CHECK_EQ(registry
                    .fence_worker(fixture.session.publisher, fixture.session.worker_boot,
                                  FenceReason::Administrative, fixture.session.epoch)
                    .code,
                OutcomeCode::Committed);
    FDR_CHECK(!registry.is_worker_live(fixture.session.publisher, fixture.session.worker_boot));
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = attach_member(registry, fixture.session.authority(), domain.id,
                                          entity_ref(EntityClass::Switch, "member-3", 1), "sb",
                                          provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::StaleWorkerBoot);
    FDR_CHECK_MSG(refused.message.find("fenced") != std::string::npos,
                 "the fenced incarnation was not the reported reason: " + describe(refused));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a fenced incarnation changed state while being refused: " + drift);
  }
  // StaleEpoch: the coordinator moved on, so the old epoch is refused before
  // the incarnation is even looked at.
  {
    CoordinatorEpoch next;
    FDR_CHECK_EQ(registry.advance_epoch(fixture.session.epoch, &next).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(next, CoordinatorEpoch(fixture.session.epoch.value() + 1));
    FDR_CHECK(!(registry.epoch() == fixture.session.epoch));
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = attach_member(registry, fixture.session.authority(), domain.id,
                                          entity_ref(EntityClass::Switch, "member-4", 1), "se",
                                          provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::StaleEpoch);
    const Outcome stale_advance = registry.advance_epoch(fixture.session.epoch, nullptr);
    FDR_CHECK_EQ(stale_advance.code, OutcomeCode::StaleEpoch);
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a stale epoch changed state: " + drift);
  }
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the stale-binding cases broke the state: " + why);
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

FDR_TEST_CASE(adversarial, a_reused_attempt_id_conflicts_unless_the_content_is_identical) {
  Fixture fixture = open();
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::Conduit);
  const Provenance provenance = authoritative("inv");
  const EntityRef member = entity_ref(EntityClass::Switch, "member-1", 1);
  const MutationAttemptId create_attempt = attempt_from("shared-create");
  const MutationAttemptId attach_attempt = attempt_from("shared-attach");
  const MutationAttemptId retire_attempt = attempt_from("shared-retire");

  // create: the same attempt id with a different identity key is a conflicting
  // replay, and the same attempt id with the same content is an exact replay.
  const Declared first = declare(registry, fixture.session.authority(), klass, "dc1", "conduit-1",
                                 "shared-create", provenance);
  FDR_CHECK_EQ(first.outcome.code, OutcomeCode::Committed);
  {
    CreateDomainRequest request;
    request.attempt = MutationAttempt{create_attempt, RequestDigest{}};
    request.authority = fixture.session.authority();
    request.domain_class = klass;
    request.administrative_scope = "dc1";
    request.identity_key = "conduit-2";
    request.name = "conduit-2";
    request.provenance = provenance;
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome conflict = registry.create_domain(request);
    FDR_CHECK_EQ(conflict.code, OutcomeCode::ConflictingReplay);
    FDR_CHECK_MSG(conflict.message.find("mutation attempt id was reused") != std::string::npos,
                 "a conflicting replay was not the reported reason: " + describe(conflict));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a conflicting create replay changed state: " + drift);
    // The identical content under the same id is recognized as a replay rather
    // than re-executed.
    request.identity_key = "conduit-1";
    request.name = "conduit-1";
    const Outcome replay = registry.create_domain(request);
    FDR_CHECK_EQ(replay.code, OutcomeCode::Idempotent);
    FDR_CHECK_MSG(replay.message.find("exact replay") != std::string::npos,
                 "an exact replay was not reported as one: " + describe(replay));
  }

  // attach: the same shape on a second operation type.
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), first.id, member,
                            "shared-attach", provenance).code,
              OutcomeCode::Committed);
  // A second domain exists so that the retire path has something real to close.
  const Declared second = declare(registry, fixture.session.authority(), klass, "dc1", "conduit-2",
                                  "make-second", provenance);
  FDR_CHECK_EQ(second.outcome.code, OutcomeCode::Committed);
  {
    AttachMemberRequest request;
    request.attempt = MutationAttempt{attach_attempt, RequestDigest{}};
    request.authority = fixture.session.authority();
    request.domain = first.id;
    request.member = entity_ref(EntityClass::Switch, "member-2", 1);
    request.role = MembershipRole::SharedRisk;
    request.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
    request.provenance = provenance;
    const Fingerprint before = Fingerprint::capture(registry);
    FDR_CHECK_EQ(registry.attach_member(request).code, OutcomeCode::ConflictingReplay);
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a conflicting attach replay changed state: " + drift);
    request.member = member;
    const Outcome replay = registry.attach_member(request);
    FDR_CHECK_EQ(replay.code, OutcomeCode::Idempotent);
    FDR_CHECK_MSG(replay.message.find("exact replay") != std::string::npos,
                 "an exact attach replay was not reported as one: " + describe(replay));
  }

  // retire: a third operation type, and the retirement really happened.
  FDR_CHECK_EQ(retire_domain(registry, fixture.session.authority(), second.id, "decommissioned",
                            "shared-retire").code,
              OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.domain(second.id)->lifecycle, DomainLifecycle::Retired);
  {
    RetireDomainRequest request;
    request.attempt = MutationAttempt{retire_attempt, RequestDigest{}};
    request.authority = fixture.session.authority();
    request.domain = second.id;
    request.reason = "decommissioned-again";
    const Fingerprint before = Fingerprint::capture(registry);
    FDR_CHECK_EQ(registry.retire_domain(request).code, OutcomeCode::ConflictingReplay);
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a conflicting retire replay changed state: " + drift);
    request.reason = "decommissioned";
    const Outcome replay = registry.retire_domain(request);
    FDR_CHECK_EQ(replay.code, OutcomeCode::Idempotent);
  }

  // A fresh attempt id with identical content is idempotent for a different
  // reason, and the message says which one: replay recognition and semantic
  // idempotence are not the same observation.
  {
    const Outcome same_content_new_id = attach_member(registry, fixture.session.authority(), first.id,
                                                      member, "fresh-id", provenance);
    FDR_CHECK_EQ(same_content_new_id.code, OutcomeCode::Idempotent);
    FDR_CHECK_MSG(same_content_new_id.message.find("exact replay") == std::string::npos,
                 "a fresh attempt id was mistaken for a replay: " + describe(same_content_new_id));
    FDR_CHECK_MSG(same_content_new_id.message.find("identical content") != std::string::npos,
                 "identical content under a fresh attempt id was not reported as such: " +
                     describe(same_content_new_id));
  }
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the replay cases broke the state: " + why);
}

// ---------------------------------------------------------------------------
// Exclusivity
// ---------------------------------------------------------------------------

FDR_TEST_CASE(adversarial, an_exclusive_class_refuses_a_second_domain_even_inside_one_publication) {
  Fixture fixture = open();
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef rack(DomainClass::Rack);
  const Provenance provenance = authoritative("inv");
  const Declared first = declare(registry, fixture.session.authority(), rack, "dc1", "rack-1",
                                 "r1", provenance);
  const Declared second = declare(registry, fixture.session.authority(), rack, "dc1", "rack-2",
                                  "r2", provenance);
  FDR_CHECK_EQ(first.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(second.outcome.code, OutcomeCode::Committed);
  FDR_CHECK(rack.is_exclusive());

  const EntityRef member = entity_ref(EntityClass::Switch, "member-1", 1);
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), first.id, member, "a1", provenance).code,
              OutcomeCode::Committed);
  {
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused =
        attach_member(registry, fixture.session.authority(), second.id, member, "a2", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::ExclusivityViolation);
    FDR_CHECK_MSG(refused.message.find("exclusive") != std::string::npos,
                 "the exclusivity refusal did not name the reason: " + describe(refused));
    FDR_CHECK_EQ(refused.related_domains.size(), std::size_t{1});
    FDR_CHECK_EQ(refused.related_domains[0], first.id);
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a refused exclusive membership changed state: " + drift);
  }
  // The same conflict inside one publication: the batch is refused whole, and
  // the registry names the other domain the member was placed in.
  {
    const EntityRef batch_member = entity_ref(EntityClass::Switch, "batch-member", 1);
    MembershipBatchRequest request = publication(fixture.session.authority(), first.id,
                                                 {batch_member}, "p1");
    MembershipBatchEntry other;
    other.domain = second.id;
    other.member = batch_member;
    other.kind = MembershipKind::Direct;
    other.role = MembershipRole::SharedRisk;
    other.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
    other.provenance = provenance;
    request.entries.push_back(std::move(other));
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = registry.publish_memberships(request);
    FDR_CHECK_EQ(refused.code, OutcomeCode::ExclusivityViolation);
    FDR_CHECK_MSG(refused.message.find("publication itself") != std::string::npos,
                 "the batch exclusivity conflict was not the reported reason: " + describe(refused));
    FDR_CHECK_EQ(refused.related_domains.size(), std::size_t{1});
    FDR_CHECK_EQ(refused.related_domains[0], first.id);
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a refused exclusive publication changed state: " + drift);
    FDR_CHECK(registry.memberships_of(batch_member.id()).empty());
  }
  // A non-exclusive class holds the same shape without complaint: exclusivity
  // is a property of the class, not a global rule.
  {
    const DomainClassRef conduit(DomainClass::Conduit);
    FDR_CHECK(!conduit.is_exclusive());
    const Declared left = declare(registry, fixture.session.authority(), conduit, "dc1", "conduit-1",
                                  "c1", provenance);
    const Declared right = declare(registry, fixture.session.authority(), conduit, "dc1", "conduit-2",
                                   "c2", provenance);
    FDR_CHECK_EQ(left.outcome.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(right.outcome.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), left.id, member, "a3", provenance).code,
                OutcomeCode::Committed);
    FDR_CHECK_EQ(
        attach_member(registry, fixture.session.authority(), right.id, member, "a4", provenance).code,
        OutcomeCode::Committed);
  }
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the exclusivity cases broke the state: " + why);
}

// ---------------------------------------------------------------------------
// Hierarchy
// ---------------------------------------------------------------------------

FDR_TEST_CASE(adversarial, a_cycle_is_rejected_and_a_chain_past_the_walk_bound_is_reported) {
  // A small cycle first, so the rejection code is pinned before the deep chain
  // makes the same shape expensive.
  {
    Fixture fixture = open();
    FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
    Registry& registry = *fixture.registry;
    const DomainClassRef rack(DomainClass::Rack);
    const Provenance provenance = authoritative("inv");
    const Declared a =
        declare_named(registry, fixture.session.authority(), rack, "dc1", "a", "a", "a", provenance);
    const Declared b =
        declare_named(registry, fixture.session.authority(), rack, "dc1", "b", "b", "b", provenance);
    const Declared c =
        declare_named(registry, fixture.session.authority(), rack, "dc1", "c", "c", "c", provenance);
    FDR_CHECK_EQ(a.outcome.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(b.outcome.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(c.outcome.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(add_relation(registry, fixture.session.authority(), a.id, b.id,
                             DomainRelationType::ContainedBy, "r1", provenance).code,
                OutcomeCode::Committed);
    FDR_CHECK_EQ(add_relation(registry, fixture.session.authority(), b.id, c.id,
                             DomainRelationType::ContainedBy, "r2", provenance).code,
                OutcomeCode::Committed);
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = add_relation(registry, fixture.session.authority(), c.id, a.id,
                                         DomainRelationType::ContainedBy, "r3", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::CycleRejected);
    FDR_CHECK_MSG(refused.message.find("cycle") != std::string::npos,
                 "a cycle was not the reported reason: " + describe(refused));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a refused cycle changed state: " + drift);
    FDR_CHECK_EQ(registry.relations_of(a.id).size(), std::size_t{1});
    // The reverse direction is a second edge and is still legitimate: the graph
    // is a chain, not a cycle.
    FDR_CHECK_EQ(add_relation(registry, fixture.session.authority(), c.id, a.id,
                             DomainRelationType::CorrelatedWith, "r4", provenance).code,
                OutcomeCode::Committed);
  }

  // A chain as deep as the default walk bound permits: closing it is a real
  // cycle, detected without recursing and without crashing.
  Fixture deep = open();
  FDR_CHECK_MSG(deep.problem().empty(), "the fixture did not open: " + deep.problem());
  Registry& registry = *deep.registry;
  const DomainClassRef rack(DomainClass::Rack);
  const Provenance provenance = authoritative("inv");
  // The depth ceiling is what bounds a containment chain, and it is enforced
  // when an edge is added, so a walk bounded by max_ancestor_walk can never
  // truncate: validate() refuses a configuration whose walk bound is below it.
  const std::size_t depth_ceiling = RegistryLimits::defaults().max_hierarchy_depth;
  FDR_CHECK_EQ(depth_ceiling, std::size_t{64});
  const std::size_t deepest = depth_ceiling + 1;
  std::vector<FailureDomainId> chain;
  chain.reserve(deepest);
  for (std::size_t index = 0; index < deepest; ++index) {
    const std::string key = "deep-" + std::to_string(index);
    const Outcome created = declare_domain(registry, deep.session.authority(), rack, "dc-deep", key,
                                           key, key, provenance);
    FDR_CHECK_MSG(created.committed(), "a chain domain was refused: " + describe(created));
    chain.push_back(domain_of("dc-deep", rack, key));
  }
  for (std::size_t index = 0; index + 1 < chain.size(); ++index) {
    const Outcome linked = add_relation(registry, deep.session.authority(), chain[index],
                                        chain[index + 1], DomainRelationType::ContainedBy,
                                        "deep-r" + std::to_string(index), provenance);
    FDR_CHECK_MSG(linked.committed(), "a chain edge was refused: " + describe(linked));
  }
  FDR_CHECK_EQ(registry.domain_count(), deepest);
  // The chain is exactly as deep as the ceiling admits: every domain is
  // reachable, and no walk truncates.
  FDR_CHECK_EQ(registry.ancestors(chain[0]).size(), deepest - 1);
  FDR_CHECK_EQ(registry.descendants(chain[deepest - 1]).size(), deepest - 1);
  {
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = add_relation(registry, deep.session.authority(), chain[deepest - 1],
                                         chain[0], DomainRelationType::ContainedBy, "deep-close",
                                         provenance);
    // The chain already sits at the depth ceiling, so closing it is refused by
    // the depth rule before the cycle rule is consulted. Both are correct
    // refusals of an illegal edge; neither is accepted.
    FDR_CHECK(refused.code == OutcomeCode::CycleRejected ||
              refused.code == OutcomeCode::InvalidHierarchy);
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "closing the permitted-depth chain changed state: " + drift);
  }
  // One domain deeper and the depth ceiling itself refuses the edge: the chain
  // already sits at max_hierarchy_depth, and a containment edge is measured when
  // it is added. Because that ceiling bounds every chain, the read-only walks can
  // never truncate: they always return the whole reachable set.
  {
    const std::string key = "deep-" + std::to_string(deepest);
    FDR_CHECK_EQ(declare_domain(registry, deep.session.authority(), rack, "dc-deep", key, key, key,
                               provenance).code,
                OutcomeCode::Committed);
    const FailureDomainId last = domain_of("dc-deep", rack, key);
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = add_relation(registry, deep.session.authority(), chain[deepest - 1],
                                        last, DomainRelationType::ContainedBy, "deep-extend",
                                        provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::InvalidHierarchy);
    FDR_CHECK_MSG(refused.message.find("max_hierarchy_depth") != std::string::npos,
                 "the depth ceiling was not the reported reason: " + describe(refused));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a refused depth-ceiling edge changed state: " + drift);
    // The refused edge is not in the graph, so the new domain stays isolated and
    // the chain is untouched and still fully walkable.
    FDR_CHECK_EQ(registry.relations_of(last).size(), std::size_t{0});
    FDR_CHECK_EQ(registry.descendants(last).size(), std::size_t{0});
    // Containment points from the contained domain to its container, so the
    // outermost domain is the one with a full descendant set, and the walk from
    // the innermost domain reaches every container.
    FDR_CHECK_EQ(registry.descendants(chain[deepest - 1]).size(), deepest - 1);
    FDR_CHECK_EQ(registry.ancestors(chain[0]).size(), deepest - 1);
  }
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the deep chain broke the state: " + why);
}

// ---------------------------------------------------------------------------
// Duplicate membership
// ---------------------------------------------------------------------------

FDR_TEST_CASE(adversarial, duplicate_memberships_are_malformed_idempotent_or_shared) {
  Fixture fixture = open();
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::Conduit);
  const Provenance provenance = authoritative("inv");
  const Declared domain =
      declare(registry, fixture.session.authority(), klass, "dc1", "conduit-1", "d1", provenance);
  FDR_CHECK_EQ(domain.outcome.code, OutcomeCode::Committed);
  const EntityRef member = entity_ref(EntityClass::Switch, "member-1", 1);
  const MembershipId membership_id = membership_of(domain.id, member);

  // The same membership twice inside one publication is a malformed request:
  // the caller has stated the same fact twice and the registry will not guess
  // which of the two entries it meant.
  {
    MembershipBatchRequest request = publication(fixture.session.authority(), domain.id, {member}, "p1");
    request.entries.push_back(request.entries[0]);
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = registry.publish_memberships(request);
    FDR_CHECK_EQ(refused.code, OutcomeCode::MalformedRequest);
    FDR_CHECK_MSG(refused.message.find("same membership twice") != std::string::npos,
                 "a duplicated batch membership was not the reported reason: " + describe(refused));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a duplicated publication changed state: " + drift);
    FDR_CHECK_EQ(registry.membership_count(), std::size_t{0});
  }
  // Attaching the same membership twice is idempotent: the second call states
  // exactly what the first one did.
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), domain.id, member, "a1", provenance).code,
              OutcomeCode::Committed);
  {
    const MembershipGeneration generation = registry.membership(membership_id)->generation;
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome again = attach_member(registry, fixture.session.authority(), domain.id, member, "a2",
                                        provenance);
    FDR_CHECK_EQ(again.code, OutcomeCode::Idempotent);
    FDR_CHECK_MSG(again.message.find("already exists") != std::string::npos,
                 "an identical second attach was not reported as such: " + describe(again));
    FDR_CHECK(again.membership.has_value());
    FDR_CHECK_EQ(*again.membership, membership_id);
    FDR_CHECK_EQ(registry.membership_count(), std::size_t{1});
    FDR_CHECK_EQ(registry.membership(membership_id)->generation, generation);
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "an idempotent attach changed state: " + drift);
  }
  // Two publishers that state the same fact share one membership record: the
  // identity is derived from the domain, the member generation and the kind,
  // never from the publisher.
  {
    Session second = add_session(registry, fixture.session.authority(), fixture.session.epoch,
                                 "second", AuthorityScope::unrestricted(),
                                 EvidenceClass::DirectAuthoritativeInfrastructure);
    FDR_CHECK_MSG(second.problem().empty(), "the second publisher did not attach: " + second.problem());
    const RegistryGeneration before_generation = registry.generation();
    const std::size_t before_domains = registry.domain_count();
    const Outcome shared = attach_member(registry, second.authority(), domain.id, member, "a3", provenance);
    // Corroboration is recorded, not discarded: an equal-rank attestation from a
    // different authority is a second claim about the same fact, so it is added
    // to the one record rather than being mistaken for an exact replay.
    FDR_CHECK_EQ(shared.code, OutcomeCode::Committed);
    FDR_CHECK(shared.membership.has_value());
    FDR_CHECK_MSG(*shared.membership == membership_id,
                 "two publishers produced two membership ids for the same fact");
    FDR_CHECK_EQ(registry.membership_count(), std::size_t{1});
    FDR_CHECK_EQ(registry.domain_count(), before_domains);
    // Corroboration is a committed change: it adds an evidence entry and moves
    // the registry generation. What must not move is the record count and the
    // record identity.
    FDR_CHECK(registry.generation() != before_generation);
    FDR_CHECK_EQ(registry.membership(*shared.membership)->live_evidence_count(), std::size_t{2});

    // The same publisher stating something different about the same key updates
    // the one record and adds its own attestation, so the count still does not
    // grow while the evidence list does.
    const Outcome updated = attach_member(registry, second.authority(), domain.id, member, "a4",
                                          provenance, MembershipRole::Primary);
    FDR_CHECK_EQ(updated.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(registry.membership_count(), std::size_t{1});
    const std::optional<Membership> record = registry.membership(membership_id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(record->role, MembershipRole::Primary);
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{3});
    FDR_CHECK_EQ(record->live_evidence_count(), std::size_t{3});
    FDR_CHECK_EQ(record->generation, MembershipGeneration(3));
  }
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the duplicate membership cases broke the state: " + why);
}

// ---------------------------------------------------------------------------
// Conflicting provenance
// ---------------------------------------------------------------------------

FDR_TEST_CASE(adversarial, equal_rank_disagreement_conflicts_and_a_weaker_class_is_rejected) {
  Fixture fixture = open();
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::Pdu);

  // Two equally strong classifications from different sources disagree: the
  // domain is marked CONFLICTED and stops carrying authority.
  const Declared original = declare(registry, fixture.session.authority(), klass, "dc1", "pdu-1",
                                    "d1", authoritative("inv-1"));
  FDR_CHECK_EQ(original.outcome.code, OutcomeCode::Committed);
  const FailureDomainGeneration first_generation = registry.domain(original.id)->generation;
  {
    // A tie is between two authorities: the rival statement comes from a
    // different publisher, not from the publisher that made the first one.
    Session rival = add_session(registry, fixture.session.authority(), fixture.session.epoch,
                                "rival", AuthorityScope::unrestricted(),
                                EvidenceClass::DirectAuthoritativeInfrastructure);
    FDR_CHECK_MSG(rival.problem().empty(), "the rival publisher did not attach: " + rival.problem());
    const Provenance other_source = provenance_of(
        ProvenanceSource::Cmdb, EvidenceClass::DirectAuthoritativeInfrastructure, "cmdb-1");
    const Outcome conflict =
        declare_domain(registry, rival.authority(), klass, "dc1", "pdu-1", "pdu-1",
                       "d2", other_source);
    FDR_CHECK_EQ(conflict.code, OutcomeCode::DomainConflict);
    FDR_CHECK_EQ(registry.domain(original.id)->lifecycle, DomainLifecycle::Conflicted);
    FDR_CHECK_EQ(registry.domain(original.id)->generation,
                FailureDomainGeneration(first_generation.value() + 1));
  }
  // The same disagreement on a membership.
  const DomainClassRef conduit(DomainClass::Conduit);
  const Declared member_domain = declare(registry, fixture.session.authority(), conduit, "dc1",
                                         "conduit-1", "c1", authoritative("inv-1"));
  FDR_CHECK_EQ(member_domain.outcome.code, OutcomeCode::Committed);
  const EntityRef member = entity_ref(EntityClass::Switch, "member-1", 1);
  const Provenance first_hand = process_bound("discovery-1");
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), member_domain.id, member, "a1",
                            first_hand).code,
              OutcomeCode::Committed);
  const MembershipId membership_id = membership_of(member_domain.id, member);
  const MembershipGeneration first_membership_generation = registry.membership(membership_id)->generation;
  {
    const Provenance second_hand = provenance_of(
        ProvenanceSource::VendorController, EvidenceClass::DirectHardwareController, "vendor-1");
    const Outcome conflict = attach_member(registry, fixture.session.authority(), member_domain.id,
                                           member, "a2", second_hand);
    FDR_CHECK_EQ(conflict.code, OutcomeCode::MembershipConflict);
    const std::optional<Membership> record = registry.membership(membership_id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Conflicted);
    FDR_CHECK_EQ(record->generation,
                MembershipGeneration(first_membership_generation.value() + 1));
  }
  // A weaker class can never replace a stronger one, on any path.
  {
    const Provenance weak = provenance_of(ProvenanceSource::DiscoveryAgent, EvidenceClass::Synthetic,
                                          "synthetic-1");
    const Fingerprint before = Fingerprint::capture(registry);
    // create_domain over an existing stronger record.
    const Outcome created = declare_domain(registry, fixture.session.authority(), conduit, "dc1",
                                           "conduit-1", "conduit-1", "w1", weak);
    FDR_CHECK_EQ(created.code, OutcomeCode::PolicyRejected);
    // update_domain asserting weaker provenance for the same record.
    UpdateDomainRequest update;
    update.attempt = MutationAttempt{attempt_from("w2"), RequestDigest{}};
    update.authority = fixture.session.authority(EvidenceClass::Synthetic);
    update.domain = member_domain.id;
    update.provenance = weak;
    FDR_CHECK_EQ(registry.update_domain(update).code, OutcomeCode::PolicyRejected);
    // attach_member re-asserting a membership with weaker evidence.
    const Outcome attached = attach_member(registry, fixture.session.authority(EvidenceClass::Synthetic),
                                           member_domain.id, member, "w3", weak,
                                           MembershipRole::Primary);
    FDR_CHECK_EQ(attached.code, OutcomeCode::PolicyRejected);
    // publish_memberships walking the same comparison in its validation phase.
    MembershipBatchRequest request = publication(fixture.session.authority(EvidenceClass::Synthetic),
                                                 member_domain.id, {member}, "w4");
    request.entries[0].provenance = weak;
    request.entries[0].role = MembershipRole::Primary;
    FDR_CHECK_EQ(registry.publish_memberships(request).code, OutcomeCode::PolicyRejected);
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a weaker provenance assertion changed state: " + drift);
  }
  // The stronger record survives every one of those attempts untouched.
  FDR_CHECK_EQ(registry.membership(membership_id)->provenance.evidence,
              EvidenceClass::DirectHardwareController);
  FDR_CHECK_EQ(registry.domain(member_domain.id)->provenance.evidence,
              EvidenceClass::DirectAuthoritativeInfrastructure);
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the provenance cases broke the state: " + why);
}

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

FDR_TEST_CASE(adversarial, unauthorized_publishers_are_refused_by_the_exact_reason) {
  Fixture fixture = open();
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef rack(DomainClass::Rack);
  const DomainClassRef pdu(DomainClass::Pdu);
  const Provenance provenance = authoritative("inv");

  // A publisher nobody ever granted has no authority at all, even when its
  // context is complete and its epoch is current.
  {
    AuthorityContext stranger = fixture.session.authority();
    stranger.publisher = publisher_from("never-granted");
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = declare_domain(registry, stranger, rack, "dc1", "rack-1", "r1", "ng",
                                           provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::StaleAuthority);
    FDR_CHECK_MSG(refused.message.find("not registered") != std::string::npos,
                 "an unregistered publisher was not the reported reason: " + describe(refused));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "an unregistered publisher changed state: " + drift);
  }

  // A registered publisher confined to one administrative scope and one class.
  AuthorityScope confined = AuthorityScope::for_classes({DomainClass::Rack},
                                                         EvidenceClass::DirectAuthoritativeInfrastructure);
  confined.administrative_scope = "dc-a";
  Session scoped = add_session(registry, fixture.session.authority(), fixture.session.epoch, "scoped",
                               confined, EvidenceClass::DirectAuthoritativeInfrastructure);
  FDR_CHECK_MSG(scoped.problem().empty(), "the scoped publisher did not attach: " + scoped.problem());
  {
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = declare_domain(registry, scoped.authority(), rack, "dc-b", "rack-1",
                                           "r1", "s1", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::UnauthorizedScope);
    FDR_CHECK_MSG(refused.message.find("administrative scope") != std::string::npos,
                 "an out-of-scope mutation was not the reported reason: " + describe(refused));
    // In scope but outside the granted classes.
    const Outcome wrong_class = declare_domain(registry, scoped.authority(), pdu, "dc-a", "pdu-1",
                                               "p1", "s2", provenance);
    FDR_CHECK_EQ(wrong_class.code, OutcomeCode::UnauthorizedScope);
    FDR_CHECK_MSG(wrong_class.message.find("domain class") != std::string::npos,
                 "an out-of-class mutation was not the reported reason: " + describe(wrong_class));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "an out-of-scope publisher changed state: " + drift);
  }

  // A publisher whose grant caps it at synthetic evidence may not assert a
  // hardware-derived class, even though the class itself is a real one.
  Session capped = add_session(registry, fixture.session.authority(), fixture.session.epoch,
                               "capped", unrestricted_at(EvidenceClass::Synthetic),
                               EvidenceClass::Synthetic);
  FDR_CHECK_MSG(capped.problem().empty(), "the capped publisher did not attach: " + capped.problem());
  {
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused = declare_domain(registry, capped.authority(), rack, "dc1", "rack-2",
                                           "r2", "c1", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::UnauthorizedScope);
    FDR_CHECK_MSG(refused.message.find("evidence class") != std::string::npos,
                 "a too-strong evidence claim was not the reported reason: " + describe(refused));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a too-strong evidence claim changed state: " + drift);
    // The same publisher may assert exactly what it was granted.
    const Provenance synthetic = provenance_of(ProvenanceSource::SyntheticTestSource,
                                               EvidenceClass::Synthetic, "synthetic-1");
    FDR_CHECK_EQ(declare_domain(registry, capped.authority(EvidenceClass::Synthetic), rack, "dc1",
                               "rack-2", "r2", "c2", synthetic).code,
                OutcomeCode::Committed);
  }
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the authority cases broke the state: " + why);
}

// ---------------------------------------------------------------------------
// Extension namespaces
// ---------------------------------------------------------------------------

FDR_TEST_CASE(adversarial, forged_extension_namespaces_are_refused_and_never_exclusive) {
  // Well-formed extensions parse, classify as Custom and are never exclusive.
  const std::optional<DomainClassRef> vendor = DomainClassRef::parse("vendor:acme/power-node");
  const std::optional<DomainClassRef> admin = DomainClassRef::parse("admin:dc1/row-label");
  FDR_CHECK(vendor.has_value());
  FDR_CHECK(admin.has_value());
  FDR_CHECK(!vendor->is_canonical());
  FDR_CHECK(vendor->is_extension());
  FDR_CHECK_EQ(vendor->classification(), DomainClass::Custom);
  FDR_CHECK(!vendor->is_exclusive());
  FDR_CHECK_EQ(vendor->to_string(), std::string("vendor:acme/power-node"));
  FDR_CHECK_EQ(admin->classification(), DomainClass::Custom);
  FDR_CHECK(!admin->is_exclusive());
  FDR_CHECK_EQ(admin->to_string(), std::string("admin:dc1/row-label"));

  // The namespace component is bounded and restricted, and both components must
  // be present.
  FDR_CHECK(DomainClassRef::extension("vendor", "acme", "power-node").has_value());
  FDR_CHECK(DomainClassRef::extension("admin", "dc1", "row-label").has_value());
  FDR_CHECK(!DomainClassRef::extension("bogus", "acme", "power-node").has_value());
  FDR_CHECK(!DomainClassRef::extension("vendor", std::string(), "power-node").has_value());
  FDR_CHECK(!DomainClassRef::extension("vendor", "acme", std::string()).has_value());
  FDR_CHECK(DomainClassRef::extension("vendor", text_of(64, 'a'), text_of(96, 'b')).has_value());
  FDR_CHECK(!DomainClassRef::extension("vendor", text_of(65, 'a'), "name").has_value());
  FDR_CHECK(!DomainClassRef::extension("vendor", "acme", text_of(97, 'b')).has_value());

  const std::string long_namespace = text_of(65, 'a');
  const std::string long_name = text_of(97, 'b');
  const std::string control_namespace = std::string("ac") + static_cast<char>(0x01) + "me";
  const std::string control_name = std::string("na") + static_cast<char>(0x7f) + "me";

  FDR_CHECK(!DomainClassRef::parse(std::string()).has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:acme").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:/power-node").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:acme/").has_value());
  FDR_CHECK(!DomainClassRef::parse("/acme/power-node").has_value());
  FDR_CHECK(!DomainClassRef::parse(":acme/power-node").has_value());
  FDR_CHECK(!DomainClassRef::parse("unknown:acme/power-node").has_value());
  FDR_CHECK(!DomainClassRef::parse("Vendor:acme/power-node").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:Acme/power-node").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:acme/Power-Node").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:acme/power node").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:acme/power/node").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:acme/power-node ").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:acme/power-node:extra").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:" + long_namespace + "/power-node").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:acme/" + long_name).has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:" + control_namespace + "/power-node").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:acme/" + control_name).has_value());
  FDR_CHECK(!DomainClassRef::parse("rack/1").has_value());

  // A segment made only of dots is a path component, not a namespace or name
  // component, so it is refused rather than accepted as opaque text.
  FDR_CHECK(!DomainClassRef::parse("vendor:../..").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:./x").has_value());
  FDR_CHECK(!DomainClassRef::parse("admin:x/..").has_value());
  FDR_CHECK(!DomainClassRef::parse("vendor:.../x").has_value());
  // A dot inside a segment is still ordinary, as long as the segment carries at
  // least one other character.
  const std::optional<DomainClassRef> dotted = DomainClassRef::parse("vendor:acme.inc/x-1");
  FDR_CHECK(dotted.has_value());
  FDR_CHECK_EQ(dotted->classification(), DomainClass::Custom);
  FDR_CHECK(!dotted->is_exclusive());

  // Through the public API a vendor class is usable, is not exclusive, and two
  // domains of it may hold the same member at once.
  Fixture fixture = open();
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef extension = *vendor;
  const Provenance provenance = authoritative("inv");
  const Declared left = declare_named(registry, fixture.session.authority(), extension, "dc1",
                                      "vendor-a", "a", "v1", provenance);
  const Declared right = declare_named(registry, fixture.session.authority(), extension, "dc1",
                                       "vendor-b", "b", "v2", provenance);
  FDR_CHECK_EQ(left.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(right.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.domain(left.id)->domain_class.classification(), DomainClass::Custom);
  const EntityRef member = entity_ref(EntityClass::Switch, "member-1", 1);
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), left.id, member, "v3", provenance).code,
              OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), right.id, member, "v4", provenance).code,
              OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{2});
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the extension cases broke the state: " + why);
}

// ---------------------------------------------------------------------------
// Resource exhaustion
// ---------------------------------------------------------------------------

FDR_TEST_CASE(adversarial, exhausting_every_bound_leaves_a_consistent_registry) {
  RegistryLimits limits = RegistryLimits::defaults();
  limits.max_domains = 2;
  limits.max_memberships = 2;
  limits.max_relations = 1;
  limits.max_publishers = 2;
  limits.max_coverage_declarations = 1;
  limits.max_metadata_entries = 1;
  limits.max_evidence_per_membership = 1;
  limits.max_members_per_batch = 1;
  limits.max_query_set_cardinality = 1;
  limits.max_history_entries_per_record = 1;
  Fixture fixture = open(limits);
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef rack(DomainClass::Rack);
  const DomainClassRef pdu(DomainClass::Pdu);
  const Provenance provenance = authoritative("inv");

  // Domains: two fit, the third does not.
  const Declared first = declare_named(registry, fixture.session.authority(), rack, "dc1", "rack-1",
                                       "r1", "d1", provenance);
  const Declared second = declare_named(registry, fixture.session.authority(), pdu, "dc1", "pdu-1",
                                        "p1", "d2", provenance);
  FDR_CHECK_EQ(first.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(second.outcome.code, OutcomeCode::Committed);
  const Outcome third_domain =
      declare_named(registry, fixture.session.authority(), rack, "dc1", "rack-2", "r2", "d3",
                    provenance)
          .outcome;
  FDR_CHECK_EQ(third_domain.code, OutcomeCode::ResourceLimit);
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{2});

  // Metadata: one entry fits, two do not.
  {
    const Outcome refused = declare_domain(registry, fixture.session.authority(), rack, "dc1",
                                           "rack-3", "r3", "d4", provenance,
                                           {MetadataEntry{"a", "1"}, MetadataEntry{"b", "2"}});
    FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
  }

  // Memberships: two fit, the third does not.
  const EntityRef member_a = entity_ref(EntityClass::Switch, "member-a", 1);
  const EntityRef member_b = entity_ref(EntityClass::Switch, "member-b", 1);
  const EntityRef member_c = entity_ref(EntityClass::Switch, "member-c", 1);
  FDR_CHECK_EQ(
      attach_member(registry, fixture.session.authority(), first.id, member_a, "m1", provenance).code,
      OutcomeCode::Committed);
  FDR_CHECK_EQ(
      attach_member(registry, fixture.session.authority(), second.id, member_b, "m2", provenance).code,
      OutcomeCode::Committed);
  const Outcome third_membership =
      attach_member(registry, fixture.session.authority(), first.id, member_c, "m3", provenance);
  FDR_CHECK_EQ(third_membership.code, OutcomeCode::ResourceLimit);
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{2});

  // Corroboration: the bound is one, so the second evidence entry is refused.
  {
    const MembershipId membership_id = membership_of(first.id, member_a);
    const Outcome refused = attach_member(registry, fixture.session.authority(), first.id, member_a,
                                          "m4", provenance, MembershipRole::Primary);
    FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
    FDR_CHECK_EQ(registry.membership(membership_id)->evidence.size(), std::size_t{1});
  }

  // Publications: a batch of one is inside max_members_per_batch, a batch of two
  // is not, and every refusal is whole-publication rather than partial.
  {
    const Fingerprint before = Fingerprint::capture(registry);
    MembershipBatchRequest request =
        publication(fixture.session.authority(), first.id, {member_c}, "p1");
    // The bulk path consults max_memberships exactly like the single-attach
    // path does, and the publication is refused before anything is applied.
    FDR_CHECK_EQ(registry.publish_memberships(request).code, OutcomeCode::ResourceLimit);
    FDR_CHECK_EQ(registry.membership_count(), std::size_t{2});
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a refused publication changed state: " + drift);
  }
  {
    MembershipBatchRequest oversized =
        publication(fixture.session.authority(), first.id, {member_c}, "p2");
    MembershipBatchEntry extra;
    extra.domain = first.id;
    extra.member = entity_ref(EntityClass::Switch, "member-d", 1);
    extra.kind = MembershipKind::Direct;
    extra.role = MembershipRole::SharedRisk;
    extra.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
    extra.provenance = provenance;
    oversized.entries.push_back(std::move(extra));
    const Fingerprint before = Fingerprint::capture(registry);
    // Two entries exceed max_members_per_batch, which is checked first; the batch
    // bound and the membership bound both refuse the whole publication.
    FDR_CHECK_EQ(registry.publish_memberships(oversized).code, OutcomeCode::ResourceLimit);
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a refused oversized publication changed state: " + drift);
  }

  // No publication path can take the registry past the configured bound: the
  // count sits exactly at max_memberships and stays there.
  FDR_CHECK_EQ(registry.membership_count(), limits.max_memberships);
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{2});

  // Relations: one edge fits, the second does not.
  FDR_CHECK_EQ(add_relation(registry, fixture.session.authority(), first.id, second.id,
                           DomainRelationType::CorrelatedWith, "r1", provenance).code,
              OutcomeCode::Committed);
  // A symmetric relation canonicalises its endpoint order, so the reverse
  // CorrelatedWith edge would be the same edge and is idempotent; a directed
  // type is a genuinely new edge, which the bound then refuses.
  FDR_CHECK_EQ(add_relation(registry, fixture.session.authority(), second.id, first.id,
                           DomainRelationType::DependsOn, "r2", provenance).code,
              OutcomeCode::ResourceLimit);
  FDR_CHECK_EQ(registry.relations_of(first.id).size(), std::size_t{1});

  // Coverage: one declaration fits, the second does not.
  {
    DeclareCoverageRequest declaration;
    declaration.attempt = MutationAttempt{attempt_from("c1"), RequestDigest{}};
    declaration.authority = fixture.session.authority();
    declaration.administrative_scope = "dc1";
    declaration.domain_class = rack;
    declaration.state = CoverageState::Complete;
    declaration.provenance = provenance;
    FDR_CHECK_EQ(registry.declare_coverage(declaration).code, OutcomeCode::Committed);
    declaration.attempt = MutationAttempt{attempt_from("c2"), RequestDigest{}};
    declaration.domain_class = pdu;
    FDR_CHECK_EQ(registry.declare_coverage(declaration).code, OutcomeCode::ResourceLimit);
  }

  // Publishers: the fixture holds one grant, one more fits, the third does not.
  {
    Session extra = add_session(registry, fixture.session.authority(), fixture.session.epoch, "extra",
                                AuthorityScope::unrestricted(),
                                EvidenceClass::DirectAuthoritativeInfrastructure);
    FDR_CHECK_MSG(extra.problem().empty(), "the second grant did not fit: " + extra.problem());
    PublisherRegistration third;
    third.publisher = publisher_from("third");
    third.name = "third";
    third.scope = AuthorityScope::unrestricted();
    FDR_CHECK_EQ(registry.grant_publisher(third, fixture.session.authority()).code,
                OutcomeCode::ResourceLimit);
    FDR_CHECK_EQ(registry.publishers().size(), std::size_t{2});
  }

  // A query set past the cardinality bound is truncated rather than refused, and
  // the registry is still usable after every refusal above.
  {
    const failure_domain_registry::OverlapResult truncated =
        registry.overlap({member_a.id(), member_b.id()});
    FDR_CHECK(truncated.truncated);
    FDR_CHECK_EQ(truncated.state, IndependenceState::Unknown);
  }
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{2});
  // The count never went past the configured bound: the bulk publication path
  // consults max_memberships exactly like the single-attach path does.
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{2});
  FDR_CHECK_EQ(registry.membership_count(), limits.max_memberships);
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "resource exhaustion left the state inconsistent: " + why);
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

FDR_TEST_CASE(adversarial, reset_drops_everything_but_the_epoch_and_the_old_incarnation_stays_dead) {
  Fixture fixture = open();
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef klass(DomainClass::Rack);
  const Provenance provenance = authoritative("inv");
  const Declared domain = declare_named(registry, fixture.session.authority(), klass, "dc1",
                                        "rack-1", "r1", "d1", provenance);
  FDR_CHECK_EQ(domain.outcome.code, OutcomeCode::Committed);
  const EntityRef member = entity_ref(EntityClass::Switch, "member-1", 1);
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), domain.id, member, "a1",
                            process_bound("discovery")).code,
              OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{1});
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{1});
  const CoordinatorEpoch preserved = registry.epoch();
  const CoordinatorEpoch before_reset = preserved;
  FDR_CHECK(!preserved.is_zero());

  const Outcome reset = registry.reset();
  FDR_CHECK_EQ(reset.code, OutcomeCode::Committed);
  FDR_CHECK_MSG(reset.steps.size() == 1 && reset.steps[0].stage == "reset",
               "the reset outcome does not report what it dropped: " + describe(reset));

  // Everything the reset drops: records, indexes, grants, sessions, fences and
  // the idempotency table. The epoch is not one of them.
  FDR_CHECK_EQ(registry.domain_count(), std::size_t{0});
  FDR_CHECK_EQ(registry.membership_count(), std::size_t{0});
  FDR_CHECK(registry.live_sessions().empty());
  FDR_CHECK(registry.publishers().empty());
  FDR_CHECK(registry.fences().empty());
  FDR_CHECK(registry.epoch() == before_reset);
  FDR_CHECK_EQ(registry.epoch(), preserved);
  FDR_CHECK(!registry.is_worker_live(fixture.session.publisher, fixture.session.worker_boot));
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the reset left the state inconsistent: " + why);

  // Traffic that carries the pre-reset incarnation is refused: the grant is
  // gone, so the publisher is unknown before the incarnation is even looked at.
  {
    const Outcome refused = declare_domain(registry, fixture.session.authority(), klass, "dc1",
                                           "rack-1", "r1", "after-reset", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::StaleAuthority);
    FDR_CHECK_MSG(refused.message.find("not registered") != std::string::npos,
                 "the pre-reset publisher was not the reported reason: " + describe(refused));
    FDR_CHECK_EQ(registry.domain_count(), std::size_t{0});
  }

  // The preserved epoch is the live one: a bootstrap grant is legal again (no
  // session exists), the old epoch is not current, and the preserved epoch is.
  Session fresh;
  fresh.publisher = publisher_from("after-reset");
  fresh.worker_boot = boot_from("after-reset");
  fresh.epoch = before_reset;
  PublisherRegistration registration;
  registration.publisher = fresh.publisher;
  registration.name = "after-reset";
  registration.scope = AuthorityScope::unrestricted();
  fresh.granted = registry.grant_publisher(registration, AuthorityContext{});
  FDR_CHECK_EQ(fresh.granted.code, OutcomeCode::Committed);
  fresh.attached = registry.attach_worker(fresh.publisher, fresh.worker_boot,
                                          CoordinatorEpoch(before_reset.value() + 1), "after-reset",
                                          EvidenceClass::DirectAuthoritativeInfrastructure);
  FDR_CHECK_EQ(fresh.attached.code, OutcomeCode::StaleEpoch);
  fresh.attached = registry.attach_worker(fresh.publisher, fresh.worker_boot, before_reset,
                                          "after-reset",
                                          EvidenceClass::DirectAuthoritativeInfrastructure);
  FDR_CHECK_MSG(fresh.attached.code == OutcomeCode::Committed,
               "the preserved epoch was not the current one: " + describe(fresh.attached));

  // A mutation that carries the pre-reset worker boot under the new grant is
  // refused: the incarnation was reset away with the session that held it.
  {
    AuthorityContext stale = fresh.authority();
    stale.worker_boot = fixture.session.worker_boot;
    FDR_CHECK(!stale.worker_boot.is_null());
    const Fingerprint before = Fingerprint::capture(registry);
    const Outcome refused =
        declare_domain(registry, stale, klass, "dc1", "rack-1", "r1", "stale-boot", provenance);
    FDR_CHECK_EQ(refused.code, OutcomeCode::StaleAuthority);
    FDR_CHECK_MSG(refused.message.find("not attached") != std::string::npos,
                 "the pre-reset incarnation was not the reported reason: " + describe(refused));
    const std::string drift = before.drift(registry);
    FDR_CHECK_MSG(drift.empty(), "a pre-reset incarnation changed state: " + drift);
  }
  std::string final_why;
  FDR_CHECK_MSG(registry.validate_state(&final_why),
                 "the recovery after reset broke the state: " + final_why);
}

// ---------------------------------------------------------------------------
// Blast radius
// ---------------------------------------------------------------------------

FDR_TEST_CASE(adversarial, blast_radius_reports_the_classes_its_members_belong_to) {
  Fixture fixture = open();
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef conduit(DomainClass::Conduit);
  const DomainClassRef cable(DomainClass::Cable);
  const Provenance provenance = authoritative("inv");
  const Declared conduit_domain = declare_named(registry, fixture.session.authority(), conduit, "dc1",
                                               "conduit-1", "conduit-1", "br1", provenance);
  const Declared cable_domain = declare_named(registry, fixture.session.authority(), cable, "dc1",
                                             "cable-1", "cable-1", "br2", provenance);
  FDR_CHECK_EQ(conduit_domain.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(cable_domain.outcome.code, OutcomeCode::Committed);

  // One member that spans both domains, so the queried domain's own class is
  // not the whole answer.
  const EntityRef spanning = entity_ref(EntityClass::Link, "spanning-link", 1);
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), conduit_domain.id, spanning,
                             "br3", provenance).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), cable_domain.id, spanning, "br4",
                             provenance).code,
               OutcomeCode::Committed);
  // A second member that belongs only to the conduit domain: it must not add a
  // duplicate class to the answer.
  const EntityRef local = entity_ref(EntityClass::Switch, "local-switch", 1);
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), conduit_domain.id, local, "br5",
                             provenance).code,
               OutcomeCode::Committed);

  const failure_domain_registry::BlastRadius radius = registry.blast_radius(conduit_domain.id);
  FDR_CHECK_EQ(radius.domain, conduit_domain.id);
  FDR_CHECK_EQ(radius.domain_class, conduit);
  FDR_CHECK_EQ(radius.members.size(), std::size_t{2});
  FDR_CHECK_EQ(radius.members[0], local);
  FDR_CHECK_EQ(radius.members[1], spanning);
  FDR_CHECK_EQ(radius.member_domain_classes.size(), std::size_t{2});
  // Canonical order by rendered name: "cable" precedes "conduit".
  FDR_CHECK_EQ(radius.member_domain_classes[0], cable);
  FDR_CHECK_EQ(radius.member_domain_classes[1], conduit);
  FDR_CHECK(radius.member_domain_classes[0].to_string() < radius.member_domain_classes[1].to_string());
  FDR_CHECK_MSG(!(radius.member_domain_classes[0] == radius.member_domain_classes[1]),
               "a member class was reported twice");
  // The set is a property of the members, not of the domain that was asked
  // about: the same answer comes back from the other side.
  const failure_domain_registry::BlastRadius mirrored = registry.blast_radius(cable_domain.id);
  FDR_CHECK_EQ(mirrored.domain_class, cable);
  FDR_CHECK(mirrored.member_domain_classes == radius.member_domain_classes);
  // The field is not an echo of the queried class: the cable query still
  // answers with the conduit class of the conduit domain its member belongs to.
  FDR_CHECK_EQ(mirrored.member_domain_classes[1], conduit);
  FDR_CHECK(!(mirrored.domain_class == mirrored.member_domain_classes[1]));
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the blast radius case broke the state: " + why);
}

// ---------------------------------------------------------------------------
// Derived membership
// ---------------------------------------------------------------------------

FDR_TEST_CASE(adversarial, a_superseded_source_generation_invalidates_a_derived_membership) {
  Fixture fixture = open();
  FDR_CHECK_MSG(fixture.problem().empty(), "the fixture did not open: " + fixture.problem());
  Registry& registry = *fixture.registry;
  const DomainClassRef chassis(DomainClass::Chassis);
  const DomainClassRef rack(DomainClass::Rack);
  const Provenance provenance = authoritative("inv");
  const Declared chassis_domain = declare_named(registry, fixture.session.authority(), chassis, "dc1",
                                               "chassis-1", "chassis-1", "dv1", provenance);
  const Declared rack_domain = declare_named(registry, fixture.session.authority(), rack, "dc1",
                                            "rack-1", "rack-1", "dv2", provenance);
  FDR_CHECK_EQ(chassis_domain.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(rack_domain.outcome.code, OutcomeCode::Committed);

  // One member of the source class, which is also a member of the target class:
  // the rule derives the target-class membership from the source-class one.
  const EntityRef link = entity_ref(EntityClass::Link, "derived-link", 1);
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), chassis_domain.id, link, "dv3",
                             provenance).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(attach_member(registry, fixture.session.authority(), rack_domain.id, link, "dv4",
                             provenance).code,
               OutcomeCode::Committed);

  DerivationRule rule;
  rule.name = "chassis-members-share-rack";
  rule.op = DerivationOperator::MembersShareContainingClass;
  rule.source_class = chassis;
  rule.target_class = rack;
  rule.derived_role = MembershipRole::Derived;
  rule.rule_version = 1;
  rule.enabled = true;
  const DerivationRuleId rule_id = failure_domain_registry::derivation_rule_id_for(rule);
  FDR_CHECK(!rule_id.is_null());
  FDR_CHECK_EQ(registry.publish_derivation_rule(rule, fixture.session.authority()).code,
               OutcomeCode::Committed);
  FDR_CHECK_EQ(registry.derivation_rules().size(), std::size_t{1});
  FDR_CHECK_EQ(registry.derivation_rules()[0].id, rule_id);

  const MembershipId derived_id = membership_of(rack_domain.id, link, MembershipKind::Derived);
  FDR_CHECK(!registry.membership(derived_id).has_value());

  DerivationRunRequest run;
  run.attempt = MutationAttempt{attempt_from("dv5"), RequestDigest{}};
  run.authority = fixture.session.authority();
  DerivationReport report;
  FDR_CHECK_EQ(registry.run_derivation(run, &report).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(report.rules_evaluated, std::size_t{1});
  FDR_CHECK_EQ(report.memberships_created, std::size_t{1});
  FDR_CHECK_EQ(report.memberships_updated, std::size_t{0});
  FDR_CHECK_EQ(report.memberships_withdrawn, std::size_t{0});
  const std::optional<Membership> derived = registry.membership(derived_id);
  FDR_CHECK(derived.has_value());
  FDR_CHECK_EQ(derived->kind, MembershipKind::Derived);
  FDR_CHECK_EQ(derived->lifecycle, MembershipLifecycle::Current);
  FDR_CHECK(derived->derivation.valid);
  FDR_CHECK_EQ(derived->derivation.rule, rule_id);
  FDR_CHECK(!derived->derivation.sources.empty());
  FDR_CHECK_EQ(derived->derivation.source_generations.size(),
              derived->derivation.sources.size());
  const MembershipGeneration derived_generation = derived->generation;

  // A second pass with the sources unchanged changes nothing at all.
  {
    DerivationRunRequest repeat = run;
    repeat.attempt = MutationAttempt{attempt_from("dv6"), RequestDigest{}};
    DerivationReport unchanged;
    FDR_CHECK_EQ(registry.run_derivation(repeat, &unchanged).code, OutcomeCode::Idempotent);
    FDR_CHECK_EQ(unchanged.memberships_unchanged, std::size_t{1});
    FDR_CHECK_EQ(unchanged.memberships_created, std::size_t{0});
    FDR_CHECK_EQ(unchanged.memberships_updated, std::size_t{0});
    FDR_CHECK_EQ(registry.membership(derived_id)->generation, derived_generation);
  }

  // The entity generation every source membership was bound to is superseded.
  const Outcome invalidated =
      invalidate_entity(registry, fixture.session.authority(), link.id(), 1, "dv7");
  FDR_CHECK_EQ(invalidated.code, OutcomeCode::Committed);
  const std::optional<Membership> invalid = registry.membership(derived_id);
  FDR_CHECK(invalid.has_value());
  FDR_CHECK_MSG(!invalid->derivation.valid,
               "a derived membership still claimed validity after its source generation moved on");
  FDR_CHECK_EQ(invalid->lifecycle, MembershipLifecycle::RevalidationRequired);

  // The next pass withdraws it rather than restoring it: the source membership
  // is no longer current, so the rule no longer produces the derived record.
  {
    DerivationRunRequest rerun = run;
    rerun.attempt = MutationAttempt{attempt_from("dv8"), RequestDigest{}};
    DerivationReport after;
    FDR_CHECK_EQ(registry.run_derivation(rerun, &after).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(after.rules_evaluated, std::size_t{1});
    FDR_CHECK_EQ(after.memberships_withdrawn, std::size_t{1});
    FDR_CHECK_EQ(after.memberships_created, std::size_t{0});
    FDR_CHECK_EQ(after.memberships_updated, std::size_t{0});
    FDR_CHECK_EQ(after.memberships_unchanged, std::size_t{0});
    const std::optional<Membership> withdrawn = registry.membership(derived_id);
    FDR_CHECK(withdrawn.has_value());
    FDR_CHECK_EQ(withdrawn->lifecycle, MembershipLifecycle::Retired);
    FDR_CHECK(!withdrawn->derivation.valid);
    FDR_CHECK(withdrawn->is_terminal());
  }
  std::string why;
  FDR_CHECK_MSG(registry.validate_state(&why), "the derivation case broke the state: " + why);
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
