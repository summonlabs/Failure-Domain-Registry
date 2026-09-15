// Failure Domain Registry — publisher authority, grants, epochs and fencing.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Connecting is not authority. A publisher may mutate only under a durable
// grant, at the coordinator epoch that is actually current, from a live
// incarnation that has not been fenced; this file pins that contract against
// the public API alone. Every grant, attach, fence and epoch advance asserts its
// exact OutcomeCode, the generation it produced and the state it left behind,
// and every refusal is also checked against the generation, the session table
// and the fence list it was supposed to leave alone, because a retry is only
// safe when a refused request moved nothing.
//
// The demotion rules are the sharpest part: fencing an incarnation withdraws the
// evidence that incarnation published, so classification which rested on a live
// process stops being current while a durable administrative statement survives.
// Each case ends with Registry::validate_state, so an operation that leaves one
// of the maintained indexes out of step fails here rather than in an unrelated
// query.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "failure_domain_registry/failure_domain_registry.hpp"
#include "support/test_harness.hpp"

namespace {

using failure_domain_registry::AttachMemberRequest;
using failure_domain_registry::AuthorityContext;
using failure_domain_registry::AuthorityScope;
using failure_domain_registry::CoordinatorEpoch;
using failure_domain_registry::CoverageState;
using failure_domain_registry::CreateDomainRequest;
using failure_domain_registry::DeclareCoverageRequest;
using failure_domain_registry::DomainClass;
using failure_domain_registry::DomainClassRef;
using failure_domain_registry::DomainLifecycle;
using failure_domain_registry::EntityClass;
using failure_domain_registry::EntityGeneration;
using failure_domain_registry::EntityRef;
using failure_domain_registry::EvidenceClass;
using failure_domain_registry::FenceReason;
using failure_domain_registry::FenceRecord;
using failure_domain_registry::FailureDomain;
using failure_domain_registry::FailureDomainGeneration;
using failure_domain_registry::FailureDomainId;
using failure_domain_registry::IdBytes;
using failure_domain_registry::Membership;
using failure_domain_registry::MembershipKey;
using failure_domain_registry::MembershipKind;
using failure_domain_registry::MembershipLifecycle;
using failure_domain_registry::MembershipRole;
using failure_domain_registry::MutationAttempt;
using failure_domain_registry::MutationAttemptId;
using failure_domain_registry::Outcome;
using failure_domain_registry::OutcomeCode;
using failure_domain_registry::Provenance;
using failure_domain_registry::ProvenanceSource;
using failure_domain_registry::PublisherId;
using failure_domain_registry::PublisherRegistration;
using failure_domain_registry::Registry;
using failure_domain_registry::RegistryGeneration;
using failure_domain_registry::RegistryLimits;
using failure_domain_registry::RequestDigest;
using failure_domain_registry::RetireDomainRequest;
using failure_domain_registry::TruthClass;
using failure_domain_registry::UpdateDomainRequest;
using failure_domain_registry::WorkerBootId;
using failure_domain_registry::WorkerSession;
using failure_domain_registry::domain_id_for;
using failure_domain_registry::is_process_bound_evidence;
using failure_domain_registry::membership_id_for;

/// One (publisher, incarnation) pair as the registry reports it.
using Incarnation = std::pair<PublisherId, WorkerBootId>;

/// A non-null identifier pattern. Two calls with different salts never collide.
IdBytes bytes_with(std::uint8_t tag, std::uint8_t salt) {
    IdBytes bytes{};
    bytes[0] = tag;
    bytes[15] = salt;
    return bytes;
}

PublisherId publisher_from(std::uint8_t seed) {
    return PublisherId::from_bytes(bytes_with(0x51u, seed));
}

WorkerBootId boot_from(std::uint8_t seed) {
    return WorkerBootId::from_bytes(bytes_with(0xB0u, seed));
}

/// An attempt id that names one call site. Every mutation gets its own index:
/// reusing an id with different content is a conflicting replay by contract.
MutationAttempt attempt_with(std::uint8_t index) {
    return MutationAttempt(MutationAttemptId::from_bytes(bytes_with(0xA7u, index)), RequestDigest{});
}

EntityRef entity_ref(EntityClass entity_class, std::uint8_t seed, std::uint64_t generation) {
    return EntityRef(entity_class, bytes_with(0xE1u, seed), EntityGeneration(generation));
}

Provenance provenance_of(ProvenanceSource source, EvidenceClass evidence, TruthClass truth,
                         std::string source_identity) {
    Provenance provenance;
    provenance.source = source;
    provenance.evidence = evidence;
    provenance.truth = truth;
    provenance.source_identity = std::move(source_identity);
    return provenance;
}

AuthorityContext authority_of(const PublisherId& publisher, const WorkerBootId& worker_boot,
                              CoordinatorEpoch epoch, EvidenceClass evidence) {
    AuthorityContext authority;
    authority.publisher = publisher;
    authority.worker_boot = worker_boot;
    authority.epoch = epoch;
    authority.evidence = evidence;
    return authority;
}

PublisherRegistration registration_of(const PublisherId& publisher, std::string name, AuthorityScope scope) {
    PublisherRegistration registration;
    registration.publisher = publisher;
    registration.name = std::move(name);
    registration.scope = std::move(scope);
    return registration;
}

/// The consistency check every accepted mutation must survive.
void check_state(const Registry& registry) {
    std::string why;
    FDR_CHECK_MSG(registry.validate_state(&why), "registry state is inconsistent: " + why);
}

/// A registry with one unrestricted publisher granted at bootstrap and one live
/// incarnation attached at epoch 1: the state every case in this file starts
/// from. Registry is not movable, so the pieces are stored in place.
struct Fixture {
    Registry registry;
    PublisherId publisher{};
    WorkerBootId boot{};
    CoordinatorEpoch epoch{};
    AuthorityContext authority{};
};

void bootstrap(Fixture& fixture, std::uint8_t seed) {
    fixture.publisher = publisher_from(seed);
    fixture.boot = boot_from(seed);

    PublisherRegistration registration;
    registration.publisher = fixture.publisher;
    registration.name = "bootstrap-publisher";
    registration.scope = AuthorityScope::unrestricted();

    // The first grant is a bootstrap: the registry is empty, so there is no
    // authority to present yet.
    const Outcome granted = fixture.registry.grant_publisher(registration, AuthorityContext{});
    FDR_CHECK_EQ(granted.code, OutcomeCode::Committed);

    CoordinatorEpoch established;
    const Outcome advanced = fixture.registry.advance_epoch(CoordinatorEpoch{}, &established);
    FDR_CHECK_EQ(advanced.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(established.value(), std::uint64_t{1});

    const Outcome attached = fixture.registry.attach_worker(fixture.publisher, fixture.boot, established, "fixture",
                                                            EvidenceClass::DirectAuthoritativeInfrastructure);
    FDR_CHECK_EQ(attached.code, OutcomeCode::Committed);

    fixture.epoch = established;
    fixture.authority.publisher = fixture.publisher;
    fixture.authority.worker_boot = fixture.boot;
    fixture.authority.epoch = established;
    // The weakest class is always inside any granted maximum, so the fixture
    // never hides a scope decision that a case is trying to make.
    fixture.authority.evidence = EvidenceClass::Synthetic;
    check_state(fixture.registry);
}

/// The same fixture with a bounded grant: `scope` replaces the unrestricted one
/// and the incarnation is attached with `session_evidence`.
void bootstrap_scoped(Fixture& fixture, std::uint8_t seed, AuthorityScope scope,
                      EvidenceClass session_evidence) {
    fixture.publisher = publisher_from(seed);
    fixture.boot = boot_from(seed);

    const Outcome granted = fixture.registry.grant_publisher(
        registration_of(fixture.publisher, "scoped-publisher", std::move(scope)), AuthorityContext{});
    FDR_CHECK_EQ(granted.code, OutcomeCode::Committed);

    CoordinatorEpoch established;
    const Outcome advanced = fixture.registry.advance_epoch(CoordinatorEpoch{}, &established);
    FDR_CHECK_EQ(advanced.code, OutcomeCode::Committed);

    const Outcome attached = fixture.registry.attach_worker(fixture.publisher, fixture.boot, established, "scoped",
                                                            session_evidence);
    FDR_CHECK_EQ(attached.code, OutcomeCode::Committed);

    fixture.epoch = established;
    fixture.authority.publisher = fixture.publisher;
    fixture.authority.worker_boot = fixture.boot;
    fixture.authority.epoch = established;
    fixture.authority.evidence = session_evidence;
    check_state(fixture.registry);
}

FailureDomainId id_of(const std::string& scope, DomainClass domain_class, const std::string& identity_key) {
    return domain_id_for(scope, DomainClassRef(domain_class), identity_key);
}

CreateDomainRequest create_request(const AuthorityContext& authority, std::uint8_t index, DomainClass domain_class,
                                   std::string scope, std::string identity_key, std::string name,
                                   Provenance provenance, bool activate = true) {
    CreateDomainRequest request;
    request.attempt = attempt_with(index);
    request.authority = authority;
    request.domain_class = DomainClassRef(domain_class);
    request.administrative_scope = std::move(scope);
    request.identity_key = std::move(identity_key);
    request.name = std::move(name);
    request.provenance = std::move(provenance);
    request.activate = activate;
    return request;
}

Outcome create_now(Registry& registry, const AuthorityContext& authority, std::uint8_t index,
                   DomainClass domain_class, const std::string& scope, const std::string& identity_key,
                   const std::string& name, const Provenance& provenance, bool activate = true) {
    return registry.create_domain(
        create_request(authority, index, domain_class, scope, identity_key, name, provenance, activate));
}

Outcome create_now(Fixture& fixture, std::uint8_t index, DomainClass domain_class, const std::string& scope,
                   const std::string& identity_key, const std::string& name, const Provenance& provenance,
                   bool activate = true) {
    return create_now(fixture.registry, fixture.authority, index, domain_class, scope, identity_key, name, provenance,
                      activate);
}

Outcome update_now(Registry& registry, const AuthorityContext& authority, std::uint8_t index,
                   const FailureDomainId& domain, FailureDomainGeneration expected, std::string name) {
    UpdateDomainRequest request;
    request.attempt = attempt_with(index);
    request.authority = authority;
    request.domain = domain;
    request.expected_generation = expected;
    request.name = std::move(name);
    return registry.update_domain(request);
}

Outcome attach_now(Registry& registry, const AuthorityContext& authority, std::uint8_t index,
                   const FailureDomainId& domain, const EntityRef& member, EvidenceClass evidence,
                   ProvenanceSource source, const std::string& source_identity) {
    AttachMemberRequest request;
    request.attempt = attempt_with(index);
    request.authority = authority;
    request.domain = domain;
    request.expected_domain_generation = FailureDomainGeneration{};
    request.member = member;
    request.kind = MembershipKind::Direct;
    request.role = MembershipRole::Primary;
    request.provenance = provenance_of(source, evidence, TruthClass::Real, source_identity);
    return registry.attach_member(request);
}

Outcome attach_now(Fixture& fixture, std::uint8_t index, const FailureDomainId& domain, const EntityRef& member,
                   EvidenceClass evidence, ProvenanceSource source, const std::string& source_identity) {
    return attach_now(fixture.registry, fixture.authority, index, domain, member, evidence, source, source_identity);
}

Outcome retire_now(Registry& registry, const AuthorityContext& authority, std::uint8_t index,
                   const FailureDomainId& domain, const std::string& reason, bool retire_memberships) {
    RetireDomainRequest request;
    request.attempt = attempt_with(index);
    request.authority = authority;
    request.domain = domain;
    request.reason = reason;
    request.retire_memberships = retire_memberships;
    return registry.retire_domain(request);
}

Outcome declare_coverage_now(Registry& registry, const AuthorityContext& authority, std::uint8_t index,
                             std::string scope, DomainClass domain_class, CoverageState state,
                             Provenance provenance) {
    DeclareCoverageRequest request;
    request.attempt = attempt_with(index);
    request.authority = authority;
    request.administrative_scope = std::move(scope);
    request.domain_class = DomainClassRef(domain_class);
    request.state = state;
    request.provenance = std::move(provenance);
    return registry.declare_coverage(request);
}

/// A durable operator statement: an administrative declaration is classification
/// that never depended on a live publishing process.
const Provenance kOperatorRecord =
    provenance_of(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration, TruthClass::Real, "cmdb-1");

/// The weakest possible statement, used where the evidence check must pass so
/// that a later class check is the one that decides.
const Provenance kSyntheticRecord = provenance_of(ProvenanceSource::SyntheticTestSource, EvidenceClass::Synthetic,
                                                  TruthClass::Synthetic, "synthetic-1");

/// A direct device reading: process-bound evidence, so it is exactly what a
/// fence is allowed to withdraw.
const Provenance kMeasuredRecord =
    provenance_of(ProvenanceSource::VendorController, EvidenceClass::DirectHardwareController, TruthClass::Real,
                  "controller-1");

} // namespace

FDR_TEST_CASE(authority, bootstrap_grant_is_accepted_only_while_no_session_is_live) {
    Fixture fixture;
    fixture.publisher = publisher_from(0x01u);
    fixture.boot = boot_from(0x01u);

    // An empty registry has nobody to present authority, so the first grant is
    // the one operation that never carries a context.
    const Outcome first = fixture.registry.grant_publisher(
        registration_of(fixture.publisher, "bootstrap-publisher", AuthorityScope::unrestricted()),
        AuthorityContext{});
    FDR_CHECK_EQ(first.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(first.message, std::string("publisher grant installed"));
    FDR_CHECK_EQ(first.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(first.steps.front().stage, std::string("authority"));
    FDR_CHECK_EQ(first.steps.front().field, std::string("publisher"));
    FDR_CHECK_EQ(first.steps.front().value, fixture.publisher.to_string());
    FDR_CHECK_EQ(first.steps.front().detail, std::string("bootstrap grant"));
    FDR_CHECK_EQ(fixture.registry.generation().value(), std::uint64_t{1});

    const std::optional<PublisherRegistration> stored = fixture.registry.publisher(fixture.publisher);
    FDR_CHECK(stored.has_value());
    FDR_CHECK_EQ(stored->publisher, fixture.publisher);
    FDR_CHECK_EQ(stored->name, std::string("bootstrap-publisher"));
    FDR_CHECK_EQ(stored->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(stored->scope, AuthorityScope::unrestricted());

    // A second publisher may still join at bootstrap: no incarnation is live
    // yet, and that is the whole condition.
    const PublisherId second = publisher_from(0x02u);
    FDR_CHECK_EQ(fixture.registry
                     .grant_publisher(registration_of(second, "second", AuthorityScope::none()),
                                      AuthorityContext{})
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(fixture.registry.publishers().size(), std::size_t{2});

    // Bring one incarnation live at epoch 1.
    CoordinatorEpoch epoch;
    FDR_CHECK_EQ(fixture.registry.advance_epoch(CoordinatorEpoch{}, &epoch).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(fixture.registry
                     .attach_worker(fixture.publisher, fixture.boot, epoch, "bootstrap",
                                    EvidenceClass::DirectAuthoritativeInfrastructure)
                     .code,
                 OutcomeCode::Committed);
    const RegistryGeneration live_at = fixture.registry.generation();

    // Every incomplete shape is refused now: empty, identity without an epoch,
    // and an epoch that is not the one the coordinator is on.
    const AuthorityContext incomplete[] = {
        AuthorityContext{},
        authority_of(fixture.publisher, fixture.boot, CoordinatorEpoch{}, EvidenceClass::Synthetic),
        authority_of(PublisherId{}, WorkerBootId{}, epoch, EvidenceClass::Synthetic),
    };
    const PublisherId third = publisher_from(0x03u);
    for (const AuthorityContext& context : incomplete) {
        const Outcome refused = fixture.registry.grant_publisher(
            registration_of(third, "third", AuthorityScope::unrestricted()), context);
        FDR_CHECK_EQ(refused.code, OutcomeCode::NoAuthority);
        FDR_CHECK_EQ(refused.message, std::string("bootstrap grant rejected: a live publisher session exists, so "
                                                  "grants now require authority"));
        FDR_CHECK_EQ(fixture.registry.generation(), live_at);
        FDR_CHECK(!fixture.registry.publisher(third).has_value());
    }
    FDR_CHECK_EQ(fixture.registry.publishers().size(), std::size_t{2});

    // The guard is exactly "no live session exists", so the window reopens when
    // the last incarnation is fenced away.
    FDR_CHECK_EQ(fixture.registry
                     .fence_worker(fixture.publisher, fixture.boot, FenceReason::Administrative, epoch)
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK(fixture.registry.live_sessions().empty());
    FDR_CHECK_EQ(fixture.registry
                     .grant_publisher(registration_of(third, "third", AuthorityScope::unrestricted()),
                                      AuthorityContext{})
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK(fixture.registry.publisher(third).has_value());
    check_state(fixture.registry);
}

FDR_TEST_CASE(authority, grant_publisher_rejects_a_null_publisher_and_an_oversized_name) {
    Registry registry(RegistryLimits::defaults());
    const RegistryLimits limits = registry.limits();

    // A grant names the identity it authorizes, so a null identity is malformed
    // before any question of authority is asked.
    PublisherRegistration null_publisher =
        registration_of(publisher_from(0x11u), "null", AuthorityScope::unrestricted());
    null_publisher.publisher = PublisherId{};
    const Outcome no_id = registry.grant_publisher(null_publisher, AuthorityContext{});
    FDR_CHECK_EQ(no_id.code, OutcomeCode::MalformedRequest);
    FDR_CHECK_EQ(no_id.message, std::string("publisher id is null"));

    // The name bound is the registry's own string bound, and it is checked
    // before the bootstrap window, so an oversized grant cannot slip in.
    const Outcome too_long = registry.grant_publisher(
        registration_of(publisher_from(0x12u), std::string(limits.max_string_bytes + 1u, 'p'),
                        AuthorityScope::unrestricted()),
        AuthorityContext{});
    FDR_CHECK_EQ(too_long.code, OutcomeCode::MalformedRequest);
    FDR_CHECK_EQ(too_long.message, std::string("publisher name too long"));

    // Exactly the bound is legal.
    const Outcome at_limit = registry.grant_publisher(
        registration_of(publisher_from(0x13u), std::string(limits.max_string_bytes, 'p'),
                        AuthorityScope::unrestricted()),
        AuthorityContext{});
    FDR_CHECK_EQ(at_limit.code, OutcomeCode::Committed);

    // Neither refusal installed anything or advanced a counter.
    FDR_CHECK_EQ(registry.publishers().size(), std::size_t{1});
    FDR_CHECK(!registry.publisher(publisher_from(0x12u)).has_value());
    FDR_CHECK_EQ(registry.generation().value(), std::uint64_t{1});
    FDR_CHECK_EQ(registry.epoch().value(), std::uint64_t{0});
    FDR_CHECK(registry.live_sessions().empty());
    check_state(registry);
}

FDR_TEST_CASE(authority, re_granting_a_publisher_advances_its_generation_and_replaces_its_scope) {
    Fixture fixture;
    bootstrap(fixture, 0x21u);
    const RegistryGeneration after_bootstrap = fixture.registry.generation();

    // A grant is durable identity, not a session: restating it replaces the
    // registration in place and counts how many times authority was restated.
    const Outcome restated = fixture.registry.grant_publisher(
        registration_of(fixture.publisher, "restated-publisher", AuthorityScope::unrestricted()),
        fixture.authority);
    FDR_CHECK_EQ(restated.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(restated.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(restated.steps.front().stage, std::string("authority"));
    FDR_CHECK_EQ(restated.steps.front().detail, std::string("authorized grant"));
    FDR_CHECK_EQ(fixture.registry.generation().value(), after_bootstrap.value() + 1u);

    std::optional<PublisherRegistration> stored = fixture.registry.publisher(fixture.publisher);
    FDR_CHECK(stored.has_value());
    FDR_CHECK_EQ(stored->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(stored->name, std::string("restated-publisher"));
    FDR_CHECK_EQ(stored->scope, AuthorityScope::unrestricted());

    // Narrowing the grant is a replacement too, and the stored authority keeps
    // the new scope rather than merging with the old one.
    const AuthorityScope narrowed =
        AuthorityScope::for_classes({DomainClass::Rack, DomainClass::Pdu}, EvidenceClass::AdministrativeDeclaration);
    const Outcome bounded = fixture.registry.grant_publisher(
        registration_of(fixture.publisher, "bounded-publisher", narrowed), fixture.authority);
    FDR_CHECK_EQ(bounded.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(bounded.steps.front().detail, std::string("authorized grant"));
    FDR_CHECK_EQ(fixture.registry.generation().value(), after_bootstrap.value() + 2u);

    stored = fixture.registry.publisher(fixture.publisher);
    FDR_CHECK(stored.has_value());
    FDR_CHECK_EQ(stored->generation.value(), std::uint64_t{3});
    FDR_CHECK_EQ(stored->name, std::string("bounded-publisher"));
    FDR_CHECK_EQ(stored->scope, narrowed);
    FDR_CHECK_EQ(stored->scope.classes.size(), std::size_t{2});
    FDR_CHECK_EQ(stored->scope.max_evidence, EvidenceClass::AdministrativeDeclaration);
    FDR_CHECK_EQ(fixture.registry.publishers().size(), std::size_t{1});

    // The replacement is in force immediately: the same publisher now carries a
    // bounded class list, so it may no longer hand out authority.
    const RegistryGeneration after_bounded = fixture.registry.generation();
    const Outcome refused = fixture.registry.grant_publisher(
        registration_of(publisher_from(0x22u), "candidate", AuthorityScope::unrestricted()), fixture.authority);
    FDR_CHECK_EQ(refused.code, OutcomeCode::UnauthorizedScope);
    FDR_CHECK_EQ(refused.message,
                 std::string("only a publisher with an unrestricted scope may grant authority"));
    FDR_CHECK_EQ(fixture.registry.generation(), after_bounded);
    FDR_CHECK(!fixture.registry.publisher(publisher_from(0x22u)).has_value());
    check_state(fixture.registry);
}

FDR_TEST_CASE(authority, an_authorized_grant_requires_a_registered_attached_granter_at_the_current_epoch) {
    Registry registry(RegistryLimits::defaults());
    const PublisherId granter = publisher_from(0x31u);
    const WorkerBootId granter_boot = boot_from(0x31u);
    const PublisherId detached = publisher_from(0x32u);
    const PublisherId candidate = publisher_from(0x33u);
    const PublisherRegistration candidate_registration =
        registration_of(candidate, "authorized-publisher", AuthorityScope::unrestricted());

    // Both grants happen before any incarnation exists, so both are bootstrap.
    FDR_CHECK_EQ(registry
                     .grant_publisher(registration_of(granter, "granter", AuthorityScope::unrestricted()),
                                      AuthorityContext{})
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(registry
                     .grant_publisher(registration_of(detached, "detached", AuthorityScope::unrestricted()),
                                      AuthorityContext{})
                     .code,
                 OutcomeCode::Committed);
    CoordinatorEpoch epoch;
    FDR_CHECK_EQ(registry.advance_epoch(CoordinatorEpoch{}, &epoch).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(registry
                     .attach_worker(granter, granter_boot, epoch, "granter", EvidenceClass::Synthetic)
                     .code,
                 OutcomeCode::Committed);
    const RegistryGeneration before = registry.generation();

    // A granter that was never registered has no authority to lend.
    const Outcome unknown = registry.grant_publisher(
        candidate_registration,
        authority_of(publisher_from(0x34u), boot_from(0x34u), epoch, EvidenceClass::Synthetic));
    FDR_CHECK_EQ(unknown.code, OutcomeCode::StaleAuthority);
    FDR_CHECK_EQ(unknown.message, std::string("publisher is not registered"));
    FDR_CHECK_EQ(unknown.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(unknown.steps.front().stage, std::string("authority"));
    FDR_CHECK_EQ(unknown.steps.front().field, std::string("publisher"));
    FDR_CHECK_EQ(unknown.steps.front().detail, std::string("unknown publisher"));
    FDR_CHECK_EQ(registry.generation(), before);
    FDR_CHECK(!registry.publisher(candidate).has_value());

    // A registration without a live incarnation is durable but not present, so
    // it may not sign anything either.
    const Outcome absent = registry.grant_publisher(
        candidate_registration, authority_of(detached, boot_from(0x32u), epoch, EvidenceClass::Synthetic));
    FDR_CHECK_EQ(absent.code, OutcomeCode::StaleAuthority);
    FDR_CHECK_EQ(absent.message, std::string("publisher has no live incarnation"));
    FDR_CHECK_EQ(absent.steps.front().field, std::string("worker-boot"));
    FDR_CHECK_EQ(absent.steps.front().detail, std::string("not attached"));
    FDR_CHECK_EQ(registry.generation(), before);
    FDR_CHECK(!registry.publisher(candidate).has_value());

    // A live incarnation at an epoch the coordinator has left behind is stale,
    // and the outcome says which epoch is current.
    const Outcome stale_epoch = registry.grant_publisher(
        candidate_registration,
        authority_of(granter, granter_boot, CoordinatorEpoch(epoch.value() + 5u), EvidenceClass::Synthetic));
    FDR_CHECK_EQ(stale_epoch.code, OutcomeCode::StaleEpoch);
    FDR_CHECK_EQ(stale_epoch.message, std::string("coordinator epoch is not current"));
    FDR_CHECK_EQ(stale_epoch.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(stale_epoch.steps.front().field, std::string("epoch"));
    FDR_CHECK_EQ(stale_epoch.steps.front().value, std::string("6"));
    FDR_CHECK_EQ(stale_epoch.steps.front().detail, std::string("current epoch is 1"));
    FDR_CHECK_EQ(registry.generation(), before);
    FDR_CHECK(!registry.publisher(candidate).has_value());

    // The registered, attached, current, unrestricted granter installs it.
    const Outcome granted = registry.grant_publisher(
        candidate_registration, authority_of(granter, granter_boot, epoch, EvidenceClass::Synthetic));
    FDR_CHECK_EQ(granted.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(granted.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(granted.steps.front().stage, std::string("authority"));
    FDR_CHECK_EQ(granted.steps.front().field, std::string("publisher"));
    FDR_CHECK_EQ(granted.steps.front().value, candidate.to_string());
    FDR_CHECK_EQ(granted.steps.front().detail, std::string("authorized grant"));
    FDR_CHECK_EQ(registry.generation().value(), before.value() + 1u);

    const std::optional<PublisherRegistration> installed = registry.publisher(candidate);
    FDR_CHECK(installed.has_value());
    FDR_CHECK_EQ(installed->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(installed->scope, AuthorityScope::unrestricted());
    FDR_CHECK_EQ(registry.publishers().size(), std::size_t{3});
    check_state(registry);
}

FDR_TEST_CASE(authority, a_grant_from_a_publisher_with_a_bounded_scope_is_unauthorized) {
    Registry registry(RegistryLimits::defaults());
    const PublisherId bounded = publisher_from(0x41u);
    const WorkerBootId bounded_boot = boot_from(0x41u);
    const PublisherId full = publisher_from(0x42u);
    const WorkerBootId full_boot = boot_from(0x42u);
    const AuthorityScope narrow =
        AuthorityScope::for_classes({DomainClass::Rack}, EvidenceClass::DirectHardwareController);
    const PublisherId candidate = publisher_from(0x43u);
    const PublisherRegistration candidate_registration =
        registration_of(candidate, "candidate", AuthorityScope::unrestricted());

    FDR_CHECK_EQ(registry
                     .grant_publisher(registration_of(bounded, "bounded", narrow), AuthorityContext{})
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(registry
                     .grant_publisher(registration_of(full, "full", AuthorityScope::unrestricted()),
                                      AuthorityContext{})
                     .code,
                 OutcomeCode::Committed);
    CoordinatorEpoch epoch;
    FDR_CHECK_EQ(registry.advance_epoch(CoordinatorEpoch{}, &epoch).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(registry
                     .attach_worker(bounded, bounded_boot, epoch, "bounded", EvidenceClass::DirectHardwareController)
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(registry.attach_worker(full, full_boot, epoch, "full", EvidenceClass::Synthetic).code,
                 OutcomeCode::Committed);
    const RegistryGeneration before = registry.generation();

    // Authority over one class is not authority over the class space: the
    // bounded publisher is live and current, and still may not grant.
    const Outcome refused = registry.grant_publisher(
        candidate_registration,
        authority_of(bounded, bounded_boot, epoch, EvidenceClass::DirectHardwareController));
    FDR_CHECK_EQ(refused.code, OutcomeCode::UnauthorizedScope);
    FDR_CHECK_EQ(refused.message,
                 std::string("only a publisher with an unrestricted scope may grant authority"));
    FDR_CHECK_EQ(registry.generation(), before);
    FDR_CHECK(!registry.publisher(candidate).has_value());

    // The only difference in the successful call is the granter's class list.
    const Outcome granted = registry.grant_publisher(
        candidate_registration, authority_of(full, full_boot, epoch, EvidenceClass::Synthetic));
    FDR_CHECK_EQ(granted.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(granted.steps.front().detail, std::string("authorized grant"));
    FDR_CHECK_EQ(registry.generation().value(), before.value() + 1u);
    FDR_CHECK(registry.publisher(candidate).has_value());
    FDR_CHECK_EQ(registry.publishers().size(), std::size_t{3});
    check_state(registry);
}

FDR_TEST_CASE(authority, a_bounded_grant_confines_class_scope_and_evidence) {
    Fixture fixture;
    AuthorityScope bounded =
        AuthorityScope::for_classes({DomainClass::Rack}, EvidenceClass::AdministrativeDeclaration);
    bounded.administrative_scope = "dc1";
    bootstrap_scoped(fixture, 0x51u, bounded, EvidenceClass::AdministrativeDeclaration);

    const std::optional<PublisherRegistration> stored = fixture.registry.publisher(fixture.publisher);
    FDR_CHECK(stored.has_value());
    FDR_CHECK_EQ(stored->scope.administrative_scope, std::string("dc1"));
    FDR_CHECK_EQ(stored->scope.classes.size(), std::size_t{1});

    const RegistryGeneration before = fixture.registry.generation();

    // A class outside the grant is refused with the class named, and nothing is
    // written: not a record, not a generation.
    const Outcome wrong_class =
        create_now(fixture, 1u, DomainClass::Pdu, "dc1", "pdu-p1", "Pdu P1", kOperatorRecord);
    FDR_CHECK_EQ(wrong_class.code, OutcomeCode::UnauthorizedScope);
    FDR_CHECK_EQ(wrong_class.message, std::string("publisher is not authorized for domain class pdu"));
    FDR_CHECK_EQ(wrong_class.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(wrong_class.steps.front().stage, std::string("authority"));
    FDR_CHECK_EQ(wrong_class.steps.front().field, std::string("class"));
    FDR_CHECK_EQ(wrong_class.steps.front().value, std::string("pdu"));
    FDR_CHECK_EQ(wrong_class.steps.front().detail, std::string("scope does not allow it"));
    FDR_CHECK_EQ(fixture.registry.generation(), before);
    FDR_CHECK_EQ(fixture.registry.domain_count(), std::size_t{0});

    // The right class in the wrong administrative scope is refused next.
    const Outcome wrong_scope =
        create_now(fixture, 2u, DomainClass::Rack, "dc2", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(wrong_scope.code, OutcomeCode::UnauthorizedScope);
    FDR_CHECK_EQ(wrong_scope.message, std::string("publisher is confined to administrative scope dc1"));
    FDR_CHECK_EQ(wrong_scope.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(wrong_scope.steps.front().field, std::string("scope"));
    FDR_CHECK_EQ(wrong_scope.steps.front().value, std::string("dc2"));
    FDR_CHECK_EQ(wrong_scope.steps.front().detail, std::string("outside the granted scope"));
    FDR_CHECK_EQ(fixture.registry.generation(), before);
    FDR_CHECK_EQ(fixture.registry.domain_count(), std::size_t{0});

    // The right class in the right scope with evidence stronger than the grant
    // is refused as well, because evidence is part of what was granted.
    const Outcome too_strong =
        create_now(fixture, 3u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kMeasuredRecord);
    FDR_CHECK_EQ(too_strong.code, OutcomeCode::UnauthorizedScope);
    FDR_CHECK_EQ(too_strong.message,
                 std::string("publisher may not assert evidence class direct-hardware-controller"));
    FDR_CHECK_EQ(too_strong.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(too_strong.steps.front().field, std::string("evidence"));
    FDR_CHECK_EQ(too_strong.steps.front().value, std::string("direct-hardware-controller"));
    FDR_CHECK_EQ(too_strong.steps.front().detail,
                 std::string("weaker than or equal to the granted maximum is required"));
    FDR_CHECK_EQ(fixture.registry.generation(), before);
    FDR_CHECK_EQ(fixture.registry.domain_count(), std::size_t{0});

    // Class, scope and evidence exactly at the boundary: this one commits, and
    // the record states who asserted it and at which epoch.
    const Outcome created =
        create_now(fixture, 4u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
    FDR_CHECK(created.domain.has_value());
    FDR_CHECK_EQ(*created.domain, id_of("dc1", DomainClass::Rack, "rack-r7"));
    FDR_CHECK(created.domain_generation.has_value());
    FDR_CHECK_EQ(created.domain_generation->value(), std::uint64_t{1});
    FDR_CHECK_EQ(fixture.registry.generation().value(), before.value() + 1u);

    const std::optional<FailureDomain> record = fixture.registry.domain(*created.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->administrative_scope, std::string("dc1"));
    FDR_CHECK_EQ(record->provenance.evidence, EvidenceClass::AdministrativeDeclaration);
    FDR_CHECK_EQ(record->provenance.publisher, fixture.publisher);
    FDR_CHECK_EQ(record->provenance.worker_boot, fixture.boot);
    FDR_CHECK_EQ(record->created_epoch, fixture.epoch);
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Current);

    // Weaker evidence is always inside the grant.
    const Outcome weaker = create_now(fixture, 5u, DomainClass::Rack, "dc1", "rack-r8", "Rack R8", kSyntheticRecord);
    FDR_CHECK_EQ(weaker.code, OutcomeCode::Committed);
    FDR_CHECK(weaker.domain.has_value());
    FDR_CHECK_EQ(fixture.registry.domain_count(), std::size_t{2});
    FDR_CHECK_EQ(fixture.registry.generation().value(), before.value() + 2u);

    // Membership on the domain the publisher owns is governed by the same
    // grant, and the membership carries the same evidence class.
    const EntityRef member = entity_ref(EntityClass::Switch, 1u, 1u);
    const Outcome attached =
        attach_now(fixture, 6u, *created.domain, member, EvidenceClass::AdministrativeDeclaration,
                   ProvenanceSource::Cmdb, "cmdb-member");
    FDR_CHECK_EQ(attached.code, OutcomeCode::Committed);
    FDR_CHECK(attached.membership.has_value());
    const std::optional<Membership> membership = fixture.registry.membership(*attached.membership);
    FDR_CHECK(membership.has_value());
    FDR_CHECK_EQ(membership->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(membership->provenance.publisher, fixture.publisher);
    check_state(fixture.registry);
}

FDR_TEST_CASE(authority, a_publisher_with_an_empty_scope_cannot_mutate_anything) {
    Registry registry(RegistryLimits::defaults());
    const PublisherId owner = publisher_from(0x61u);
    const WorkerBootId owner_boot = boot_from(0x61u);
    const PublisherId powerless = publisher_from(0x62u);
    const WorkerBootId powerless_boot = boot_from(0x62u);

    FDR_CHECK_EQ(registry
                     .grant_publisher(registration_of(owner, "owner", AuthorityScope::unrestricted()),
                                      AuthorityContext{})
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(registry
                     .grant_publisher(registration_of(powerless, "powerless", AuthorityScope::none()),
                                      AuthorityContext{})
                     .code,
                 OutcomeCode::Committed);

    // An empty class list is not "all classes", and its default maximum evidence
    // is the weakest class, so an empty-scope publisher can still be attached.
    const std::optional<PublisherRegistration> empty_scope = registry.publisher(powerless);
    FDR_CHECK(empty_scope.has_value());
    FDR_CHECK(empty_scope->scope.is_empty());
    FDR_CHECK_EQ(empty_scope->scope.classes.size(), std::size_t{0});
    FDR_CHECK_EQ(empty_scope->scope.max_evidence, EvidenceClass::Synthetic);

    CoordinatorEpoch epoch;
    FDR_CHECK_EQ(registry.advance_epoch(CoordinatorEpoch{}, &epoch).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(registry.attach_worker(owner, owner_boot, epoch, "owner", EvidenceClass::Synthetic).code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(registry
                     .attach_worker(powerless, powerless_boot, epoch, "powerless", EvidenceClass::Synthetic)
                     .code,
                 OutcomeCode::Committed);
    const AuthorityContext owner_authority = authority_of(owner, owner_boot, epoch, EvidenceClass::Synthetic);
    const AuthorityContext powerless_authority =
        authority_of(powerless, powerless_boot, epoch, EvidenceClass::Synthetic);

    // One current domain exists, so every refusal below is about authority and
    // not about a missing record.
    const Outcome owned =
        create_now(registry, owner_authority, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(owned.code, OutcomeCode::Committed);
    FDR_CHECK(owned.domain.has_value());
    const RegistryGeneration before = registry.generation();

    const Outcome refused_create =
        create_now(registry, powerless_authority, 2u, DomainClass::Rack, "dc1", "rack-r8", "Rack R8",
                   kSyntheticRecord);
    FDR_CHECK_EQ(refused_create.code, OutcomeCode::UnauthorizedScope);
    FDR_CHECK_EQ(refused_create.message, std::string("publisher is not authorized for domain class rack"));

    const EntityRef member = entity_ref(EntityClass::Switch, 7u, 1u);
    const Outcome refused_attach =
        attach_now(registry, powerless_authority, 3u, *owned.domain, member, EvidenceClass::Synthetic,
                   ProvenanceSource::SyntheticTestSource, "synthetic-member");
    FDR_CHECK_EQ(refused_attach.code, OutcomeCode::UnauthorizedScope);
    FDR_CHECK_EQ(refused_attach.message, std::string("publisher is not authorized for domain class rack"));

    const Outcome refused_update =
        update_now(registry, powerless_authority, 4u, *owned.domain, FailureDomainGeneration(1u), "Rack R7 (mine)");
    FDR_CHECK_EQ(refused_update.code, OutcomeCode::UnauthorizedScope);

    const Outcome refused_retire =
        retire_now(registry, powerless_authority, 5u, *owned.domain, "not mine to close", true);
    FDR_CHECK_EQ(refused_retire.code, OutcomeCode::UnauthorizedScope);

    const Outcome refused_coverage =
        declare_coverage_now(registry, powerless_authority, 6u, "dc1", DomainClass::Rack, CoverageState::Complete,
                             kSyntheticRecord);
    FDR_CHECK_EQ(refused_coverage.code, OutcomeCode::UnauthorizedScope);

    // Five refusals moved nothing at all.
    FDR_CHECK_EQ(registry.generation(), before);
    FDR_CHECK_EQ(registry.domain_count(), std::size_t{1});
    FDR_CHECK_EQ(registry.membership_count(), std::size_t{0});
    const std::optional<FailureDomain> record = registry.domain(*owned.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Current);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(record->name, std::string("Rack R7"));
    check_state(registry);
}

FDR_TEST_CASE(authority, attach_worker_rejects_malformed_unregistered_and_stale_incarnations) {
    Fixture fixture;
    bootstrap(fixture, 0x71u);
    const RegistryGeneration after_bootstrap = fixture.registry.generation();

    // A missing identity is malformed whatever else the request says.
    const Outcome no_publisher =
        fixture.registry.attach_worker(PublisherId{}, fixture.boot, fixture.epoch, "null",
                                       EvidenceClass::Synthetic);
    FDR_CHECK_EQ(no_publisher.code, OutcomeCode::MalformedRequest);
    FDR_CHECK_EQ(no_publisher.message, std::string("publisher and worker boot are required"));
    const Outcome no_boot =
        fixture.registry.attach_worker(fixture.publisher, WorkerBootId{}, fixture.epoch, "null",
                                       EvidenceClass::Synthetic);
    FDR_CHECK_EQ(no_boot.code, OutcomeCode::MalformedRequest);
    FDR_CHECK_EQ(no_boot.message, std::string("publisher and worker boot are required"));

    // An unregistered publisher cannot attach at any epoch.
    const Outcome unknown = fixture.registry.attach_worker(publisher_from(0x72u), boot_from(0x72u), fixture.epoch,
                                                           "unknown", EvidenceClass::Synthetic);
    FDR_CHECK_EQ(unknown.code, OutcomeCode::StaleAuthority);
    FDR_CHECK_EQ(unknown.message, std::string("publisher is not registered"));
    FDR_CHECK_EQ(unknown.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(unknown.steps.front().stage, std::string("authority"));
    FDR_CHECK_EQ(unknown.steps.front().field, std::string("publisher"));
    FDR_CHECK_EQ(unknown.steps.front().value, publisher_from(0x72u).to_string());
    FDR_CHECK_EQ(unknown.steps.front().detail, std::string("unknown publisher"));

    // A zero epoch and a wrong epoch are the same complaint, and the outcome
    // names the epoch that is actually current so the caller can retry.
    const Outcome zero_epoch = fixture.registry.attach_worker(fixture.publisher, boot_from(0x73u), CoordinatorEpoch{},
                                                              "zero", EvidenceClass::Synthetic);
    FDR_CHECK_EQ(zero_epoch.code, OutcomeCode::StaleEpoch);
    FDR_CHECK_EQ(zero_epoch.message, std::string("coordinator epoch is not current"));
    FDR_CHECK_EQ(zero_epoch.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(zero_epoch.steps.front().stage, std::string("authority"));
    FDR_CHECK_EQ(zero_epoch.steps.front().field, std::string("epoch"));
    FDR_CHECK_EQ(zero_epoch.steps.front().value, std::string("0"));
    FDR_CHECK_EQ(zero_epoch.steps.front().detail, std::string("current epoch is 1"));

    const Outcome wrong_epoch = fixture.registry.attach_worker(fixture.publisher, boot_from(0x74u),
                                                               CoordinatorEpoch(9u), "wrong",
                                                               EvidenceClass::Synthetic);
    FDR_CHECK_EQ(wrong_epoch.code, OutcomeCode::StaleEpoch);
    FDR_CHECK_EQ(wrong_epoch.message, std::string("coordinator epoch is not current"));
    FDR_CHECK_EQ(wrong_epoch.steps.front().value, std::string("9"));
    FDR_CHECK_EQ(wrong_epoch.steps.front().detail, std::string("current epoch is 1"));

    // A registry whose epoch was never established says that instead of
    // pretending the caller supplied a stale one.
    Registry fresh(RegistryLimits::defaults());
    FDR_CHECK_EQ(fresh
                     .grant_publisher(registration_of(publisher_from(0x75u), "fresh", AuthorityScope::unrestricted()),
                                      AuthorityContext{})
                     .code,
                 OutcomeCode::Committed);
    const Outcome no_epoch = fresh.attach_worker(publisher_from(0x75u), boot_from(0x75u), CoordinatorEpoch{},
                                                 "fresh", EvidenceClass::Synthetic);
    FDR_CHECK_EQ(no_epoch.code, OutcomeCode::StaleEpoch);
    FDR_CHECK_EQ(no_epoch.message, std::string("coordinator epoch has not been established"));
    FDR_CHECK(no_epoch.steps.empty());
    FDR_CHECK(fresh.live_sessions().empty());

    // Every refusal left the one live incarnation exactly where it was.
    FDR_CHECK_EQ(fixture.registry.generation(), after_bootstrap);
    FDR_CHECK_EQ(fixture.registry.live_sessions().size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.live_sessions().front().worker_boot, fixture.boot);
    FDR_CHECK(fixture.registry.is_worker_live(fixture.publisher, fixture.boot));
    FDR_CHECK(!fixture.registry.is_worker_live(fixture.publisher, boot_from(0x73u)));
    FDR_CHECK(fixture.registry.fences().empty());
    check_state(fixture.registry);
}

FDR_TEST_CASE(authority, attach_worker_is_idempotent_for_the_same_incarnation) {
    Fixture fixture;
    bootstrap(fixture, 0x81u);
    const RegistryGeneration after_bootstrap = fixture.registry.generation();

    // Restating the same incarnation is the same fact, so the session is
    // refreshed in place and no generation is produced.
    const Outcome again = fixture.registry.attach_worker(fixture.publisher, fixture.boot, fixture.epoch,
                                                         "relabelled", EvidenceClass::DirectHardwareController);
    FDR_CHECK_EQ(again.code, OutcomeCode::Idempotent);
    FDR_CHECK_EQ(again.message, std::string("worker incarnation already attached"));
    FDR_CHECK_EQ(fixture.registry.generation(), after_bootstrap);
    FDR_CHECK(fixture.registry.fences().empty());

    const std::vector<WorkerSession> sessions = fixture.registry.live_sessions();
    FDR_CHECK_EQ(sessions.size(), std::size_t{1});
    FDR_CHECK_EQ(sessions.front().publisher, fixture.publisher);
    FDR_CHECK_EQ(sessions.front().worker_boot, fixture.boot);
    FDR_CHECK_EQ(sessions.front().attached_epoch, fixture.epoch);
    FDR_CHECK_EQ(sessions.front().client_label, std::string("relabelled"));
    FDR_CHECK_EQ(sessions.front().max_evidence, EvidenceClass::DirectHardwareController);
    FDR_CHECK(fixture.registry.is_worker_live(fixture.publisher, fixture.boot));
    check_state(fixture.registry);
}

FDR_TEST_CASE(authority, attach_worker_refuses_evidence_stronger_than_the_grant) {
    Fixture fixture;
    const AuthorityScope bounded =
        AuthorityScope::for_classes({DomainClass::Rack}, EvidenceClass::AdministrativeDeclaration);
    bootstrap_scoped(fixture, 0x91u, bounded, EvidenceClass::AdministrativeDeclaration);
    const RegistryGeneration before = fixture.registry.generation();

    // A session may not be opened with more evidence authority than the grant
    // carries, even when it is the incarnation that is already attached.
    const Outcome too_strong = fixture.registry.attach_worker(fixture.publisher, fixture.boot, fixture.epoch,
                                                              "stronger", EvidenceClass::DirectHardwareController);
    FDR_CHECK_EQ(too_strong.code, OutcomeCode::UnauthorizedScope);
    FDR_CHECK_EQ(too_strong.message, std::string("publisher may not assert the requested evidence class"));
    FDR_CHECK_EQ(fixture.registry.generation(), before);
    FDR_CHECK_EQ(fixture.registry.live_sessions().size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.live_sessions().front().max_evidence, EvidenceClass::AdministrativeDeclaration);

    // Exactly the granted maximum is allowed.
    const Outcome at_bound = fixture.registry.attach_worker(fixture.publisher, fixture.boot, fixture.epoch,
                                                            "at-bound", EvidenceClass::AdministrativeDeclaration);
    FDR_CHECK_EQ(at_bound.code, OutcomeCode::Idempotent);
    FDR_CHECK_EQ(fixture.registry.live_sessions().front().max_evidence, EvidenceClass::AdministrativeDeclaration);
    FDR_CHECK_EQ(fixture.registry.generation(), before);

    // Weaker evidence is always allowed, and opening a second incarnation with
    // it fences the first.
    const WorkerBootId weaker_boot = boot_from(0x92u);
    const Outcome weaker = fixture.registry.attach_worker(fixture.publisher, weaker_boot, fixture.epoch, "weaker",
                                                          EvidenceClass::Synthetic);
    FDR_CHECK_EQ(weaker.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(fixture.registry.generation().value(), before.value() + 1u);
    const std::vector<WorkerSession> sessions = fixture.registry.live_sessions();
    FDR_CHECK_EQ(sessions.size(), std::size_t{1});
    FDR_CHECK_EQ(sessions.front().worker_boot, weaker_boot);
    FDR_CHECK_EQ(sessions.front().max_evidence, EvidenceClass::Synthetic);
    FDR_CHECK(fixture.registry.is_worker_live(fixture.publisher, weaker_boot));
    FDR_CHECK(!fixture.registry.is_worker_live(fixture.publisher, fixture.boot));
    const std::vector<FenceRecord> fences = fixture.registry.fences();
    FDR_CHECK_EQ(fences.size(), std::size_t{1});
    FDR_CHECK_EQ(fences.front().worker_boot, fixture.boot);
    FDR_CHECK_EQ(fences.front().reason, FenceReason::Reincarnated);
    check_state(fixture.registry);
}

FDR_TEST_CASE(authority, a_fresh_boot_fences_the_previous_incarnation_and_withdraws_its_evidence) {
    Fixture fixture;
    bootstrap(fixture, 0xA1u);

    // Two classifications: one resting on a device reading taken by this
    // incarnation, one on a durable administrative declaration.
    const Outcome process_bound =
        create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-measured", "Rack (measured)", kMeasuredRecord);
    const Outcome durable =
        create_now(fixture, 2u, DomainClass::Rack, "dc1", "rack-declared", "Rack (declared)", kOperatorRecord);
    FDR_CHECK_EQ(process_bound.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(durable.code, OutcomeCode::Committed);
    FDR_CHECK(process_bound.domain.has_value());
    FDR_CHECK(durable.domain.has_value());

    const EntityRef member = entity_ref(EntityClass::Switch, 3u, 1u);
    FDR_CHECK_EQ(attach_now(fixture, 3u, *process_bound.domain, member, EvidenceClass::DirectHardwareController,
                            ProvenanceSource::VendorController, "controller-member")
                     .code,
                 OutcomeCode::Committed);

    const RegistryGeneration before_attach = fixture.registry.generation();
    const WorkerBootId reincarnation = boot_from(0xA2u);
    const Outcome attached = fixture.registry.attach_worker(fixture.publisher, reincarnation, fixture.epoch,
                                                            "reincarnation",
                                                            EvidenceClass::DirectAuthoritativeInfrastructure);
    FDR_CHECK_EQ(attached.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(attached.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(attached.steps.front().stage, std::string("authority"));
    FDR_CHECK_EQ(attached.steps.front().field, std::string("worker-boot"));
    FDR_CHECK_EQ(attached.steps.front().value, reincarnation.to_string());
    FDR_CHECK_EQ(attached.steps.front().detail, std::string("attached at epoch 1"));
    FDR_CHECK_EQ(fixture.registry.generation().value(), before_attach.value() + 1u);

    // The replaced incarnation is fenced permanently, against the generation
    // the fence was recorded at.
    const std::vector<FenceRecord> fences = fixture.registry.fences();
    FDR_CHECK_EQ(fences.size(), std::size_t{1});
    FDR_CHECK_EQ(fences.front().publisher, fixture.publisher);
    FDR_CHECK_EQ(fences.front().worker_boot, fixture.boot);
    FDR_CHECK_EQ(fences.front().reason, FenceReason::Reincarnated);
    FDR_CHECK_EQ(fences.front().epoch, fixture.epoch);
    FDR_CHECK_EQ(fences.front().at_generation, before_attach);

    // One incarnation per publisher stays live, and it is the new one.
    const std::vector<WorkerSession> sessions = fixture.registry.live_sessions();
    FDR_CHECK_EQ(sessions.size(), std::size_t{1});
    FDR_CHECK_EQ(sessions.front().worker_boot, reincarnation);
    FDR_CHECK(!fixture.registry.is_worker_live(fixture.publisher, fixture.boot));
    FDR_CHECK(fixture.registry.is_worker_live(fixture.publisher, reincarnation));

    // The membership the old incarnation published loses its evidence and must
    // be reconciled before it counts again.
    const MembershipKey key{*process_bound.domain, member.id(), member.generation(), MembershipKind::Direct};
    const std::optional<Membership> membership = fixture.registry.membership(membership_id_for(key));
    FDR_CHECK(membership.has_value());
    FDR_CHECK_EQ(membership->lifecycle, MembershipLifecycle::RevalidationRequired);
    FDR_CHECK_EQ(membership->generation.value(), std::uint64_t{2});
    FDR_CHECK(membership->evidence.empty());
    FDR_CHECK_EQ(membership->history.size(), std::size_t{1});
    FDR_CHECK_EQ(membership->history.front().cause,
                 std::string("publisher reincarnated with a fresh worker boot"));
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(), std::size_t{0});

    // A durable administrative classification never depended on the process, so
    // it keeps its lifecycle and its generation.
    std::optional<FailureDomain> record = fixture.registry.domain(*durable.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Current);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK(record->history.empty());

    // A domain that rests on process-bound evidence is NOT demoted here: this
    // path fences the old incarnation and withdraws its membership evidence,
    // while demoting domains is done by an explicit fence_worker call (see
    // fencing_demotes_process_bound_classification_and_keeps_durable_classification).
    // The difference is asserted so that a change to either path is caught.
    record = fixture.registry.domain(*process_bound.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Current);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK(is_process_bound_evidence(record->provenance.evidence));
    check_state(fixture.registry);
}

FDR_TEST_CASE(authority, fence_worker_records_the_fence_and_stales_the_incarnation) {
    Fixture fixture;
    bootstrap(fixture, 0xB1u);
    const RegistryGeneration after_bootstrap = fixture.registry.generation();

    // An unknown publisher has nothing to fence.
    const Outcome unknown = fixture.registry.fence_worker(publisher_from(0xB2u), boot_from(0xB2u),
                                                          FenceReason::Administrative, fixture.epoch);
    FDR_CHECK_EQ(unknown.code, OutcomeCode::StaleAuthority);
    FDR_CHECK_EQ(unknown.message, std::string("publisher is not registered"));
    FDR_CHECK_EQ(fixture.registry.generation(), after_bootstrap);
    FDR_CHECK(fixture.registry.fences().empty());

    const Outcome fenced = fixture.registry.fence_worker(fixture.publisher, fixture.boot, FenceReason::Administrative,
                                                         fixture.epoch);
    FDR_CHECK_EQ(fenced.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(fenced.message, std::string("worker incarnation fenced"));
    FDR_CHECK_EQ(fenced.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(fenced.steps.front().stage, std::string("authority"));
    FDR_CHECK_EQ(fenced.steps.front().field, std::string("worker-boot"));
    FDR_CHECK_EQ(fenced.steps.front().value, fixture.boot.to_string());
    FDR_CHECK_EQ(fenced.steps.front().detail, std::string("reason=administrative"));
    FDR_CHECK_EQ(fixture.registry.generation().value(), after_bootstrap.value() + 1u);

    // The fence names the incarnation, the reason, the epoch it was recorded
    // under and the generation the registry was at when it was recorded.
    const std::vector<FenceRecord> fences = fixture.registry.fences();
    FDR_CHECK_EQ(fences.size(), std::size_t{1});
    FDR_CHECK_EQ(fences.front().publisher, fixture.publisher);
    FDR_CHECK_EQ(fences.front().worker_boot, fixture.boot);
    FDR_CHECK_EQ(fences.front().reason, FenceReason::Administrative);
    FDR_CHECK_EQ(fences.front().epoch, fixture.epoch);
    FDR_CHECK_EQ(fences.front().at_generation, after_bootstrap);

    FDR_CHECK(fixture.registry.live_sessions().empty());
    FDR_CHECK(!fixture.registry.is_worker_live(fixture.publisher, fixture.boot));
    const RegistryGeneration after_fence = fixture.registry.generation();

    // Fencing the same incarnation again is already satisfied.
    const Outcome again = fixture.registry.fence_worker(fixture.publisher, fixture.boot, FenceReason::Administrative,
                                                        fixture.epoch);
    FDR_CHECK_EQ(again.code, OutcomeCode::Idempotent);
    FDR_CHECK_EQ(again.message, std::string("worker incarnation is already fenced"));
    FDR_CHECK_EQ(fixture.registry.generation().value(), after_fence.value());
    FDR_CHECK_EQ(fixture.registry.fences().size(), std::size_t{1});

    // The fenced incarnation can no longer attach, and everything it sends is
    // refused as a fenced boot rather than as a missing session.
    const Outcome reattach = fixture.registry.attach_worker(fixture.publisher, fixture.boot, fixture.epoch,
                                                            "fenced", EvidenceClass::Synthetic);
    FDR_CHECK_EQ(reattach.code, OutcomeCode::StaleWorkerBoot);
    FDR_CHECK_EQ(reattach.message, std::string("worker incarnation has been fenced"));
    FDR_CHECK_EQ(reattach.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(reattach.steps.front().field, std::string("worker-boot"));
    FDR_CHECK_EQ(reattach.steps.front().detail, std::string("fenced"));

    const Outcome create = create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(create.code, OutcomeCode::StaleWorkerBoot);
    FDR_CHECK_EQ(create.message, std::string("worker incarnation has been fenced"));
    FDR_CHECK_EQ(create.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(create.steps.front().stage, std::string("authority"));
    FDR_CHECK_EQ(create.steps.front().field, std::string("worker-boot"));
    FDR_CHECK_EQ(create.steps.front().detail, std::string("fenced"));

    // Granting authority is a mutation too, and a fenced incarnation may not
    // perform it.
    const Outcome grant = fixture.registry.grant_publisher(
        registration_of(publisher_from(0xB3u), "after-fence", AuthorityScope::unrestricted()), fixture.authority);
    FDR_CHECK_EQ(grant.code, OutcomeCode::StaleWorkerBoot);

    FDR_CHECK_EQ(fixture.registry.generation(), after_fence);
    FDR_CHECK_EQ(fixture.registry.domain_count(), std::size_t{0});
    FDR_CHECK_EQ(fixture.registry.publishers().size(), std::size_t{1});
    FDR_CHECK(fixture.registry.live_sessions().empty());
    check_state(fixture.registry);
}

FDR_TEST_CASE(authority, fencing_demotes_process_bound_classification_and_keeps_durable_classification) {
    Fixture fixture;
    bootstrap(fixture, 0xC1u);

    // The premise of the rule is the library's own classification of evidence.
    FDR_CHECK(is_process_bound_evidence(EvidenceClass::DirectHardwareController));
    FDR_CHECK(!is_process_bound_evidence(EvidenceClass::AdministrativeDeclaration));

    const Outcome process_bound =
        create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-measured", "Rack (measured)", kMeasuredRecord);
    const Outcome durable =
        create_now(fixture, 2u, DomainClass::Rack, "dc1", "rack-declared", "Rack (declared)", kOperatorRecord);
    FDR_CHECK_EQ(process_bound.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(durable.code, OutcomeCode::Committed);
    FDR_CHECK(process_bound.domain.has_value());
    FDR_CHECK(durable.domain.has_value());

    const EntityRef measured_member = entity_ref(EntityClass::Switch, 4u, 1u);
    const EntityRef declared_member = entity_ref(EntityClass::Switch, 5u, 1u);
    FDR_CHECK_EQ(attach_now(fixture, 3u, *process_bound.domain, measured_member,
                            EvidenceClass::DirectHardwareController, ProvenanceSource::VendorController,
                            "measured-member")
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(attach_now(fixture, 4u, *durable.domain, declared_member,
                            EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb, "declared-member")
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(fixture.registry.domains_in_lifecycle(DomainLifecycle::Current).size(), std::size_t{2});
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(), std::size_t{2});

    FDR_CHECK_EQ(fixture.registry
                     .fence_worker(fixture.publisher, fixture.boot, FenceReason::SessionLost, fixture.epoch)
                     .code,
                 OutcomeCode::Committed);

    // A classification that rested on the process stops being current: it is
    // not wrong, it is unknown, and the record says why.
    std::optional<FailureDomain> record = fixture.registry.domain(*process_bound.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::RevalidationRequired);
    FDR_CHECK(!record->is_current());
    FDR_CHECK(!record->is_terminal());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->history.size(), std::size_t{1});
    FDR_CHECK_EQ(record->history.front().cause, std::string("publishing incarnation was fenced"));
    // The entry records the generation the change started from; the record's own
    // generation above is the one the change produced.
    FDR_CHECK_EQ(record->history.front().previous_generation.value(), std::uint64_t{1});

    // A durable administrative classification never depended on the process,
    // so it keeps its lifecycle, its generation and its empty history.
    record = fixture.registry.domain(*durable.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Current);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK(record->history.empty());
    FDR_CHECK_EQ(fixture.registry.domains_in_lifecycle(DomainLifecycle::Current).size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.domains_in_lifecycle(DomainLifecycle::RevalidationRequired).size(), std::size_t{1});

    // Membership evidence is an attestation by an incarnation: the entries the
    // fenced incarnation published are withdrawn, and a membership left without
    // live evidence must be reconciled. That is true of the durable class as
    // well, which is why the domain, not the membership, is what survives.
    const MembershipKey measured_key{*process_bound.domain, measured_member.id(), measured_member.generation(),
                                     MembershipKind::Direct};
    const MembershipKey declared_key{*durable.domain, declared_member.id(), declared_member.generation(),
                                     MembershipKind::Direct};
    std::optional<Membership> membership = fixture.registry.membership(membership_id_for(measured_key));
    FDR_CHECK(membership.has_value());
    FDR_CHECK_EQ(membership->lifecycle, MembershipLifecycle::RevalidationRequired);
    FDR_CHECK_EQ(membership->generation.value(), std::uint64_t{2});
    FDR_CHECK(membership->evidence.empty());
    FDR_CHECK_EQ(membership->live_evidence_count(), std::size_t{0});
    FDR_CHECK_EQ(membership->history.size(), std::size_t{1});
    FDR_CHECK_EQ(membership->history.front().cause, std::string("publishing incarnation was fenced"));

    membership = fixture.registry.membership(membership_id_for(declared_key));
    FDR_CHECK(membership.has_value());
    FDR_CHECK_EQ(membership->lifecycle, MembershipLifecycle::RevalidationRequired);
    FDR_CHECK(membership->evidence.empty());
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(), std::size_t{0});

    // The domain the fence demoted refuses members until it is revalidated.
    const EntityRef later_member = entity_ref(EntityClass::Switch, 6u, 1u);
    const Outcome too_late = attach_now(fixture, 5u, *process_bound.domain, later_member,
                                        EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb,
                                        "cmdb-later");
    FDR_CHECK_EQ(too_late.code, OutcomeCode::RevalidationRequired);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{2});
    check_state(fixture.registry);
}

FDR_TEST_CASE(authority, advance_epoch_rejects_a_stale_expectation_without_changing_anything) {
    Fixture fixture;
    bootstrap(fixture, 0xD1u);
    const CoordinatorEpoch current = fixture.registry.epoch();
    const RegistryGeneration before = fixture.registry.generation();

    // The caller states the epoch it believes is current; a wrong belief is
    // stale, and the outcome reports the epoch that actually is current.
    CoordinatorEpoch reported(99u);
    const Outcome refused = fixture.registry.advance_epoch(CoordinatorEpoch(current.value() + 5u), &reported);
    FDR_CHECK_EQ(refused.code, OutcomeCode::StaleEpoch);
    FDR_CHECK_EQ(refused.message, std::string("coordinator epoch is not current"));
    FDR_CHECK_EQ(refused.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(refused.steps.front().stage, std::string("epoch"));
    FDR_CHECK_EQ(refused.steps.front().field, std::string("expected"));
    FDR_CHECK_EQ(refused.steps.front().value, std::string("6"));
    FDR_CHECK_EQ(refused.steps.front().detail, std::string("current epoch is 1"));

    // The out-parameter is untouched by a refusal: there is no new epoch.
    FDR_CHECK_EQ(reported.value(), std::uint64_t{99});
    FDR_CHECK_EQ(fixture.registry.epoch(), current);
    FDR_CHECK_EQ(fixture.registry.generation(), before);
    FDR_CHECK_EQ(fixture.registry.live_sessions().size(), std::size_t{1});
    FDR_CHECK(fixture.registry.is_worker_live(fixture.publisher, fixture.boot));
    FDR_CHECK(fixture.registry.fences().empty());

    // The bootstrap epoch is no longer acceptable either.
    CoordinatorEpoch untouched(77u);
    FDR_CHECK_EQ(fixture.registry.advance_epoch(CoordinatorEpoch{}, &untouched).code, OutcomeCode::StaleEpoch);
    FDR_CHECK_EQ(untouched.value(), std::uint64_t{77});
    FDR_CHECK_EQ(fixture.registry.epoch(), current);
    FDR_CHECK_EQ(fixture.registry.generation(), before);
    FDR_CHECK(fixture.registry.live_sessions().size() == std::size_t{1});
    check_state(fixture.registry);
}

FDR_TEST_CASE(authority, advance_epoch_fences_every_live_incarnation_and_stales_the_old_epoch) {
    Registry registry(RegistryLimits::defaults());
    const PublisherId alpha = publisher_from(0xE1u);
    const WorkerBootId alpha_boot = boot_from(0xE1u);
    const PublisherId beta = publisher_from(0xE2u);
    const WorkerBootId beta_boot = boot_from(0xE2u);

    FDR_CHECK_EQ(registry
                     .grant_publisher(registration_of(alpha, "alpha", AuthorityScope::unrestricted()),
                                      AuthorityContext{})
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(registry
                     .grant_publisher(registration_of(beta, "beta", AuthorityScope::unrestricted()),
                                      AuthorityContext{})
                     .code,
                 OutcomeCode::Committed);
    CoordinatorEpoch epoch;
    FDR_CHECK_EQ(registry.advance_epoch(CoordinatorEpoch{}, &epoch).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(epoch.value(), std::uint64_t{1});
    FDR_CHECK_EQ(registry.attach_worker(alpha, alpha_boot, epoch, "alpha", EvidenceClass::Synthetic).code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(registry.attach_worker(beta, beta_boot, epoch, "beta", EvidenceClass::Synthetic).code,
                 OutcomeCode::Committed);
    const AuthorityContext alpha_authority = authority_of(alpha, alpha_boot, epoch, EvidenceClass::Synthetic);
    const AuthorityContext beta_authority = authority_of(beta, beta_boot, epoch, EvidenceClass::Synthetic);

    // beta publishes a durable classification, alpha attests a membership with
    // a device reading, so the advance has one of each to demote.
    const Outcome durable_domain =
        create_now(registry, beta_authority, 1u, DomainClass::Rack, "dc1", "rack-declared", "Rack (declared)",
                   kOperatorRecord);
    FDR_CHECK_EQ(durable_domain.code, OutcomeCode::Committed);
    FDR_CHECK(durable_domain.domain.has_value());
    const EntityRef member = entity_ref(EntityClass::Switch, 9u, 1u);
    FDR_CHECK_EQ(attach_now(registry, alpha_authority, 2u, *durable_domain.domain, member,
                            EvidenceClass::DirectHardwareController, ProvenanceSource::VendorController,
                            "alpha-member")
                     .code,
                 OutcomeCode::Committed);

    const std::size_t live_before = registry.live_sessions().size();
    FDR_CHECK_EQ(live_before, std::size_t{2});
    const RegistryGeneration before = registry.generation();

    CoordinatorEpoch next;
    const Outcome advanced = registry.advance_epoch(epoch, &next);
    FDR_CHECK_EQ(advanced.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(advanced.message, std::string("coordinator epoch advanced"));
    FDR_CHECK_EQ(advanced.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(advanced.steps.front().stage, std::string("epoch"));
    FDR_CHECK_EQ(advanced.steps.front().value, std::string("2"));
    FDR_CHECK_EQ(advanced.steps.front().detail, std::string("2 live incarnation(s) fenced"));
    FDR_CHECK_EQ(next.value(), std::uint64_t{2});
    FDR_CHECK_EQ(registry.epoch().value(), std::uint64_t{2});
    FDR_CHECK_EQ(registry.generation().value(), before.value() + 1u);

    // Exactly one fence per live incarnation, all of them coordinator restarts,
    // recorded against the generation the advance started from and the epoch it
    // produced.
    const std::vector<FenceRecord> fences = registry.fences();
    FDR_CHECK_EQ(fences.size(), live_before);
    FDR_CHECK_EQ(fences.front().publisher, alpha);
    FDR_CHECK_EQ(fences.front().worker_boot, alpha_boot);
    FDR_CHECK_EQ(fences.front().reason, FenceReason::CoordinatorRestart);
    FDR_CHECK_EQ(fences.front().epoch, next);
    FDR_CHECK_EQ(fences.front().at_generation, before);
    FDR_CHECK_EQ(fences.back().publisher, beta);
    FDR_CHECK_EQ(fences.back().worker_boot, beta_boot);
    FDR_CHECK_EQ(fences.back().reason, FenceReason::CoordinatorRestart);
    FDR_CHECK_EQ(fences.back().epoch, next);
    FDR_CHECK_EQ(fences.back().at_generation, before);

    FDR_CHECK(registry.live_sessions().empty());
    FDR_CHECK(!registry.is_worker_live(alpha, alpha_boot));
    FDR_CHECK(!registry.is_worker_live(beta, beta_boot));

    // The attestation alpha published is withdrawn; the durable domain it
    // pointed at survives.
    const MembershipKey key{*durable_domain.domain, member.id(), member.generation(), MembershipKind::Direct};
    const std::optional<Membership> membership = registry.membership(membership_id_for(key));
    FDR_CHECK(membership.has_value());
    FDR_CHECK_EQ(membership->lifecycle, MembershipLifecycle::RevalidationRequired);
    FDR_CHECK(membership->evidence.empty());
    FDR_CHECK_EQ(membership->history.front().cause, std::string("coordinator epoch advanced"));

    const std::optional<FailureDomain> record = registry.domain(*durable_domain.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Current);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});

    // The epoch and the incarnation are separate checks: traffic from the old
    // epoch is stale, and traffic naming an old incarnation at the new epoch is
    // a fenced boot.
    const RegistryGeneration after_advance = registry.generation();
    const Outcome old_epoch = create_now(registry, alpha_authority, 3u, DomainClass::Rack, "dc1", "rack-late",
                                         "Rack Late", kOperatorRecord);
    FDR_CHECK_EQ(old_epoch.code, OutcomeCode::StaleEpoch);
    FDR_CHECK_EQ(old_epoch.message, std::string("coordinator epoch is not current"));
    FDR_CHECK_EQ(old_epoch.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(old_epoch.steps.front().field, std::string("epoch"));
    FDR_CHECK_EQ(old_epoch.steps.front().detail, std::string("current epoch is 2"));
    FDR_CHECK_EQ(registry.generation(), after_advance);
    FDR_CHECK_EQ(registry.domain_count(), std::size_t{1});

    const AuthorityContext old_boot_new_epoch = authority_of(alpha, alpha_boot, next, EvidenceClass::Synthetic);
    const Outcome fenced_boot = create_now(registry, old_boot_new_epoch, 4u, DomainClass::Rack, "dc1", "rack-late",
                                           "Rack Late", kOperatorRecord);
    FDR_CHECK_EQ(fenced_boot.code, OutcomeCode::StaleWorkerBoot);
    FDR_CHECK_EQ(fenced_boot.message, std::string("worker incarnation has been fenced"));
    FDR_CHECK_EQ(registry.generation(), after_advance);
    FDR_CHECK_EQ(registry.domain_count(), std::size_t{1});

    // A fresh incarnation at the new epoch restores mutation.
    const WorkerBootId alpha_again = boot_from(0xE3u);
    FDR_CHECK_EQ(registry.attach_worker(alpha, alpha_again, next, "alpha-again", EvidenceClass::Synthetic).code,
                 OutcomeCode::Committed);
    const Outcome committed =
        create_now(registry, authority_of(alpha, alpha_again, next, EvidenceClass::Synthetic), 5u, DomainClass::Rack,
                   "dc1", "rack-late", "Rack Late", kOperatorRecord);
    FDR_CHECK_EQ(committed.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(registry.domain_count(), std::size_t{2});
    check_state(registry);
}

FDR_TEST_CASE(authority, process_bound_incarnations_lists_every_incarnation_in_current_state_in_order) {
    Registry registry(RegistryLimits::defaults());
    const PublisherId alpha = publisher_from(0x71u);
    const WorkerBootId alpha_boot = boot_from(0x71u);
    const PublisherId beta = publisher_from(0x72u);
    const WorkerBootId beta_boot = boot_from(0x72u);

    FDR_CHECK_EQ(registry
                     .grant_publisher(registration_of(alpha, "alpha", AuthorityScope::unrestricted()),
                                      AuthorityContext{})
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(registry
                     .grant_publisher(registration_of(beta, "beta", AuthorityScope::unrestricted()),
                                      AuthorityContext{})
                     .code,
                 OutcomeCode::Committed);
    CoordinatorEpoch epoch;
    FDR_CHECK_EQ(registry.advance_epoch(CoordinatorEpoch{}, &epoch).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(registry.attach_worker(alpha, alpha_boot, epoch, "alpha", EvidenceClass::Synthetic).code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(registry.attach_worker(beta, beta_boot, epoch, "beta", EvidenceClass::Synthetic).code,
                 OutcomeCode::Committed);
    const AuthorityContext alpha_authority = authority_of(alpha, alpha_boot, epoch, EvidenceClass::Synthetic);
    const AuthorityContext beta_authority = authority_of(beta, beta_boot, epoch, EvidenceClass::Synthetic);

    FDR_CHECK(registry.process_bound_incarnations().empty());

    // beta publishes a process-bound classification first, so a listing that
    // followed insertion order would put beta before alpha.
    const Outcome beta_domain =
        create_now(registry, beta_authority, 1u, DomainClass::Rack, "dc1", "rack-beta", "Rack Beta",
                   provenance_of(ProvenanceSource::VendorController, EvidenceClass::DirectHardwareController,
                                 TruthClass::Real, "beta-controller"));
    FDR_CHECK_EQ(beta_domain.code, OutcomeCode::Committed);
    FDR_CHECK(beta_domain.domain.has_value());
    const Outcome alpha_domain =
        create_now(registry, alpha_authority, 1u, DomainClass::Rack, "dc1", "rack-alpha", "Rack Alpha",
                   kOperatorRecord);
    FDR_CHECK_EQ(alpha_domain.code, OutcomeCode::Committed);
    FDR_CHECK(alpha_domain.domain.has_value());

    // alpha contributes no domain, only a membership resting on its own
    // incarnation, which is enough to name it.
    const EntityRef member = entity_ref(EntityClass::Switch, 6u, 1u);
    FDR_CHECK_EQ(attach_now(registry, alpha_authority, 2u, *alpha_domain.domain, member,
                            EvidenceClass::DirectHardwareController, ProvenanceSource::DiscoveryAgent,
                            "alpha-member")
                     .code,
                 OutcomeCode::Committed);

    // The order is the identifier order, and the seeds fix which identifier is
    // smaller, so this expectation is exact rather than merely "some order".
    FDR_CHECK(alpha < beta);
    const std::vector<Incarnation> both{Incarnation{alpha, alpha_boot}, Incarnation{beta, beta_boot}};
    FDR_CHECK_EQ(registry.process_bound_incarnations(), both);

    // Fencing alpha withdraws the only evidence that named it, so the pair is
    // gone from the answer.
    FDR_CHECK_EQ(registry.fence_worker(alpha, alpha_boot, FenceReason::SessionLost, epoch).code,
                 OutcomeCode::Committed);
    const std::vector<Incarnation> only_beta{Incarnation{beta, beta_boot}};
    FDR_CHECK_EQ(registry.process_bound_incarnations(), only_beta);

    // beta's domain keeps its provenance even after the fence demotes its
    // lifecycle, so the pair stays listed: the answer names the process the
    // current state still rests on, not a live session.
    FDR_CHECK_EQ(registry.fence_worker(beta, beta_boot, FenceReason::SessionLost, epoch).code,
                 OutcomeCode::Committed);
    const std::optional<FailureDomain> demoted = registry.domain(*beta_domain.domain);
    FDR_CHECK(demoted.has_value());
    FDR_CHECK_EQ(demoted->lifecycle, DomainLifecycle::RevalidationRequired);
    FDR_CHECK_EQ(demoted->provenance.publisher, beta);
    FDR_CHECK_EQ(demoted->provenance.worker_boot, beta_boot);
    FDR_CHECK_EQ(registry.process_bound_incarnations(), only_beta);
    FDR_CHECK(registry.live_sessions().empty());
    check_state(registry);
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
