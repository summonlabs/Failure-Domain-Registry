// Failure Domain Registry — membership identity, evidence and lifecycle.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A membership is the only record that says "this member, at this exact entity
// generation, belongs to this domain, at this exact domain generation", and it
// carries its own evidence set, generation and lifecycle. Everything a caller
// may rely on about that record is pinned here against the public API alone:
// the deterministic key, the evidence precedence rule, the exclusivity rule of
// a domain class, the terminality of a detach, and the exact behaviour of the
// bulk publication, evidence withdrawal and reconciliation paths.
//
// Every case asserts the exact OutcomeCode of every call and the exact
// generation and lifecycle that resulted, and every refusal is also checked
// against the state it was supposed to leave alone. Each accepted mutation is
// followed by Registry::validate_state, so an operation that leaves one of the
// maintained indexes out of step fails here rather than much later in an
// unrelated query.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "failure_domain_registry/failure_domain_registry.hpp"
#include "support/test_harness.hpp"

namespace {

using failure_domain_registry::AttachMemberRequest;
using failure_domain_registry::AuthorityContext;
using failure_domain_registry::AuthorityScope;
using failure_domain_registry::CoordinatorEpoch;
using failure_domain_registry::CreateDomainRequest;
using failure_domain_registry::DependencySemantics;
using failure_domain_registry::DerivationOperator;
using failure_domain_registry::DerivationReport;
using failure_domain_registry::DerivationRule;
using failure_domain_registry::DerivationRunRequest;
using failure_domain_registry::DetachMemberRequest;
using failure_domain_registry::DomainClass;
using failure_domain_registry::DomainClassRef;
using failure_domain_registry::DomainLifecycle;
using failure_domain_registry::EntityClass;
using failure_domain_registry::EntityGeneration;
using failure_domain_registry::EntityRef;
using failure_domain_registry::EvidenceClass;
using failure_domain_registry::FailureDomain;
using failure_domain_registry::FailureDomainGeneration;
using failure_domain_registry::FailureDomainId;
using failure_domain_registry::IdBytes;
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
using failure_domain_registry::MergeDomainsRequest;
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
using failure_domain_registry::ReconcileMembershipRequest;
using failure_domain_registry::Registry;
using failure_domain_registry::RegistryGeneration;
using failure_domain_registry::RegistryLimits;
using failure_domain_registry::ReplaceMembershipRequest;
using failure_domain_registry::RequestDigest;
using failure_domain_registry::RetireDomainRequest;
using failure_domain_registry::SupersedeDomainRequest;
using failure_domain_registry::TruthClass;
using failure_domain_registry::UpdateDomainRequest;
using failure_domain_registry::WithdrawEvidenceRequest;
using failure_domain_registry::WorkerBootId;
using failure_domain_registry::domain_id_for;
using failure_domain_registry::is_indeterminate;
using failure_domain_registry::membership_id_for;

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

std::vector<MetadataEntry> metadata_of(std::string key, std::string value) {
    std::vector<MetadataEntry> metadata;
    metadata.push_back(MetadataEntry{std::move(key), std::move(value)});
    return metadata;
}

MembershipKey membership_key(const FailureDomainId& domain, const EntityRef& member,
                             MembershipKind kind) {
    MembershipKey key;
    key.domain = domain;
    key.member = member.id();
    key.member_generation = member.generation();
    key.kind = kind;
    return key;
}

FailureDomainId id_of(const std::string& scope, DomainClass domain_class,
                      const std::string& identity_key) {
    return domain_id_for(scope, DomainClassRef(domain_class), identity_key);
}

/// The durable operator record every case falls back to when it is not testing
/// provenance.
const Provenance kOperatorRecord = provenance_of(ProvenanceSource::Cmdb,
                                                 EvidenceClass::AdministrativeDeclaration,
                                                 TruthClass::Real, "cmdb-1");

/// The consistency check every accepted mutation must survive.
void check_state(const Registry& registry) {
    std::string why;
    FDR_CHECK_MSG(registry.validate_state(&why), "registry state is inconsistent: " + why);
}

/// A registry with one unrestricted publisher granted at bootstrap and one live
/// incarnation attached at epoch 1: the state every case in this file starts
/// from. Registry is not movable, so the pieces are stored in place.
struct Fixture {
    explicit Fixture(RegistryLimits limits_in = RegistryLimits::defaults())
        : registry(limits_in) {}

    Registry registry;
    PublisherId publisher{};
    WorkerBootId boot{};
    CoordinatorEpoch epoch{};
    AuthorityContext authority{};
    /// Set by add_second_publisher for the cases that need two writers.
    AuthorityContext second_authority{};
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

    const Outcome attached = fixture.registry.attach_worker(
        fixture.publisher, fixture.boot, established, "fixture",
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

/// Grants and attaches a second unrestricted publisher at the same epoch, so a
/// case can prove that membership identity never depends on who asserted it.
void add_second_publisher(Fixture& fixture, std::uint8_t seed) {
    const PublisherId publisher = publisher_from(seed);
    const WorkerBootId boot = boot_from(seed);

    PublisherRegistration registration;
    registration.publisher = publisher;
    registration.name = "second-publisher";
    registration.scope = AuthorityScope::unrestricted();

    const Outcome granted = fixture.registry.grant_publisher(registration, fixture.authority);
    FDR_CHECK_EQ(granted.code, OutcomeCode::Committed);
    const Outcome attached = fixture.registry.attach_worker(
        publisher, boot, fixture.epoch, "second",
        EvidenceClass::DirectAuthoritativeInfrastructure);
    FDR_CHECK_EQ(attached.code, OutcomeCode::Committed);

    fixture.second_authority = fixture.authority;
    fixture.second_authority.publisher = publisher;
    fixture.second_authority.worker_boot = boot;
}

CreateDomainRequest create_request(const Fixture& fixture, std::uint8_t index,
                                   DomainClass domain_class, std::string scope,
                                   std::string identity_key, std::string name,
                                   Provenance provenance, bool activate = true) {
    CreateDomainRequest request;
    request.attempt = attempt_with(index);
    request.authority = fixture.authority;
    request.domain_class = DomainClassRef(domain_class);
    request.administrative_scope = std::move(scope);
    request.identity_key = std::move(identity_key);
    request.name = std::move(name);
    request.provenance = std::move(provenance);
    request.activate = activate;
    return request;
}

Outcome create_now(Fixture& fixture, std::uint8_t index, DomainClass domain_class,
                   const std::string& scope, const std::string& identity_key,
                   const std::string& name, const Provenance& provenance, bool activate = true) {
    return fixture.registry.create_domain(
        create_request(fixture, index, domain_class, scope, identity_key, name, provenance, activate));
}

/// Every field of an attach a case may need to vary, so a case states only the
/// part it is testing.
struct AttachSpec {
    FailureDomainGeneration expected{};
    MembershipKind kind{MembershipKind::Direct};
    MembershipRole role{MembershipRole::Primary};
    DependencySemantics dependency{DependencySemantics::AllDependenciesRequired};
    Provenance provenance{};
    std::vector<MetadataEntry> metadata{};
};

/// A DIRECT, PRIMARY membership whose existence the member depends on.
AttachSpec direct_spec(ProvenanceSource source, EvidenceClass evidence, std::string source_identity) {
    AttachSpec spec;
    spec.provenance = provenance_of(source, evidence, TruthClass::Real, std::move(source_identity));
    return spec;
}

Outcome attach_as(Fixture& fixture, const AuthorityContext& authority, std::uint8_t index,
                  const FailureDomainId& domain, const EntityRef& member, const AttachSpec& spec) {
    AttachMemberRequest request;
    request.attempt = attempt_with(index);
    request.authority = authority;
    request.domain = domain;
    request.expected_domain_generation = spec.expected;
    request.member = member;
    request.kind = spec.kind;
    request.role = spec.role;
    request.dependency = spec.dependency;
    request.provenance = spec.provenance;
    request.metadata = spec.metadata;
    return fixture.registry.attach_member(request);
}

Outcome attach_with(Fixture& fixture, std::uint8_t index, const FailureDomainId& domain,
                    const EntityRef& member, const AttachSpec& spec) {
    return attach_as(fixture, fixture.authority, index, domain, member, spec);
}

Outcome attach_now(Fixture& fixture, std::uint8_t index, const FailureDomainId& domain,
                   const EntityRef& member, EvidenceClass evidence, ProvenanceSource source,
                   const std::string& source_identity) {
    return attach_with(fixture, index, domain, member, direct_spec(source, evidence, source_identity));
}

DetachMemberRequest detach_request(const Fixture& fixture, std::uint8_t index,
                                   const FailureDomainId& domain, const EntityRef& member,
                                   MembershipGeneration expected, std::string reason) {
    DetachMemberRequest request;
    request.attempt = attempt_with(index);
    request.authority = fixture.authority;
    request.domain = domain;
    request.member = member;
    request.kind = MembershipKind::Direct;
    request.expected_membership_generation = expected;
    request.reason = std::move(reason);
    return request;
}

/// Every field of a replace a case may need to vary. Unspecified role and
/// dependency mean "leave it alone", and an Unknown evidence class means "leave
/// the evidence set alone".
struct ReplaceSpec {
    MembershipGeneration expected{};
    MembershipRole role{MembershipRole::Unspecified};
    DependencySemantics dependency{DependencySemantics::Unspecified};
    Provenance provenance{};
    bool replace_metadata{false};
    std::vector<MetadataEntry> metadata{};
};

ReplaceMembershipRequest replace_request(const Fixture& fixture, std::uint8_t index,
                                         const MembershipId& membership, const ReplaceSpec& spec) {
    ReplaceMembershipRequest request;
    request.attempt = attempt_with(index);
    request.authority = fixture.authority;
    request.membership = membership;
    request.expected_generation = spec.expected;
    request.role = spec.role;
    request.dependency = spec.dependency;
    request.provenance = spec.provenance;
    request.replace_metadata = spec.replace_metadata;
    request.metadata = spec.metadata;
    return request;
}

/// Withdraw as an explicit publisher: withdrawal is scoped to the publisher
/// whose evidence is on the record, not to the record the request names.
WithdrawEvidenceRequest withdraw_as(const AuthorityContext& authority, std::uint8_t index,
                                    const MembershipId& membership, MembershipGeneration expected,
                                    bool only_this_worker_boot, std::string reason) {
    WithdrawEvidenceRequest request;
    request.attempt = attempt_with(index);
    request.authority = authority;
    request.membership = membership;
    request.expected_generation = expected;
    request.only_this_worker_boot = only_this_worker_boot;
    request.reason = std::move(reason);
    return request;
}

WithdrawEvidenceRequest withdraw_request(const Fixture& fixture, std::uint8_t index,
                                         const MembershipId& membership,
                                         MembershipGeneration expected, bool only_this_worker_boot,
                                         std::string reason) {
    return withdraw_as(fixture.authority, index, membership, expected, only_this_worker_boot,
                       std::move(reason));
}

ReconcileMembershipRequest reconcile_request(const Fixture& fixture, std::uint8_t index,
                                             const FailureDomainId& domain, const EntityRef& member) {
    ReconcileMembershipRequest request;
    request.attempt = attempt_with(index);
    request.authority = fixture.authority;
    request.domain = domain;
    request.member = member;
    request.kind = MembershipKind::Direct;
    return request;
}

MarkRevalidationRequest mark_request(const Fixture& fixture, std::uint8_t index,
                                     const FailureDomainId& domain, std::string reason) {
    MarkRevalidationRequest request;
    request.attempt = attempt_with(index);
    request.authority = fixture.authority;
    request.domain = domain;
    request.reason = std::move(reason);
    return request;
}

Outcome supersede_now(Fixture& fixture, std::uint8_t index, const FailureDomainId& domain,
                      const FailureDomainId& successor, bool demote) {
    SupersedeDomainRequest request;
    request.attempt = attempt_with(index);
    request.authority = fixture.authority;
    request.domain = domain;
    request.successor = successor;
    request.demote_memberships = demote;
    return fixture.registry.supersede_domain(request);
}

Outcome retire_now(Fixture& fixture, std::uint8_t index, const FailureDomainId& domain,
                   const std::string& reason, bool retire_memberships) {
    RetireDomainRequest request;
    request.attempt = attempt_with(index);
    request.authority = fixture.authority;
    request.domain = domain;
    request.reason = reason;
    request.retire_memberships = retire_memberships;
    return fixture.registry.retire_domain(request);
}

Outcome merge_now(Fixture& fixture, std::uint8_t index, const FailureDomainId& survivor,
                  const FailureDomainId& absorbed, bool memberships_equivalent) {
    MergeDomainsRequest request;
    request.attempt = attempt_with(index);
    request.authority = fixture.authority;
    request.survivor = survivor;
    request.absorbed = absorbed;
    request.memberships_equivalent = memberships_equivalent;
    request.reason = "the same factor was named twice";
    return fixture.registry.merge_domains(request);
}

MembershipBatchEntry batch_entry(const FailureDomainId& domain, const EntityRef& member,
                                 const Provenance& provenance) {
    MembershipBatchEntry entry;
    entry.domain = domain;
    entry.member = member;
    entry.kind = MembershipKind::Direct;
    entry.role = MembershipRole::Primary;
    entry.dependency = DependencySemantics::AllDependenciesRequired;
    entry.provenance = provenance;
    return entry;
}

Outcome publish_now(Fixture& fixture, std::uint8_t index, MembershipBatchRequest request) {
    request.attempt = attempt_with(index);
    request.authority = fixture.authority;
    return fixture.registry.publish_memberships(request);
}

/// One derived membership, produced by the only evaluator this build publishes.
/// A DERIVED membership cannot be attached directly, so the derivation engine is
/// the only honest way to reach it.
struct DerivedSetup {
    FailureDomainId rack{};
    FailureDomainId pdu{};
    EntityRef anchor{};   ///< Switch that is a direct member of the Pdu.
    EntityRef subject{};  ///< Switch that receives the derived membership.
    MembershipId derived{};  ///< (pdu, subject, subject generation, DERIVED).
};

void bootstrap_derivation(Fixture& fixture, std::uint8_t base, DerivedSetup& setup) {
    setup.rack = id_of("dc1", DomainClass::Rack, "derived-rack");
    setup.pdu = id_of("dc1", DomainClass::Pdu, "derived-pdu");
    setup.anchor = entity_ref(EntityClass::Switch, 21u, 4u);
    setup.subject = entity_ref(EntityClass::Switch, 22u, 4u);

    FDR_CHECK_EQ(create_now(fixture, base, DomainClass::Rack, "dc1", "derived-rack", "Rack D",
                            kOperatorRecord)
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(create_now(fixture, static_cast<std::uint8_t>(base + 1u), DomainClass::Pdu, "dc1",
                            "derived-pdu", "Pdu D", kOperatorRecord)
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(attach_now(fixture, static_cast<std::uint8_t>(base + 2u), setup.rack, setup.anchor,
                            EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb, "cmdb-d1")
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(attach_now(fixture, static_cast<std::uint8_t>(base + 3u), setup.pdu, setup.anchor,
                            EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb, "cmdb-d2")
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(attach_now(fixture, static_cast<std::uint8_t>(base + 4u), setup.rack, setup.subject,
                            EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb, "cmdb-d3")
                     .code,
                 OutcomeCode::Committed);

    DerivationRule rule;
    rule.name = "switch-shares-its-pdu";
    rule.op = DerivationOperator::MembersShareContainingClass;
    rule.source_class = DomainClassRef(DomainClass::Rack);
    rule.target_class = DomainClassRef(DomainClass::Pdu);
    rule.member_class = EntityClass::Switch;
    rule.derived_role = MembershipRole::Derived;
    rule.dependency = DependencySemantics::Unspecified;
    FDR_CHECK_EQ(fixture.registry.publish_derivation_rule(rule, fixture.authority).code,
                 OutcomeCode::Committed);

    DerivationReport report;
    DerivationRunRequest run;
    run.attempt = attempt_with(static_cast<std::uint8_t>(base + 5u));
    run.authority = fixture.authority;
    const Outcome derived = fixture.registry.run_derivation(run, &report);
    FDR_CHECK_EQ(derived.code, OutcomeCode::Committed);
    // Both Switch members of the rack inherit the Pdu that one of them is in.
    FDR_CHECK_EQ(report.memberships_created, std::size_t{2});

    setup.derived = membership_id_for(membership_key(setup.pdu, setup.subject, MembershipKind::Derived));
    FDR_CHECK(!setup.derived.is_null());
}

} // namespace

FDR_TEST_CASE(membership, attach_member_commits_generation_one_and_binds_both_generations) {
    Fixture fixture;
    bootstrap(fixture, 0x11u);
    const FailureDomainId rack = id_of("dc1", DomainClass::Rack, "rack-r7");
    const Outcome created = create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7",
                                       kOperatorRecord);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
    FDR_CHECK(created.domain.has_value());
    FDR_CHECK_EQ(*created.domain, rack);

    const EntityRef member = entity_ref(EntityClass::Switch, 1u, 5u);
    const MembershipId expected_id = membership_id_for(membership_key(rack, member, MembershipKind::Direct));
    FDR_CHECK(!expected_id.is_null());

    AttachSpec spec = direct_spec(ProvenanceSource::VendorController,
                                  EvidenceClass::DirectHardwareController, "controller-7");
    spec.metadata = metadata_of("ticket", "MR-1");

    const RegistryGeneration before_attach = fixture.registry.generation();
    const Outcome attached = attach_with(fixture, 2u, rack, member, spec);
    FDR_CHECK_EQ(attached.code, OutcomeCode::Committed);
    FDR_CHECK(attached.domain.has_value());
    FDR_CHECK_EQ(*attached.domain, rack);
    FDR_CHECK(attached.membership.has_value());
    FDR_CHECK_EQ(*attached.membership, expected_id);
    FDR_CHECK(attached.member.has_value());
    FDR_CHECK_EQ(*attached.member, member);
    FDR_CHECK(attached.membership_generation.has_value());
    FDR_CHECK_EQ(attached.membership_generation->value(), std::uint64_t{1});
    FDR_CHECK_EQ(fixture.registry.generation().value(), before_attach.value() + 1u);
    // The outcome reports the state generation the caller must now hold.
    FDR_CHECK(attached.state_generation.has_value());
    FDR_CHECK_EQ(*attached.state_generation, fixture.registry.generation());
    FDR_CHECK(attached.epoch.has_value());
    FDR_CHECK_EQ(*attached.epoch, fixture.epoch);

    std::optional<Membership> record = fixture.registry.membership(expected_id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->id, expected_id);
    FDR_CHECK_EQ(record->domain, rack);
    // Both bindings are exact: the domain generation that was current, and the
    // entity generation the caller named.
    FDR_CHECK_EQ(record->domain_generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(record->member, member);
    FDR_CHECK_EQ(record->member.generation().value(), std::uint64_t{5});
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK(record->is_current());
    FDR_CHECK(!record->is_terminal());
    FDR_CHECK(!is_indeterminate(record->lifecycle));
    FDR_CHECK_EQ(record->kind, MembershipKind::Direct);
    FDR_CHECK_EQ(record->role, MembershipRole::Primary);
    FDR_CHECK_EQ(record->dependency, DependencySemantics::AllDependenciesRequired);
    FDR_CHECK_EQ(record->metadata.size(), std::size_t{1});
    FDR_CHECK_EQ(record->metadata.front().key, std::string("ticket"));
    FDR_CHECK_EQ(record->metadata.front().value, std::string("MR-1"));
    FDR_CHECK_EQ(record->created_at.value(), before_attach.value());
    FDR_CHECK_EQ(record->created_epoch.value(), std::uint64_t{1});
    FDR_CHECK(record->superseded_by.is_null());
    FDR_CHECK(record->supersedes.is_null());
    FDR_CHECK(record->history.empty());

    // Exactly one live corroboration, and it is the assertion itself: the
    // evidence entry and the headline provenance are the same statement.
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{1});
    FDR_CHECK_EQ(record->live_evidence_count(), std::size_t{1});
    FDR_CHECK(record->evidence.front().live);
    FDR_CHECK_EQ(record->evidence.front().provenance, record->provenance);
    FDR_CHECK_EQ(record->provenance.source, ProvenanceSource::VendorController);
    FDR_CHECK_EQ(record->provenance.evidence, EvidenceClass::DirectHardwareController);
    FDR_CHECK_EQ(record->provenance.truth, TruthClass::Real);
    FDR_CHECK_EQ(record->provenance.source_identity, std::string("controller-7"));
    // Provenance is attributed to the calling incarnation, not to the caller's
    // claim about itself.
    FDR_CHECK_EQ(record->provenance.publisher, fixture.publisher);
    FDR_CHECK_EQ(record->provenance.worker_boot, fixture.boot);
    FDR_CHECK(!record->evidence_generation.is_zero());
    FDR_CHECK_EQ(record->provenance.evidence_generation, record->evidence_generation);

    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.members_of(rack).size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.memberships_of(member.id()).size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(),
                 std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Retired).size(),
                 std::size_t{0});
    check_state(fixture.registry);

    // The binding is to the domain generation in force at the moment of the
    // assertion: a domain that moved on re-binds the membership instead of
    // leaving it silently attached to a generation that no longer exists.
    UpdateDomainRequest rename;
    rename.attempt = attempt_with(3u);
    rename.authority = fixture.authority;
    rename.domain = rack;
    rename.expected_generation = FailureDomainGeneration(1u);
    rename.name = "Rack R7 (row A)";
    const Outcome renamed = fixture.registry.update_domain(rename);
    FDR_CHECK_EQ(renamed.code, OutcomeCode::Committed);
    FDR_CHECK(renamed.domain_generation.has_value());
    FDR_CHECK_EQ(renamed.domain_generation->value(), std::uint64_t{2});

    AttachSpec stronger = direct_spec(ProvenanceSource::PhysicalInfrastructure,
                                      EvidenceClass::DirectAuthoritativeInfrastructure, "dcim-1");
    stronger.metadata = metadata_of("ticket", "MR-1");
    const Outcome rebound = attach_with(fixture, 4u, rack, member, stronger);
    FDR_CHECK_EQ(rebound.code, OutcomeCode::Committed);
    FDR_CHECK(rebound.membership_generation.has_value());
    FDR_CHECK_EQ(rebound.membership_generation->value(), std::uint64_t{2});

    record = fixture.registry.membership(expected_id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->domain_generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{2});
    FDR_CHECK_EQ(record->live_evidence_count(), std::size_t{2});
    FDR_CHECK_EQ(record->provenance.evidence, EvidenceClass::DirectAuthoritativeInfrastructure);
    FDR_CHECK_EQ(record->provenance.source_identity, std::string("dcim-1"));
    FDR_CHECK_EQ(record->history.size(), std::size_t{1});
    FDR_CHECK_EQ(record->history.front().cause, std::string("reasserted"));
    FDR_CHECK_EQ(record->history.front().previous_generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{1});
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, membership_id_for_depends_only_on_the_four_key_components) {
    const FailureDomainId rack = id_of("dc1", DomainClass::Rack, "rack-r7");
    const FailureDomainId pod = id_of("dc1", DomainClass::Pod, "pod-p1");
    const EntityRef member = entity_ref(EntityClass::Switch, 4u, 3u);
    const EntityRef other_entity = entity_ref(EntityClass::Switch, 5u, 3u);
    const EntityRef other_generation = entity_ref(EntityClass::Switch, 4u, 4u);

    const MembershipId base = membership_id_for(membership_key(rack, member, MembershipKind::Direct));
    FDR_CHECK(!base.is_null());
    // The same key is the same identity, whenever it is computed.
    FDR_CHECK_EQ(membership_id_for(membership_key(rack, member, MembershipKind::Direct)), base);
    FDR_CHECK_EQ(membership_id_for(membership_key(rack, member, MembershipKind::Direct)).to_string(),
                 base.to_string());

    // Each of the four components participates: changing any one of them
    // addresses a different membership and must never resolve to the same record.
    const MembershipId other_domain = membership_id_for(membership_key(pod, member, MembershipKind::Direct));
    const MembershipId other_member = membership_id_for(membership_key(rack, other_entity, MembershipKind::Direct));
    const MembershipId other_member_generation =
        membership_id_for(membership_key(rack, other_generation, MembershipKind::Direct));
    const MembershipId asserted = membership_id_for(membership_key(rack, member, MembershipKind::Asserted));
    const MembershipId inherited = membership_id_for(membership_key(rack, member, MembershipKind::Inherited));
    FDR_CHECK(!(other_domain == base));
    FDR_CHECK(!(other_member == base));
    FDR_CHECK(!(other_member_generation == base));
    FDR_CHECK(!(asserted == base));
    FDR_CHECK(!(inherited == base));
    FDR_CHECK(!(asserted == inherited));
    FDR_CHECK(!(other_member == other_member_generation));

    // Two entries in the same domain for the same entity at two generations are
    // two memberships, never one that was overwritten.
    Fixture fixture;
    bootstrap(fixture, 0x21u);
    FDR_CHECK_EQ(create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord).code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(create_now(fixture, 2u, DomainClass::Pod, "dc1", "pod-p1", "Pod P1", kOperatorRecord).code,
                 OutcomeCode::Committed);

    const Outcome first = attach_now(fixture, 3u, rack, member, EvidenceClass::AdministrativeDeclaration,
                                     ProvenanceSource::Cmdb, "cmdb-1");
    FDR_CHECK_EQ(first.code, OutcomeCode::Committed);
    FDR_CHECK(first.membership.has_value());
    FDR_CHECK_EQ(*first.membership, base);

    const Outcome second = attach_now(fixture, 4u, pod, member, EvidenceClass::AdministrativeDeclaration,
                                      ProvenanceSource::Cmdb, "cmdb-2");
    FDR_CHECK_EQ(second.code, OutcomeCode::Committed);
    FDR_CHECK(second.membership.has_value());
    FDR_CHECK_EQ(*second.membership, other_domain);

    const Outcome third = attach_now(fixture, 5u, rack, other_generation,
                                     EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb,
                                     "cmdb-3");
    FDR_CHECK_EQ(third.code, OutcomeCode::Committed);
    FDR_CHECK(third.membership.has_value());
    FDR_CHECK_EQ(*third.membership, other_member_generation);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{3});

    const std::optional<Membership> stored = fixture.registry.membership(base);
    FDR_CHECK(stored.has_value());
    FDR_CHECK_EQ(stored->member.generation().value(), std::uint64_t{3});
    const std::optional<Membership> later = fixture.registry.membership(other_member_generation);
    FDR_CHECK(later.has_value());
    FDR_CHECK_EQ(later->member.generation().value(), std::uint64_t{4});
    FDR_CHECK_EQ(later->domain, rack);
    check_state(fixture.registry);

    // The id is a pure function of its four inputs: a registry that saw the
    // unrelated traffic in the opposite order mints the same id.
    Fixture reversed;
    bootstrap(reversed, 0x22u);
    FDR_CHECK_EQ(create_now(reversed, 1u, DomainClass::Pod, "dc1", "pod-p1", "Pod P1", kOperatorRecord).code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(create_now(reversed, 2u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord).code,
                 OutcomeCode::Committed);
    const Outcome replayed = attach_now(reversed, 3u, rack, member,
                                        EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb,
                                        "cmdb-elsewhere");
    FDR_CHECK_EQ(replayed.code, OutcomeCode::Committed);
    FDR_CHECK(replayed.membership.has_value());
    FDR_CHECK_EQ(*replayed.membership, base);
    FDR_CHECK_EQ(reversed.registry.membership(base)->domain, rack);
    check_state(reversed.registry);
}

FDR_TEST_CASE(membership, two_publishers_publish_one_membership_record) {
    Fixture fixture;
    bootstrap(fixture, 0x31u);
    add_second_publisher(fixture, 0x32u);
    const FailureDomainId rack = id_of("dc1", DomainClass::Rack, "rack-r7");
    FDR_CHECK_EQ(create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord).code,
                 OutcomeCode::Committed);

    const EntityRef member = entity_ref(EntityClass::Switch, 6u, 2u);
    const MembershipId id = membership_id_for(membership_key(rack, member, MembershipKind::Direct));
    FDR_CHECK_EQ(attach_now(fixture, 2u, rack, member, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-1")
                     .code,
                 OutcomeCode::Committed);
    std::optional<Membership> record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(record->provenance.publisher, fixture.publisher);
    const RegistryGeneration created_at = record->created_at;

    // The key names the member, not the writer: a second publisher that states
    // something stronger about the same member addresses the same record.
    AttachSpec spec = direct_spec(ProvenanceSource::OperatorInventory,
                                  EvidenceClass::DirectHardwareController, "inventory-1");
    const Outcome second = attach_as(fixture, fixture.second_authority, 3u, rack, member, spec);
    FDR_CHECK_EQ(second.code, OutcomeCode::Committed);
    FDR_CHECK(second.membership.has_value());
    FDR_CHECK_EQ(*second.membership, id);
    FDR_CHECK(second.membership_generation.has_value());
    FDR_CHECK_EQ(second.membership_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{1});

    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->id, id);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    // The record keeps its creation point; only the headline assertion moved.
    FDR_CHECK_EQ(record->created_at, created_at);
    FDR_CHECK_EQ(record->provenance.publisher, fixture.second_authority.publisher);
    FDR_CHECK_EQ(record->provenance.worker_boot, fixture.second_authority.worker_boot);
    FDR_CHECK_EQ(record->provenance.source, ProvenanceSource::OperatorInventory);
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{2});
    FDR_CHECK_EQ(record->live_evidence_count(), std::size_t{2});

    // The publisher index follows the headline provenance, so the record leaves
    // the first publisher's index even though that publisher's evidence entry is
    // still there.
    FDR_CHECK_EQ(fixture.registry.memberships_of_publisher(fixture.publisher).size(), std::size_t{0});
    FDR_CHECK_EQ(fixture.registry.memberships_of_publisher(fixture.second_authority.publisher).size(),
                 std::size_t{1});
    check_state(fixture.registry);

    // Restating exactly the same statement is idempotent: the caller's intent is
    // satisfied and nothing is written.
    const RegistryGeneration after_second = fixture.registry.generation();
    const Outcome again = attach_as(fixture, fixture.second_authority, 4u, rack, member, spec);
    FDR_CHECK_EQ(again.code, OutcomeCode::Idempotent);
    FDR_CHECK(again.membership_generation.has_value());
    FDR_CHECK_EQ(again.membership_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(fixture.registry.generation(), after_second);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{1});
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{2});
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, evidence_corroboration_follows_the_implemented_precedence) {
    Fixture fixture;
    bootstrap(fixture, 0x41u);
    const FailureDomainId rack = id_of("dc1", DomainClass::Rack, "rack-r7");
    FDR_CHECK_EQ(create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord).code,
                 OutcomeCode::Committed);
    const EntityRef member = entity_ref(EntityClass::Switch, 7u, 1u);
    const MembershipId id = membership_id_for(membership_key(rack, member, MembershipKind::Direct));

    // The first assertion is the record, and it is the only corroboration.
    FDR_CHECK_EQ(attach_now(fixture, 2u, rack, member, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-1")
                     .code,
                 OutcomeCode::Committed);
    std::optional<Membership> record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{1});
    FDR_CHECK_EQ(record->live_evidence_count(), std::size_t{1});
    FDR_CHECK_EQ(record->provenance.source_identity, std::string("cmdb-1"));
    const RegistryGeneration after_first = fixture.registry.generation();

    // A weaker class can never replace a stronger statement about the same
    // member, so the record keeps what it had.
    const Outcome weaker = attach_now(fixture, 3u, rack, member, EvidenceClass::Synthetic,
                                      ProvenanceSource::SyntheticTestSource, "synthetic-1");
    FDR_CHECK_EQ(weaker.code, OutcomeCode::PolicyRejected);
    FDR_CHECK_MSG(weaker.message.find("weaker") != std::string::npos, weaker.message);
    FDR_CHECK(weaker.membership.has_value());
    FDR_CHECK_EQ(*weaker.membership, id);
    FDR_CHECK_EQ(fixture.registry.generation(), after_first);
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{1});
    FDR_CHECK_EQ(record->provenance.source_identity, std::string("cmdb-1"));

    // A stronger class updates the record, appends a second corroboration and
    // advances the membership generation. Corroboration is additive: the weaker
    // source is still on the record as evidence.
    const Outcome stronger = attach_now(fixture, 4u, rack, member, EvidenceClass::DirectHardwareController,
                                        ProvenanceSource::VendorController, "controller-7");
    FDR_CHECK_EQ(stronger.code, OutcomeCode::Committed);
    FDR_CHECK(stronger.membership_generation.has_value());
    FDR_CHECK_EQ(stronger.membership_generation->value(), std::uint64_t{2});
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{2});
    FDR_CHECK_EQ(record->live_evidence_count(), std::size_t{2});
    FDR_CHECK_EQ(record->evidence.front().provenance.source_identity, std::string("cmdb-1"));
    FDR_CHECK_EQ(record->evidence.back().provenance.source_identity, std::string("controller-7"));
    FDR_CHECK_EQ(record->provenance.evidence, EvidenceClass::DirectHardwareController);
    FDR_CHECK_EQ(record->provenance.source_identity, std::string("controller-7"));
    check_state(fixture.registry);

    // An equally strong statement from a different source is not a tie to be
    // broken: the membership becomes indeterminate, and neither assertion is
    // stored as the record's headline.
    const Outcome conflicted = attach_now(fixture, 5u, rack, member,
                                          EvidenceClass::DirectHardwareController,
                                          ProvenanceSource::OperatorInventory, "inventory-1");
    FDR_CHECK_EQ(conflicted.code, OutcomeCode::MembershipConflict);
    FDR_CHECK_MSG(conflicted.message.find("CONFLICTED") != std::string::npos, conflicted.message);
    FDR_CHECK(conflicted.membership.has_value());
    FDR_CHECK_EQ(*conflicted.membership, id);
    FDR_CHECK(conflicted.membership_generation.has_value());
    FDR_CHECK_EQ(conflicted.membership_generation->value(), std::uint64_t{3});
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{3});
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Conflicted);
    FDR_CHECK(!record->is_current());
    FDR_CHECK(!record->is_terminal());
    FDR_CHECK(is_indeterminate(record->lifecycle));
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{2});
    FDR_CHECK_EQ(record->live_evidence_count(), std::size_t{2});
    FDR_CHECK_EQ(record->provenance.source_identity, std::string("controller-7"));
    FDR_CHECK_EQ(record->history.size(), std::size_t{2});
    FDR_CHECK_EQ(record->history.front().cause, std::string("reasserted"));
    FDR_CHECK_EQ(record->history.back().cause, std::string("conflicting evidence"));
    // The step records the state the record was in when the conflict arrived.
    FDR_CHECK_EQ(record->history.back().lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(record->history.back().generation.value(), std::uint64_t{2});
    check_state(fixture.registry);

    // Exactly the same statement is idempotent, and it does not silently clear
    // the conflict: the caller's intent is satisfied, the disagreement is not.
    const RegistryGeneration after_conflict = fixture.registry.generation();
    const Outcome restated = attach_now(fixture, 6u, rack, member,
                                        EvidenceClass::DirectHardwareController,
                                        ProvenanceSource::VendorController, "controller-7");
    FDR_CHECK_EQ(restated.code, OutcomeCode::Idempotent);
    FDR_CHECK(restated.membership_generation.has_value());
    FDR_CHECK_EQ(restated.membership_generation->value(), std::uint64_t{3});
    FDR_CHECK_EQ(fixture.registry.generation(), after_conflict);
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{3});
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Conflicted);
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{2});
    FDR_CHECK_EQ(record->provenance.source_identity, std::string("controller-7"));
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, attach_member_rejects_stale_and_closed_domains) {
    Fixture fixture;
    bootstrap(fixture, 0x51u);
    const FailureDomainId live = id_of("dc1", DomainClass::Rack, "live-rack");
    const FailureDomainId revalidation = id_of("dc1", DomainClass::Rack, "reval-rack");
    const FailureDomainId conflicted = id_of("dc1", DomainClass::Rack, "conflicted-rack");
    const FailureDomainId retired = id_of("dc1", DomainClass::Rack, "retired-rack");
    const FailureDomainId superseded = id_of("dc1", DomainClass::Rack, "superseded-rack");
    const FailureDomainId successor = id_of("dc1", DomainClass::Rack, "successor-rack");

    std::uint8_t attempt = 1u;
    FDR_CHECK_EQ(create_now(fixture, attempt++, DomainClass::Rack, "dc1", "live-rack", "Live Rack",
                            kOperatorRecord)
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(create_now(fixture, attempt++, DomainClass::Rack, "dc1", "reval-rack", "Reval Rack",
                            kOperatorRecord)
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(create_now(fixture, attempt++, DomainClass::Rack, "dc1", "conflicted-rack",
                            "Conflicted Rack", kOperatorRecord)
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(create_now(fixture, attempt++, DomainClass::Rack, "dc1", "retired-rack", "Retired Rack",
                            kOperatorRecord)
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(create_now(fixture, attempt++, DomainClass::Rack, "dc1", "superseded-rack",
                            "Superseded Rack", kOperatorRecord)
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(create_now(fixture, attempt++, DomainClass::Rack, "dc1", "successor-rack",
                            "Successor Rack", kOperatorRecord)
                     .code,
                 OutcomeCode::Committed);

    // The live domain moves to generation 2 so a stale expectation is reachable.
    UpdateDomainRequest rename;
    rename.attempt = attempt_with(attempt++);
    rename.authority = fixture.authority;
    rename.domain = live;
    rename.expected_generation = FailureDomainGeneration(1u);
    rename.name = "Live Rack (renamed)";
    FDR_CHECK_EQ(fixture.registry.update_domain(rename).code, OutcomeCode::Committed);

    // A domain parked for revalidation refuses new members: its classification is
    // not known to be true yet.
    UpdateDomainRequest park;
    park.attempt = attempt_with(attempt++);
    park.authority = fixture.authority;
    park.domain = revalidation;
    park.expected_generation = FailureDomainGeneration(1u);
    park.transition = DomainLifecycle::RevalidationRequired;
    const Outcome parked = fixture.registry.update_domain(park);
    FDR_CHECK_EQ(parked.code, OutcomeCode::Committed);
    FDR_CHECK(parked.domain_generation.has_value());
    FDR_CHECK_EQ(parked.domain_generation->value(), std::uint64_t{2});

    // An equally strong declaration from another source leaves the domain
    // CONFLICTED, which is also not a state that may carry members.
    const Outcome clash =
        create_now(fixture, attempt++, DomainClass::Rack, "dc1", "conflicted-rack", "Conflicted Rack",
                   provenance_of(ProvenanceSource::PowerManagement,
                                 EvidenceClass::AdministrativeDeclaration, TruthClass::Real, "pm-1"));
    FDR_CHECK_EQ(clash.code, OutcomeCode::DomainConflict);

    FDR_CHECK_EQ(retire_now(fixture, attempt++, retired, "decommissioned", true).code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(supersede_now(fixture, attempt++, superseded, successor, true).code,
                 OutcomeCode::Committed);

    const RegistryGeneration before = fixture.registry.generation();
    const std::size_t domains = fixture.registry.domain_count();
    FDR_CHECK_EQ(domains, std::size_t{6});

    // A domain generation the caller believed in and that has moved on.
    AttachSpec stale_spec = direct_spec(ProvenanceSource::Cmdb,
                                        EvidenceClass::AdministrativeDeclaration, "cmdb-stale");
    stale_spec.expected = FailureDomainGeneration(1u);
    const Outcome stale = attach_with(fixture, attempt++, live, entity_ref(EntityClass::Switch, 31u, 1u),
                                      stale_spec);
    FDR_CHECK_EQ(stale.code, OutcomeCode::StaleDomain);
    // The current generation is reported so the caller can retry without a
    // second read.
    FDR_CHECK(stale.domain_generation.has_value());
    FDR_CHECK_EQ(stale.domain_generation->value(), std::uint64_t{2});
    FDR_CHECK(stale.domain.has_value());
    FDR_CHECK_EQ(*stale.domain, live);

    FDR_CHECK_EQ(attach_now(fixture, attempt++, revalidation, entity_ref(EntityClass::Switch, 32u, 1u),
                            EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb, "cmdb-r")
                     .code,
                 OutcomeCode::RevalidationRequired);
    FDR_CHECK_EQ(attach_now(fixture, attempt++, conflicted, entity_ref(EntityClass::Switch, 33u, 1u),
                            EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb, "cmdb-c")
                     .code,
                 OutcomeCode::DomainConflict);
    FDR_CHECK_EQ(attach_now(fixture, attempt++, retired, entity_ref(EntityClass::Switch, 34u, 1u),
                            EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb, "cmdb-t")
                     .code,
                 OutcomeCode::Retired);
    FDR_CHECK_EQ(attach_now(fixture, attempt++, superseded, entity_ref(EntityClass::Switch, 35u, 1u),
                            EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb, "cmdb-s")
                     .code,
                 OutcomeCode::Superseded);

    // Every refusal left the registry exactly where it was.
    FDR_CHECK_EQ(fixture.registry.generation(), before);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{0});
    FDR_CHECK_EQ(fixture.registry.domain_count(), domains);
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(),
                 std::size_t{0});
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, attach_member_rejects_structurally_invalid_members) {
    Fixture fixture;
    bootstrap(fixture, 0x61u);
    const FailureDomainId rack = id_of("dc1", DomainClass::Rack, "rack-r7");
    FDR_CHECK_EQ(create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord).code,
                 OutcomeCode::Committed);
    const RegistryGeneration before = fixture.registry.generation();

    // A domain that does not exist is a named refusal, never a silent create.
    const Outcome unknown =
        attach_now(fixture, 2u, FailureDomainId::from_bytes(bytes_with(0xD0u, 9u)),
                   entity_ref(EntityClass::Switch, 41u, 1u), EvidenceClass::AdministrativeDeclaration,
                   ProvenanceSource::Cmdb, "cmdb-1");
    FDR_CHECK_EQ(unknown.code, OutcomeCode::UnknownDomain);
    FDR_CHECK(unknown.domain.has_value());

    // A member without an identity or without a generation is not a member.
    AttachSpec spec = direct_spec(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration, "cmdb-2");
    const Outcome null_member = attach_with(fixture, 3u, rack, EntityRef{}, spec);
    FDR_CHECK_EQ(null_member.code, OutcomeCode::MalformedRequest);
    FDR_CHECK_MSG(null_member.message.find("null") != std::string::npos, null_member.message);

    // DERIVED membership is produced by the derivation engine, never published
    // by a caller: accepting it would let a publisher claim a rule ran.
    AttachSpec derived = direct_spec(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration, "cmdb-3");
    derived.kind = MembershipKind::Derived;
    const Outcome derived_member = attach_with(fixture, 4u, rack, entity_ref(EntityClass::Switch, 42u, 1u),
                                               derived);
    FDR_CHECK_EQ(derived_member.code, OutcomeCode::MalformedRequest);
    FDR_CHECK_MSG(derived_member.message.find("DIRECT") != std::string::npos, derived_member.message);

    AttachSpec bad_role = direct_spec(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration, "cmdb-4");
    bad_role.role = static_cast<MembershipRole>(200);
    const Outcome role_refused =
        attach_with(fixture, 5u, rack, entity_ref(EntityClass::Switch, 43u, 1u), bad_role);
    FDR_CHECK_EQ(role_refused.code, OutcomeCode::MalformedRequest);

    AttachSpec bad_dependency =
        direct_spec(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration, "cmdb-5");
    bad_dependency.dependency = static_cast<DependencySemantics>(99);
    const Outcome dependency_refused =
        attach_with(fixture, 6u, rack, entity_ref(EntityClass::Switch, 44u, 1u), bad_dependency);
    FDR_CHECK_EQ(dependency_refused.code, OutcomeCode::MalformedRequest);

    FDR_CHECK_EQ(fixture.registry.generation(), before);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{0});
    check_state(fixture.registry);

    // The refusals did not poison the registry: a well-formed attach still lands.
    FDR_CHECK_EQ(attach_now(fixture, 7u, rack, entity_ref(EntityClass::Switch, 45u, 1u),
                            EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb, "cmdb-6")
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{1});
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, one_entity_may_belong_to_many_non_exclusive_classes) {
    Fixture fixture;
    bootstrap(fixture, 0x71u);
    const DomainClass klass[5] = {DomainClass::PowerFeed, DomainClass::CoolingZone, DomainClass::Conduit,
                                  DomainClass::NetworkProvider, DomainClass::Pdu};
    const EntityRef member = entity_ref(EntityClass::Switch, 9u, 1u);

    FailureDomainId domains[5] = {};
    std::uint8_t attempt = 1u;
    for (std::size_t i = 0; i < 5; ++i) {
        const std::string index = std::to_string(i);
        const Outcome created = create_now(fixture, attempt++, klass[i], "dc1", "shared-" + index,
                                           "Shared " + index, kOperatorRecord);
        FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
        FDR_CHECK(created.domain.has_value());
        domains[i] = *created.domain;
        FDR_CHECK_EQ(attach_now(fixture, attempt++, domains[i], member,
                                EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb,
                                "cmdb-" + index)
                         .code,
                     OutcomeCode::Committed);
    }

    // None of these classes is exclusive, so the same entity is a member of all
    // five at once and every membership has its own identity.
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{5});
    const std::vector<Membership> memberships = fixture.registry.memberships_of(member.id());
    FDR_CHECK_EQ(memberships.size(), std::size_t{5});
    for (std::size_t i = 0; i < memberships.size(); ++i) {
        FDR_CHECK_EQ(memberships[i].member, member);
        FDR_CHECK_EQ(memberships[i].kind, MembershipKind::Direct);
        FDR_CHECK_EQ(memberships[i].lifecycle, MembershipLifecycle::Current);
        FDR_CHECK_EQ(memberships[i].domain_generation.value(), std::uint64_t{1});
        for (std::size_t j = i + 1; j < memberships.size(); ++j) {
            FDR_CHECK(!(memberships[i].id == memberships[j].id));
        }
    }
    for (std::size_t i = 0; i < 5; ++i) {
        FDR_CHECK_EQ(fixture.registry.members_of(domains[i]).size(), std::size_t{1});
        FDR_CHECK_EQ(fixture.registry.members_of(domains[i]).front().member, member);
    }

    // memberships_of(EntityRef) filters by the exact generation: a later
    // generation of the same canonical identity is a different membership.
    FDR_CHECK_EQ(fixture.registry.memberships_of(EntityRef(member.id(), EntityGeneration(1u))).size(),
                 std::size_t{5});
    FDR_CHECK_EQ(fixture.registry.memberships_of(EntityRef(member.id(), EntityGeneration(2u))).size(),
                 std::size_t{0});
    FDR_CHECK_EQ(fixture.registry.memberships_of(entity_ref(EntityClass::Switch, 9u, 2u)).size(),
                 std::size_t{0});
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(),
                 std::size_t{5});
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, exclusive_classes_admit_one_current_domain_per_member) {
    Fixture fixture;
    bootstrap(fixture, 0x81u);
    const DomainClass exclusive[3] = {DomainClass::Rack, DomainClass::Row, DomainClass::Pod};

    FailureDomainId first[3] = {};
    FailureDomainId second[3] = {};
    std::uint8_t attempt = 1u;
    for (std::size_t i = 0; i < 3; ++i) {
        const std::string prefix = std::string(failure_domain_registry::to_string(exclusive[i]));
        const Outcome left = create_now(fixture, attempt++, exclusive[i], "dc1", prefix + "-a",
                                        "First", kOperatorRecord);
        FDR_CHECK_EQ(left.code, OutcomeCode::Committed);
        FDR_CHECK(left.domain.has_value());
        first[i] = *left.domain;
        const Outcome right = create_now(fixture, attempt++, exclusive[i], "dc1", prefix + "-b",
                                         "Second", kOperatorRecord);
        FDR_CHECK_EQ(right.code, OutcomeCode::Committed);
        FDR_CHECK(right.domain.has_value());
        second[i] = *right.domain;
    }

    const EntityRef members[3] = {entity_ref(EntityClass::Switch, 11u, 1u),
                                  entity_ref(EntityClass::Switch, 12u, 1u),
                                  entity_ref(EntityClass::Switch, 13u, 1u)};
    for (std::size_t i = 0; i < 3; ++i) {
        FDR_CHECK_EQ(attach_now(fixture, attempt++, first[i], members[i],
                                EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb,
                                "cmdb-first")
                         .code,
                     OutcomeCode::Committed);
    }
    const RegistryGeneration before_rejections = fixture.registry.generation();
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{3});

    // One entity may not be in two racks at once: the second domain is refused
    // and named, so the caller can go and look at the conflict.
    for (std::size_t i = 0; i < 3; ++i) {
        const Outcome violation = attach_now(fixture, attempt++, second[i], members[i],
                                             EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb,
                                             "cmdb-second");
        FDR_CHECK_EQ(violation.code, OutcomeCode::ExclusivityViolation);
        FDR_CHECK_MSG(violation.message.find("exclusive") != std::string::npos, violation.message);
        FDR_CHECK_EQ(violation.related_domains.size(), std::size_t{1});
        FDR_CHECK_EQ(violation.related_domains.front(), first[i]);
        FDR_CHECK(violation.domain.has_value());
        FDR_CHECK_EQ(*violation.domain, second[i]);
        FDR_CHECK(violation.member.has_value());
        FDR_CHECK_EQ(*violation.member, members[i]);
        // The refused membership was never created, not even as a placeholder.
        FDR_CHECK(!fixture.registry
                       .membership(membership_id_for(
                           membership_key(second[i], members[i], MembershipKind::Direct)))
                       .has_value());
    }
    FDR_CHECK_EQ(fixture.registry.generation(), before_rejections);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{3});

    // The non-exclusive classes are never refused, however many domains of one
    // class a member joins.
    const FailureDomainId feed_a = id_of("dc1", DomainClass::PowerFeed, "feed-a");
    const FailureDomainId feed_b = id_of("dc1", DomainClass::PowerFeed, "feed-b");
    FDR_CHECK_EQ(create_now(fixture, attempt++, DomainClass::PowerFeed, "dc1", "feed-a", "Feed A",
                            kOperatorRecord)
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(create_now(fixture, attempt++, DomainClass::PowerFeed, "dc1", "feed-b", "Feed B",
                            kOperatorRecord)
                     .code,
                 OutcomeCode::Committed);
    const EntityRef fed = entity_ref(EntityClass::Host, 14u, 2u);
    FDR_CHECK_EQ(attach_now(fixture, attempt++, feed_a, fed, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-feed-a")
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(attach_now(fixture, attempt++, feed_b, fed, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-feed-b")
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(fixture.registry.members_of(feed_a).size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.members_of(feed_b).size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.memberships_of(fed.id()).size(), std::size_t{2});
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{5});
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, detach_member_retires_the_membership_and_is_idempotent) {
    Fixture fixture;
    bootstrap(fixture, 0x91u);
    const FailureDomainId rack = id_of("dc1", DomainClass::Rack, "rack-r7");
    FDR_CHECK_EQ(create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord).code,
                 OutcomeCode::Committed);
    const EntityRef member = entity_ref(EntityClass::Switch, 15u, 3u);
    const MembershipId id = membership_id_for(membership_key(rack, member, MembershipKind::Direct));
    FDR_CHECK_EQ(attach_now(fixture, 2u, rack, member, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-1")
                     .code,
                 OutcomeCode::Committed);

    // An expectation that does not hold is refused before anything is written,
    // and the current generation is reported.
    const RegistryGeneration before = fixture.registry.generation();
    const Outcome stale = fixture.registry.detach_member(
        detach_request(fixture, 3u, rack, member, MembershipGeneration(99u), "too late"));
    FDR_CHECK_EQ(stale.code, OutcomeCode::StaleMembership);
    FDR_CHECK(stale.membership_generation.has_value());
    FDR_CHECK_EQ(stale.membership_generation->value(), std::uint64_t{1});
    FDR_CHECK(stale.membership.has_value());
    FDR_CHECK_EQ(*stale.membership, id);
    FDR_CHECK_EQ(fixture.registry.generation(), before);

    // An unknown membership is a named refusal, not a silent success.
    const Outcome unknown = fixture.registry.detach_member(detach_request(
        fixture, 4u, rack, entity_ref(EntityClass::Switch, 16u, 1u), MembershipGeneration{}, "unknown"));
    FDR_CHECK_EQ(unknown.code, OutcomeCode::NotFound);
    FDR_CHECK(unknown.membership.has_value());
    FDR_CHECK_EQ(fixture.registry.generation(), before);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{1});

    // The detach commits and the membership is terminal: it is closed, not
    // deleted, because the fact that it existed is part of the record.
    const Outcome detached = fixture.registry.detach_member(
        detach_request(fixture, 5u, rack, member, MembershipGeneration(1u), "decommissioned"));
    FDR_CHECK_EQ(detached.code, OutcomeCode::Committed);
    FDR_CHECK(detached.membership_generation.has_value());
    FDR_CHECK_EQ(detached.membership_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(fixture.registry.generation().value(), before.value() + 1u);
    std::optional<Membership> record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Retired);
    FDR_CHECK(record->is_terminal());
    FDR_CHECK(!record->is_current());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{1});
    FDR_CHECK_EQ(record->live_evidence_count(), std::size_t{1});
    FDR_CHECK_EQ(record->history.size(), std::size_t{1});
    FDR_CHECK_EQ(record->history.front().cause, std::string("decommissioned"));
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(),
                 std::size_t{0});
    check_state(fixture.registry);

    // Retirement is terminal: the second demand is satisfied, not re-applied.
    const RegistryGeneration after_detach = fixture.registry.generation();
    const Outcome again = fixture.registry.detach_member(
        detach_request(fixture, 6u, rack, member, MembershipGeneration{}, "again"));
    FDR_CHECK_EQ(again.code, OutcomeCode::Idempotent);
    FDR_CHECK(again.membership_generation.has_value());
    FDR_CHECK_EQ(again.membership_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(fixture.registry.generation(), after_detach);

    // Nothing may revive it, however strong the new assertion is.
    const Outcome revived =
        attach_now(fixture, 7u, rack, member, EvidenceClass::DirectAuthoritativeInfrastructure,
                   ProvenanceSource::PhysicalInfrastructure, "dcim-1");
    FDR_CHECK_EQ(revived.code, OutcomeCode::Retired);
    FDR_CHECK(revived.membership.has_value());
    FDR_CHECK_EQ(*revived.membership, id);
    FDR_CHECK_EQ(fixture.registry.generation(), after_detach);
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Retired);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->provenance.source_identity, std::string("cmdb-1"));
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{1});
    check_state(fixture.registry);

    // A closed domain never gates a detach: the request addresses the record by
    // key, so a membership left CURRENT while its domain was superseded without
    // demotion can still be closed.
    const FailureDomainId old_rack = id_of("dc1", DomainClass::Rack, "closed-rack");
    const FailureDomainId new_rack = id_of("dc1", DomainClass::Rack, "replacement-rack");
    FDR_CHECK_EQ(create_now(fixture, 8u, DomainClass::Rack, "dc1", "closed-rack", "Closed Rack",
                            kOperatorRecord)
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(create_now(fixture, 9u, DomainClass::Rack, "dc1", "replacement-rack", "Replacement",
                            kOperatorRecord)
                     .code,
                 OutcomeCode::Committed);
    const EntityRef survivor_member = entity_ref(EntityClass::Switch, 17u, 1u);
    FDR_CHECK_EQ(attach_now(fixture, 10u, old_rack, survivor_member,
                            EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb, "cmdb-old")
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(supersede_now(fixture, 11u, old_rack, new_rack, false).code, OutcomeCode::Committed);
    const std::optional<FailureDomain> closed = fixture.registry.domain(old_rack);
    FDR_CHECK(closed.has_value());
    FDR_CHECK_EQ(closed->lifecycle, DomainLifecycle::Superseded);
    const Outcome closed_detach = fixture.registry.detach_member(detach_request(
        fixture, 12u, old_rack, survivor_member, MembershipGeneration(1u), "closed with its domain"));
    FDR_CHECK_EQ(closed_detach.code, OutcomeCode::Committed);
    FDR_CHECK(closed_detach.membership_generation.has_value());
    FDR_CHECK_EQ(closed_detach.membership_generation->value(), std::uint64_t{2});
    const std::optional<Membership> closed_membership = fixture.registry.membership(
        membership_id_for(membership_key(old_rack, survivor_member, MembershipKind::Direct)));
    FDR_CHECK(closed_membership.has_value());
    FDR_CHECK_EQ(closed_membership->lifecycle, MembershipLifecycle::Retired);
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, replace_membership_changes_role_dependency_and_metadata) {
    Fixture fixture;
    bootstrap(fixture, 0xA1u);
    const FailureDomainId rack = id_of("dc1", DomainClass::Rack, "rack-r7");
    FDR_CHECK_EQ(create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord).code,
                 OutcomeCode::Committed);
    const EntityRef member = entity_ref(EntityClass::Switch, 18u, 1u);
    const MembershipId id = membership_id_for(membership_key(rack, member, MembershipKind::Direct));

    AttachSpec attach = direct_spec(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration,
                                    "cmdb-1");
    attach.metadata = metadata_of("ticket", "MR-1");
    FDR_CHECK_EQ(attach_with(fixture, 2u, rack, member, attach).code, OutcomeCode::Committed);

    // An unknown membership is a named refusal.
    const Outcome unknown = fixture.registry.replace_membership(
        replace_request(fixture, 3u, membership_id_for(membership_key(rack, member, MembershipKind::Asserted)),
                        ReplaceSpec{}));
    FDR_CHECK_EQ(unknown.code, OutcomeCode::NotFound);
    FDR_CHECK(unknown.membership.has_value());

    // Changing the role is a real change and advances the membership.
    ReplaceSpec role_change;
    role_change.expected = MembershipGeneration(1u);
    role_change.role = MembershipRole::Redundant;
    const Outcome replaced = fixture.registry.replace_membership(replace_request(fixture, 4u, id, role_change));
    FDR_CHECK_EQ(replaced.code, OutcomeCode::Committed);
    FDR_CHECK(replaced.membership.has_value());
    FDR_CHECK_EQ(*replaced.membership, id);
    FDR_CHECK(replaced.membership_generation.has_value());
    FDR_CHECK_EQ(replaced.membership_generation->value(), std::uint64_t{2});
    std::optional<Membership> record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->role, MembershipRole::Redundant);
    FDR_CHECK_EQ(record->dependency, DependencySemantics::AllDependenciesRequired);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->metadata.size(), std::size_t{1});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{1});
    FDR_CHECK_EQ(record->history.size(), std::size_t{1});
    FDR_CHECK_EQ(record->history.front().cause, std::string("replaced"));

    // A request that asks for what already holds is idempotent: it does not bump
    // the generation and does not append a corroboration.
    const RegistryGeneration after_replace = fixture.registry.generation();
    ReplaceSpec nothing;
    nothing.expected = MembershipGeneration(2u);
    nothing.role = MembershipRole::Redundant;
    const Outcome unchanged =
        fixture.registry.replace_membership(replace_request(fixture, 5u, id, nothing));
    FDR_CHECK_EQ(unchanged.code, OutcomeCode::Idempotent);
    FDR_CHECK(unchanged.membership_generation.has_value());
    FDR_CHECK_EQ(unchanged.membership_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(fixture.registry.generation(), after_replace);
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{1});

    // Dependency semantics is the other half of the same promise: a change to
    // it advances the membership exactly like a role change.
    ReplaceSpec dependency_change;
    dependency_change.expected = MembershipGeneration(2u);
    dependency_change.dependency = DependencySemantics::RedundantSource;
    const Outcome depend =
        fixture.registry.replace_membership(replace_request(fixture, 6u, id, dependency_change));
    FDR_CHECK_EQ(depend.code, OutcomeCode::Committed);
    FDR_CHECK(depend.membership_generation.has_value());
    FDR_CHECK_EQ(depend.membership_generation->value(), std::uint64_t{3});
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->dependency, DependencySemantics::RedundantSource);
    FDR_CHECK_EQ(record->role, MembershipRole::Redundant);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{3});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{1});

    // replace_metadata replaces the set rather than merging into it.
    ReplaceSpec metadata_change;
    metadata_change.expected = MembershipGeneration(3u);
    metadata_change.replace_metadata = true;
    metadata_change.metadata = metadata_of("owner", "platform-ops");
    const Outcome remeta =
        fixture.registry.replace_membership(replace_request(fixture, 7u, id, metadata_change));
    FDR_CHECK_EQ(remeta.code, OutcomeCode::Committed);
    FDR_CHECK(remeta.membership_generation.has_value());
    FDR_CHECK_EQ(remeta.membership_generation->value(), std::uint64_t{4});
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{4});
    FDR_CHECK_EQ(record->metadata.size(), std::size_t{1});
    FDR_CHECK_EQ(record->metadata.front().key, std::string("owner"));
    FDR_CHECK_EQ(record->metadata.front().value, std::string("platform-ops"));
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{1});
    check_state(fixture.registry);

    // A weaker replacement assertion is refused before anything is written.
    const RegistryGeneration before_weaker = fixture.registry.generation();
    ReplaceSpec weaker;
    weaker.expected = MembershipGeneration(4u);
    weaker.role = MembershipRole::Backup;
    weaker.provenance = provenance_of(ProvenanceSource::SyntheticTestSource, EvidenceClass::Synthetic,
                                      TruthClass::Synthetic, "synthetic-1");
    const Outcome weaker_outcome =
        fixture.registry.replace_membership(replace_request(fixture, 8u, id, weaker));
    FDR_CHECK_EQ(weaker_outcome.code, OutcomeCode::PolicyRejected);
    FDR_CHECK_EQ(fixture.registry.generation(), before_weaker);
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->role, MembershipRole::Redundant);
    FDR_CHECK_EQ(record->dependency, DependencySemantics::RedundantSource);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{4});
    FDR_CHECK_EQ(record->provenance.source_identity, std::string("cmdb-1"));

    // An equally strong replacement from a different source is a disagreement:
    // the caller is told to reconcile, and the record is left alone.
    ReplaceSpec rival;
    rival.expected = MembershipGeneration(4u);
    rival.provenance = provenance_of(ProvenanceSource::PowerManagement,
                                     EvidenceClass::AdministrativeDeclaration, TruthClass::Real, "pm-1");
    const Outcome rival_outcome =
        fixture.registry.replace_membership(replace_request(fixture, 9u, id, rival));
    FDR_CHECK_EQ(rival_outcome.code, OutcomeCode::MembershipConflict);
    FDR_CHECK_EQ(fixture.registry.generation(), before_weaker);
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{4});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{1});
    FDR_CHECK_EQ(record->provenance.source_identity, std::string("cmdb-1"));

    // A replacement assertion that is stronger lands, appends a corroboration
    // and keeps the metadata the caller did not ask to change.
    ReplaceSpec stronger;
    stronger.expected = MembershipGeneration(4u);
    stronger.provenance = provenance_of(ProvenanceSource::VendorController,
                                        EvidenceClass::DirectHardwareController, TruthClass::Real,
                                        "controller-7");
    const Outcome upgraded =
        fixture.registry.replace_membership(replace_request(fixture, 10u, id, stronger));
    FDR_CHECK_EQ(upgraded.code, OutcomeCode::Committed);
    FDR_CHECK(upgraded.membership_generation.has_value());
    FDR_CHECK_EQ(upgraded.membership_generation->value(), std::uint64_t{5});
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{5});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{2});
    FDR_CHECK_EQ(record->live_evidence_count(), std::size_t{2});
    FDR_CHECK_EQ(record->provenance.evidence, EvidenceClass::DirectHardwareController);
    FDR_CHECK_EQ(record->role, MembershipRole::Redundant);
    FDR_CHECK_EQ(record->dependency, DependencySemantics::RedundantSource);
    FDR_CHECK_EQ(record->metadata.front().key, std::string("owner"));

    // The same thing: a stale expectation is refused and reports the truth.
    const RegistryGeneration before_stale = fixture.registry.generation();
    ReplaceSpec stale;
    stale.expected = MembershipGeneration(3u);
    stale.role = MembershipRole::Backup;
    const Outcome stale_outcome =
        fixture.registry.replace_membership(replace_request(fixture, 11u, id, stale));
    FDR_CHECK_EQ(stale_outcome.code, OutcomeCode::StaleMembership);
    FDR_CHECK(stale_outcome.membership_generation.has_value());
    FDR_CHECK_EQ(stale_outcome.membership_generation->value(), std::uint64_t{5});
    FDR_CHECK_EQ(fixture.registry.generation(), before_stale);
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->role, MembershipRole::Redundant);
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, replace_membership_refuses_terminal_memberships) {
    Fixture fixture;
    bootstrap(fixture, 0xA2u);
    const FailureDomainId survivor = id_of("dc1", DomainClass::Rack, "rack-a");
    const FailureDomainId absorbed = id_of("dc1", DomainClass::Rack, "rack-b");
    FDR_CHECK_EQ(create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-a", "Rack A", kOperatorRecord).code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(create_now(fixture, 2u, DomainClass::Rack, "dc1", "rack-b", "Rack B", kOperatorRecord).code,
                 OutcomeCode::Committed);

    // A merge moves the membership to the survivor's key and closes the record
    // the caller used to hold.
    const EntityRef member = entity_ref(EntityClass::Switch, 19u, 1u);
    const MembershipId absorbed_id =
        membership_id_for(membership_key(absorbed, member, MembershipKind::Direct));
    FDR_CHECK_EQ(attach_now(fixture, 3u, absorbed, member, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-1")
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(merge_now(fixture, 4u, survivor, absorbed, true).code, OutcomeCode::Committed);

    const std::optional<Membership> moved = fixture.registry.membership(absorbed_id);
    FDR_CHECK(moved.has_value());
    FDR_CHECK_EQ(moved->lifecycle, MembershipLifecycle::Superseded);
    FDR_CHECK(moved->is_terminal());
    FDR_CHECK_EQ(moved->generation.value(), std::uint64_t{2});
    const MembershipId moved_id = membership_id_for(membership_key(survivor, member, MembershipKind::Direct));
    FDR_CHECK_EQ(moved->superseded_by, moved_id);
    const std::optional<Membership> live = fixture.registry.membership(moved_id);
    FDR_CHECK(live.has_value());
    FDR_CHECK_EQ(live->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(live->generation.value(), std::uint64_t{1});
    check_state(fixture.registry);

    const RegistryGeneration before = fixture.registry.generation();
    ReplaceSpec spec;
    spec.role = MembershipRole::Backup;
    const Outcome superseded = fixture.registry.replace_membership(
        replace_request(fixture, 5u, absorbed_id, spec));
    FDR_CHECK_EQ(superseded.code, OutcomeCode::Superseded);
    FDR_CHECK(superseded.membership.has_value());
    FDR_CHECK_EQ(*superseded.membership, absorbed_id);

    // The record the merge produced is live and replaceable.
    const Outcome moved_replace =
        fixture.registry.replace_membership(replace_request(fixture, 6u, moved_id, spec));
    FDR_CHECK_EQ(moved_replace.code, OutcomeCode::Committed);
    FDR_CHECK(moved_replace.membership_generation.has_value());
    FDR_CHECK_EQ(moved_replace.membership_generation->value(), std::uint64_t{2});

    // A detached membership is Retired, and Retired is refused as itself.
    const Outcome detached = fixture.registry.detach_member(
        detach_request(fixture, 7u, survivor, member, MembershipGeneration(2u), "gone"));
    FDR_CHECK_EQ(detached.code, OutcomeCode::Committed);
    FDR_CHECK(detached.membership_generation.has_value());
    FDR_CHECK_EQ(detached.membership_generation->value(), std::uint64_t{3});
    const RegistryGeneration after_detach = fixture.registry.generation();
    ReplaceSpec retry;
    retry.role = MembershipRole::Primary;
    const Outcome retired =
        fixture.registry.replace_membership(replace_request(fixture, 8u, moved_id, retry));
    FDR_CHECK_EQ(retired.code, OutcomeCode::Retired);
    const std::optional<Membership> closed = fixture.registry.membership(moved_id);
    FDR_CHECK(closed.has_value());
    FDR_CHECK_EQ(closed->lifecycle, MembershipLifecycle::Retired);
    FDR_CHECK_EQ(closed->generation.value(), std::uint64_t{3});
    FDR_CHECK_EQ(closed->role, MembershipRole::Backup);
    FDR_CHECK_EQ(fixture.registry.generation(), after_detach);
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, withdraw_evidence_demotes_and_removes_the_entry) {
    Fixture fixture;
    bootstrap(fixture, 0xB1u);
    add_second_publisher(fixture, 0xB2u);
    const FailureDomainId rack = id_of("dc1", DomainClass::Rack, "rack-r7");
    FDR_CHECK_EQ(create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord).code,
                 OutcomeCode::Committed);
    const EntityRef member = entity_ref(EntityClass::Switch, 23u, 1u);
    const MembershipId id = membership_id_for(membership_key(rack, member, MembershipKind::Direct));
    FDR_CHECK_EQ(attach_now(fixture, 2u, rack, member, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-1")
                     .code,
                 OutcomeCode::Committed);

    // An unknown membership is a named refusal.
    const Outcome unknown = fixture.registry.withdraw_evidence(withdraw_request(
        fixture, 3u, membership_id_for(membership_key(rack, member, MembershipKind::Asserted)),
        MembershipGeneration{}, true, "unknown"));
    FDR_CHECK_EQ(unknown.code, OutcomeCode::NotFound);

    // A stale expectation is refused and reports the current generation.
    const RegistryGeneration before = fixture.registry.generation();
    const Outcome stale = fixture.registry.withdraw_evidence(
        withdraw_request(fixture, 4u, id, MembershipGeneration(9u), true, "stale"));
    FDR_CHECK_EQ(stale.code, OutcomeCode::StaleMembership);
    FDR_CHECK(stale.membership_generation.has_value());
    FDR_CHECK_EQ(stale.membership_generation->value(), std::uint64_t{1});
    FDR_CHECK_EQ(fixture.registry.generation(), before);

    // Withdrawing the only corroboration does not guess: the membership becomes
    // REVALIDATION_REQUIRED and the evidence entry is gone.
    const Outcome withdrawn = fixture.registry.withdraw_evidence(
        withdraw_request(fixture, 5u, id, MembershipGeneration(1u), true, "source retracted"));
    FDR_CHECK_EQ(withdrawn.code, OutcomeCode::Committed);
    FDR_CHECK(withdrawn.membership.has_value());
    FDR_CHECK_EQ(*withdrawn.membership, id);
    FDR_CHECK(withdrawn.membership_generation.has_value());
    FDR_CHECK_EQ(withdrawn.membership_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(withdrawn.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(withdrawn.steps.front().stage, std::string("evidence"));
    FDR_CHECK_EQ(withdrawn.steps.front().field, std::string("lifecycle"));
    FDR_CHECK_EQ(withdrawn.steps.front().value, std::string("REVALIDATION_REQUIRED"));
    FDR_CHECK_MSG(withdrawn.steps.front().detail.find("0 live evidence") == 0,
                  withdrawn.steps.front().detail);
    std::optional<Membership> record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::RevalidationRequired);
    FDR_CHECK(!record->is_current());
    FDR_CHECK(!record->is_terminal());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{0});
    FDR_CHECK_EQ(record->live_evidence_count(), std::size_t{0});
    // The headline provenance survives as the record of what was claimed, even
    // though the corroboration that carried it is gone.
    FDR_CHECK_EQ(record->provenance.source_identity, std::string("cmdb-1"));
    FDR_CHECK_EQ(record->history.size(), std::size_t{1});
    FDR_CHECK_EQ(record->history.back().cause, std::string("source retracted"));
    check_state(fixture.registry);

    // A publisher with no matching evidence on the record has nothing to
    // withdraw, and the demand is satisfied rather than re-applied.
    const RegistryGeneration after_withdrawal = fixture.registry.generation();
    const Outcome nothing = fixture.registry.withdraw_evidence(
        withdraw_request(fixture, 6u, id, MembershipGeneration(2u), true, "nothing left"));
    FDR_CHECK_EQ(nothing.code, OutcomeCode::Idempotent);
    FDR_CHECK_MSG(nothing.message.find("no matching evidence") != std::string::npos, nothing.message);
    FDR_CHECK(nothing.membership_generation.has_value());
    FDR_CHECK_EQ(nothing.membership_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(fixture.registry.generation(), after_withdrawal);

    // A second record published by another publisher is untouched by a demand
    // from the first: withdrawal is scoped to the publisher that published.
    const EntityRef other_member = entity_ref(EntityClass::Switch, 24u, 1u);
    const MembershipId other_id =
        membership_id_for(membership_key(rack, other_member, MembershipKind::Direct));
    AttachSpec other_spec = direct_spec(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration,
                                        "cmdb-2");
    FDR_CHECK_EQ(attach_as(fixture, fixture.second_authority, 7u, rack, other_member, other_spec).code,
                 OutcomeCode::Committed);
    const Outcome not_mine = fixture.registry.withdraw_evidence(
        withdraw_request(fixture, 8u, other_id, MembershipGeneration(1u), true, "not mine"));
    FDR_CHECK_EQ(not_mine.code, OutcomeCode::Idempotent);
    const std::optional<Membership> untouched = fixture.registry.membership(other_id);
    FDR_CHECK(untouched.has_value());
    FDR_CHECK_EQ(untouched->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(untouched->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(untouched->evidence.size(), std::size_t{1});

    // Re-asserting with a different role restores the membership, and then the
    // wider selector withdraws the only incarnation that can hold evidence: a
    // fresh worker boot permanently removes the evidence of the boot it
    // replaced, so one publisher never has two live incarnations on a record.
    AttachSpec restored = direct_spec(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration,
                                      "cmdb-1");
    restored.role = MembershipRole::Redundant;
    FDR_CHECK_EQ(attach_with(fixture, 9u, rack, member, restored).code, OutcomeCode::Committed);
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{3});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{1});
    check_state(fixture.registry);

    const Outcome every_incarnation = fixture.registry.withdraw_evidence(
        withdraw_request(fixture, 10u, id, MembershipGeneration(3u), false, "every incarnation"));
    FDR_CHECK_EQ(every_incarnation.code, OutcomeCode::Committed);
    FDR_CHECK(every_incarnation.membership_generation.has_value());
    FDR_CHECK_EQ(every_incarnation.membership_generation->value(), std::uint64_t{4});
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::RevalidationRequired);
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{0});
    FDR_CHECK_EQ(record->live_evidence_count(), std::size_t{0});
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, withdraw_evidence_demotes_every_record_that_publisher_published) {
    Fixture fixture;
    bootstrap(fixture, 0xB4u);
    add_second_publisher(fixture, 0xB5u);
    const FailureDomainId feed = id_of("dc1", DomainClass::PowerFeed, "feed-a");
    FDR_CHECK_EQ(create_now(fixture, 1u, DomainClass::PowerFeed, "dc1", "feed-a", "Feed A",
                            kOperatorRecord)
                     .code,
                 OutcomeCode::Committed);
    const EntityRef first = entity_ref(EntityClass::Switch, 60u, 1u);
    const EntityRef colleague = entity_ref(EntityClass::Switch, 61u, 1u);
    const EntityRef foreign = entity_ref(EntityClass::Switch, 62u, 1u);
    AttachSpec named = direct_spec(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration,
                                   "cmdb-a");
    AttachSpec sibling = direct_spec(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration,
                                     "cmdb-b");
    FDR_CHECK_EQ(attach_with(fixture, 2u, feed, first, named).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(attach_with(fixture, 3u, feed, colleague, sibling).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(attach_as(fixture, fixture.second_authority, 4u, feed, foreign, named).code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{3});

    // The request names one record, but the withdrawal is scoped to the
    // publisher: every record that publisher's evidence reaches loses it, while
    // the record another publisher vouches for is untouched.
    const MembershipId first_id = membership_id_for(membership_key(feed, first, MembershipKind::Direct));
    const MembershipId colleague_id =
        membership_id_for(membership_key(feed, colleague, MembershipKind::Direct));
    const MembershipId foreign_id = membership_id_for(membership_key(feed, foreign, MembershipKind::Direct));
    const RegistryGeneration before = fixture.registry.generation();
    const Outcome withdrawn = fixture.registry.withdraw_evidence(
        withdraw_request(fixture, 5u, first_id, MembershipGeneration(1u), true, "retracted"));
    FDR_CHECK_EQ(withdrawn.code, OutcomeCode::Committed);
    FDR_CHECK(withdrawn.membership.has_value());
    FDR_CHECK_EQ(*withdrawn.membership, first_id);
    FDR_CHECK_EQ(fixture.registry.generation().value(), before.value() + 1u);

    std::optional<Membership> record = fixture.registry.membership(first_id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::RevalidationRequired);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{0});

    record = fixture.registry.membership(colleague_id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::RevalidationRequired);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{0});
    FDR_CHECK_EQ(record->live_evidence_count(), std::size_t{0});

    record = fixture.registry.membership(foreign_id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(),
                 std::size_t{1});
    FDR_CHECK_EQ(
        fixture.registry.memberships_in_lifecycle(MembershipLifecycle::RevalidationRequired).size(),
        std::size_t{2});
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, withdraw_evidence_cannot_reach_a_derived_membership) {
    Fixture fixture;
    bootstrap(fixture, 0xB3u);
    DerivedSetup setup;
    bootstrap_derivation(fixture, 1u, setup);

    const std::optional<Membership> derived = fixture.registry.membership(setup.derived);
    FDR_CHECK(derived.has_value());
    FDR_CHECK_EQ(derived->kind, MembershipKind::Derived);
    FDR_CHECK_EQ(derived->domain, setup.pdu);
    FDR_CHECK_EQ(derived->member, setup.subject);
    FDR_CHECK_EQ(derived->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(derived->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(derived->evidence.size(), std::size_t{1});
    FDR_CHECK_EQ(derived->provenance.source, ProvenanceSource::DerivationRule);
    FDR_CHECK_EQ(derived->provenance.evidence, EvidenceClass::DerivedTopology);
    FDR_CHECK(derived->provenance.publisher.is_null());
    FDR_CHECK_EQ(derived->derivation.sources.size(), std::size_t{2});
    FDR_CHECK(derived->derivation.valid);
    check_state(fixture.registry);

    // A derived membership carries no publisher on its evidence, so a publisher
    // demand can never match it. The refusal a caller actually receives is
    // Idempotent ("nothing of mine is here"), never PolicyRejected, because the
    // DERIVED guard sits behind the evidence match.
    const RegistryGeneration before = fixture.registry.generation();
    const Outcome attempted = fixture.registry.withdraw_evidence(
        withdraw_request(fixture, 7u, setup.derived, MembershipGeneration(1u), true, "not mine"));
    FDR_CHECK_EQ(attempted.code, OutcomeCode::Idempotent);
    FDR_CHECK_MSG(attempted.message.find("no matching evidence") != std::string::npos,
                  attempted.message);
    FDR_CHECK_EQ(fixture.registry.generation(), before);

    const std::optional<Membership> after = fixture.registry.membership(setup.derived);
    FDR_CHECK(after.has_value());
    FDR_CHECK_EQ(after->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(after->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(after->evidence.size(), std::size_t{1});
    FDR_CHECK(after->derivation.valid);
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(),
                 std::size_t{5});
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, reconcile_membership_returns_a_revalidated_membership_to_current) {
    Fixture fixture;
    bootstrap(fixture, 0xC1u);
    // The second record of this case is published by another publisher: a
    // withdrawal reaches every record its publisher's evidence sits on, so a
    // second record by the same publisher would be demoted by it too.
    add_second_publisher(fixture, 0xC2u);
    const FailureDomainId rack = id_of("dc1", DomainClass::Rack, "rack-r7");
    FDR_CHECK_EQ(create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord).code,
                 OutcomeCode::Committed);
    const EntityRef member = entity_ref(EntityClass::Switch, 25u, 1u);
    const MembershipId id = membership_id_for(membership_key(rack, member, MembershipKind::Direct));
    FDR_CHECK_EQ(attach_now(fixture, 2u, rack, member, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-1")
                     .code,
                 OutcomeCode::Committed);

    // Reconciling a membership whose lifecycle is already right changes nothing.
    const RegistryGeneration before = fixture.registry.generation();
    const Outcome already =
        fixture.registry.reconcile_membership(reconcile_request(fixture, 3u, rack, member));
    FDR_CHECK_EQ(already.code, OutcomeCode::Idempotent);
    FDR_CHECK_MSG(already.message.find("no lifecycle change") != std::string::npos, already.message);
    FDR_CHECK(already.membership_generation.has_value());
    FDR_CHECK_EQ(already.membership_generation->value(), std::uint64_t{1});
    FDR_CHECK_EQ(fixture.registry.generation(), before);

    // An unknown membership is a named refusal and reports the key it computed.
    const Outcome unknown = fixture.registry.reconcile_membership(
        reconcile_request(fixture, 4u, rack, entity_ref(EntityClass::Switch, 26u, 1u)));
    FDR_CHECK_EQ(unknown.code, OutcomeCode::NotFound);
    FDR_CHECK(unknown.membership.has_value());
    FDR_CHECK_EQ(*unknown.membership,
                 membership_id_for(
                     membership_key(rack, entity_ref(EntityClass::Switch, 26u, 1u), MembershipKind::Direct)));

    // A revalidation demand demotes the membership without touching its evidence:
    // the corroboration is still there, only the authority is suspended.
    const Outcome demanded = fixture.registry.mark_revalidation_required(
        mark_request(fixture, 5u, rack, "the domain was redeclared"));
    FDR_CHECK_EQ(demanded.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(demanded.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(demanded.steps.front().stage, std::string("revalidation"));
    FDR_CHECK_EQ(demanded.steps.front().value, std::string("1"));
    std::optional<Membership> record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::RevalidationRequired);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{1});
    FDR_CHECK_EQ(record->live_evidence_count(), std::size_t{1});
    check_state(fixture.registry);

    // With live evidence on the record, reconciliation is allowed to restore it.
    const Outcome reconciled =
        fixture.registry.reconcile_membership(reconcile_request(fixture, 6u, rack, member));
    FDR_CHECK_EQ(reconciled.code, OutcomeCode::Committed);
    FDR_CHECK(reconciled.membership.has_value());
    FDR_CHECK_EQ(*reconciled.membership, id);
    FDR_CHECK(reconciled.membership_generation.has_value());
    FDR_CHECK_EQ(reconciled.membership_generation->value(), std::uint64_t{3});
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{3});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{1});
    FDR_CHECK_EQ(record->history.size(), std::size_t{2});
    FDR_CHECK_EQ(record->history.back().cause, std::string("reconciled"));
    check_state(fixture.registry);

    // The second reconciliation has nothing left to do.
    const RegistryGeneration after_reconcile = fixture.registry.generation();
    const Outcome again =
        fixture.registry.reconcile_membership(reconcile_request(fixture, 7u, rack, member));
    FDR_CHECK_EQ(again.code, OutcomeCode::Idempotent);
    FDR_CHECK(again.membership_generation.has_value());
    FDR_CHECK_EQ(again.membership_generation->value(), std::uint64_t{3});
    FDR_CHECK_EQ(fixture.registry.generation(), after_reconcile);

    // With no live evidence left there is nothing to reconcile back to: the
    // membership stays indeterminate rather than becoming true again.
    const EntityRef unsupported = entity_ref(EntityClass::Switch, 27u, 1u);
    const MembershipId unsupported_id =
        membership_id_for(membership_key(rack, unsupported, MembershipKind::Direct));
    AttachSpec unsupported_spec = direct_spec(ProvenanceSource::Cmdb,
                                              EvidenceClass::AdministrativeDeclaration, "cmdb-2");
    FDR_CHECK_EQ(attach_as(fixture, fixture.second_authority, 8u, rack, unsupported, unsupported_spec).code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(fixture.registry
                     .withdraw_evidence(withdraw_as(fixture.second_authority, 9u, unsupported_id,
                                                    MembershipGeneration(1u), true, "retracted"))
                     .code,
                 OutcomeCode::Committed);
    // The first record is untouched: the demand was scoped to the other
    // publisher, whose evidence is the only evidence it matched.
    const std::optional<Membership> untouched = fixture.registry.membership(id);
    FDR_CHECK(untouched.has_value());
    FDR_CHECK_EQ(untouched->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(untouched->generation.value(), std::uint64_t{3});
    FDR_CHECK_EQ(untouched->evidence.size(), std::size_t{1});
    const RegistryGeneration before_empty = fixture.registry.generation();
    const Outcome empty = fixture.registry.reconcile_membership(
        reconcile_request(fixture, 10u, rack, unsupported));
    FDR_CHECK_EQ(empty.code, OutcomeCode::Idempotent);
    FDR_CHECK(empty.membership_generation.has_value());
    FDR_CHECK_EQ(empty.membership_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(fixture.registry.generation(), before_empty);
    record = fixture.registry.membership(unsupported_id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::RevalidationRequired);
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{0});

    // A terminal membership is never reconciled back into authority.
    const Outcome detached = fixture.registry.detach_member(
        detach_request(fixture, 11u, rack, member, MembershipGeneration(3u), "gone"));
    FDR_CHECK_EQ(detached.code, OutcomeCode::Committed);
    FDR_CHECK(detached.membership_generation.has_value());
    FDR_CHECK_EQ(detached.membership_generation->value(), std::uint64_t{4});
    const RegistryGeneration after_detach = fixture.registry.generation();
    const Outcome terminal =
        fixture.registry.reconcile_membership(reconcile_request(fixture, 12u, rack, member));
    FDR_CHECK_EQ(terminal.code, OutcomeCode::Idempotent);
    FDR_CHECK_MSG(terminal.message.find("terminal") != std::string::npos, terminal.message);
    FDR_CHECK(terminal.membership_generation.has_value());
    FDR_CHECK_EQ(terminal.membership_generation->value(), std::uint64_t{4});
    FDR_CHECK_EQ(fixture.registry.generation(), after_detach);
    record = fixture.registry.membership(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Retired);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{4});
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, incremental_publication_adds_and_updates_only) {
    Fixture fixture;
    bootstrap(fixture, 0xD1u);
    const FailureDomainId rack = id_of("dc1", DomainClass::Rack, "rack-r7");
    FDR_CHECK_EQ(create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord).code,
                 OutcomeCode::Committed);
    const EntityRef known = entity_ref(EntityClass::Switch, 28u, 2u);
    const EntityRef fresh = entity_ref(EntityClass::Switch, 29u, 2u);
    const MembershipId known_id = membership_id_for(membership_key(rack, known, MembershipKind::Direct));
    FDR_CHECK_EQ(attach_now(fixture, 2u, rack, known, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-1")
                     .code,
                 OutcomeCode::Committed);

    // One publication, one generation: an incremental publication adds what is
    // new and re-states what is not, and removes nothing.
    MembershipBatchRequest incremental;
    incremental.mode = PublicationMode::Incremental;
    incremental.entries.push_back(batch_entry(rack, known, kOperatorRecord));
    incremental.entries.push_back(batch_entry(rack, fresh, kOperatorRecord));
    const RegistryGeneration before_publish = fixture.registry.generation();
    const Outcome published = publish_now(fixture, 3u, incremental);
    FDR_CHECK_EQ(published.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(published.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(published.steps.front().stage, std::string("commit"));
    FDR_CHECK_EQ(published.steps.front().field, std::string("mode"));
    FDR_CHECK_EQ(published.steps.front().value, std::string("incremental"));
    FDR_CHECK_EQ(published.steps.front().detail, std::string("1 added, 1 updated, 0 retired"));
    FDR_CHECK_EQ(fixture.registry.generation().value(), before_publish.value() + 1u);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{2});

    std::optional<Membership> record = fixture.registry.membership(known_id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{2});
    FDR_CHECK_EQ(record->live_evidence_count(), std::size_t{2});
    FDR_CHECK_EQ(record->history.size(), std::size_t{1});
    FDR_CHECK_EQ(record->history.front().cause, std::string("republished"));
    FDR_CHECK_EQ(record->domain_generation.value(), std::uint64_t{1});

    const MembershipId fresh_id = membership_id_for(membership_key(rack, fresh, MembershipKind::Direct));
    record = fixture.registry.membership(fresh_id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{1});
    FDR_CHECK_EQ(record->provenance.source, ProvenanceSource::Cmdb);
    FDR_CHECK_EQ(record->provenance.publisher, fixture.publisher);
    FDR_CHECK_EQ(record->role, MembershipRole::Primary);
    FDR_CHECK_EQ(record->dependency, DependencySemantics::AllDependenciesRequired);
    check_state(fixture.registry);

    // A batch is applied whole or not at all: a weaker re-statement of the
    // second member refuses the whole publication, including the part that
    // would have been accepted.
    MembershipBatchRequest mixed;
    mixed.mode = PublicationMode::Incremental;
    mixed.entries.push_back(batch_entry(rack, known, kOperatorRecord));
    mixed.entries.push_back(batch_entry(
        rack, fresh,
        provenance_of(ProvenanceSource::SyntheticTestSource, EvidenceClass::Synthetic,
                      TruthClass::Synthetic, "synthetic-1")));
    const RegistryGeneration before_refusal = fixture.registry.generation();
    const Outcome refused = publish_now(fixture, 4u, mixed);
    FDR_CHECK_EQ(refused.code, OutcomeCode::PolicyRejected);
    FDR_CHECK_MSG(refused.message.find("weaker") != std::string::npos, refused.message);
    FDR_CHECK(refused.membership.has_value());
    FDR_CHECK_EQ(*refused.membership, fresh_id);
    FDR_CHECK_EQ(fixture.registry.generation(), before_refusal);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{2});
    record = fixture.registry.membership(known_id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{2});
    record = fixture.registry.membership(fresh_id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{1});
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, authoritative_publication_retires_only_the_named_class) {
    Fixture fixture;
    bootstrap(fixture, 0xD3u);
    DerivedSetup setup;
    bootstrap_derivation(fixture, 1u, setup);

    // Extras that an authoritative publication about the Pdu must not touch: a
    // Switch that is absent from the named set, and a Host in the same domain.
    const EntityRef orphan = entity_ref(EntityClass::Switch, 30u, 2u);
    const EntityRef host = entity_ref(EntityClass::Host, 31u, 2u);
    const EntityRef host_in_rack = entity_ref(EntityClass::Host, 32u, 2u);
    const MembershipId orphan_id = membership_id_for(membership_key(setup.pdu, orphan, MembershipKind::Direct));
    AttachSpec cmdb = direct_spec(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration,
                                  "cmdb-pdu");
    FDR_CHECK_EQ(attach_with(fixture, 7u, setup.pdu, orphan, cmdb).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(attach_with(fixture, 8u, setup.pdu, host, cmdb).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(attach_with(fixture, 9u, setup.rack, host_in_rack, cmdb).code, OutcomeCode::Committed);
    const MembershipId host_id = membership_id_for(membership_key(setup.pdu, host, MembershipKind::Direct));
    const MembershipId host_in_rack_id =
        membership_id_for(membership_key(setup.rack, host_in_rack, MembershipKind::Direct));
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{8});
    check_state(fixture.registry);

    // The named set is complete for SWITCH members of the Pdu. The Switch that
    // is absent is retired; the Derived memberships in the same domain and the
    // Host memberships are not, and neither is anything in another domain.
    MembershipBatchRequest authoritative;
    authoritative.mode = PublicationMode::Authoritative;
    authoritative.authoritative_entity_class = EntityClass::Switch;
    authoritative.authoritative_domains.push_back(setup.pdu);
    // The named member is re-stated with the exact assertion the record already
    // holds: a different source identity would be an equal-rank disagreement and
    // would refuse the publication instead of updating the record.
    const Provenance anchor_record = provenance_of(ProvenanceSource::Cmdb,
                                                   EvidenceClass::AdministrativeDeclaration,
                                                   TruthClass::Real, "cmdb-d2");
    authoritative.entries.push_back(batch_entry(setup.pdu, setup.anchor, anchor_record));
    const RegistryGeneration before = fixture.registry.generation();
    const Outcome published = publish_now(fixture, 10u, authoritative);
    FDR_CHECK_EQ(published.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(published.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(published.steps.front().value, std::string("authoritative"));
    FDR_CHECK_EQ(published.steps.front().detail, std::string("0 added, 1 updated, 1 retired"));
    FDR_CHECK_EQ(fixture.registry.generation().value(), before.value() + 1u);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{8});

    // The absent Switch is closed with a reason.
    std::optional<Membership> record = fixture.registry.membership(orphan_id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Retired);
    FDR_CHECK(record->is_terminal());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->history.size(), std::size_t{1});
    FDR_CHECK_EQ(record->history.front().cause,
                 std::string("absent from an authoritative publication"));

    // The named member was updated and its evidence corroborated.
    record = fixture.registry.membership(
        membership_id_for(membership_key(setup.pdu, setup.anchor, MembershipKind::Direct)));
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->evidence.size(), std::size_t{2});

    // A Host in the same domain is outside the claimed class, and a Host in
    // another domain is outside the claimed domains.
    record = fixture.registry.membership(host_id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    record = fixture.registry.membership(host_in_rack_id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});

    // Derived membership is recomputed from its sources, never retired by a
    // publisher's claim about a class.
    record = fixture.registry.membership(setup.derived);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->kind, MembershipKind::Derived);
    FDR_CHECK_EQ(record->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK(record->derivation.valid);
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(),
                 std::size_t{7});
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Retired).size(),
                 std::size_t{1});
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, publish_memberships_rejects_the_whole_publication) {
    Fixture fixture;
    bootstrap(fixture, 0xE1u);
    const FailureDomainId rack_a = id_of("dc1", DomainClass::Rack, "rack-a");
    const FailureDomainId rack_b = id_of("dc1", DomainClass::Rack, "rack-b");
    const FailureDomainId feed = id_of("dc1", DomainClass::PowerFeed, "feed-a");
    FDR_CHECK_EQ(create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-a", "Rack A", kOperatorRecord).code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(create_now(fixture, 2u, DomainClass::Rack, "dc1", "rack-b", "Rack B", kOperatorRecord).code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(create_now(fixture, 3u, DomainClass::PowerFeed, "dc1", "feed-a", "Feed A",
                            kOperatorRecord)
                     .code,
                 OutcomeCode::Committed);
    const EntityRef member = entity_ref(EntityClass::Switch, 33u, 1u);
    const EntityRef other = entity_ref(EntityClass::Switch, 34u, 1u);
    const RegistryGeneration before = fixture.registry.generation();

    // An empty publication claims nothing and means nothing.
    MembershipBatchRequest empty;
    empty.mode = PublicationMode::Incremental;
    const Outcome empty_outcome = publish_now(fixture, 4u, empty);
    FDR_CHECK_EQ(empty_outcome.code, OutcomeCode::MalformedRequest);
    FDR_CHECK_MSG(empty_outcome.message.find("empty") != std::string::npos, empty_outcome.message);

    // An authoritative publication has to say what it claims to be complete for.
    MembershipBatchRequest unqualified;
    unqualified.mode = PublicationMode::Authoritative;
    unqualified.authoritative_entity_class = EntityClass::Switch;
    unqualified.entries.push_back(batch_entry(rack_a, member, kOperatorRecord));
    const Outcome unqualified_outcome = publish_now(fixture, 5u, unqualified);
    FDR_CHECK_EQ(unqualified_outcome.code, OutcomeCode::MalformedRequest);
    FDR_CHECK_MSG(unqualified_outcome.message.find("complete for") != std::string::npos,
                  unqualified_outcome.message);

    // A named domain that does not exist.
    MembershipBatchRequest unknown_domain;
    unknown_domain.mode = PublicationMode::Incremental;
    unknown_domain.entries.push_back(
        batch_entry(FailureDomainId::from_bytes(bytes_with(0xD0u, 4u)), member, kOperatorRecord));
    const Outcome unknown_outcome = publish_now(fixture, 6u, unknown_domain);
    FDR_CHECK_EQ(unknown_outcome.code, OutcomeCode::UnknownDomain);
    FDR_CHECK(unknown_outcome.domain.has_value());
    // None of the refusals above moved the registry.
    FDR_CHECK_EQ(fixture.registry.generation(), before);

    // A domain generation the publisher believed in and that has moved on.
    UpdateDomainRequest rename;
    rename.attempt = attempt_with(7u);
    rename.authority = fixture.authority;
    rename.domain = rack_a;
    rename.expected_generation = FailureDomainGeneration(1u);
    rename.name = "Rack A (renamed)";
    FDR_CHECK_EQ(fixture.registry.update_domain(rename).code, OutcomeCode::Committed);

    MembershipBatchRequest stale;
    stale.mode = PublicationMode::Incremental;
    MembershipBatchEntry stale_entry = batch_entry(rack_a, member, kOperatorRecord);
    stale_entry.expected_domain_generation = FailureDomainGeneration(1u);
    stale.entries.push_back(stale_entry);
    const RegistryGeneration after_rename = fixture.registry.generation();
    const Outcome stale_outcome = publish_now(fixture, 8u, stale);
    FDR_CHECK_EQ(stale_outcome.code, OutcomeCode::StaleDomain);
    FDR_CHECK(stale_outcome.domain_generation.has_value());
    FDR_CHECK_EQ(stale_outcome.domain_generation->value(), std::uint64_t{2});

    // The same membership twice in one batch is a caller error, not a merge.
    MembershipBatchRequest duplicated;
    duplicated.mode = PublicationMode::Incremental;
    duplicated.entries.push_back(batch_entry(feed, member, kOperatorRecord));
    duplicated.entries.push_back(batch_entry(feed, member, kOperatorRecord));
    const Outcome duplicate_outcome = publish_now(fixture, 9u, duplicated);
    FDR_CHECK_EQ(duplicate_outcome.code, OutcomeCode::MalformedRequest);
    FDR_CHECK_MSG(duplicate_outcome.message.find("twice") != std::string::npos,
                  duplicate_outcome.message);

    // One member in two domains of an exclusive class, inside the publication
    // itself: the publication is refused whole, so nothing is half applied.
    MembershipBatchRequest exclusive;
    exclusive.mode = PublicationMode::Incremental;
    exclusive.entries.push_back(batch_entry(rack_a, other, kOperatorRecord));
    exclusive.entries.push_back(batch_entry(rack_b, other, kOperatorRecord));
    const Outcome exclusive_outcome = publish_now(fixture, 10u, exclusive);
    FDR_CHECK_EQ(exclusive_outcome.code, OutcomeCode::ExclusivityViolation);
    FDR_CHECK_EQ(exclusive_outcome.related_domains.size(), std::size_t{1});
    FDR_CHECK_EQ(exclusive_outcome.related_domains.front(), rack_a);
    FDR_CHECK(exclusive_outcome.member.has_value());
    FDR_CHECK_EQ(*exclusive_outcome.member, other);

    FDR_CHECK_EQ(fixture.registry.generation(), after_rename);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{0});
    FDR_CHECK(!fixture.registry
                   .membership(membership_id_for(membership_key(rack_a, other, MembershipKind::Direct)))
                   .has_value());
    FDR_CHECK(!fixture.registry
                   .membership(membership_id_for(membership_key(rack_b, other, MembershipKind::Direct)))
                   .has_value());
    check_state(fixture.registry);
}

FDR_TEST_CASE(membership, an_oversized_publication_is_refused_by_the_configured_bound) {
    // A lowered bound is the only way to reach the batch limit deterministically:
    // the compiled default is far above anything a case may build.
    RegistryLimits limits = RegistryLimits::defaults();
    limits.max_members_per_batch = 2;
    Fixture fixture(limits);
    bootstrap(fixture, 0xE2u);
    const FailureDomainId feed = id_of("dc1", DomainClass::PowerFeed, "feed-a");
    FDR_CHECK_EQ(create_now(fixture, 1u, DomainClass::PowerFeed, "dc1", "feed-a", "Feed A",
                            kOperatorRecord)
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(fixture.registry.limits().max_members_per_batch, std::size_t{2});

    const RegistryGeneration before = fixture.registry.generation();
    MembershipBatchRequest oversized;
    oversized.mode = PublicationMode::Incremental;
    for (std::uint8_t index = 0; index < 3; ++index) {
        oversized.entries.push_back(
            batch_entry(feed, entity_ref(EntityClass::Switch, static_cast<std::uint8_t>(40u + index), 1u),
                        kOperatorRecord));
    }
    const Outcome refused = publish_now(fixture, 2u, oversized);
    FDR_CHECK_EQ(refused.code, OutcomeCode::ResourceLimit);
    FDR_CHECK_MSG(refused.message.find("max_members_per_batch") != std::string::npos, refused.message);
    FDR_CHECK_EQ(refused.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(refused.steps.front().stage, std::string("limit"));
    FDR_CHECK_EQ(refused.steps.front().field, std::string("entries"));
    FDR_CHECK_EQ(refused.steps.front().value, std::string("3"));
    FDR_CHECK_EQ(fixture.registry.generation(), before);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{0});
    check_state(fixture.registry);

    // Exactly the bound still lands: the limit is a bound, not an off-by-one.
    MembershipBatchRequest at_bound;
    at_bound.mode = PublicationMode::Incremental;
    at_bound.entries.push_back(batch_entry(feed, entity_ref(EntityClass::Switch, 50u, 1u), kOperatorRecord));
    at_bound.entries.push_back(batch_entry(feed, entity_ref(EntityClass::Switch, 51u, 1u), kOperatorRecord));
    const Outcome accepted = publish_now(fixture, 3u, at_bound);
    FDR_CHECK_EQ(accepted.code, OutcomeCode::Committed);
    FDR_CHECK_EQ(accepted.steps.front().detail, std::string("2 added, 0 updated, 0 retired"));
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{2});
    check_state(fixture.registry);
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
