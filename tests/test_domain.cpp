// Failure Domain Registry — domain identity, lifecycle and precedence.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A failure domain is the only record in this runtime that carries
// classification authority, so the promises made about identity, generation,
// precedence and closure are pinned here against the public API alone. Every
// case asserts the exact OutcomeCode of every call and the exact generation and
// lifecycle that resulted; every refusal is also checked against the state it
// was supposed to leave alone, because an optimistic retry is only safe when a
// refused request moved nothing.
//
// Each accepted mutation is followed by Registry::validate_state, so an
// operation that leaves one of the maintained indexes out of step fails here
// rather than much later in an unrelated query.

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
using failure_domain_registry::kMaxIdentityKeyBytes;
using failure_domain_registry::Membership;
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
using failure_domain_registry::PublisherId;
using failure_domain_registry::PublisherRegistration;
using failure_domain_registry::Registry;
using failure_domain_registry::RegistryGeneration;
using failure_domain_registry::RegistryLimits;
using failure_domain_registry::RequestDigest;
using failure_domain_registry::RetireDomainRequest;
using failure_domain_registry::SupersedeDomainRequest;
using failure_domain_registry::TruthClass;
using failure_domain_registry::UpdateDomainRequest;
using failure_domain_registry::WorkerBootId;
using failure_domain_registry::domain_id_for;
using failure_domain_registry::membership_id_for;
using failure_domain_registry::validate_identity_key;
using failure_domain_registry::validate_scope_name;

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

    const Outcome attached =
        fixture.registry.attach_worker(fixture.publisher, fixture.boot, established, "fixture", EvidenceClass::DirectAuthoritativeInfrastructure);
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

CreateDomainRequest create_request(const Fixture& fixture, std::uint8_t index, DomainClass domain_class,
                                   std::string scope, std::string identity_key, std::string name,
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

Outcome create_now(Fixture& fixture, std::uint8_t index, DomainClass domain_class, const std::string& scope,
                   const std::string& identity_key, const std::string& name, const Provenance& provenance,
                   bool activate = true) {
    return fixture.registry.create_domain(
        create_request(fixture, index, domain_class, scope, identity_key, name, provenance, activate));
}

Outcome attach_now(Fixture& fixture, std::uint8_t index, const FailureDomainId& domain,
                   const EntityRef& member, EvidenceClass evidence, ProvenanceSource source,
                   const std::string& source_identity) {
    AttachMemberRequest request;
    request.attempt = attempt_with(index);
    request.authority = fixture.authority;
    request.domain = domain;
    request.expected_domain_generation = FailureDomainGeneration{};
    request.member = member;
    request.kind = MembershipKind::Direct;
    request.role = MembershipRole::Primary;
    request.provenance = provenance_of(source, evidence, TruthClass::Real, source_identity);
    return fixture.registry.attach_member(request);
}

FailureDomainId id_of(const std::string& scope, DomainClass domain_class, const std::string& identity_key) {
    return domain_id_for(scope, DomainClassRef(domain_class), identity_key);
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

const Provenance kOperatorRecord =
    provenance_of(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration, TruthClass::Real, "cmdb-1");

} // namespace

FDR_TEST_CASE(domain, domain_id_for_depends_only_on_scope_class_and_key) {
    const FailureDomainId rack_r7 = id_of("dc1", DomainClass::Rack, "rack-r7");
    FDR_CHECK(!rack_r7.is_null());

    // The same triple is the same identity, whenever it is computed.
    FDR_CHECK_EQ(id_of("dc1", DomainClass::Rack, "rack-r7"), rack_r7);
    FDR_CHECK_EQ(id_of("dc1", DomainClass::Rack, "rack-r7").to_string(), rack_r7.to_string());

    // Each component participates: changing any one of them addresses a
    // different factor and must never resolve to the same record.
    const FailureDomainId other_scope = id_of("dc2", DomainClass::Rack, "rack-r7");
    const FailureDomainId other_class = id_of("dc1", DomainClass::Pod, "rack-r7");
    const FailureDomainId other_key = id_of("dc1", DomainClass::Rack, "rack-r8");
    FDR_CHECK(!(other_scope == rack_r7));
    FDR_CHECK(!(other_class == rack_r7));
    FDR_CHECK(!(other_key == rack_r7));
    FDR_CHECK(!(other_scope == other_class));
    FDR_CHECK(!(other_scope == other_key));
    FDR_CHECK(!(other_class == other_key));

    // An extension class names its own classification space.
    const std::optional<DomainClassRef> extension =
        DomainClassRef::extension("vendor", "acme", "cooling-loop");
    FDR_CHECK(extension.has_value());
    const FailureDomainId extension_id = domain_id_for("dc1", *extension, "rack-r7");
    FDR_CHECK(!(extension_id == rack_r7));

    // The identity is the identity the mutation mints, not a value the caller
    // supplies.
    Fixture fixture;
    bootstrap(fixture, 0x11u);
    const Outcome created = create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
    FDR_CHECK(created.domain.has_value());
    FDR_CHECK_EQ(*created.domain, rack_r7);
    FDR_CHECK_EQ(fixture.registry.domain_count(), std::size_t{1});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, domain_id_for_ignores_call_order_and_registry_contents) {
    // The id is a pure function of its three inputs: computing it before,
    // during and after unrelated registry traffic yields one value.
    const FailureDomainId first = id_of("dc1", DomainClass::Rack, "order-key");
    const FailureDomainId second = id_of("dc1", DomainClass::Pod, "order-key");

    Fixture fixture;
    bootstrap(fixture, 0x12u);
    const Outcome pod = create_now(fixture, 1u, DomainClass::Pod, "dc1", "order-key", "Pod", kOperatorRecord);
    FDR_CHECK_EQ(pod.code, OutcomeCode::Committed);
    const Outcome rack = create_now(fixture, 2u, DomainClass::Rack, "dc1", "order-key", "Rack", kOperatorRecord);
    FDR_CHECK_EQ(rack.code, OutcomeCode::Committed);
    FDR_CHECK(rack.domain.has_value());
    FDR_CHECK(pod.domain.has_value());
    FDR_CHECK_EQ(*rack.domain, first);
    FDR_CHECK_EQ(*pod.domain, second);

    FDR_CHECK_EQ(id_of("dc1", DomainClass::Rack, "order-key"), first);
    FDR_CHECK_EQ(id_of("dc1", DomainClass::Pod, "order-key"), second);

    // A second registry that saw the reverse order mints the same two ids.
    Fixture reversed;
    bootstrap(reversed, 0x13u);
    const Outcome rack_first = create_now(reversed, 1u, DomainClass::Rack, "dc1", "order-key", "Rack", kOperatorRecord);
    FDR_CHECK_EQ(rack_first.code, OutcomeCode::Committed);
    FDR_CHECK(rack_first.domain.has_value());
    FDR_CHECK_EQ(*rack_first.domain, first);
}

FDR_TEST_CASE(domain, create_domain_commits_generation_one_and_records_its_origin) {
    Fixture fixture;
    bootstrap(fixture, 0x21u);
    // The fixture itself committed three mutations: the grant, the epoch
    // advance and the attach.
    FDR_CHECK_EQ(fixture.registry.generation().value(), std::uint64_t{3});

    const Provenance provenance = provenance_of(ProvenanceSource::PhysicalInfrastructure,
                                                EvidenceClass::DirectAuthoritativeInfrastructure, TruthClass::Real,
                                                "dcim-rack-r7");
    const Outcome outcome = create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", provenance);
    FDR_CHECK_EQ(outcome.code, OutcomeCode::Committed);
    FDR_CHECK(outcome.domain.has_value());
    FDR_CHECK(outcome.domain_generation.has_value());
    FDR_CHECK_EQ(outcome.domain_generation->value(), std::uint64_t{1});

    const std::optional<FailureDomain> record = fixture.registry.domain(*outcome.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->domain_class, DomainClassRef(DomainClass::Rack));
    FDR_CHECK_EQ(record->administrative_scope, std::string("dc1"));
    FDR_CHECK_EQ(record->name, std::string("Rack R7"));
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(record->created_generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Current);
    FDR_CHECK(record->is_current());
    FDR_CHECK(!record->is_terminal());
    FDR_CHECK(record->superseded_by.is_null());
    FDR_CHECK(record->supersedes.is_null());
    FDR_CHECK(record->merged_into.is_null());
    FDR_CHECK(record->metadata.empty());

    // Provenance is attributed to the calling incarnation, so the record states
    // who said it rather than only what was said.
    FDR_CHECK_EQ(record->provenance.evidence, EvidenceClass::DirectAuthoritativeInfrastructure);
    FDR_CHECK_EQ(record->provenance.source, ProvenanceSource::PhysicalInfrastructure);
    FDR_CHECK_EQ(record->provenance.truth, TruthClass::Real);
    FDR_CHECK_EQ(record->provenance.source_identity, std::string("dcim-rack-r7"));
    FDR_CHECK_EQ(record->provenance.publisher, fixture.publisher);
    FDR_CHECK_EQ(record->provenance.worker_boot, fixture.boot);

    // created_at is the registry generation the commit started from, and
    // created_epoch is the epoch that authorized it.
    FDR_CHECK_EQ(record->created_at.value(), std::uint64_t{3});
    FDR_CHECK_EQ(record->created_epoch.value(), std::uint64_t{1});
    FDR_CHECK_EQ(fixture.registry.generation().value(), std::uint64_t{4});
    FDR_CHECK(outcome.state_generation.has_value());
    FDR_CHECK_EQ(outcome.state_generation->value(), std::uint64_t{4});

    FDR_CHECK_EQ(fixture.registry.domain_count(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.domains_of_class(DomainClassRef(DomainClass::Rack)).size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.domains_in_scope("dc1").size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.domains_in_lifecycle(DomainLifecycle::Current).size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.domains_in_lifecycle(DomainLifecycle::Candidate).size(), std::size_t{0});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, activate_false_parks_a_domain_in_candidate) {
    Fixture fixture;
    bootstrap(fixture, 0x22u);
    const Outcome outcome =
        create_now(fixture, 1u, DomainClass::Rack, "dc1", "candidate-rack", "Unconfirmed rack", kOperatorRecord,
                   false);
    FDR_CHECK_EQ(outcome.code, OutcomeCode::Committed);
    FDR_CHECK(outcome.domain.has_value());
    FDR_CHECK(outcome.domain_generation.has_value());
    FDR_CHECK_EQ(outcome.domain_generation->value(), std::uint64_t{1});

    const std::optional<FailureDomain> record = fixture.registry.domain(*outcome.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Candidate);
    FDR_CHECK(!record->is_current());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(fixture.registry.domains_in_lifecycle(DomainLifecycle::Candidate).size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.domains_in_lifecycle(DomainLifecycle::Current).size(), std::size_t{0});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, a_candidate_domain_answers_no_overlap_until_promoted) {
    Fixture fixture;
    bootstrap(fixture, 0x23u);
    const FailureDomainId candidate = id_of("dc1", DomainClass::Rack, "candidate-rack");
    const Outcome created =
        create_now(fixture, 1u, DomainClass::Rack, "dc1", "candidate-rack", "Unconfirmed rack", kOperatorRecord,
                   false);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);

    const EntityRef left = entity_ref(EntityClass::Switch, 1u, 3u);
    const EntityRef right = entity_ref(EntityClass::Switch, 2u, 3u);
    FDR_CHECK_EQ(attach_now(fixture, 2u, candidate, left, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-l")
                     .code,
                 OutcomeCode::Committed);
    FDR_CHECK_EQ(attach_now(fixture, 3u, candidate, right, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-r")
                     .code,
                 OutcomeCode::Committed);

    // Two members of one CANDIDATE domain share nothing: a candidate has not
    // been confirmed and never answers a query about common failure.
    const failure_domain_registry::OverlapResult before = fixture.registry.overlap(left.id(), right.id());
    FDR_CHECK(before.shared.empty());
    FDR_CHECK(!before.shares_any_domain());

    // The very same membership answers as soon as the record carries authority.
    UpdateDomainRequest promote;
    promote.attempt = attempt_with(4u);
    promote.authority = fixture.authority;
    promote.domain = candidate;
    promote.expected_generation = FailureDomainGeneration(1u);
    promote.transition = DomainLifecycle::Current;
    const Outcome promoted = fixture.registry.update_domain(promote);
    FDR_CHECK_EQ(promoted.code, OutcomeCode::Committed);
    FDR_CHECK(promoted.domain_generation.has_value());
    FDR_CHECK_EQ(promoted.domain_generation->value(), std::uint64_t{2});

    const failure_domain_registry::OverlapResult after = fixture.registry.overlap(left.id(), right.id());
    FDR_CHECK_EQ(after.state, failure_domain_registry::IndependenceState::SharedDomain);
    FDR_CHECK_EQ(after.shared.size(), std::size_t{1});
    FDR_CHECK_EQ(after.shared.front().domain, candidate);
    FDR_CHECK_EQ(after.shared.front().domain_class, DomainClassRef(DomainClass::Rack));
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, identity_key_validation_enforces_the_documented_boundaries) {
    FDR_CHECK_EQ(validate_identity_key(std::string()).code, OutcomeCode::MalformedRequest);
    FDR_CHECK_EQ(validate_identity_key("rack-r7").code, OutcomeCode::Committed);

    // Exactly the bound is legal; one byte more is not.
    const std::string at_limit(kMaxIdentityKeyBytes, 'k');
    const std::string over_limit(kMaxIdentityKeyBytes + 1u, 'k');
    FDR_CHECK_EQ(validate_identity_key(at_limit).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(validate_identity_key(over_limit).code, OutcomeCode::MalformedRequest);

    // The registry's own string bound is far above the identity-key bound, so a
    // key that is legal for a name is still refused as an identity key.
    FDR_CHECK_EQ(RegistryLimits::defaults().max_string_bytes, std::size_t{1024});
    const std::string library_limit(RegistryLimits::defaults().max_string_bytes + 1u, 'k');
    FDR_CHECK_EQ(validate_identity_key(library_limit).code, OutcomeCode::MalformedRequest);

    // Control characters and DEL can never travel through an identity key.
    FDR_CHECK_EQ(validate_identity_key(std::string("rack\x01r7", 7)).code, OutcomeCode::MalformedRequest);
    FDR_CHECK_EQ(validate_identity_key(std::string("rack\x7fr7", 7)).code, OutcomeCode::MalformedRequest);
    FDR_CHECK_EQ(validate_identity_key(std::string("\t")).code, OutcomeCode::MalformedRequest);

    // Whitespace is not a control character: leading and trailing spaces are
    // accepted and are part of the key exactly as written.
    FDR_CHECK_EQ(validate_identity_key(" rack-r7 ").code, OutcomeCode::Committed);
    FDR_CHECK_EQ(validate_identity_key(" ").code, OutcomeCode::Committed);
    FDR_CHECK(!(id_of("dc1", DomainClass::Rack, " rack-r7 ") == id_of("dc1", DomainClass::Rack, "rack-r7")));
}

FDR_TEST_CASE(domain, scope_name_validation_enforces_the_documented_boundaries) {
    FDR_CHECK_EQ(validate_scope_name(std::string()).code, OutcomeCode::MalformedRequest);
    FDR_CHECK_EQ(validate_scope_name("dc1").code, OutcomeCode::Committed);

    const std::string at_limit(256, 's');
    const std::string over_limit(257, 's');
    FDR_CHECK_EQ(validate_scope_name(at_limit).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(validate_scope_name(over_limit).code, OutcomeCode::MalformedRequest);
    FDR_CHECK_EQ(validate_scope_name(std::string(RegistryLimits::defaults().max_string_bytes + 1u, 's')).code,
                 OutcomeCode::MalformedRequest);

    FDR_CHECK_EQ(validate_scope_name(std::string("dc\x01", 3)).code, OutcomeCode::MalformedRequest);
    FDR_CHECK_EQ(validate_scope_name(std::string("dc\x7f", 3)).code, OutcomeCode::MalformedRequest);
    FDR_CHECK_EQ(validate_scope_name(std::string("\n")).code, OutcomeCode::MalformedRequest);

    FDR_CHECK_EQ(validate_scope_name(" dc1 ").code, OutcomeCode::Committed);

    // A scope the validator accepted is stored verbatim, spaces included.
    Fixture fixture;
    bootstrap(fixture, 0x24u);
    const Outcome outcome = create_now(fixture, 1u, DomainClass::Rack, " dc1 ", "rack-spaced", "Rack", kOperatorRecord);
    FDR_CHECK_EQ(outcome.code, OutcomeCode::Committed);
    FDR_CHECK(outcome.domain.has_value());
    const std::optional<FailureDomain> record = fixture.registry.domain(*outcome.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->administrative_scope, std::string(" dc1 "));
    FDR_CHECK_EQ(fixture.registry.domains_in_scope(" dc1 ").size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.domains_in_scope("dc1").size(), std::size_t{0});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, create_domain_refuses_invalid_keys_and_scopes_without_a_trace) {
    Fixture fixture;
    bootstrap(fixture, 0x25u);
    const RegistryGeneration generation = fixture.registry.generation();

    const Outcome empty_key = create_now(fixture, 1u, DomainClass::Rack, "dc1", "", "Rack", kOperatorRecord);
    FDR_CHECK_EQ(empty_key.code, OutcomeCode::MalformedRequest);
    FDR_CHECK_EQ(empty_key.message, std::string("identity key is empty"));

    const Outcome long_key =
        create_now(fixture, 2u, DomainClass::Rack, "dc1", std::string(kMaxIdentityKeyBytes + 1u, 'k'), "Rack",
                   kOperatorRecord);
    FDR_CHECK_EQ(long_key.code, OutcomeCode::MalformedRequest);

    const Outcome empty_scope = create_now(fixture, 3u, DomainClass::Rack, "", "rack-r7", "Rack", kOperatorRecord);
    FDR_CHECK_EQ(empty_scope.code, OutcomeCode::MalformedRequest);
    FDR_CHECK_EQ(empty_scope.message, std::string("administrative scope is empty"));

    const Outcome long_scope =
        create_now(fixture, 4u, DomainClass::Rack, std::string(257, 's'), "rack-r7", "Rack", kOperatorRecord);
    FDR_CHECK_EQ(long_scope.code, OutcomeCode::MalformedRequest);

    // A malformed domain class is refused as a malformed request as well.
    const Outcome no_class = create_now(fixture, 5u, DomainClass::Unknown, "dc1", "rack-r7", "Rack", kOperatorRecord);
    FDR_CHECK_EQ(no_class.code, OutcomeCode::MalformedRequest);

    // None of the five refusals created a record or advanced a counter.
    FDR_CHECK_EQ(fixture.registry.domain_count(), std::size_t{0});
    FDR_CHECK_EQ(fixture.registry.generation(), generation);
    FDR_CHECK(!fixture.registry.domain(id_of("dc1", DomainClass::Rack, "rack-r7")).has_value());
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, create_domain_exact_replay_is_idempotent) {
    Fixture fixture;
    bootstrap(fixture, 0x26u);
    const CreateDomainRequest request =
        create_request(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    const Outcome first = fixture.registry.create_domain(request);
    FDR_CHECK_EQ(first.code, OutcomeCode::Committed);
    const RegistryGeneration after_first = fixture.registry.generation();

    // The same attempt id with the same content is the same intent, already
    // satisfied: no new generation, no second record, no bumped counter.
    const Outcome replay = fixture.registry.create_domain(request);
    FDR_CHECK_EQ(replay.code, OutcomeCode::Idempotent);
    FDR_CHECK(replay.domain.has_value());
    FDR_CHECK(replay.domain_generation.has_value());
    FDR_CHECK_EQ(replay.domain_generation->value(), std::uint64_t{1});
    FDR_CHECK_EQ(fixture.registry.generation(), after_first);
    FDR_CHECK_EQ(fixture.registry.domain_count(), std::size_t{1});

    // A fresh attempt that restates the very same fact is also idempotent: the
    // record already says exactly that.
    CreateDomainRequest restated = request;
    restated.attempt = attempt_with(2u);
    const Outcome again = fixture.registry.create_domain(restated);
    FDR_CHECK_EQ(again.code, OutcomeCode::Idempotent);
    FDR_CHECK_EQ(fixture.registry.generation(), after_first);

    const std::optional<FailureDomain> record = fixture.registry.domain(*first.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(record->name, std::string("Rack R7"));
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, create_domain_attempt_reuse_with_new_content_conflicts) {
    Fixture fixture;
    bootstrap(fixture, 0x27u);
    CreateDomainRequest request =
        create_request(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    const Outcome first = fixture.registry.create_domain(request);
    FDR_CHECK_EQ(first.code, OutcomeCode::Committed);
    const RegistryGeneration after_first = fixture.registry.generation();

    request.name = "Rack R7 (renamed)";
    const Outcome reused = fixture.registry.create_domain(request);
    FDR_CHECK_EQ(reused.code, OutcomeCode::ConflictingReplay);
    FDR_CHECK_MSG(!reused.message.empty(), "a conflicting replay must say what conflicted");
    FDR_CHECK_EQ(fixture.registry.generation(), after_first);
    FDR_CHECK_EQ(fixture.registry.domain_count(), std::size_t{1});

    const std::optional<FailureDomain> record = fixture.registry.domain(*first.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->name, std::string("Rack R7"));
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, weaker_evidence_cannot_replace_a_stronger_classification) {
    Fixture fixture;
    bootstrap(fixture, 0x31u);
    const FailureDomainId id = id_of("dc1", DomainClass::Rack, "rack-r7");
    const Provenance authoritative = provenance_of(ProvenanceSource::PhysicalInfrastructure,
                                                   EvidenceClass::DirectAuthoritativeInfrastructure, TruthClass::Real,
                                                   "dcim-1");
    const Outcome created = create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", authoritative);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
    const RegistryGeneration after_create = fixture.registry.generation();

    // A synthetic re-declaration out of the same registry is weaker evidence
    // for the same factor, so the stronger record stands untouched.
    const Provenance synthetic = provenance_of(ProvenanceSource::SyntheticTestSource, EvidenceClass::Synthetic,
                                               TruthClass::Synthetic, "synthetic-1");
    const Outcome refused = create_now(fixture, 2u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", synthetic);
    FDR_CHECK_EQ(refused.code, OutcomeCode::PolicyRejected);
    FDR_CHECK_MSG(refused.message.find("weaker") != std::string::npos, refused.message);
    FDR_CHECK(refused.domain.has_value());
    FDR_CHECK_EQ(*refused.domain, id);
    FDR_CHECK_EQ(fixture.registry.generation(), after_create);

    const std::optional<FailureDomain> record = fixture.registry.domain(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->provenance.evidence, EvidenceClass::DirectAuthoritativeInfrastructure);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Current);
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, stronger_evidence_replaces_the_classification) {
    Fixture fixture;
    bootstrap(fixture, 0x32u);
    const FailureDomainId id = id_of("dc1", DomainClass::Rack, "rack-r7");
    const Provenance inferred = provenance_of(ProvenanceSource::DiscoveryAgent, EvidenceClass::Inferred,
                                              TruthClass::Real, "agent-1");
    const Outcome created = create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", inferred);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
    const RegistryGeneration after_create = fixture.registry.generation();

    const Provenance measured =
        provenance_of(ProvenanceSource::VendorController, EvidenceClass::DirectHardwareController, TruthClass::Real,
                      "controller-7");
    const Outcome upgraded = create_now(fixture, 2u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", measured);
    FDR_CHECK_EQ(upgraded.code, OutcomeCode::Committed);
    FDR_CHECK(upgraded.domain_generation.has_value());
    FDR_CHECK_EQ(upgraded.domain_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(fixture.registry.generation().value(), after_create.value() + 1u);

    const std::optional<FailureDomain> record = fixture.registry.domain(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->provenance.evidence, EvidenceClass::DirectHardwareController);
    FDR_CHECK_EQ(record->provenance.source_identity, std::string("controller-7"));
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->created_generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Current);
    FDR_CHECK_EQ(record->history.size(), std::size_t{1});
    FDR_CHECK_EQ(record->history.front().cause, std::string("redeclared"));
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, equal_rank_from_a_different_source_marks_the_domain_conflicted) {
    Fixture fixture;
    bootstrap(fixture, 0x33u);
    const FailureDomainId id = id_of("dc1", DomainClass::Rack, "rack-r7");
    const Provenance cmdb = provenance_of(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration,
                                          TruthClass::Real, "cmdb-1");
    const Outcome created = create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", cmdb);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
    const RegistryGeneration after_create = fixture.registry.generation();

    // Equally strong statements from two different sources disagree: neither
    // wins, so the record becomes indeterminate rather than silently picking
    // one.
    const Provenance power = provenance_of(ProvenanceSource::PowerManagement, EvidenceClass::AdministrativeDeclaration,
                                           TruthClass::Real, "pm-1");
    const Outcome conflicted = create_now(fixture, 2u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7 (renamed)", power);
    FDR_CHECK_EQ(conflicted.code, OutcomeCode::DomainConflict);
    FDR_CHECK(conflicted.domain.has_value());
    FDR_CHECK_EQ(*conflicted.domain, id);
    FDR_CHECK(conflicted.domain_generation.has_value());
    FDR_CHECK_EQ(conflicted.domain_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(conflicted.steps.size(), std::size_t{2});
    FDR_CHECK_EQ(fixture.registry.generation().value(), after_create.value() + 1u);

    const std::optional<FailureDomain> record = fixture.registry.domain(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Conflicted);
    FDR_CHECK(!record->is_current());
    FDR_CHECK(!record->is_terminal());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    // The losing statement is refused whole: the record keeps what it had.
    FDR_CHECK_EQ(record->name, std::string("Rack R7"));
    FDR_CHECK_EQ(record->provenance.source, ProvenanceSource::Cmdb);
    FDR_CHECK_EQ(record->provenance.source_identity, std::string("cmdb-1"));
    FDR_CHECK_EQ(fixture.registry.domains_in_lifecycle(DomainLifecycle::Conflicted).size(), std::size_t{1});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, update_domain_changes_name_and_metadata) {
    Fixture fixture;
    bootstrap(fixture, 0x34u);
    const Outcome created = create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
    FDR_CHECK(created.domain.has_value());
    const FailureDomainId id = *created.domain;
    const RegistryGeneration after_create = fixture.registry.generation();

    UpdateDomainRequest update;
    update.attempt = attempt_with(2u);
    update.authority = fixture.authority;
    update.domain = id;
    update.expected_generation = FailureDomainGeneration(1u);
    update.name = "Rack R7 row A";
    update.replace_metadata = true;
    update.metadata = metadata_of("owner", "platform-ops");
    const Outcome renamed = fixture.registry.update_domain(update);
    FDR_CHECK_EQ(renamed.code, OutcomeCode::Committed);
    FDR_CHECK(renamed.domain_generation.has_value());
    FDR_CHECK_EQ(renamed.domain_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(fixture.registry.generation().value(), after_create.value() + 1u);

    std::optional<FailureDomain> record = fixture.registry.domain(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->name, std::string("Rack R7 row A"));
    FDR_CHECK_EQ(record->metadata.size(), std::size_t{1});
    FDR_CHECK_EQ(record->metadata.front().key, std::string("owner"));
    FDR_CHECK_EQ(record->metadata.front().value, std::string("platform-ops"));
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});

    // Replacing the metadata set with an equal set changes nothing, and a
    // request that asks for nothing is idempotent rather than a new generation.
    UpdateDomainRequest no_change;
    no_change.attempt = attempt_with(3u);
    no_change.authority = fixture.authority;
    no_change.domain = id;
    no_change.expected_generation = FailureDomainGeneration(2u);
    no_change.name = "Rack R7 row A";
    no_change.replace_metadata = true;
    no_change.metadata = metadata_of("owner", "platform-ops");
    const Outcome unchanged = fixture.registry.update_domain(no_change);
    FDR_CHECK_EQ(unchanged.code, OutcomeCode::Idempotent);
    FDR_CHECK(unchanged.domain_generation.has_value());
    FDR_CHECK_EQ(unchanged.domain_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(fixture.registry.generation().value(), after_create.value() + 1u);

    record = fixture.registry.domain(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->metadata.front().value, std::string("platform-ops"));
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, update_domain_applies_evidence_precedence) {
    Fixture fixture;
    bootstrap(fixture, 0x35u);
    const FailureDomainId id = id_of("dc1", DomainClass::Rack, "rack-r7");
    const Outcome created = create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);

    // Restating the record's own provenance is not a change.
    UpdateDomainRequest same;
    same.attempt = attempt_with(2u);
    same.authority = fixture.authority;
    same.domain = id;
    same.expected_generation = FailureDomainGeneration(1u);
    same.provenance = kOperatorRecord;
    const Outcome restated = fixture.registry.update_domain(same);
    FDR_CHECK_EQ(restated.code, OutcomeCode::Idempotent);
    FDR_CHECK_EQ(fixture.registry.generation().value(), std::uint64_t{4});

    // Weaker evidence is refused before anything is written.
    UpdateDomainRequest weaker;
    weaker.attempt = attempt_with(3u);
    weaker.authority = fixture.authority;
    weaker.domain = id;
    weaker.expected_generation = FailureDomainGeneration(1u);
    weaker.provenance = provenance_of(ProvenanceSource::SyntheticTestSource, EvidenceClass::Synthetic,
                                      TruthClass::Synthetic, "synthetic-1");
    const Outcome refused = fixture.registry.update_domain(weaker);
    FDR_CHECK_EQ(refused.code, OutcomeCode::PolicyRejected);
    FDR_CHECK_EQ(fixture.registry.generation().value(), std::uint64_t{4});

    // Stronger evidence replaces the assertion and advances the record.
    UpdateDomainRequest stronger;
    stronger.attempt = attempt_with(4u);
    stronger.authority = fixture.authority;
    stronger.domain = id;
    stronger.expected_generation = FailureDomainGeneration(1u);
    stronger.provenance = provenance_of(ProvenanceSource::PhysicalInfrastructure,
                                        EvidenceClass::DirectAuthoritativeInfrastructure, TruthClass::Real, "dcim-1");
    const Outcome upgraded = fixture.registry.update_domain(stronger);
    FDR_CHECK_EQ(upgraded.code, OutcomeCode::Committed);
    FDR_CHECK(upgraded.domain_generation.has_value());
    FDR_CHECK_EQ(upgraded.domain_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(fixture.registry.generation().value(), std::uint64_t{5});

    // An equally strong statement from another source is a conflict, and the
    // update path refuses it without changing the record's lifecycle.
    UpdateDomainRequest rival;
    rival.attempt = attempt_with(5u);
    rival.authority = fixture.authority;
    rival.domain = id;
    rival.expected_generation = FailureDomainGeneration(2u);
    rival.provenance = provenance_of(ProvenanceSource::OperatorInventory,
                                     EvidenceClass::DirectAuthoritativeInfrastructure, TruthClass::Real,
                                     "inventory-1");
    const Outcome conflicted = fixture.registry.update_domain(rival);
    FDR_CHECK_EQ(conflicted.code, OutcomeCode::DomainConflict);
    FDR_CHECK(conflicted.domain_generation.has_value());
    FDR_CHECK_EQ(conflicted.domain_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(fixture.registry.generation().value(), std::uint64_t{5});

    const std::optional<FailureDomain> record = fixture.registry.domain(id);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Current);
    FDR_CHECK_EQ(record->provenance.source_identity, std::string("dcim-1"));
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, update_domain_reports_the_current_generation_on_a_stale_expectation) {
    Fixture fixture;
    bootstrap(fixture, 0x36u);
    const Outcome created = create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
    FDR_CHECK(created.domain.has_value());
    const RegistryGeneration after_create = fixture.registry.generation();

    UpdateDomainRequest stale;
    stale.attempt = attempt_with(2u);
    stale.authority = fixture.authority;
    stale.domain = *created.domain;
    stale.expected_generation = FailureDomainGeneration(99u);
    stale.name = "Rack R7 (stale)";
    const Outcome refused = fixture.registry.update_domain(stale);
    FDR_CHECK_EQ(refused.code, OutcomeCode::StaleGeneration);
    // The current generation is reported so the caller can retry without a
    // second read.
    FDR_CHECK(refused.domain_generation.has_value());
    FDR_CHECK_EQ(refused.domain_generation->value(), std::uint64_t{1});
    FDR_CHECK_EQ(fixture.registry.generation(), after_create);

    const std::optional<FailureDomain> record = fixture.registry.domain(*created.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->name, std::string("Rack R7"));
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, update_domain_rejects_an_unknown_domain) {
    Fixture fixture;
    bootstrap(fixture, 0x37u);
    const RegistryGeneration before = fixture.registry.generation();

    UpdateDomainRequest unknown;
    unknown.attempt = attempt_with(1u);
    unknown.authority = fixture.authority;
    unknown.domain = FailureDomainId::from_bytes(bytes_with(0xD0u, 9u));
    unknown.name = "nowhere";
    const Outcome refused = fixture.registry.update_domain(unknown);
    FDR_CHECK_EQ(refused.code, OutcomeCode::UnknownDomain);
    FDR_CHECK_MSG(refused.domain.has_value(), "the refused id must be reported back");
    FDR_CHECK_EQ(fixture.registry.generation(), before);
    FDR_CHECK_EQ(fixture.registry.domain_count(), std::size_t{0});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, supersede_links_predecessor_and_successor_and_demotes_memberships) {
    Fixture fixture;
    bootstrap(fixture, 0x41u);
    const Outcome created =
        create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
    const Outcome successor =
        create_now(fixture, 2u, DomainClass::Rack, "dc1", "rack-r7-b", "Rack R7 (rebuilt)", kOperatorRecord);
    FDR_CHECK_EQ(successor.code, OutcomeCode::Committed);
    FDR_CHECK(created.domain.has_value());
    FDR_CHECK(successor.domain.has_value());

    const EntityRef member = entity_ref(EntityClass::Switch, 1u, 2u);
    FDR_CHECK_EQ(attach_now(fixture, 3u, *created.domain, member, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-member")
                     .code,
                 OutcomeCode::Committed);
    const RegistryGeneration before_supersede = fixture.registry.generation();

    const Outcome superseded = supersede_now(fixture, 4u, *created.domain, *successor.domain, true);
    FDR_CHECK_EQ(superseded.code, OutcomeCode::Committed);
    FDR_CHECK(superseded.domain.has_value());
    FDR_CHECK_EQ(*superseded.domain, *created.domain);
    FDR_CHECK(superseded.domain_generation.has_value());
    FDR_CHECK_EQ(superseded.domain_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(superseded.related_domains.size(), std::size_t{1});
    FDR_CHECK_EQ(superseded.related_domains.front(), *successor.domain);
    FDR_CHECK_EQ(fixture.registry.generation().value(), before_supersede.value() + 1u);

    const std::optional<FailureDomain> predecessor = fixture.registry.domain(*created.domain);
    FDR_CHECK(predecessor.has_value());
    FDR_CHECK_EQ(predecessor->lifecycle, DomainLifecycle::Superseded);
    FDR_CHECK(predecessor->is_terminal());
    FDR_CHECK_EQ(predecessor->superseded_by, *successor.domain);
    FDR_CHECK_EQ(predecessor->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(predecessor->history.size(), std::size_t{1});
    FDR_CHECK_EQ(predecessor->history.front().cause, std::string("superseded"));

    const std::optional<FailureDomain> survivor = fixture.registry.domain(*successor.domain);
    FDR_CHECK(survivor.has_value());
    FDR_CHECK_EQ(survivor->lifecycle, DomainLifecycle::Current);
    FDR_CHECK_EQ(survivor->supersedes, *created.domain);
    FDR_CHECK_EQ(survivor->generation.value(), std::uint64_t{1});
    FDR_CHECK(survivor->superseded_by.is_null());

    // The membership was bound to the old generation and is never re-bound: it
    // is demoted and must be reconciled explicitly.
    const MembershipKey key{*created.domain, member.id(), member.generation(), MembershipKind::Direct};
    const std::optional<Membership> membership = fixture.registry.membership(membership_id_for(key));
    FDR_CHECK(membership.has_value());
    FDR_CHECK_EQ(membership->lifecycle, MembershipLifecycle::RevalidationRequired);
    FDR_CHECK_EQ(membership->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(membership->domain_generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(), std::size_t{0});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, supersede_without_demotion_leaves_memberships_current) {
    Fixture fixture;
    bootstrap(fixture, 0x42u);
    const Outcome created =
        create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
    const Outcome successor =
        create_now(fixture, 2u, DomainClass::Rack, "dc1", "rack-r7-b", "Rack R7 (rebuilt)", kOperatorRecord);
    FDR_CHECK_EQ(successor.code, OutcomeCode::Committed);
    FDR_CHECK(created.domain.has_value());
    FDR_CHECK(successor.domain.has_value());

    const EntityRef member = entity_ref(EntityClass::Switch, 1u, 2u);
    FDR_CHECK_EQ(attach_now(fixture, 3u, *created.domain, member, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-member")
                     .code,
                 OutcomeCode::Committed);

    const Outcome superseded = supersede_now(fixture, 4u, *created.domain, *successor.domain, false);
    FDR_CHECK_EQ(superseded.code, OutcomeCode::Committed);

    const MembershipKey key{*created.domain, member.id(), member.generation(), MembershipKind::Direct};
    const std::optional<Membership> membership = fixture.registry.membership(membership_id_for(key));
    FDR_CHECK(membership.has_value());
    FDR_CHECK_EQ(membership->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(membership->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(membership->domain_generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(), std::size_t{1});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, supersede_rejects_self_unknown_and_closed_endpoints) {
    Fixture fixture;
    bootstrap(fixture, 0x43u);
    const Outcome created =
        create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
    const Outcome successor =
        create_now(fixture, 2u, DomainClass::Rack, "dc1", "rack-r7-b", "Rack R7 (rebuilt)", kOperatorRecord);
    FDR_CHECK_EQ(successor.code, OutcomeCode::Committed);
    FDR_CHECK(created.domain.has_value());
    FDR_CHECK(successor.domain.has_value());
    const RegistryGeneration before = fixture.registry.generation();

    const Outcome itself = supersede_now(fixture, 3u, *created.domain, *created.domain, true);
    FDR_CHECK_EQ(itself.code, OutcomeCode::MalformedRequest);
    FDR_CHECK_EQ(itself.message, std::string("a domain cannot supersede itself"));

    const Outcome unknown =
        supersede_now(fixture, 4u, *created.domain, FailureDomainId::from_bytes(bytes_with(0xD0u, 7u)), true);
    FDR_CHECK_EQ(unknown.code, OutcomeCode::UnknownDomain);

    FDR_CHECK_EQ(fixture.registry.generation(), before);
    std::optional<FailureDomain> record = fixture.registry.domain(*created.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Current);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{1});
    FDR_CHECK(record->superseded_by.is_null());

    // A second supersession of an already closed predecessor is refused with
    // the closed state, not with a generation complaint.
    FDR_CHECK_EQ(supersede_now(fixture, 5u, *created.domain, *successor.domain, true).code, OutcomeCode::Committed);
    const RegistryGeneration after_first_supersede = fixture.registry.generation();
    const Outcome again = supersede_now(fixture, 6u, *created.domain, *successor.domain, true);
    FDR_CHECK_EQ(again.code, OutcomeCode::Superseded);
    FDR_CHECK_EQ(fixture.registry.generation(), after_first_supersede);

    record = fixture.registry.domain(*created.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->superseded_by, *successor.domain);
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, a_superseded_domain_is_closed_against_replay_update_and_retirement) {
    Fixture fixture;
    bootstrap(fixture, 0x44u);
    const Outcome created =
        create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
    const Outcome successor =
        create_now(fixture, 2u, DomainClass::Rack, "dc1", "rack-r7-b", "Rack R7 (rebuilt)", kOperatorRecord);
    FDR_CHECK_EQ(successor.code, OutcomeCode::Committed);
    FDR_CHECK(created.domain.has_value());
    FDR_CHECK(successor.domain.has_value());
    FDR_CHECK_EQ(supersede_now(fixture, 3u, *created.domain, *successor.domain, true).code, OutcomeCode::Committed);
    const RegistryGeneration closed_at = fixture.registry.generation();

    // Recreating the identity by replay must never resurrect the record: the
    // caller is told the identity was superseded, not that it was retired.
    const Outcome recreated = create_now(fixture, 4u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(recreated.code, OutcomeCode::Superseded);
    FDR_CHECK(recreated.domain.has_value());
    FDR_CHECK_EQ(*recreated.domain, *created.domain);
    FDR_CHECK(recreated.domain_generation.has_value());
    FDR_CHECK_EQ(recreated.domain_generation->value(), std::uint64_t{2});

    UpdateDomainRequest update;
    update.attempt = attempt_with(5u);
    update.authority = fixture.authority;
    update.domain = *created.domain;
    update.expected_generation = FailureDomainGeneration(2u);
    update.name = "Rack R7 (resurrected)";
    FDR_CHECK_EQ(fixture.registry.update_domain(update).code, OutcomeCode::Superseded);

    const EntityRef member = entity_ref(EntityClass::Switch, 1u, 1u);
    FDR_CHECK_EQ(attach_now(fixture, 6u, *created.domain, member, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-member")
                     .code,
                 OutcomeCode::Superseded);
    FDR_CHECK_EQ(retire_now(fixture, 7u, *created.domain, "close it properly", true).code, OutcomeCode::Superseded);

    FDR_CHECK_EQ(fixture.registry.generation(), closed_at);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{0});
    const std::optional<FailureDomain> record = fixture.registry.domain(*created.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Superseded);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->superseded_by, *successor.domain);
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, retire_is_terminal_and_the_second_retire_is_idempotent) {
    Fixture fixture;
    bootstrap(fixture, 0x45u);
    const Outcome created =
        create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
    FDR_CHECK(created.domain.has_value());

    const EntityRef member = entity_ref(EntityClass::Switch, 1u, 2u);
    FDR_CHECK_EQ(attach_now(fixture, 2u, *created.domain, member, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-member")
                     .code,
                 OutcomeCode::Committed);
    const RegistryGeneration before_retire = fixture.registry.generation();

    const Outcome retired = retire_now(fixture, 3u, *created.domain, "decommissioned", true);
    FDR_CHECK_EQ(retired.code, OutcomeCode::Committed);
    FDR_CHECK(retired.domain_generation.has_value());
    FDR_CHECK_EQ(retired.domain_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(fixture.registry.generation().value(), before_retire.value() + 1u);

    std::optional<FailureDomain> record = fixture.registry.domain(*created.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Retired);
    FDR_CHECK(record->is_terminal());
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->history.size(), std::size_t{1});
    FDR_CHECK_EQ(record->history.front().cause, std::string("decommissioned"));

    const MembershipKey key{*created.domain, member.id(), member.generation(), MembershipKind::Direct};
    std::optional<Membership> membership = fixture.registry.membership(membership_id_for(key));
    FDR_CHECK(membership.has_value());
    FDR_CHECK_EQ(membership->lifecycle, MembershipLifecycle::Retired);
    FDR_CHECK_EQ(membership->generation.value(), std::uint64_t{2});

    // Retirement is terminal: the second demand is satisfied, not re-applied.
    const Outcome again = retire_now(fixture, 4u, *created.domain, "again", true);
    FDR_CHECK_EQ(again.code, OutcomeCode::Idempotent);
    FDR_CHECK(again.domain_generation.has_value());
    FDR_CHECK_EQ(again.domain_generation->value(), std::uint64_t{2});
    FDR_CHECK_EQ(fixture.registry.generation().value(), before_retire.value() + 1u);

    // Nothing may revive the record: not a create, not an update, not an
    // attach, and not a second retirement.
    FDR_CHECK_EQ(create_now(fixture, 5u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord).code,
                 OutcomeCode::Retired);
    UpdateDomainRequest update;
    update.attempt = attempt_with(6u);
    update.authority = fixture.authority;
    update.domain = *created.domain;
    update.name = "Rack R7 (resurrected)";
    FDR_CHECK_EQ(fixture.registry.update_domain(update).code, OutcomeCode::Retired);
    FDR_CHECK_EQ(attach_now(fixture, 7u, *created.domain, entity_ref(EntityClass::Switch, 2u, 1u),
                            EvidenceClass::AdministrativeDeclaration, ProvenanceSource::Cmdb, "cmdb-other")
                     .code,
                 OutcomeCode::Retired);
    FDR_CHECK_EQ(fixture.registry.generation().value(), before_retire.value() + 1u);

    record = fixture.registry.domain(*created.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Retired);
    FDR_CHECK_EQ(record->generation.value(), std::uint64_t{2});
    FDR_CHECK_EQ(record->name, std::string("Rack R7"));
    membership = fixture.registry.membership(membership_id_for(key));
    FDR_CHECK(membership.has_value());
    FDR_CHECK_EQ(membership->lifecycle, MembershipLifecycle::Retired);
    FDR_CHECK_EQ(fixture.registry.membership_count(), std::size_t{1});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, retire_memberships_false_leaves_memberships_current) {
    Fixture fixture;
    bootstrap(fixture, 0x46u);
    const Outcome created =
        create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(created.code, OutcomeCode::Committed);
    FDR_CHECK(created.domain.has_value());

    const EntityRef member = entity_ref(EntityClass::Switch, 1u, 4u);
    FDR_CHECK_EQ(attach_now(fixture, 2u, *created.domain, member, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-member")
                     .code,
                 OutcomeCode::Committed);

    const Outcome retired = retire_now(fixture, 3u, *created.domain, "kept for the record", false);
    FDR_CHECK_EQ(retired.code, OutcomeCode::Committed);

    const MembershipKey key{*created.domain, member.id(), member.generation(), MembershipKind::Direct};
    const std::optional<Membership> membership = fixture.registry.membership(membership_id_for(key));
    FDR_CHECK(membership.has_value());
    FDR_CHECK_EQ(membership->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(membership->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Retired).size(), std::size_t{0});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, merge_requires_the_same_class) {
    Fixture fixture;
    bootstrap(fixture, 0x51u);
    const Outcome rack = create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-r7", "Rack R7", kOperatorRecord);
    FDR_CHECK_EQ(rack.code, OutcomeCode::Committed);
    const Outcome pod = create_now(fixture, 2u, DomainClass::Pod, "dc1", "pod-p1", "Pod P1", kOperatorRecord);
    FDR_CHECK_EQ(pod.code, OutcomeCode::Committed);
    FDR_CHECK(rack.domain.has_value());
    FDR_CHECK(pod.domain.has_value());
    const RegistryGeneration before = fixture.registry.generation();

    // Two different factors are not one factor, however similar the names are.
    const Outcome refused = merge_now(fixture, 3u, *rack.domain, *pod.domain, false);
    FDR_CHECK_EQ(refused.code, OutcomeCode::PolicyRejected);
    FDR_CHECK_MSG(refused.message.find("same class") != std::string::npos, refused.message);
    FDR_CHECK_EQ(fixture.registry.generation(), before);

    const std::optional<FailureDomain> survivor = fixture.registry.domain(*rack.domain);
    const std::optional<FailureDomain> absorbed = fixture.registry.domain(*pod.domain);
    FDR_CHECK(survivor.has_value());
    FDR_CHECK(absorbed.has_value());
    FDR_CHECK_EQ(survivor->lifecycle, DomainLifecycle::Current);
    FDR_CHECK_EQ(absorbed->lifecycle, DomainLifecycle::Current);
    FDR_CHECK_EQ(survivor->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(absorbed->generation.value(), std::uint64_t{1});
    FDR_CHECK(absorbed->merged_into.is_null());
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, merge_requires_explicit_membership_equivalence) {
    Fixture fixture;
    bootstrap(fixture, 0x52u);
    const Outcome survivor =
        create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-a", "Rack A", kOperatorRecord);
    FDR_CHECK_EQ(survivor.code, OutcomeCode::Committed);
    const Outcome absorbed =
        create_now(fixture, 2u, DomainClass::Rack, "dc1", "rack-b", "Rack B", kOperatorRecord);
    FDR_CHECK_EQ(absorbed.code, OutcomeCode::Committed);
    FDR_CHECK(survivor.domain.has_value());
    FDR_CHECK(absorbed.domain.has_value());

    const EntityRef member = entity_ref(EntityClass::Switch, 5u, 1u);
    FDR_CHECK_EQ(attach_now(fixture, 3u, *absorbed.domain, member, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-member")
                     .code,
                 OutcomeCode::Committed);
    const RegistryGeneration before = fixture.registry.generation();

    // The registry never guesses that two member sets mean the same thing.
    const Outcome refused = merge_now(fixture, 4u, *survivor.domain, *absorbed.domain, false);
    FDR_CHECK_EQ(refused.code, OutcomeCode::PolicyRejected);
    FDR_CHECK_MSG(refused.message.find("equivalent") != std::string::npos, refused.message);
    FDR_CHECK_EQ(refused.steps.size(), std::size_t{1});
    FDR_CHECK_EQ(refused.steps.front().stage, std::string("merge"));
    FDR_CHECK_EQ(refused.steps.front().field, std::string("current-memberships"));
    FDR_CHECK_EQ(refused.steps.front().value, std::string("1"));
    FDR_CHECK_EQ(fixture.registry.generation(), before);

    const std::optional<FailureDomain> record = fixture.registry.domain(*absorbed.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Current);
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(), std::size_t{1});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, merge_moves_memberships_to_the_survivor_with_the_deterministic_key) {
    Fixture fixture;
    bootstrap(fixture, 0x53u);
    const Outcome survivor =
        create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-a", "Rack A", kOperatorRecord);
    FDR_CHECK_EQ(survivor.code, OutcomeCode::Committed);
    const Outcome absorbed =
        create_now(fixture, 2u, DomainClass::Rack, "dc1", "rack-b", "Rack B", kOperatorRecord);
    FDR_CHECK_EQ(absorbed.code, OutcomeCode::Committed);
    FDR_CHECK(survivor.domain.has_value());
    FDR_CHECK(absorbed.domain.has_value());

    const EntityRef member = entity_ref(EntityClass::Switch, 5u, 2u);
    AttachMemberRequest attach;
    attach.attempt = attempt_with(3u);
    attach.authority = fixture.authority;
    attach.domain = *absorbed.domain;
    attach.member = member;
    attach.kind = MembershipKind::Direct;
    attach.role = MembershipRole::Primary;
    attach.dependency = failure_domain_registry::DependencySemantics::AllDependenciesRequired;
    attach.provenance = provenance_of(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration,
                                      TruthClass::Real, "cmdb-member");
    attach.metadata = metadata_of("ticket", "MRG-1");
    FDR_CHECK_EQ(fixture.registry.attach_member(attach).code, OutcomeCode::Committed);

    const MembershipId old_id =
        membership_id_for(MembershipKey{*absorbed.domain, member.id(), member.generation(), MembershipKind::Direct});
    const MembershipId new_id =
        membership_id_for(MembershipKey{*survivor.domain, member.id(), member.generation(), MembershipKind::Direct});
    FDR_CHECK(!(old_id == new_id));
    FDR_CHECK(fixture.registry.membership(old_id).has_value());
    FDR_CHECK(!fixture.registry.membership(new_id).has_value());
    const RegistryGeneration before = fixture.registry.generation();

    const Outcome merged = merge_now(fixture, 4u, *survivor.domain, *absorbed.domain, true);
    FDR_CHECK_EQ(merged.code, OutcomeCode::Committed);
    FDR_CHECK(merged.domain.has_value());
    FDR_CHECK_EQ(*merged.domain, *survivor.domain);
    FDR_CHECK_EQ(merged.related_domains.size(), std::size_t{1});
    FDR_CHECK_EQ(merged.related_domains.front(), *absorbed.domain);
    FDR_CHECK_EQ(fixture.registry.generation().value(), before.value() + 1u);

    const std::optional<FailureDomain> absorbed_record = fixture.registry.domain(*absorbed.domain);
    FDR_CHECK(absorbed_record.has_value());
    FDR_CHECK_EQ(absorbed_record->lifecycle, DomainLifecycle::Superseded);
    FDR_CHECK(absorbed_record->is_terminal());
    FDR_CHECK_EQ(absorbed_record->merged_into, *survivor.domain);
    FDR_CHECK_EQ(absorbed_record->superseded_by, *survivor.domain);
    FDR_CHECK_EQ(absorbed_record->generation.value(), std::uint64_t{2});

    const std::optional<FailureDomain> survivor_record = fixture.registry.domain(*survivor.domain);
    FDR_CHECK(survivor_record.has_value());
    FDR_CHECK_EQ(survivor_record->lifecycle, DomainLifecycle::Current);
    FDR_CHECK_EQ(survivor_record->generation.value(), std::uint64_t{1});
    FDR_CHECK(survivor_record->supersedes.is_null());

    const std::optional<Membership> moved = fixture.registry.membership(new_id);
    FDR_CHECK(moved.has_value());
    FDR_CHECK_EQ(moved->domain, *survivor.domain);
    FDR_CHECK_EQ(moved->domain_generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(moved->member, member);
    FDR_CHECK_EQ(moved->kind, MembershipKind::Direct);
    FDR_CHECK_EQ(moved->role, MembershipRole::Primary);
    FDR_CHECK_EQ(moved->lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(moved->generation.value(), std::uint64_t{1});
    FDR_CHECK_EQ(moved->metadata.size(), std::size_t{1});
    FDR_CHECK_EQ(moved->metadata.front().key, std::string("ticket"));
    FDR_CHECK_EQ(moved->evidence.size(), std::size_t{1});

    const std::optional<Membership> superseded = fixture.registry.membership(old_id);
    FDR_CHECK(superseded.has_value());
    FDR_CHECK_EQ(superseded->domain, *absorbed.domain);
    FDR_CHECK_EQ(superseded->lifecycle, MembershipLifecycle::Superseded);
    FDR_CHECK(superseded->is_terminal());
    FDR_CHECK_EQ(superseded->superseded_by, new_id);
    FDR_CHECK_EQ(superseded->generation.value(), std::uint64_t{2});

    FDR_CHECK_EQ(fixture.registry.members_of(*survivor.domain).size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.members_of(*survivor.domain).front().id, new_id);
    FDR_CHECK_EQ(fixture.registry.members_of(*absorbed.domain).size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Current).size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.memberships_in_lifecycle(MembershipLifecycle::Superseded).size(), std::size_t{1});
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, merge_rejects_self_unknown_and_closed_endpoints) {
    Fixture fixture;
    bootstrap(fixture, 0x54u);
    const Outcome left = create_now(fixture, 1u, DomainClass::Rack, "dc1", "rack-a", "Rack A", kOperatorRecord);
    FDR_CHECK_EQ(left.code, OutcomeCode::Committed);
    const Outcome right = create_now(fixture, 2u, DomainClass::Rack, "dc1", "rack-b", "Rack B", kOperatorRecord);
    FDR_CHECK_EQ(right.code, OutcomeCode::Committed);
    FDR_CHECK(left.domain.has_value());
    FDR_CHECK(right.domain.has_value());
    const RegistryGeneration before = fixture.registry.generation();

    FDR_CHECK_EQ(merge_now(fixture, 3u, *left.domain, *left.domain, true).code, OutcomeCode::MalformedRequest);
    FDR_CHECK_EQ(merge_now(fixture, 4u, *left.domain, FailureDomainId::from_bytes(bytes_with(0xD0u, 3u)), true).code,
                 OutcomeCode::UnknownDomain);
    FDR_CHECK_EQ(fixture.registry.generation(), before);

    // A closed endpoint is not a merge partner, even when the classes agree.
    FDR_CHECK_EQ(retire_now(fixture, 5u, *right.domain, "closed", true).code, OutcomeCode::Committed);
    const RegistryGeneration after_retire = fixture.registry.generation();
    const Outcome closed = merge_now(fixture, 6u, *left.domain, *right.domain, true);
    FDR_CHECK_EQ(closed.code, OutcomeCode::NotCurrent);
    FDR_CHECK_EQ(fixture.registry.generation(), after_retire);

    const Outcome third = create_now(fixture, 7u, DomainClass::Rack, "dc1", "rack-c", "Rack C", kOperatorRecord);
    FDR_CHECK_EQ(third.code, OutcomeCode::Committed);
    FDR_CHECK(third.domain.has_value());
    FDR_CHECK_EQ(supersede_now(fixture, 8u, *third.domain, *left.domain, true).code, OutcomeCode::Committed);
    FDR_CHECK_EQ(merge_now(fixture, 9u, *left.domain, *third.domain, true).code, OutcomeCode::NotCurrent);

    const std::optional<FailureDomain> record = fixture.registry.domain(*left.domain);
    FDR_CHECK(record.has_value());
    FDR_CHECK_EQ(record->lifecycle, DomainLifecycle::Current);
    FDR_CHECK(record->merged_into.is_null());
    check_state(fixture.registry);
}

FDR_TEST_CASE(domain, a_mixed_domain_sequence_keeps_every_index_consistent) {
    Fixture fixture;
    bootstrap(fixture, 0x61u);
    const Provenance durable = provenance_of(ProvenanceSource::Cmdb, EvidenceClass::AdministrativeDeclaration,
                                             TruthClass::Real, "cmdb-1");
    const Provenance measured = provenance_of(ProvenanceSource::VendorController,
                                              EvidenceClass::DirectHardwareController, TruthClass::Real, "vc-1");

    std::uint8_t attempt = 1u;
    const Outcome rack_a = create_now(fixture, attempt++, DomainClass::Rack, "dc1", "rack-a", "Rack A", durable);
    FDR_CHECK_EQ(rack_a.code, OutcomeCode::Committed);
    check_state(fixture.registry);
    const Outcome rack_b = create_now(fixture, attempt++, DomainClass::Rack, "dc1", "rack-b", "Rack B", measured);
    FDR_CHECK_EQ(rack_b.code, OutcomeCode::Committed);
    check_state(fixture.registry);
    const Outcome feed = create_now(fixture, attempt++, DomainClass::PowerFeed, "dc1", "feed-1", "Feed 1", durable);
    FDR_CHECK_EQ(feed.code, OutcomeCode::Committed);
    check_state(fixture.registry);
    FDR_CHECK(rack_a.domain.has_value());
    FDR_CHECK(rack_b.domain.has_value());
    FDR_CHECK(feed.domain.has_value());

    // One entity in one rack and one power feed: exclusivity permits the feed.
    const EntityRef member = entity_ref(EntityClass::Switch, 8u, 3u);
    FDR_CHECK_EQ(attach_now(fixture, attempt++, *rack_a.domain, member, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-member")
                     .code,
                 OutcomeCode::Committed);
    check_state(fixture.registry);
    FDR_CHECK_EQ(attach_now(fixture, attempt++, *feed.domain, member, EvidenceClass::AdministrativeDeclaration,
                            ProvenanceSource::Cmdb, "cmdb-feed")
                     .code,
                 OutcomeCode::Committed);
    check_state(fixture.registry);

    UpdateDomainRequest rename;
    rename.attempt = attempt_with(attempt++);
    rename.authority = fixture.authority;
    rename.domain = *feed.domain;
    rename.expected_generation = FailureDomainGeneration(1u);
    rename.name = "Feed 1 (renamed)";
    FDR_CHECK_EQ(fixture.registry.update_domain(rename).code, OutcomeCode::Committed);
    check_state(fixture.registry);

    FDR_CHECK_EQ(supersede_now(fixture, attempt++, *rack_a.domain, *rack_b.domain, true).code,
                 OutcomeCode::Committed);
    check_state(fixture.registry);
    FDR_CHECK_EQ(retire_now(fixture, attempt++, *feed.domain, "removed", true).code, OutcomeCode::Committed);
    check_state(fixture.registry);

    const Outcome rack_c = create_now(fixture, attempt++, DomainClass::Rack, "dc1", "rack-c", "Rack C", durable);
    FDR_CHECK_EQ(rack_c.code, OutcomeCode::Committed);
    FDR_CHECK(rack_c.domain.has_value());
    FDR_CHECK_EQ(merge_now(fixture, attempt++, *rack_b.domain, *rack_c.domain, true).code, OutcomeCode::Committed);
    check_state(fixture.registry);

    FDR_CHECK_EQ(fixture.registry.domain_count(), std::size_t{4});
    FDR_CHECK_EQ(fixture.registry.domains_in_lifecycle(DomainLifecycle::Current).size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.domains_in_lifecycle(DomainLifecycle::Superseded).size(), std::size_t{2});
    FDR_CHECK_EQ(fixture.registry.domains_in_lifecycle(DomainLifecycle::Retired).size(), std::size_t{1});
    FDR_CHECK_EQ(fixture.registry.domains_in_scope("dc1").size(), std::size_t{4});
    FDR_CHECK_EQ(fixture.registry.domains_of_class(DomainClassRef(DomainClass::Rack)).size(), std::size_t{3});
    FDR_CHECK_EQ(fixture.registry.domains_of_class(DomainClassRef(DomainClass::PowerFeed)).size(), std::size_t{1});
    check_state(fixture.registry);
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
