// Failure Domain Registry - downstream package consumer.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Built as a standalone project against an installed FailureDomainRegistry
// package: it includes the public headers by their installed names, links the
// exported target SummonSoftwareLabs::FailureDomainRegistry, creates failure
// domains, attaches members and runs an overlap query, an independence query and
// a coverage query. The output is deterministic and the program returns 0.

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <failure_domain_registry/digest.hpp>
#include <failure_domain_registry/registry.hpp>
#include <failure_domain_registry/version.hpp>

namespace fdr = failure_domain_registry;

namespace {

class ConsumerError : public std::runtime_error {
public:
  explicit ConsumerError(const std::string& message) : std::runtime_error(message) {}
};

void require(bool condition, const std::string& message) {
  if (!condition) {
    throw ConsumerError(message);
  }
}

/// A downstream project owns its own identity source; this one derives stable
/// identifiers from a label with the public SHA-256 so the output is the same on
/// every run.
fdr::IdBytes bytes_for(std::string_view label) {
  const std::string framed = std::string("consumer/") + std::string(label);
  const fdr::DigestBytes digest = fdr::sha256(framed);
  fdr::IdBytes bytes{};
  bool all_zero = true;
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    bytes[index] = digest[index];
    if (bytes[index] != 0) {
      all_zero = false;
    }
  }
  if (all_zero) {
    bytes[0] = 0xC1u;
  }
  return bytes;
}

fdr::EntityId entity_for(std::string_view label) {
  return fdr::EntityId(fdr::EntityClass::Switch, bytes_for(label));
}

fdr::EntityRef member_for(std::string_view label) {
  return fdr::EntityRef(entity_for(label), fdr::EntityGeneration(1));
}

fdr::Provenance provenance_for(std::string_view source_identity) {
  fdr::Provenance provenance;
  provenance.source = fdr::ProvenanceSource::OperatorInventory;
  provenance.evidence = fdr::EvidenceClass::DirectAuthoritativeInfrastructure;
  provenance.truth = fdr::TruthClass::Real;
  provenance.source_identity = std::string(source_identity);
  return provenance;
}

fdr::DomainClassRef class_of(fdr::DomainClass value) { return fdr::DomainClassRef(value); }

std::string_view state_text(fdr::IndependenceState state) { return fdr::to_string(state); }

/// One attached publisher, obtained through the documented bootstrap path.
struct Session {
  fdr::PublisherId publisher{};
  fdr::WorkerBootId worker_boot{};
  fdr::CoordinatorEpoch epoch{};

  fdr::AuthorityContext authority() const {
    fdr::AuthorityContext context;
    context.publisher = publisher;
    context.worker_boot = worker_boot;
    context.epoch = epoch;
    context.evidence = fdr::EvidenceClass::DirectAuthoritativeInfrastructure;
    return context;
  }
};

Session bootstrap(fdr::Registry& registry) {
  Session session;
  session.publisher = fdr::PublisherId::from_bytes(bytes_for("publisher"));
  session.worker_boot = fdr::WorkerBootId::from_bytes(bytes_for("boot"));
  fdr::CoordinatorEpoch epoch;
  require(registry.advance_epoch(registry.epoch(), &epoch).committed(),
          "cannot establish the coordinator epoch");
  session.epoch = epoch;
  fdr::PublisherRegistration registration;
  registration.publisher = session.publisher;
  registration.name = "consumer";
  registration.scope = fdr::AuthorityScope::unrestricted();
  require(registry.grant_publisher(registration, fdr::AuthorityContext{}).committed(),
          "cannot install the bootstrap publisher grant");
  require(registry.attach_worker(session.publisher, session.worker_boot, session.epoch, "consumer",
                                 fdr::EvidenceClass::DirectAuthoritativeInfrastructure)
              .committed(),
          "cannot attach the publisher incarnation");
  return session;
}

std::size_t attempt_counter = 1;

fdr::MutationAttemptId next_attempt() {
  fdr::IdBytes bytes{};
  bytes[0] = static_cast<std::uint8_t>(attempt_counter & 0xFFu);
  bytes[1] = static_cast<std::uint8_t>((attempt_counter >> 8) & 0xFFu);
  bytes[15] = 0x5Au;
  ++attempt_counter;
  return fdr::MutationAttemptId::from_bytes(bytes);
}

fdr::FailureDomainId create_domain(fdr::Registry& registry, const Session& session,
                                   const fdr::DomainClassRef& domain_class, std::string_view key,
                                   std::string_view name) {
  fdr::CreateDomainRequest request;
  request.attempt = fdr::MutationAttempt{next_attempt(), fdr::RequestDigest{}};
  request.authority = session.authority();
  request.domain_class = domain_class;
  request.administrative_scope = "dc1";
  request.identity_key = std::string(key);
  request.name = std::string(name);
  request.provenance = provenance_for(std::string("consumer/") + std::string(key));
  const fdr::Outcome outcome = registry.create_domain(request);
  require(outcome.succeeded(), "cannot create domain " + std::string(key) + ": " + outcome.message);
  return fdr::domain_id_for("dc1", domain_class, key);
}

void attach(fdr::Registry& registry, const Session& session, const fdr::FailureDomainId& domain,
            const fdr::EntityRef& member) {
  fdr::AttachMemberRequest request;
  request.attempt = fdr::MutationAttempt{next_attempt(), fdr::RequestDigest{}};
  request.authority = session.authority();
  request.domain = domain;
  request.member = member;
  request.kind = fdr::MembershipKind::Direct;
  request.role = fdr::MembershipRole::SharedRisk;
  request.dependency = fdr::DependencySemantics::AnyDependencyFailureAffectsMember;
  request.provenance = provenance_for("consumer/member/" + member.to_string());
  const fdr::Outcome outcome = registry.attach_member(request);
  require(outcome.succeeded(), "cannot attach " + member.to_string() + ": " + outcome.message);
}

void declare_complete_coverage(fdr::Registry& registry, const Session& session,
                               const fdr::DomainClassRef& domain_class) {
  fdr::DeclareCoverageRequest request;
  request.attempt = fdr::MutationAttempt{next_attempt(), fdr::RequestDigest{}};
  request.authority = session.authority();
  request.administrative_scope = "dc1";
  request.domain_class = domain_class;
  request.state = fdr::CoverageState::Complete;
  request.provenance = provenance_for("consumer/coverage");
  const fdr::Outcome outcome = registry.declare_coverage(request);
  require(outcome.succeeded(), "cannot declare coverage: " + outcome.message);
}

void print_coverage(const std::vector<fdr::DomainClassRef>& classes,
                    const fdr::CoverageReport& report) {
  std::cout << "coverage query for scope dc1:\n";
  for (const fdr::CoverageEntry& entry : report.entries) {
    std::cout << "  class=" << entry.domain_class.to_string()
              << " state=" << fdr::to_string(entry.state)
              << " declared=" << (entry.declared ? "yes" : "no")
              << " evidence=" << fdr::to_string(entry.evidence) << "\n";
  }
  std::cout << "  complete-for-all=" << (report.complete_for_all ? "yes" : "no")
            << " has-partial=" << (report.has_partial ? "yes" : "no")
            << " has-unknown=" << (report.has_unknown ? "yes" : "no")
            << " addressed-classes=" << classes.size() << "\n";
}

} // namespace

int main() {
  std::cout << "failure_domain_registry " << fdr::version_string() << "\n";
  try {
    fdr::Registry registry;
    const Session session = bootstrap(registry);

    const fdr::DomainClassRef rack = class_of(fdr::DomainClass::Rack);
    const fdr::DomainClassRef pdu = class_of(fdr::DomainClass::Pdu);
    const fdr::FailureDomainId rack_r7 = create_domain(registry, session, rack, "rack-r7", "Rack R7");
    const fdr::FailureDomainId rack_r8 = create_domain(registry, session, rack, "rack-r8", "Rack R8");
    const fdr::FailureDomainId pdu_p3 = create_domain(registry, session, pdu, "pdu-p3-a", "PDU P3 feed A");

    const fdr::EntityRef leaf01 = member_for("leaf-01");
    const fdr::EntityRef leaf02 = member_for("leaf-02");
    const fdr::EntityRef leaf03 = member_for("leaf-03");
    attach(registry, session, rack_r7, leaf01);
    attach(registry, session, rack_r7, leaf02);
    attach(registry, session, pdu_p3, leaf01);
    attach(registry, session, pdu_p3, leaf02);
    attach(registry, session, rack_r8, leaf03);
    std::cout << "domains=" << registry.domain_count()
              << " memberships=" << registry.membership_count()
              << " live-sessions=" << registry.live_sessions().size() << "\n";

    // 1) Overlap: the two switches in rack R7 share a rack and a PDU feed.
    const fdr::OverlapResult overlap = registry.overlap(leaf01.id(), leaf02.id());
    std::cout << "overlap(leaf-01, leaf-02): " << state_text(overlap.state)
              << " shared=" << overlap.shared.size() << "\n";
    for (const fdr::SharedDomain& shared : overlap.shared) {
      std::cout << "  class=" << shared.domain_class.to_string()
                << " domain=" << shared.domain.to_string()
                << " members=" << shared.members.size()
                << " most-specific=" << (shared.most_specific ? "yes" : "no") << "\n";
    }
    require(overlap.state == fdr::IndependenceState::SharedDomain,
            "the two switches share failure domains");

    // 2) Coverage: nothing has been declared for the scope yet. This is the
    //    public coverage query; the independence answer below is decided from the
    //    declarations themselves, so the two are printed next to each other.
    const std::vector<fdr::DomainClassRef> classes{rack, pdu};
    print_coverage(classes, registry.coverage("dc1", classes));

    // 3) Independence before the declaration: absence of a shared domain is not
    //    yet a proof, because the classes are not declared completely classified.
    const std::vector<fdr::EntityId> far_apart{leaf01.id(), leaf03.id()};
    const fdr::IndependenceResult unknown = registry.independence(far_apart, classes);
    std::cout << "independence(leaf-01, leaf-03): " << state_text(unknown.state)
              << " shared=" << unknown.shared.size() << "\n";

    // 4) Declare both addressed classes complete for the scope and ask again.
    declare_complete_coverage(registry, session, rack);
    declare_complete_coverage(registry, session, pdu);
    print_coverage(classes, registry.coverage("dc1", classes));
    const fdr::IndependenceResult proven = registry.independence(far_apart, classes);
    std::cout << "independence(leaf-01, leaf-03): " << state_text(proven.state)
              << " shared=" << proven.shared.size() << "\n";
    require(proven.proven_independent(), "complete coverage proves the two switches independent");

    // The registry says so in words as well as in state.
    const fdr::Explanation explanation = registry.explain_independence(far_apart, classes);
    std::cout << "explanation: " << explanation.subject << " (" << explanation.steps.size()
              << " steps, complete=" << (explanation.complete ? "yes" : "no") << ")\n";
    std::cout << "state digest: " << registry.state_digest().to_string() << "\n";
    std::cout << "consumer finished\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "package consumer failed: " << error.what() << "\n";
    return 1;
  }
}
