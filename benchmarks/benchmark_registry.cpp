// Failure Domain Registry - the guarded registry benchmark.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every line of the table below reports *completed* operations. The clock starts
// once the workload body is entered and stops only after it has returned, and the
// count that is printed is the number of operations that actually completed. No
// figure here is a submission rate, a projection or a queue depth: the public API
// is synchronous, and a mutation that was rejected is not counted. The exact
// counts and the exact elapsed milliseconds are printed side by side so the claim
// can be checked by reading it.
//
// There are no thresholds and no performance assertions: the program measures,
// reports and exits zero. A workload that could not run at the selected scale
// prints "not attempted" plus the reason instead of a number.
//
//   fdr-benchmarks [--scale=N] [--quick] [--help]
//
//   --scale=N  number of memberships the fixture holds (default 100000)
//   --quick    --scale=1000, a smoke run
//
// The 1M membership insertion is attempted only when N >= 1000000. When it is
// attempted and does not complete, the row reports exactly how far it got.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "failure_domain_registry/failure_domain_registry.hpp"

namespace fdr = failure_domain_registry;

namespace {

#if defined(NDEBUG)
constexpr bool kReleaseBuild = true;
#else
constexpr bool kReleaseBuild = false;
#endif

/// Entries per membership publication. Batches keep the per-call bookkeeping
/// (idempotency, canonical request framing) proportional to the batch rather than
/// to the whole state.
constexpr std::size_t kBatchSize = 512;

/// Entities per rack domain in the fixture. Chosen so a domain->members lookup
/// returns a realistic but bounded number of records.
constexpr std::size_t kMembersPerRack = 100;

/// Publishers that are fenced at the end. Each one owns one process-bound domain.
constexpr std::size_t kFencePublishers = 8;

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

struct Measurement {
  std::string workload;
  /// Operations that completed, which is the only number reported.
  std::size_t completed{0};
  /// Operations the workload asked for. completed < requested is reported as a
  /// shortfall on stderr, never smoothed over.
  std::size_t requested{0};
  std::string detail;
  double milliseconds{0.0};
  bool attempted{true};
  std::string not_attempted_reason;
};

class Stopwatch {
public:
  void start() noexcept { begin_ = std::chrono::steady_clock::now(); }

  double elapsed_milliseconds() const noexcept {
    const std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(end - begin_).count();
  }

private:
  std::chrono::steady_clock::time_point begin_{};
};

struct WorkResult {
  std::size_t completed{0};
  std::size_t requested{0};
  std::string detail;
};

template <class Body>
Measurement measure(const std::string& workload, Body body) {
  Stopwatch watch;
  watch.start();
  WorkResult result = body();
  const double milliseconds = watch.elapsed_milliseconds();
  Measurement measurement;
  measurement.workload = workload;
  measurement.completed = result.completed;
  measurement.requested = result.requested;
  measurement.detail = std::move(result.detail);
  measurement.milliseconds = milliseconds;
  return measurement;
}

void report(const Measurement& measurement) {
  if (!measurement.attempted) {
    std::printf("%-36s %10s %14s  %s\n", measurement.workload.c_str(), "-", "-",
                measurement.not_attempted_reason.c_str());
    return;
  }
  std::printf("%-36s %10zu %11.3f ms  %s\n", measurement.workload.c_str(), measurement.completed,
              measurement.milliseconds, measurement.detail.c_str());
  if (measurement.completed < measurement.requested) {
    std::fprintf(stderr, "benchmark warning: %s completed %zu of %zu requested operations\n",
                 measurement.workload.c_str(), measurement.completed, measurement.requested);
  }
}

std::string size_tag(std::size_t size) {
  if (size >= 1000000 && size % 1000000 == 0) {
    return std::to_string(size / 1000000) + "m";
  }
  if (size >= 1000 && size % 1000 == 0) {
    return std::to_string(size / 1000) + "k";
  }
  return std::to_string(size);
}

// ---------------------------------------------------------------------------
// Deterministic identities
// ---------------------------------------------------------------------------

fdr::IdBytes bytes_for(std::string_view domain, std::size_t index) {
  const std::string framed = std::string("fdr/benchmark/") + std::string(domain) + "/" +
                             std::to_string(index);
  const fdr::DigestBytes digest = fdr::sha256(framed);
  fdr::IdBytes bytes{};
  for (std::size_t byte = 0; byte < bytes.size(); ++byte) {
    bytes[byte] = digest[byte];
  }
  return bytes;
}

fdr::EntityRef entity_for(std::size_t index) {
  return fdr::EntityRef(
      fdr::EntityId(fdr::EntityClass::Switch, bytes_for("entity", index)),
      fdr::EntityGeneration(1));
}

fdr::MutationAttemptId attempt_for(std::size_t index) {
  return fdr::MutationAttemptId::from_bytes(bytes_for("attempt", index));
}

fdr::PublisherId publisher_for(std::string_view label) {
  return fdr::PublisherId::from_bytes(bytes_for(std::string("publisher/") + std::string(label), 0));
}

fdr::WorkerBootId boot_for(std::string_view label) {
  return fdr::WorkerBootId::from_bytes(bytes_for(std::string("boot/") + std::string(label), 0));
}

fdr::Provenance durable_provenance(std::string_view source_identity) {
  fdr::Provenance provenance;
  provenance.source = fdr::ProvenanceSource::OperatorInventory;
  provenance.evidence = fdr::EvidenceClass::DirectAuthoritativeInfrastructure;
  provenance.truth = fdr::TruthClass::Real;
  provenance.source_identity = std::string(source_identity);
  return provenance;
}

fdr::Provenance process_bound_provenance(std::string_view source_identity) {
  fdr::Provenance provenance;
  provenance.source = fdr::ProvenanceSource::DiscoveryAgent;
  provenance.evidence = fdr::EvidenceClass::DirectHardwareController;
  provenance.truth = fdr::TruthClass::Real;
  provenance.source_identity = std::string(source_identity);
  return provenance;
}

fdr::DomainClassRef klass_of(fdr::DomainClass value) { return fdr::DomainClassRef(value); }

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

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

/// Establishes the epoch and installs one unrestricted publisher through the
/// documented bootstrap path. A failure here is fatal: without authority nothing
/// below can be measured at all.
Session bootstrap(fdr::Registry& registry, std::string_view label) {
  Session session;
  session.publisher = publisher_for(label);
  session.worker_boot = boot_for(label);
  fdr::CoordinatorEpoch epoch;
  const fdr::Outcome advanced = registry.advance_epoch(registry.epoch(), &epoch);
  if (!advanced.committed()) {
    throw std::runtime_error("cannot establish the coordinator epoch: " + advanced.message);
  }
  session.epoch = epoch;
  fdr::PublisherRegistration registration;
  registration.publisher = session.publisher;
  registration.name = std::string(label);
  registration.scope = fdr::AuthorityScope::unrestricted();
  const fdr::Outcome granted =
      registry.grant_publisher(registration, fdr::AuthorityContext{});
  if (!granted.committed()) {
    throw std::runtime_error("cannot install the bootstrap publisher grant: " + granted.message);
  }
  const fdr::Outcome attached = registry.attach_worker(
      session.publisher, session.worker_boot, session.epoch, std::string(label),
      fdr::EvidenceClass::DirectAuthoritativeInfrastructure);
  if (!attached.committed()) {
    throw std::runtime_error("cannot attach the publisher incarnation: " + attached.message);
  }
  return session;
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Scale {
  std::size_t memberships{100000};
  std::size_t lookups{2000};
  std::size_t domain_lookups{500};
  std::size_t pairs{500};
  std::size_t multi_sets{200};
  std::size_t independence_queries{200};
  std::size_t snapshots{4};
  std::size_t digests{4};
  std::size_t saves{2};
  std::size_t loads{2};
  std::size_t invalidations{16};
};

Scale scale_for(std::size_t memberships) {
  Scale scale;
  scale.memberships = memberships;
  if (memberships >= 1000000) {
    // The heavy whole-state workloads stay measurable without turning the run
    // into a multi-minute one at the 1M scale.
    scale.lookups = 1000;
    scale.domain_lookups = 250;
    scale.pairs = 200;
    scale.multi_sets = 100;
    scale.independence_queries = 100;
    scale.snapshots = 2;
    scale.digests = 1;
    scale.saves = 1;
    scale.loads = 1;
    scale.invalidations = 8;
  } else if (memberships <= 10000) {
    scale.lookups = 500;
    scale.domain_lookups = 200;
    scale.pairs = 200;
    scale.multi_sets = 100;
    scale.independence_queries = 100;
    scale.snapshots = 4;
    scale.digests = 4;
    scale.saves = 2;
    scale.loads = 2;
    scale.invalidations = 32;
  }
  return scale;
}

struct Fixture {
  std::unique_ptr<fdr::Registry> registry;
  Session session;
  /// The two measured setup rows. Everything else in the fixture is setup cost
  /// and is reported once, separately, as the total fixture build time.
  Measurement domain_creation;
  Measurement membership_insertion;
  std::vector<fdr::FailureDomainId> racks;
  std::vector<fdr::FailureDomainId> pdus;
  std::vector<Session> fencers;
  std::size_t entities{0};
  std::size_t memberships{0};
  std::size_t attempt_counter{0};
  /// False when the membership insertion stopped early, so the workloads that
  /// need the complete fixture are not attempted.
  bool complete{true};
};

std::size_t racks_for(std::size_t entities) {
  return std::max<std::size_t>(1, entities / kMembersPerRack);
}

/// Builds the registry the measured workloads run against. Everything here is
/// setup: the domain creation and the membership insertion are the only two
/// steps whose cost is reported, and they are reported by the caller.
std::unique_ptr<Fixture> make_fixture(const Scale& scale) {
  auto fixture = std::make_unique<Fixture>();
  fixture->registry = std::make_unique<fdr::Registry>();
  fixture->session = bootstrap(*fixture->registry, "benchmark-operator");
  fixture->entities = scale.memberships / 2;
  fixture->memberships = fixture->entities * 2;

  const std::size_t rack_count = racks_for(fixture->entities);
  const std::size_t pdu_count = std::max<std::size_t>(1, rack_count / 4);
  fixture->racks.reserve(rack_count);
  fixture->pdus.reserve(pdu_count);

  // --- measured: domain creation -------------------------------------------
  fixture->domain_creation = measure("domain_create_" + size_tag(scale.memberships), [&] {
    WorkResult result;
    result.requested = rack_count + pdu_count;
    for (std::size_t index = 0; index < rack_count; ++index) {
      fdr::CreateDomainRequest request;
      request.attempt = fdr::MutationAttempt{attempt_for(fixture->attempt_counter++),
                                             fdr::RequestDigest{}};
      request.authority = fixture->session.authority();
      request.domain_class = klass_of(fdr::DomainClass::Rack);
      request.administrative_scope = "bench";
      request.identity_key = "bench-rack-" + std::to_string(index);
      request.name = "bench rack " + std::to_string(index);
      request.provenance = durable_provenance("benchmark/rack/" + std::to_string(index));
      const fdr::Outcome outcome = fixture->registry->create_domain(request);
      if (!outcome.succeeded()) {
        result.detail = "first failure: " + std::string(fdr::to_string(outcome.code));
        return result;
      }
      fixture->racks.push_back(fdr::domain_id_for("bench", request.domain_class,
                                                  request.identity_key));
      ++result.completed;
    }
    for (std::size_t index = 0; index < pdu_count; ++index) {
      fdr::CreateDomainRequest request;
      request.attempt = fdr::MutationAttempt{attempt_for(fixture->attempt_counter++),
                                             fdr::RequestDigest{}};
      request.authority = fixture->session.authority();
      request.domain_class = klass_of(fdr::DomainClass::Pdu);
      request.administrative_scope = "bench";
      request.identity_key = "bench-pdu-" + std::to_string(index);
      request.name = "bench pdu " + std::to_string(index);
      request.provenance = durable_provenance("benchmark/pdu/" + std::to_string(index));
      const fdr::Outcome outcome = fixture->registry->create_domain(request);
      if (!outcome.succeeded()) {
        result.detail = "first failure: " + std::string(fdr::to_string(outcome.code));
        return result;
      }
      fixture->pdus.push_back(fdr::domain_id_for("bench", request.domain_class,
                                                 request.identity_key));
      ++result.completed;
    }
    result.detail = std::to_string(result.completed) + " committed domain creations (" +
                    std::to_string(rack_count) + " racks, " + std::to_string(pdu_count) + " pdus)";
    return result;
  });

  // Coverage is what makes an independence answer a proof rather than a guess,
  // so the fixture declares the two classes it classifies as complete.
  for (const fdr::DomainClass value : {fdr::DomainClass::Rack, fdr::DomainClass::Pdu}) {
    fdr::DeclareCoverageRequest request;
    request.attempt = fdr::MutationAttempt{attempt_for(fixture->attempt_counter++),
                                           fdr::RequestDigest{}};
    request.authority = fixture->session.authority();
    request.administrative_scope = "bench";
    request.domain_class = klass_of(value);
    request.state = fdr::CoverageState::Complete;
    request.provenance = durable_provenance("benchmark/coverage");
    const fdr::Outcome outcome = fixture->registry->declare_coverage(request);
    if (!outcome.succeeded()) {
      throw std::runtime_error("cannot declare benchmark coverage: " + outcome.message);
    }
  }

  // --- measured: membership insertion --------------------------------------
  const std::size_t batches = (fixture->memberships + kBatchSize - 1) / kBatchSize;
  fixture->membership_insertion = measure("membership_insert_" + size_tag(scale.memberships), [&] {
    WorkResult result;
    result.requested = fixture->memberships;
    for (std::size_t batch = 0; batch < batches; ++batch) {
      const std::size_t first = batch * kBatchSize;
      const std::size_t last = std::min(first + kBatchSize, fixture->memberships);
      fdr::MembershipBatchRequest request;
      request.attempt = fdr::MutationAttempt{attempt_for(fixture->attempt_counter++),
                                             fdr::RequestDigest{}};
      request.authority = fixture->session.authority();
      request.mode = fdr::PublicationMode::Incremental;
      request.entries.reserve(last - first);
      for (std::size_t index = first; index < last; ++index) {
        const std::size_t entity = index / 2;
        fdr::MembershipBatchEntry entry;
        entry.member = entity_for(entity);
        if (index % 2 == 0) {
          entry.domain = fixture->racks[entity / kMembersPerRack];
          entry.role = fdr::MembershipRole::Containment;
        } else {
          entry.domain = fixture->pdus[(entity / kMembersPerRack) % pdu_count];
          entry.role = fdr::MembershipRole::SharedRisk;
        }
        entry.kind = fdr::MembershipKind::Direct;
        entry.dependency = fdr::DependencySemantics::AnyDependencyFailureAffectsMember;
        entry.provenance = durable_provenance("benchmark/member/" + std::to_string(entity));
        request.entries.push_back(std::move(entry));
      }
      const fdr::Outcome outcome = fixture->registry->publish_memberships(request);
      if (!outcome.succeeded()) {
        result.detail = "stopped after " + std::to_string(result.completed) + " insertions: " +
                        std::string(fdr::to_string(outcome.code)) + " - " + outcome.message;
        return result;
      }
      result.completed += last - first;
    }
    result.detail = std::to_string(result.completed) + " committed insertions in " +
                    std::to_string(batches) + " publications of up to " +
                    std::to_string(kBatchSize) + " entries";
    return result;
  });
  if (fixture->membership_insertion.completed != fixture->membership_insertion.requested) {
    // The insertion stopped early. The row above already reports the count that
    // really completed and why it stopped; nothing is invented, and the workloads
    // that need the complete fixture are simply not attempted.
    fixture->membership_insertion.detail =
        "not attempted in full: " + std::to_string(fixture->membership_insertion.completed) +
        " of " + std::to_string(fixture->membership_insertion.requested) + " insertions (" +
        fixture->membership_insertion.detail + ")";
    fixture->complete = false;
    return fixture;
  }

  // --- unmeasured: publishers that the fencing workload will fence ----------
  for (std::size_t index = 0; index < kFencePublishers; ++index) {
    const std::string label = "benchmark-fencer-" + std::to_string(index);
    Session fencer;
    fencer.publisher = publisher_for(label);
    fencer.worker_boot = boot_for(label);
    fencer.epoch = fixture->session.epoch;
    fdr::PublisherRegistration registration;
    registration.publisher = fencer.publisher;
    registration.name = label;
    registration.scope = fdr::AuthorityScope::unrestricted();
    const fdr::Outcome granted =
        fixture->registry->grant_publisher(registration, fixture->session.authority());
    if (!granted.committed()) {
      throw std::runtime_error("cannot grant a fence publisher: " + granted.message);
    }
    const fdr::Outcome attached = fixture->registry->attach_worker(
        fencer.publisher, fencer.worker_boot, fencer.epoch, label,
        fdr::EvidenceClass::DirectAuthoritativeInfrastructure);
    if (!attached.committed()) {
      throw std::runtime_error("cannot attach a fence publisher: " + attached.message);
    }
    fdr::CreateDomainRequest domain;
    domain.attempt = fdr::MutationAttempt{attempt_for(fixture->attempt_counter++),
                                          fdr::RequestDigest{}};
    domain.authority = fencer.authority();
    domain.domain_class = klass_of(fdr::DomainClass::Rack);
    domain.administrative_scope = "bench";
    domain.identity_key = "bench-fenced-rack-" + std::to_string(index);
    domain.name = "bench fenced rack " + std::to_string(index);
    domain.provenance = process_bound_provenance("benchmark/fenced/" + std::to_string(index));
    const fdr::Outcome created = fixture->registry->create_domain(domain);
    if (!created.committed()) {
      throw std::runtime_error("cannot create a fence publisher's domain: " + created.message);
    }
    fdr::AttachMemberRequest member;
    member.attempt = fdr::MutationAttempt{attempt_for(fixture->attempt_counter++),
                                          fdr::RequestDigest{}};
    member.authority = fencer.authority();
    member.domain = fdr::domain_id_for("bench", domain.domain_class, domain.identity_key);
    member.member = entity_for(fixture->entities + index);
    member.provenance = process_bound_provenance("benchmark/fenced/member/" + std::to_string(index));
    const fdr::Outcome attached_member = fixture->registry->attach_member(member);
    if (!attached_member.committed()) {
      throw std::runtime_error("cannot attach a fence publisher's member: " +
                               attached_member.message);
    }
    fixture->fencers.push_back(fencer);
  }
  return fixture;
}

// ---------------------------------------------------------------------------
// Workloads
// ---------------------------------------------------------------------------

Measurement benchmark_entity_domains(const Fixture& fixture, const Scale& scale) {
  return measure("entity_to_domains_lookup", [&] {
    WorkResult result;
    result.requested = scale.lookups;
    std::size_t memberships_seen = 0;
    for (std::size_t index = 0; index < scale.lookups; ++index) {
      const std::size_t entity = (index * 7919u) % fixture.entities;
      const std::vector<fdr::Membership> found =
          fixture.registry->memberships_of(entity_for(entity).id());
      if (!found.empty()) {
        ++result.completed;
        memberships_seen += found.size();
      }
    }
    result.detail = std::to_string(result.completed) + " lookups returned memberships (" +
                    std::to_string(memberships_seen) + " membership records in total)";
    return result;
  });
}

Measurement benchmark_domain_members(const Fixture& fixture, const Scale& scale) {
  return measure("domain_to_members_lookup", [&] {
    WorkResult result;
    result.requested = scale.domain_lookups;
    std::size_t members_seen = 0;
    for (std::size_t index = 0; index < scale.domain_lookups; ++index) {
      const fdr::FailureDomainId& domain = fixture.racks[index % fixture.racks.size()];
      const std::vector<fdr::Membership> found = fixture.registry->members_of(domain);
      if (!found.empty()) {
        ++result.completed;
        members_seen += found.size();
      }
    }
    result.detail = std::to_string(result.completed) + " lookups returned members (" +
                    std::to_string(members_seen) + " membership records in total)";
    return result;
  });
}

Measurement benchmark_pairwise_overlap(const Fixture& fixture, const Scale& scale) {
  return measure("overlap_pairwise", [&] {
    WorkResult result;
    result.requested = scale.pairs;
    std::size_t shared_total = 0;
    std::size_t shared_answers = 0;
    for (std::size_t index = 0; index < scale.pairs; ++index) {
      const std::size_t rack = index % fixture.racks.size();
      const std::size_t first = rack * kMembersPerRack;
      const fdr::EntityId left = entity_for(first).id();
      const fdr::EntityId right = entity_for(first + 1).id();
      const fdr::OverlapResult overlap = fixture.registry->overlap(left, right);
      ++result.completed;
      shared_total += overlap.shared.size();
      if (overlap.state == fdr::IndependenceState::SharedDomain) {
        ++shared_answers;
      }
    }
    result.detail = std::to_string(shared_answers) + " SHARED_DOMAIN answers, " +
                    std::to_string(shared_total) + " shared domains in total";
    return result;
  });
}

Measurement benchmark_multi_overlap(const Fixture& fixture, const Scale& scale) {
  return measure("overlap_multi_set_4", [&] {
    WorkResult result;
    result.requested = scale.multi_sets;
    std::size_t shared_total = 0;
    for (std::size_t index = 0; index < scale.multi_sets; ++index) {
      const std::size_t rack = index % fixture.racks.size();
      const std::size_t first = rack * kMembersPerRack;
      std::vector<fdr::EntityId> entities;
      entities.reserve(4);
      for (std::size_t offset = 0; offset < 4; ++offset) {
        entities.push_back(entity_for(first + offset).id());
      }
      const fdr::OverlapResult overlap = fixture.registry->overlap(entities);
      ++result.completed;
      shared_total += overlap.shared.size();
    }
    result.detail = std::to_string(result.completed) + " four-entity queries, " +
                    std::to_string(shared_total) + " shared domains in total";
    return result;
  });
}

/// Groups of four entities that share no rack and no PDU domain, built outside
/// the clock. Consecutive rack groups map to different PDU domains because the
/// fixture assigns racks to PDUs in blocks.
std::vector<std::vector<fdr::EntityId>> independent_quadruples(const Fixture& fixture) {
  std::vector<std::vector<fdr::EntityId>> quads;
  const std::size_t groups = fixture.racks.size() / kMembersPerRack;
  for (std::size_t group = 0; group + 4 <= groups; ++group) {
    std::vector<fdr::EntityId> entities;
    entities.reserve(4);
    for (std::size_t offset = 0; offset < 4; ++offset) {
      entities.push_back(entity_for((group + offset) * kMembersPerRack).id());
    }
    quads.push_back(std::move(entities));
  }
  if (quads.empty()) {
    // Too small a fixture to hold four mutually disjoint entities; the query is
    // still run and whatever it answers is what gets reported.
    std::vector<fdr::EntityId> fallback;
    for (std::size_t offset = 0; offset < 4 && offset < fixture.racks.size(); ++offset) {
      fallback.push_back(entity_for(offset * kMembersPerRack).id());
    }
    quads.push_back(std::move(fallback));
  }
  return quads;
}

Measurement benchmark_independence(const Fixture& fixture, const Scale& scale) {
  const std::vector<fdr::DomainClassRef> classes{klass_of(fdr::DomainClass::Rack),
                                                 klass_of(fdr::DomainClass::Pdu)};
  const std::vector<std::vector<fdr::EntityId>> quads = independent_quadruples(fixture);
  return measure("independence_query_4", [&] {
    WorkResult result;
    result.requested = scale.independence_queries;
    std::size_t independent = 0;
    for (std::size_t index = 0; index < scale.independence_queries; ++index) {
      const fdr::IndependenceResult answer =
          fixture.registry->independence(quads[index % quads.size()], classes);
      ++result.completed;
      if (answer.proven_independent()) {
        ++independent;
      }
    }
    result.detail = std::to_string(independent) + " PROVEN_INDEPENDENT answers over " +
                    std::to_string(classes.size()) +
                    " addressed classes declared completely covered";
    return result;
  });
}

Measurement benchmark_snapshot(const Fixture& fixture, const Scale& scale) {
  return measure("snapshot", [&] {
    WorkResult result;
    result.requested = scale.snapshots;
    std::size_t domains = 0;
    std::size_t memberships = 0;
    for (std::size_t index = 0; index < scale.snapshots; ++index) {
      const fdr::Snapshot snapshot = fixture.registry->snapshot("benchmark");
      domains = snapshot.domains.size();
      memberships = snapshot.memberships.size();
      if (domains == fixture.registry->domain_count() &&
          memberships == fixture.registry->membership_count()) {
        ++result.completed;
      }
    }
    result.detail = "snapshots of " + std::to_string(domains) + " domains and " +
                    std::to_string(memberships) + " memberships";
    return result;
  });
}

Measurement benchmark_state_digest(const Fixture& fixture, const Scale& scale) {
  return measure("state_digest", [&] {
    WorkResult result;
    result.requested = scale.digests;
    fdr::StateDigest digest;
    for (std::size_t index = 0; index < scale.digests; ++index) {
      digest = fixture.registry->state_digest();
      if (!digest.is_null()) {
        ++result.completed;
      }
    }
    result.detail = "digest " + digest.to_string();
    return result;
  });
}

std::vector<Measurement> benchmark_persistence(Fixture& fixture, const Scale& scale,
                                               const std::filesystem::path& path) {
  std::vector<Measurement> results;
  fdr::PersistenceConfig config;
  config.path = path.string();
  config.durable = true;
  config.atomic = true;

  results.push_back(measure("persistence_save", [&] {
    WorkResult result;
    result.requested = scale.saves;
    std::size_t bytes = 0;
    for (std::size_t index = 0; index < scale.saves; ++index) {
      const fdr::Outcome outcome = fixture.registry->save(config);
      if (outcome.committed()) {
        ++result.completed;
        std::error_code error;
        const std::uintmax_t size = std::filesystem::file_size(path, error);
        if (!error) {
          bytes = static_cast<std::size_t>(size);
        }
      } else {
        result.detail = "first failure: " + std::string(fdr::to_string(outcome.code)) + " - " +
                        outcome.message;
        return result;
      }
    }
    result.detail = "images of " + std::to_string(bytes) + " bytes";
    return result;
  }));

  results.push_back(measure("persistence_load", [&] {
    WorkResult result;
    result.requested = scale.loads;
    std::size_t domains = 0;
    std::size_t memberships = 0;
    for (std::size_t index = 0; index < scale.loads; ++index) {
      fdr::Registry recovered;
      const fdr::Outcome outcome = recovered.load(config);
      if (!outcome.committed()) {
        result.detail = "first failure: " + std::string(fdr::to_string(outcome.code)) + " - " +
                        outcome.message;
        return result;
      }
      ++result.completed;
      domains = recovered.domain_count();
      memberships = recovered.membership_count();
    }
    result.detail = "each load restored " + std::to_string(domains) + " domains and " +
                    std::to_string(memberships) + " memberships with no live session";
    return result;
  }));
  return results;
}

Measurement benchmark_mass_invalidation(Fixture& fixture, const Scale& scale) {
  const std::size_t before =
      fixture.registry->memberships_in_lifecycle(fdr::MembershipLifecycle::RevalidationRequired)
          .size();
  Measurement measurement = measure("mass_invalidation", [&] {
    WorkResult result;
    result.requested = scale.invalidations;
    for (std::size_t index = 0; index < scale.invalidations; ++index) {
      fdr::EntityInvalidationRequest request;
      request.attempt = fdr::MutationAttempt{attempt_for(fixture.attempt_counter++),
                                             fdr::RequestDigest{}};
      request.authority = fixture.session.authority();
      request.entity = entity_for(index).id();
      request.superseded_generation = fdr::EntityGeneration(1);
      request.successor_class = fdr::EntityClass::Switch;
      request.successor_id = entity_for(index).id().bytes();
      request.successor_generation = fdr::EntityGeneration(2);
      request.reason = "benchmark replacement";
      const fdr::Outcome outcome = fixture.registry->invalidate_entity(request);
      if (outcome.committed()) {
        ++result.completed;
      } else {
        result.detail = "first failure: " + std::string(fdr::to_string(outcome.code));
        return result;
      }
    }
    result.detail = "entity generations invalidated, each demoting its own memberships";
    return result;
  });
  const std::size_t after =
      fixture.registry->memberships_in_lifecycle(fdr::MembershipLifecycle::RevalidationRequired)
          .size();
  measurement.detail = std::to_string(after > before ? after - before : 0) +
                       " memberships demoted to REVALIDATION_REQUIRED";
  return measurement;
}

std::size_t fenced_incarnations(const Fixture& fixture) {
  std::size_t fences = 0;
  for (const Session& fencer : fixture.fencers) {
    if (!fixture.registry->is_worker_live(fencer.publisher, fencer.worker_boot)) {
      ++fences;
    }
  }
  return fences;
}

Measurement benchmark_publisher_fencing(Fixture& fixture) {
  const std::size_t before =
      fixture.registry->domains_in_lifecycle(fdr::DomainLifecycle::RevalidationRequired).size();
  Measurement measurement = measure("publisher_fencing", [&] {
    WorkResult result;
    result.requested = fixture.fencers.size();
    for (const Session& fencer : fixture.fencers) {
      const fdr::Outcome outcome = fixture.registry->fence_worker(
          fencer.publisher, fencer.worker_boot, fdr::FenceReason::SessionLost, fencer.epoch);
      if (outcome.committed()) {
        ++result.completed;
      }
    }
    result.detail = "incarnations fenced, each losing its process-bound evidence";
    return result;
  });
  const std::size_t after =
      fixture.registry->domains_in_lifecycle(fdr::DomainLifecycle::RevalidationRequired).size();
  measurement.detail = std::to_string(fenced_incarnations(fixture)) + " incarnations no longer live; " +
                       std::to_string(after > before ? after - before : 0) +
                       " process-bound domains demoted";
  return measurement;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Runs the workloads of one scale. Returns false when the fixture itself was
/// incomplete, in which case nothing beyond the two setup rows is attempted.
bool run_workloads(const Scale& scale, const std::filesystem::path& state_path,
                   const std::string& tag, bool with_queries) {
  Stopwatch build_watch;
  build_watch.start();
  std::unique_ptr<Fixture> fixture = make_fixture(scale);
  const double build_milliseconds = build_watch.elapsed_milliseconds();
  std::printf("fixture %s: %zu domains, %zu memberships, %zu publishers (%0.3f ms of fixture "
              "build, including the two rows below)\n",
              tag.c_str(), fixture->registry->domain_count(),
              fixture->registry->membership_count(), fixture->registry->publishers().size(),
              build_milliseconds);
  report(fixture->domain_creation);
  report(fixture->membership_insertion);
  if (!fixture->complete) {
    std::fprintf(stderr,
                 "benchmark: the %s fixture is incomplete; the remaining %s workloads were not "
                 "attempted\n",
                 tag.c_str(), tag.c_str());
    return false;
  }
  if (!with_queries) {
    return true;
  }

  report(benchmark_entity_domains(*fixture, scale));
  report(benchmark_domain_members(*fixture, scale));
  report(benchmark_pairwise_overlap(*fixture, scale));
  report(benchmark_multi_overlap(*fixture, scale));
  report(benchmark_independence(*fixture, scale));
  report(benchmark_snapshot(*fixture, scale));
  report(benchmark_state_digest(*fixture, scale));
  for (const Measurement& measurement : benchmark_persistence(*fixture, scale, state_path)) {
    report(measurement);
  }
  report(benchmark_mass_invalidation(*fixture, scale));
  report(benchmark_publisher_fencing(*fixture));
  return true;
}

} // namespace

int main(int argc, char** argv) {
  std::size_t membership_scale = 100000;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument = argv[index] != nullptr ? std::string_view(argv[index])
                                                             : std::string_view();
    if (argument == "--quick") {
      membership_scale = 1000;
    } else if (argument == "--help" || argument == "-h") {
      std::printf("usage: fdr-benchmarks [--scale=N] [--quick]\n"
                  "  --scale=N  memberships in the fixture (default 100000;\n"
                  "             the 1M insertion is attempted when N >= 1000000)\n"
                  "  --quick    --scale=1000\n"
                  "Every row reports completed operations and the exact elapsed milliseconds.\n");
      return 0;
    } else if (argument.rfind("--scale=", 0) == 0) {
      const std::string text(argument.substr(8));
      char* end = nullptr;
      const unsigned long long parsed = std::strtoull(text.c_str(), &end, 10);
      if (end == nullptr || *end != '\0' || parsed == 0) {
        std::fprintf(stderr, "benchmark: ignoring unusable --scale value '%s'\n", text.c_str());
      } else {
        // An even membership count keeps the fixture at exactly two memberships
        // per entity, so the reported count is the count that was asked for.
        membership_scale = static_cast<std::size_t>(parsed) + (parsed % 2);
      }
    } else if (!argument.empty()) {
      std::fprintf(stderr, "benchmark: ignoring unknown argument '%s'\n",
                   std::string(argument).c_str());
    }
  }

  std::printf("failure_domain_registry benchmarks: %s build, %zu memberships requested\n",
              kReleaseBuild ? "release" : "debug", membership_scale);
  std::printf("the table counts completed operations only; a rejected operation is not counted\n");
  std::printf("%-36s %10s %14s  %s\n", "workload", "completed", "elapsed", "what completed");

  const std::filesystem::path state_path =
      std::filesystem::temp_directory_path() / "fdr-benchmark-state.bin";
  std::error_code ignored;
  std::filesystem::remove(state_path, ignored);

  try {
    if (membership_scale >= 1000000) {
      // The 100k reference point is measured first, on its own fixture, so that a
      // run at the 1M scale still reports both insertion sizes.
      (void)run_workloads(scale_for(100000), state_path, "100k reference", false);
    }
    const Scale scale = scale_for(membership_scale);
    (void)run_workloads(scale, state_path, size_tag(scale.memberships), true);
    if (scale.memberships < 1000000) {
      Measurement not_attempted;
      not_attempted.workload = "membership_insert_1m";
      not_attempted.attempted = false;
      not_attempted.not_attempted_reason =
          "not attempted at " + size_tag(scale.memberships) + " memberships; pass --scale=1000000";
      report(not_attempted);
    }
  } catch (const std::bad_alloc&) {
    Measurement not_attempted;
    not_attempted.workload = "membership_insert_1m";
    not_attempted.attempted = false;
    not_attempted.not_attempted_reason =
        "not attempted: the process ran out of memory before the fixture was built";
    report(not_attempted);
    std::fprintf(stderr, "benchmark: out of memory at this scale\n");
  } catch (const std::exception& error) {
    std::fprintf(stderr, "benchmark: %s\n", error.what());
    std::filesystem::remove(state_path, ignored);
    return 1;
  }

  std::filesystem::remove(state_path, ignored);
  return 0;
}
