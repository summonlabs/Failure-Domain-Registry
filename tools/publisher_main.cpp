// Failure Domain Registry - publisher process.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Usage:
//   fdr-publisher --endpoint HOST:PORT --publisher HEX --boot HEX
//                 [--label TEXT] [--evidence CLASS]
//
// The process attaches to the coordinator, then reads commands from standard
// input, one per line, writing exactly one deterministic result line per
// command:
//
//   OK <CODE> <detail>
//   ERR <CODE> <message>
//
// Commands:
//   status
//   create <class> <scope> <identity-key> [name]
//   attach <domain-id> <entity-ref>            (entity-ref is class:hex@generation)
//   publish <mode> <scope> <entity-class> <domain-id> <entity-ref> ...
//   create-domain-id <class> <scope> <identity-key>   (prints the derived id)
//   coverage <scope> <class> <COMPLETE|PARTIAL|UNKNOWN>
//   withdraw <membership-id>
//   derive
//   invalidate <class:hex> <generation>
//   members <domain-id>
//   domains <class:hex>
//   overlap <class:hex> <class:hex>
//   independence <class:hex> <class:hex> -- <class> ...
//   snapshot [scope]
//   explain <domain-id> <class:hex>
//   quit

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "failure_domain_registry/failure_domain_registry.hpp"

namespace {

using namespace failure_domain_registry;

std::vector<std::string> tokenize(const std::string& line) {
  std::vector<std::string> tokens;
  std::string current;
  for (char c : line) {
    if (c == ' ' || c == '\t') {
      if (!current.empty()) {
        tokens.push_back(current);
        current.clear();
      }
    } else {
      current.push_back(c);
    }
  }
  if (!current.empty()) {
    tokens.push_back(current);
  }
  return tokens;
}

Provenance base_provenance(const std::string& label, EvidenceClass evidence) {
  Provenance provenance;
  provenance.source = ProvenanceSource::DiscoveryAgent;
  provenance.evidence = evidence;
  provenance.truth = TruthClass::Real;
  provenance.source_identity = label;
  return provenance;
}

/// Mutation attempt ids are minted per publisher incarnation: a restarted
/// publisher is a different incarnation and must not collide with the attempt
/// space of the incarnation it replaced.
MutationAttempt attempt_for(const WorkerBootId& boot, std::size_t index) {
  std::string canonical = "fdr/publisher-cli/attempt/";
  canonical.append(boot.to_string());
  canonical.push_back('/');
  canonical.append(std::to_string(index));
  return MutationAttempt(MutationAttemptId::from_digest(sha256(canonical)), RequestDigest{});
}

} // namespace

int main(int argc, char** argv) {
  PublisherClientConfig config;
  config.label = "fdr-publisher";
  config.max_evidence = EvidenceClass::DirectHardwareController;

  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    const auto value_of = [&](const char* name) -> std::string {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "fdr-publisher: %s requires a value\n", name);
        std::exit(2);
      }
      return argv[++i];
    };
    if (argument == "--endpoint") {
      const std::optional<Endpoint> endpoint = Endpoint::parse(value_of("--endpoint"));
      if (!endpoint.has_value()) {
        std::fputs("fdr-publisher: malformed --endpoint\n", stderr);
        return 2;
      }
      config.endpoint = *endpoint;
    } else if (argument == "--publisher") {
      const std::optional<PublisherId> id = PublisherId::parse(value_of("--publisher"));
      if (!id.has_value()) {
        std::fputs("fdr-publisher: malformed --publisher\n", stderr);
        return 2;
      }
      config.publisher = *id;
    } else if (argument == "--boot") {
      const std::optional<WorkerBootId> id = WorkerBootId::parse(value_of("--boot"));
      if (!id.has_value()) {
        std::fputs("fdr-publisher: malformed --boot\n", stderr);
        return 2;
      }
      config.worker_boot = *id;
    } else if (argument == "--label") {
      config.label = value_of("--label");
    } else if (argument == "--fixed-epoch") {
      const std::optional<CoordinatorEpoch> epoch = CoordinatorEpoch::parse(value_of("--fixed-epoch"));
      if (!epoch.has_value()) {
        std::fputs("fdr-publisher: malformed --fixed-epoch\n", stderr);
        return 2;
      }
      config.epoch = *epoch;
      config.learn_epoch = false;
    } else if (argument == "--evidence") {
      const std::optional<EvidenceClass> klass = evidence_class_from_string(value_of("--evidence"));
      if (!klass.has_value()) {
        std::fputs("fdr-publisher: malformed --evidence\n", stderr);
        return 2;
      }
      config.max_evidence = *klass;
    } else {
      std::fprintf(stderr, "fdr-publisher: unknown argument '%s'\n", argument.c_str());
      return 2;
    }
  }

  const EvidenceClass evidence = config.max_evidence;
  PublisherClient client(config);
  const Outcome attached = client.connect();
  if (!attached.committed()) {
    std::printf("ERR %s %s\n", std::string(to_string(attached.code)).c_str(),
                attached.message.c_str());
    std::fflush(stdout);
    return 1;
  }
  std::printf("OK CONNECTED epoch=%s\n", client.epoch().to_string().c_str());
  std::fflush(stdout);

  std::size_t index = 0;
  std::string line;
  while (std::getline(std::cin, line)) {
    const std::vector<std::string> tokens = tokenize(line);
    if (tokens.empty() || tokens[0] == "#") {
      continue;
    }
    ++index;
    const MutationAttempt attempt = attempt_for(config.worker_boot, index);
    const std::string& command = tokens[0];
    Outcome outcome = Outcome::make(OutcomeCode::MalformedRequest, "unknown command");

    if (command == "quit") {
      break;
    } else if (command == "status") {
      std::string rendered;
      outcome = client.query_status(&rendered);
      if (outcome.succeeded()) {
        std::printf("OK STATUS %s\n", rendered.c_str());
        std::fflush(stdout);
        continue;
      }
    } else if (command == "create" && tokens.size() >= 4) {
      CreateDomainRequest request;
      request.attempt = attempt;
      request.provenance = base_provenance(config.label, evidence);
      const std::optional<DomainClassRef> klass = DomainClassRef::parse(tokens[1]);
      if (!klass.has_value()) {
        outcome = Outcome::make(OutcomeCode::MalformedRequest, "unknown domain class");
      } else {
        request.domain_class = *klass;
        request.administrative_scope = tokens[2];
        request.identity_key = tokens[3];
        if (tokens.size() >= 5) {
          request.name = tokens[4];
        }
        outcome = client.create_domain(request);
      }
    } else if (command == "create-domain-id" && tokens.size() >= 4) {
      const std::optional<DomainClassRef> klass = DomainClassRef::parse(tokens[1]);
      if (!klass.has_value()) {
        outcome = Outcome::make(OutcomeCode::MalformedRequest, "unknown domain class");
      } else {
        const FailureDomainId id = domain_id_for(tokens[2], *klass, tokens[3]);
        std::printf("OK DOMAIN-ID %s\n", id.to_string().c_str());
        std::fflush(stdout);
        continue;
      }
    } else if (command == "reattest" && tokens.size() >= 2) {
      UpdateDomainRequest request;
      request.attempt = attempt;
      request.provenance = base_provenance(config.label, evidence);
      const std::optional<FailureDomainId> domain = FailureDomainId::parse(tokens[1]);
      if (!domain.has_value()) {
        outcome = Outcome::make(OutcomeCode::MalformedRequest, "malformed domain id");
      } else {
        request.domain = *domain;
        request.transition = DomainLifecycle::Current;
        outcome = client.update_domain(request);
      }
    } else if (command == "attach" && tokens.size() >= 3) {
      AttachMemberRequest request;
      request.attempt = attempt;
      request.provenance = base_provenance(config.label, evidence);
      const std::optional<FailureDomainId> domain = FailureDomainId::parse(tokens[1]);
      const std::optional<EntityRef> member = EntityRef::parse(tokens[2]);
      if (!domain.has_value() || !member.has_value()) {
        outcome = Outcome::make(OutcomeCode::MalformedRequest, "malformed domain or member");
      } else {
        request.domain = *domain;
        request.member = *member;
        request.kind = MembershipKind::Direct;
        request.role = MembershipRole::Primary;
        request.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
        outcome = client.attach_member(request);
      }
    } else if (command == "publish" && tokens.size() >= 5) {
      MembershipBatchRequest request;
      request.attempt = attempt;
      const std::string mode = tokens[1];
      request.mode = mode == "authoritative" ? PublicationMode::Authoritative
                     : mode == "partial"     ? PublicationMode::Partial
                                             : PublicationMode::Incremental;
      request.administrative_scope = tokens[2];
      const std::optional<EntityClass> entity_class = entity_class_from_string(tokens[3]);
      if (!entity_class.has_value()) {
        outcome = Outcome::make(OutcomeCode::MalformedRequest, "unknown entity class");
      } else {
        request.authoritative_entity_class = *entity_class;
        bool ok = true;
        for (std::size_t i = 4; i + 1 < tokens.size() + 1 && i < tokens.size(); i += 2) {
          if (i + 1 >= tokens.size()) {
            ok = false;
            break;
          }
          MembershipBatchEntry entry;
          const std::optional<FailureDomainId> domain = FailureDomainId::parse(tokens[i]);
          const std::optional<EntityRef> member = EntityRef::parse(tokens[i + 1]);
          if (!domain.has_value() || !member.has_value()) {
            ok = false;
            break;
          }
          entry.domain = *domain;
          entry.member = *member;
          entry.kind = MembershipKind::Direct;
          entry.role = MembershipRole::Primary;
          entry.dependency = DependencySemantics::AnyDependencyFailureAffectsMember;
          entry.provenance = base_provenance(config.label, evidence);
          if (request.mode == PublicationMode::Authoritative) {
            if (std::find(request.authoritative_domains.begin(),
                          request.authoritative_domains.end(),
                          entry.domain) == request.authoritative_domains.end()) {
              request.authoritative_domains.push_back(entry.domain);
            }
          }
          request.entries.push_back(std::move(entry));
        }
        if (!ok) {
          outcome = Outcome::make(OutcomeCode::MalformedRequest, "malformed publication entry");
        } else {
          outcome = client.publish_memberships(request);
        }
      }
    } else if (command == "coverage" && tokens.size() >= 4) {
      DeclareCoverageRequest request;
      request.attempt = attempt;
      request.provenance = base_provenance(config.label, evidence);
      const std::optional<DomainClassRef> klass = DomainClassRef::parse(tokens[2]);
      CoverageState state = CoverageState::UnknownCoverage;
      if (tokens[3] == "COMPLETE") {
        state = CoverageState::Complete;
      } else if (tokens[3] == "PARTIAL") {
        state = CoverageState::Partial;
      }
      if (!klass.has_value()) {
        outcome = Outcome::make(OutcomeCode::MalformedRequest, "unknown domain class");
      } else {
        request.administrative_scope = tokens[1];
        request.domain_class = *klass;
        request.state = state;
        outcome = client.declare_coverage(request);
      }
    } else if (command == "withdraw" && tokens.size() >= 2) {
      WithdrawEvidenceRequest request;
      request.attempt = attempt;
      const std::optional<MembershipId> membership = MembershipId::parse(tokens[1]);
      if (!membership.has_value()) {
        outcome = Outcome::make(OutcomeCode::MalformedRequest, "malformed membership id");
      } else {
        request.membership = *membership;
        outcome = client.withdraw_evidence(request);
      }
    } else if (command == "derive") {
      DerivationRunRequest request;
      request.attempt = attempt;
      std::string rendered;
      outcome = client.run_derivation(request, &rendered);
      if (outcome.succeeded()) {
        std::printf("OK DERIVE %s\n", rendered.c_str());
        std::fflush(stdout);
        continue;
      }
    } else if (command == "invalidate" && tokens.size() >= 3) {
      EntityInvalidationRequest request;
      request.attempt = attempt;
      const std::optional<EntityId> entity = EntityId::parse(tokens[1]);
      const std::optional<EntityGeneration> generation = EntityGeneration::parse(tokens[2]);
      if (!entity.has_value() || !generation.has_value()) {
        outcome = Outcome::make(OutcomeCode::MalformedRequest, "malformed entity or generation");
      } else {
        request.entity = *entity;
        request.superseded_generation = *generation;
        outcome = client.invalidate_entity(request);
      }
    } else if (command == "members" && tokens.size() >= 2) {
      const std::optional<FailureDomainId> domain = FailureDomainId::parse(tokens[1]);
      std::string rendered;
      if (!domain.has_value()) {
        outcome = Outcome::make(OutcomeCode::MalformedRequest, "malformed domain id");
      } else {
        outcome = client.query_domain_members(*domain, &rendered);
        if (outcome.succeeded()) {
          std::printf("OK MEMBERS %s\n", rendered.c_str());
          std::fflush(stdout);
          continue;
        }
      }
    } else if (command == "domains" && tokens.size() >= 2) {
      const std::optional<EntityId> entity = EntityId::parse(tokens[1]);
      std::string rendered;
      if (!entity.has_value()) {
        outcome = Outcome::make(OutcomeCode::MalformedRequest, "malformed entity id");
      } else {
        outcome = client.query_entity_domains(*entity, &rendered);
        if (outcome.succeeded()) {
          std::printf("OK DOMAINS %s\n", rendered.c_str());
          std::fflush(stdout);
          continue;
        }
      }
    } else if (command == "overlap" && tokens.size() >= 3) {
      std::vector<EntityId> entities;
      bool ok = true;
      for (std::size_t i = 1; i < tokens.size(); ++i) {
        const std::optional<EntityId> entity = EntityId::parse(tokens[i]);
        if (!entity.has_value()) {
          ok = false;
          break;
        }
        entities.push_back(*entity);
      }
      std::string rendered;
      if (!ok) {
        outcome = Outcome::make(OutcomeCode::MalformedRequest, "malformed entity id");
      } else {
        outcome = client.query_overlap(entities, &rendered);
        if (outcome.succeeded()) {
          std::printf("OK OVERLAP %s\n", rendered.c_str());
          std::fflush(stdout);
          continue;
        }
      }
    } else if (command == "independence" && tokens.size() >= 3) {
      std::vector<EntityId> entities;
      std::vector<DomainClassRef> classes;
      bool in_classes = false;
      bool ok = true;
      for (std::size_t i = 1; i < tokens.size(); ++i) {
        if (tokens[i] == "--") {
          in_classes = true;
          continue;
        }
        if (!in_classes) {
          const std::optional<EntityId> entity = EntityId::parse(tokens[i]);
          if (!entity.has_value()) {
            ok = false;
            break;
          }
          entities.push_back(*entity);
        } else {
          const std::optional<DomainClassRef> klass = DomainClassRef::parse(tokens[i]);
          if (!klass.has_value()) {
            ok = false;
            break;
          }
          classes.push_back(*klass);
        }
      }
      std::string rendered;
      if (!ok || entities.size() < 2) {
        outcome = Outcome::make(OutcomeCode::MalformedRequest, "malformed independence query");
      } else {
        outcome = client.query_independence(entities, classes, &rendered);
        if (outcome.succeeded()) {
          std::printf("OK INDEPENDENCE %s\n", rendered.c_str());
          std::fflush(stdout);
          continue;
        }
      }
    } else if (command == "snapshot") {
      std::string rendered;
      outcome = client.query_snapshot(tokens.size() >= 2 ? tokens[1] : std::string(), &rendered);
      if (outcome.succeeded()) {
        std::printf("OK SNAPSHOT %s\n", rendered.c_str());
        std::fflush(stdout);
        continue;
      }
    } else if (command == "explain" && tokens.size() >= 3) {
      const std::optional<FailureDomainId> domain = FailureDomainId::parse(tokens[1]);
      const std::optional<EntityId> entity = EntityId::parse(tokens[2]);
      std::string rendered;
      if (!domain.has_value() || !entity.has_value()) {
        outcome = Outcome::make(OutcomeCode::MalformedRequest, "malformed explanation subject");
      } else {
        outcome = client.query_explain_membership(*domain, *entity, &rendered);
        if (outcome.succeeded()) {
          std::printf("OK EXPLAIN %s\n", rendered.c_str());
          std::fflush(stdout);
          continue;
        }
      }
    }

    if (outcome.succeeded()) {
      std::printf("OK %s %s\n", std::string(to_string(outcome.code)).c_str(),
                  outcome.message.c_str());
    } else {
      std::printf("ERR %s %s\n", std::string(to_string(outcome.code)).c_str(),
                  outcome.message.c_str());
    }
    std::fflush(stdout);
  }

  static_cast<void>(client.close());
  std::printf("OK DETACHED\n");
  std::fflush(stdout);
  return 0;
}
