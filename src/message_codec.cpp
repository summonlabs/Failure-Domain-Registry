// Failure Domain Registry - control protocol payload codec.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "message_codec.hpp"

#include "byte_codec.hpp"

namespace failure_domain_registry {
namespace {

constexpr std::size_t kMaxWireEntities = hard_limits::kMaxQuerySetCardinality;
constexpr std::size_t kMaxWireClasses = 64;
constexpr std::size_t kMaxWireEntries = hard_limits::kMaxMembersPerBatch;
constexpr std::size_t kMaxWireString = hard_limits::kMaxStringBytes;
constexpr std::size_t kMaxWireRendered = 262144;

void write_authority(codec::Writer& writer, const WireAuthority& authority) {
  writer.bytes(authority.attempt.to_string());
  writer.u64(authority.epoch.value());
  writer.bytes(authority.publisher.to_string());
  writer.bytes(authority.worker_boot.to_string());
  writer.u8(static_cast<std::uint8_t>(authority.evidence));
}

bool read_authority(codec::Reader& reader, WireAuthority* authority) {
  std::string attempt;
  std::string publisher;
  std::string boot;
  std::uint64_t epoch = 0;
  std::uint8_t evidence = 0;
  if (!reader.bytes(&attempt, kOpaqueIdTextLength) || !reader.u64(&epoch) ||
      !reader.bytes(&publisher, kOpaqueIdTextLength) ||
      !reader.bytes(&boot, kOpaqueIdTextLength) || !reader.u8(&evidence)) {
    return false;
  }
  if (evidence != 0 && !is_valid_evidence_class(static_cast<EvidenceClass>(evidence))) {
    return false;
  }
  authority->evidence = static_cast<EvidenceClass>(evidence);
  authority->epoch = CoordinatorEpoch(epoch);
  if (!attempt.empty()) {
    const std::optional<MutationAttemptId> parsed = MutationAttemptId::parse(attempt);
    if (!parsed.has_value()) {
      return false;
    }
    authority->attempt = *parsed;
  }
  if (!publisher.empty()) {
    const std::optional<PublisherId> parsed = PublisherId::parse(publisher);
    if (!parsed.has_value()) {
      return false;
    }
    authority->publisher = *parsed;
  }
  if (!boot.empty()) {
    const std::optional<WorkerBootId> parsed = WorkerBootId::parse(boot);
    if (!parsed.has_value()) {
      return false;
    }
    authority->worker_boot = *parsed;
  }
  return true;
}

void write_provenance(codec::Writer& writer, const Provenance& provenance) {
  writer.u8(static_cast<std::uint8_t>(provenance.source));
  writer.u8(static_cast<std::uint8_t>(provenance.evidence));
  writer.u8(static_cast<std::uint8_t>(provenance.truth));
  writer.bytes(provenance.source_identity);
  writer.u64(provenance.evidence_generation.value());
}

bool read_provenance(codec::Reader& reader, Provenance* provenance) {
  std::uint8_t source = 0;
  std::uint8_t evidence = 0;
  std::uint8_t truth = 0;
  std::uint64_t generation = 0;
  if (!reader.u8(&source) || !reader.u8(&evidence) || !reader.u8(&truth) ||
      !reader.bytes(&provenance->source_identity, kMaxWireString) || !reader.u64(&generation)) {
    return false;
  }
  if (source == 0 || evidence == 0 || truth == 0) {
    return false;
  }
  if (!is_valid_provenance_source(static_cast<ProvenanceSource>(source)) ||
      !is_valid_evidence_class(static_cast<EvidenceClass>(evidence)) ||
      !is_valid_truth_class(static_cast<TruthClass>(truth))) {
    return false;
  }
  provenance->source = static_cast<ProvenanceSource>(source);
  provenance->evidence = static_cast<EvidenceClass>(evidence);
  provenance->truth = static_cast<TruthClass>(truth);
  provenance->evidence_generation = EvidenceGeneration(generation);
  return true;
}

void write_classes(codec::Writer& writer, const std::vector<DomainClassRef>& classes) {
  writer.u32(static_cast<std::uint32_t>(classes.size()));
  for (const DomainClassRef& klass : classes) {
    writer.bytes(klass.to_string());
  }
}

bool read_classes(codec::Reader& reader, std::vector<DomainClassRef>* classes) {
  std::uint32_t count = 0;
  if (!reader.count(&count, 4, kMaxWireClasses)) {
    return false;
  }
  for (std::uint32_t i = 0; i < count; ++i) {
    std::string text;
    if (!reader.bytes(&text, 128)) {
      return false;
    }
    const std::optional<DomainClassRef> klass = DomainClassRef::parse(text);
    if (!klass.has_value()) {
      return false;
    }
    classes->push_back(*klass);
  }
  return true;
}

void write_entities(codec::Writer& writer, const std::vector<EntityId>& entities) {
  writer.u32(static_cast<std::uint32_t>(entities.size()));
  for (const EntityId& entity : entities) {
    writer.bytes(entity.to_string());
  }
}

bool read_entities(codec::Reader& reader, std::vector<EntityId>* entities) {
  std::uint32_t count = 0;
  if (!reader.count(&count, 4, kMaxWireEntities)) {
    return false;
  }
  for (std::uint32_t i = 0; i < count; ++i) {
    std::string text;
    if (!reader.bytes(&text, 96)) {
      return false;
    }
    const std::optional<EntityId> entity = EntityId::parse(text);
    if (!entity.has_value() || entity->is_null()) {
      return false;
    }
    entities->push_back(*entity);
  }
  return true;
}

} // namespace

std::string_view to_string(Operation value) noexcept {
  switch (value) {
    case Operation::Hello: return "hello";
    case Operation::HelloAck: return "hello-ack";
    case Operation::Bye: return "bye";
    case Operation::Heartbeat: return "heartbeat";
    case Operation::CreateDomain: return "create-domain";
    case Operation::SupersedeDomain: return "supersede-domain";
    case Operation::RetireDomain: return "retire-domain";
    case Operation::AttachMember: return "attach-member";
    case Operation::PublishMemberships: return "publish-memberships";
    case Operation::WithdrawEvidence: return "withdraw-evidence";
    case Operation::DeclareCoverage: return "declare-coverage";
    case Operation::InvalidateEntity: return "invalidate-entity";
    case Operation::RunDerivation: return "run-derivation";
    case Operation::QueryStatus: return "query-status";
    case Operation::QueryDomain: return "query-domain";
    case Operation::QueryDomainMembers: return "query-domain-members";
    case Operation::QueryEntityDomains: return "query-entity-domains";
    case Operation::QueryOverlap: return "query-overlap";
    case Operation::QueryCoverage: return "query-coverage";
    case Operation::QueryIndependence: return "query-independence";
    case Operation::QuerySnapshot: return "query-snapshot";
    case Operation::QueryExplainMembership: return "query-explain-membership";
    case Operation::Response: return "response";
    default: return "unknown";
  }
}

bool is_valid_operation(Operation value) noexcept {
  switch (value) {
    case Operation::Hello:
    case Operation::HelloAck:
    case Operation::Bye:
    case Operation::Heartbeat:
    case Operation::CreateDomain:
    case Operation::SupersedeDomain:
    case Operation::RetireDomain:
    case Operation::AttachMember:
    case Operation::PublishMemberships:
    case Operation::WithdrawEvidence:
    case Operation::DeclareCoverage:
    case Operation::InvalidateEntity:
    case Operation::RunDerivation:
    case Operation::QueryStatus:
    case Operation::QueryDomain:
    case Operation::QueryDomainMembers:
    case Operation::QueryEntityDomains:
    case Operation::QueryOverlap:
    case Operation::QueryCoverage:
    case Operation::QueryIndependence:
    case Operation::QuerySnapshot:
    case Operation::QueryExplainMembership:
    case Operation::Response:
      return true;
    default:
      return false;
  }
}

bool is_mutation_operation(Operation value) noexcept {
  switch (value) {
    case Operation::CreateDomain:
    case Operation::SupersedeDomain:
    case Operation::RetireDomain:
    case Operation::AttachMember:
    case Operation::PublishMemberships:
    case Operation::WithdrawEvidence:
    case Operation::DeclareCoverage:
    case Operation::InvalidateEntity:
    case Operation::RunDerivation:
      return true;
    default:
      return false;
  }
}

Outcome encode_wire_request(const WireRequest& request, std::string* payload) {
  if (!is_valid_operation(request.op)) {
    return Outcome::make(OutcomeCode::ProtocolViolation, "operation is not valid");
  }
  codec::Writer writer;
  writer.u16(static_cast<std::uint16_t>(request.op));
  switch (request.op) {
    case Operation::Hello:
    case Operation::Bye:
    case Operation::Heartbeat:
    case Operation::QueryStatus:
      write_authority(writer, request.authority);
      writer.bytes(request.label);
      break;
    case Operation::CreateDomain: {
      write_authority(writer, request.authority);
      const CreateDomainRequest& body = request.create_domain;
      writer.bytes(body.domain_class.to_string());
      writer.bytes(body.administrative_scope);
      writer.bytes(body.identity_key);
      writer.bytes(body.name);
      write_provenance(writer, body.provenance);
      writer.u8(body.activate ? 1 : 0);
      break;
    }
    case Operation::SupersedeDomain: {
      write_authority(writer, request.authority);
      const SupersedeDomainRequest& body = request.supersede;
      writer.bytes(body.domain.to_string());
      writer.u64(body.expected_generation.value());
      writer.bytes(body.successor.to_string());
      writer.u8(body.demote_memberships ? 1 : 0);
      break;
    }
    case Operation::RetireDomain: {
      write_authority(writer, request.authority);
      const RetireDomainRequest& body = request.retire;
      writer.bytes(body.domain.to_string());
      writer.u64(body.expected_generation.value());
      writer.bytes(body.reason);
      writer.u8(body.retire_memberships ? 1 : 0);
      break;
    }
    case Operation::AttachMember: {
      write_authority(writer, request.authority);
      const AttachMemberRequest& body = request.attach_member;
      writer.bytes(body.domain.to_string());
      writer.u64(body.expected_domain_generation.value());
      writer.bytes(body.member.to_string());
      writer.u8(static_cast<std::uint8_t>(body.kind));
      writer.u8(static_cast<std::uint8_t>(body.role));
      writer.u8(static_cast<std::uint8_t>(body.dependency));
      write_provenance(writer, body.provenance);
      break;
    }
    case Operation::PublishMemberships: {
      write_authority(writer, request.authority);
      const MembershipBatchRequest& body = request.publish;
      writer.u8(static_cast<std::uint8_t>(body.mode));
      writer.bytes(body.administrative_scope);
      writer.u8(static_cast<std::uint8_t>(body.authoritative_entity_class));
      writer.u32(static_cast<std::uint32_t>(body.authoritative_domains.size()));
      for (const FailureDomainId& domain : body.authoritative_domains) {
        writer.bytes(domain.to_string());
      }
      writer.u32(static_cast<std::uint32_t>(body.entries.size()));
      for (const MembershipBatchEntry& entry : body.entries) {
        writer.bytes(entry.domain.to_string());
        writer.u64(entry.expected_domain_generation.value());
        writer.bytes(entry.member.to_string());
        writer.u8(static_cast<std::uint8_t>(entry.kind));
        writer.u8(static_cast<std::uint8_t>(entry.role));
        writer.u8(static_cast<std::uint8_t>(entry.dependency));
        write_provenance(writer, entry.provenance);
      }
      break;
    }
    case Operation::WithdrawEvidence: {
      write_authority(writer, request.authority);
      const WithdrawEvidenceRequest& body = request.withdraw;
      writer.bytes(body.membership.to_string());
      writer.u64(body.expected_generation.value());
      writer.u8(body.only_this_worker_boot ? 1 : 0);
      writer.bytes(body.reason);
      break;
    }
    case Operation::DeclareCoverage: {
      write_authority(writer, request.authority);
      const DeclareCoverageRequest& body = request.coverage;
      writer.bytes(body.administrative_scope);
      writer.bytes(body.domain_class.to_string());
      writer.u8(static_cast<std::uint8_t>(body.state));
      write_provenance(writer, body.provenance);
      break;
    }
    case Operation::InvalidateEntity: {
      write_authority(writer, request.authority);
      const EntityInvalidationRequest& body = request.invalidate;
      writer.bytes(body.entity.to_string());
      writer.u64(body.superseded_generation.value());
      writer.bytes(body.reason);
      break;
    }
    case Operation::RunDerivation: {
      write_authority(writer, request.authority);
      writer.bytes(request.derivation.rule.to_string());
      break;
    }
    case Operation::QueryDomain:
    case Operation::QueryDomainMembers:
    case Operation::QueryExplainMembership:
      write_authority(writer, request.authority);
      writer.bytes(request.domain.to_string());
      writer.bytes(request.entity.to_string());
      break;
    case Operation::QueryEntityDomains:
      write_authority(writer, request.authority);
      writer.bytes(request.entity.to_string());
      break;
    case Operation::QueryOverlap:
    case Operation::QueryIndependence:
      write_authority(writer, request.authority);
      write_entities(writer, request.entities);
      write_classes(writer, request.classes);
      writer.bytes(request.scope);
      break;
    case Operation::QueryCoverage:
      write_authority(writer, request.authority);
      writer.bytes(request.scope);
      write_classes(writer, request.classes);
      break;
    case Operation::QuerySnapshot:
      write_authority(writer, request.authority);
      writer.bytes(request.scope);
      break;
    default:
      return Outcome::make(OutcomeCode::ProtocolViolation, "operation cannot be encoded");
  }
  *payload = writer.buffer();
  return Outcome::make(OutcomeCode::Committed, "request encoded");
}

namespace {

/// An absent identifier renders as the empty string or as "null", so both are
/// accepted here as "no identifier". An operation that requires one rejects the
/// null value itself, with a specific outcome, instead of being reported as a
/// framing violation.
bool is_absent_id(std::string_view text) { return text.empty() || text == "null"; }

bool read_domain_id(codec::Reader& reader, FailureDomainId* out) {
  std::string text;
  if (!reader.bytes(&text, kOpaqueIdTextLength)) {
    return false;
  }
  if (is_absent_id(text)) {
    *out = FailureDomainId{};
    return true;
  }
  const std::optional<FailureDomainId> parsed = FailureDomainId::parse(text);
  if (!parsed.has_value()) {
    return false;
  }
  *out = *parsed;
  return true;
}

bool read_membership_id(codec::Reader& reader, MembershipId* out) {
  std::string text;
  if (!reader.bytes(&text, kOpaqueIdTextLength)) {
    return false;
  }
  if (is_absent_id(text)) {
    *out = MembershipId{};
    return true;
  }
  const std::optional<MembershipId> parsed = MembershipId::parse(text);
  if (!parsed.has_value()) {
    return false;
  }
  *out = *parsed;
  return true;
}

bool read_entity_ref(codec::Reader& reader, EntityRef* out) {
  std::string text;
  if (!reader.bytes(&text, 96)) {
    return false;
  }
  if (is_absent_id(text)) {
    *out = EntityRef{};
    return true;
  }
  const std::optional<EntityRef> parsed = EntityRef::parse(text);
  if (!parsed.has_value() || parsed->is_null()) {
    return false;
  }
  *out = *parsed;
  return true;
}

bool read_entity_id(codec::Reader& reader, EntityId* out) {
  std::string text;
  if (!reader.bytes(&text, 96)) {
    return false;
  }
  if (is_absent_id(text)) {
    *out = EntityId{};
    return true;
  }
  const std::optional<EntityId> parsed = EntityId::parse(text);
  if (!parsed.has_value() || parsed->is_null()) {
    return false;
  }
  *out = *parsed;
  return true;
}

bool read_derivation_rule_id(codec::Reader& reader, DerivationRuleId* out) {
  std::string text;
  if (!reader.bytes(&text, kOpaqueIdTextLength)) {
    return false;
  }
  if (text.empty()) {
    return true;
  }
  const std::optional<DerivationRuleId> parsed = DerivationRuleId::parse(text);
  if (!parsed.has_value()) {
    return false;
  }
  *out = *parsed;
  return true;
}

Outcome malformed() {
  return Outcome::make(OutcomeCode::ProtocolViolation, "request payload is malformed");
}

} // namespace

Outcome decode_wire_request(std::string_view payload, WireRequest* request) {
  codec::Reader reader(payload);
  std::uint16_t raw_op = 0;
  if (!reader.u16(&raw_op)) {
    return Outcome::make(OutcomeCode::ProtocolViolation, "request payload is empty");
  }
  const auto op = static_cast<Operation>(raw_op);
  if (!is_valid_operation(op)) {
    return Outcome::make(OutcomeCode::ProtocolViolation, "request names an unknown operation");
  }
  request->op = op;
  std::uint64_t counter = 0;
  switch (op) {
    case Operation::Hello:
    case Operation::Bye:
    case Operation::Heartbeat:
    case Operation::QueryStatus:
      if (!read_authority(reader, &request->authority) ||
          !reader.bytes(&request->label, kMaxWireString)) {
        return malformed();
      }
      break;
    case Operation::CreateDomain: {
      CreateDomainRequest& body = request->create_domain;
      std::string klass;
      std::uint8_t activate = 0;
      if (!read_authority(reader, &request->authority) || !reader.bytes(&klass, 128) ||
          !reader.bytes(&body.administrative_scope, 256) ||
          !reader.bytes(&body.identity_key, kMaxIdentityKeyBytes) ||
          !reader.bytes(&body.name, kMaxWireString) ||
          !read_provenance(reader, &body.provenance) || !reader.u8(&activate)) {
        return malformed();
      }
      const std::optional<DomainClassRef> parsed = DomainClassRef::parse(klass);
      if (!parsed.has_value()) {
        return Outcome::make(OutcomeCode::ProtocolViolation, "request names an invalid class");
      }
      body.domain_class = *parsed;
      body.activate = activate != 0;
      break;
    }
    case Operation::SupersedeDomain: {
      SupersedeDomainRequest& body = request->supersede;
      std::uint8_t demote = 0;
      if (!read_authority(reader, &request->authority) || !read_domain_id(reader, &body.domain) ||
          !reader.u64(&counter)) {
        return malformed();
      }
      body.expected_generation = FailureDomainGeneration(counter);
      if (!read_domain_id(reader, &body.successor) || !reader.u8(&demote)) {
        return malformed();
      }
      body.demote_memberships = demote != 0;
      break;
    }
    case Operation::RetireDomain: {
      RetireDomainRequest& body = request->retire;
      std::uint8_t retire_memberships = 0;
      if (!read_authority(reader, &request->authority) || !read_domain_id(reader, &body.domain) ||
          !reader.u64(&counter)) {
        return malformed();
      }
      body.expected_generation = FailureDomainGeneration(counter);
      if (!reader.bytes(&body.reason, kMaxWireString) || !reader.u8(&retire_memberships)) {
        return malformed();
      }
      body.retire_memberships = retire_memberships != 0;
      break;
    }
    case Operation::AttachMember: {
      AttachMemberRequest& body = request->attach_member;
      std::uint8_t kind = 0;
      std::uint8_t role = 0;
      std::uint8_t dependency = 0;
      if (!read_authority(reader, &request->authority) || !read_domain_id(reader, &body.domain) ||
          !reader.u64(&counter)) {
        return malformed();
      }
      body.expected_domain_generation = FailureDomainGeneration(counter);
      if (!read_entity_ref(reader, &body.member) || !reader.u8(&kind) || !reader.u8(&role) ||
          !reader.u8(&dependency) || !read_provenance(reader, &body.provenance)) {
        return malformed();
      }
      if (!is_valid_membership_kind(static_cast<MembershipKind>(kind)) ||
          !is_valid_membership_role(static_cast<MembershipRole>(role)) ||
          !is_valid_dependency_semantics(static_cast<DependencySemantics>(dependency))) {
        return malformed();
      }
      body.kind = static_cast<MembershipKind>(kind);
      body.role = static_cast<MembershipRole>(role);
      body.dependency = static_cast<DependencySemantics>(dependency);
      break;
    }
    case Operation::PublishMemberships: {
      MembershipBatchRequest& body = request->publish;
      std::uint8_t mode = 0;
      std::uint8_t entity_class = 0;
      std::uint32_t domain_count = 0;
      std::uint32_t entry_count = 0;
      if (!read_authority(reader, &request->authority) || !reader.u8(&mode) ||
          !reader.bytes(&body.administrative_scope, 256) || !reader.u8(&entity_class) ||
          !reader.count(&domain_count, 4, kMaxWireEntries)) {
        return malformed();
      }
      if (!is_valid_publication_mode(static_cast<PublicationMode>(mode))) {
        return Outcome::make(OutcomeCode::ProtocolViolation, "publication mode is not valid");
      }
      body.mode = static_cast<PublicationMode>(mode);
      if (entity_class != 0) {
        if (!is_valid_entity_class(static_cast<EntityClass>(entity_class))) {
          return malformed();
        }
        body.authoritative_entity_class = static_cast<EntityClass>(entity_class);
      }
      for (std::uint32_t i = 0; i < domain_count; ++i) {
        FailureDomainId domain;
        if (!read_domain_id(reader, &domain)) {
          return malformed();
        }
        body.authoritative_domains.push_back(domain);
      }
      if (!reader.count(&entry_count, 40, kMaxWireEntries)) {
        return malformed();
      }
      for (std::uint32_t i = 0; i < entry_count; ++i) {
        MembershipBatchEntry entry;
        std::uint8_t kind = 0;
        std::uint8_t role = 0;
        std::uint8_t dependency = 0;
        if (!read_domain_id(reader, &entry.domain) || !reader.u64(&counter)) {
          return malformed();
        }
        entry.expected_domain_generation = FailureDomainGeneration(counter);
        if (!read_entity_ref(reader, &entry.member) || !reader.u8(&kind) || !reader.u8(&role) ||
            !reader.u8(&dependency) || !read_provenance(reader, &entry.provenance)) {
          return malformed();
        }
        if (!is_valid_membership_kind(static_cast<MembershipKind>(kind)) ||
            !is_valid_membership_role(static_cast<MembershipRole>(role)) ||
            !is_valid_dependency_semantics(static_cast<DependencySemantics>(dependency))) {
          return malformed();
        }
        entry.kind = static_cast<MembershipKind>(kind);
        entry.role = static_cast<MembershipRole>(role);
        entry.dependency = static_cast<DependencySemantics>(dependency);
        body.entries.push_back(std::move(entry));
      }
      break;
    }
    case Operation::WithdrawEvidence: {
      WithdrawEvidenceRequest& body = request->withdraw;
      std::uint8_t only_boot = 0;
      if (!read_authority(reader, &request->authority) ||
          !read_membership_id(reader, &body.membership) || !reader.u64(&counter) ||
          !reader.u8(&only_boot) || !reader.bytes(&body.reason, kMaxWireString)) {
        return malformed();
      }
      body.expected_generation = MembershipGeneration(counter);
      body.only_this_worker_boot = only_boot != 0;
      break;
    }
    case Operation::DeclareCoverage: {
      DeclareCoverageRequest& body = request->coverage;
      std::string klass;
      std::uint8_t state = 0;
      if (!read_authority(reader, &request->authority) ||
          !reader.bytes(&body.administrative_scope, 256) || !reader.bytes(&klass, 128) ||
          !reader.u8(&state) || !read_provenance(reader, &body.provenance)) {
        return malformed();
      }
      const std::optional<DomainClassRef> parsed = DomainClassRef::parse(klass);
      if (!parsed.has_value() || !is_valid_coverage_state(static_cast<CoverageState>(state))) {
        return malformed();
      }
      body.domain_class = *parsed;
      body.state = static_cast<CoverageState>(state);
      break;
    }
    case Operation::InvalidateEntity: {
      EntityInvalidationRequest& body = request->invalidate;
      if (!read_authority(reader, &request->authority) || !read_entity_id(reader, &body.entity) ||
          !reader.u64(&counter) || !reader.bytes(&body.reason, kMaxWireString)) {
        return malformed();
      }
      body.superseded_generation = EntityGeneration(counter);
      break;
    }
    case Operation::RunDerivation:
      if (!read_authority(reader, &request->authority) ||
          !read_derivation_rule_id(reader, &request->derivation.rule)) {
        return malformed();
      }
      break;
    case Operation::QueryDomain:
    case Operation::QueryDomainMembers:
    case Operation::QueryExplainMembership:
      if (!read_authority(reader, &request->authority) || !read_domain_id(reader, &request->domain) ||
          !read_entity_id(reader, &request->entity)) {
        return malformed();
      }
      break;
    case Operation::QueryEntityDomains:
      if (!read_authority(reader, &request->authority) ||
          !read_entity_id(reader, &request->entity)) {
        return malformed();
      }
      break;
    case Operation::QueryOverlap:
    case Operation::QueryIndependence:
      if (!read_authority(reader, &request->authority) ||
          !read_entities(reader, &request->entities) ||
          !read_classes(reader, &request->classes) ||
          !reader.bytes(&request->scope, 256)) {
        return malformed();
      }
      break;
    case Operation::QueryCoverage:
      if (!read_authority(reader, &request->authority) ||
          !reader.bytes(&request->scope, 256) || !read_classes(reader, &request->classes)) {
        return malformed();
      }
      break;
    case Operation::QuerySnapshot:
      if (!read_authority(reader, &request->authority) ||
          !reader.bytes(&request->scope, 256)) {
        return malformed();
      }
      break;
    default:
      return Outcome::make(OutcomeCode::ProtocolViolation,
                           "this build cannot decode that operation");
  }
  if (!reader.exhausted()) {
    return Outcome::make(OutcomeCode::ProtocolViolation, "request payload carries trailing bytes");
  }
  return Outcome::make(OutcomeCode::Committed, "request decoded");
}

Outcome encode_wire_response(const WireResponse& response, std::string* payload) {
  codec::Writer writer;
  writer.u8(static_cast<std::uint8_t>(response.code));
  writer.bytes(response.message);
  writer.bytes(response.rendered);
  writer.u64(response.epoch.value());
  writer.u64(response.generation.value());
  writer.bytes(response.domain.to_string());
  writer.bytes(response.membership.to_string());
  writer.bytes(response.request_digest.to_string());
  *payload = writer.buffer();
  return Outcome::make(OutcomeCode::Committed, "response encoded");
}

Outcome decode_wire_response(std::string_view payload, WireResponse* response) {
  codec::Reader reader(payload);
  std::uint8_t code = 0;
  std::string domain;
  std::string membership;
  std::string digest;
  std::uint64_t epoch = 0;
  std::uint64_t generation = 0;
  if (!reader.u8(&code) || !reader.bytes(&response->message, kMaxWireString) ||
      !reader.bytes(&response->rendered, kMaxWireRendered) || !reader.u64(&epoch) ||
      !reader.u64(&generation) || !reader.bytes(&domain, kOpaqueIdTextLength) ||
      !reader.bytes(&membership, kOpaqueIdTextLength) ||
      !reader.bytes(&digest, kDigestBytes * 2)) {
    return Outcome::make(OutcomeCode::ProtocolViolation, "response payload is malformed");
  }
  if (static_cast<std::uint8_t>(OutcomeCode::Committed) > code || code > kOutcomeCodeCount) {
    return Outcome::make(OutcomeCode::ProtocolViolation, "response carries an unknown code");
  }
  response->code = static_cast<OutcomeCode>(code);
  response->epoch = CoordinatorEpoch(epoch);
  response->generation = RegistryGeneration(generation);
  if (!domain.empty()) {
    const std::optional<FailureDomainId> parsed = FailureDomainId::parse(domain);
    if (!parsed.has_value()) {
      return Outcome::make(OutcomeCode::ProtocolViolation, "response carries a bad domain id");
    }
    response->domain = *parsed;
  }
  if (!membership.empty()) {
    const std::optional<MembershipId> parsed = MembershipId::parse(membership);
    if (!parsed.has_value()) {
      return Outcome::make(OutcomeCode::ProtocolViolation, "response carries a bad membership id");
    }
    response->membership = *parsed;
  }
  if (!digest.empty()) {
    const std::optional<RequestDigest> parsed = RequestDigest::parse(digest);
    if (!parsed.has_value()) {
      return Outcome::make(OutcomeCode::ProtocolViolation, "response carries a bad digest");
    }
    response->request_digest = *parsed;
  }
  if (!reader.exhausted()) {
    return Outcome::make(OutcomeCode::ProtocolViolation, "response payload carries trailing bytes");
  }
  return Outcome::make(OutcomeCode::Committed, "response decoded");
}

} // namespace failure_domain_registry
