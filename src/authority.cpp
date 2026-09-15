// Failure Domain Registry — authority scopes and fence records.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/authority.hpp"

#include <algorithm>

namespace failure_domain_registry {

AuthorityScope AuthorityScope::unrestricted() noexcept {
  AuthorityScope scope;
  for (std::uint8_t raw = 1; raw <= kDomainClassCount; ++raw) {
    scope.classes.push_back(static_cast<DomainClass>(raw));
  }
  scope.max_evidence = EvidenceClass::DirectAuthoritativeInfrastructure;
  return scope;
}

AuthorityScope AuthorityScope::for_classes(std::vector<DomainClass> classes,
                                           EvidenceClass max_evidence) noexcept {
  AuthorityScope scope;
  std::sort(classes.begin(), classes.end());
  classes.erase(std::unique(classes.begin(), classes.end()), classes.end());
  scope.classes = std::move(classes);
  scope.max_evidence = max_evidence;
  return scope;
}

bool AuthorityScope::allows_class(DomainClass value) const noexcept {
  return std::find(classes.begin(), classes.end(), value) != classes.end();
}

bool AuthorityScope::allows_scope(const std::string& scope_name) const noexcept {
  if (administrative_scope.empty()) {
    return true;
  }
  return administrative_scope == scope_name;
}

bool AuthorityScope::allows_evidence(EvidenceClass value) const noexcept {
  if (!is_valid_evidence_class(value)) {
    return false;
  }
  if (!is_valid_evidence_class(max_evidence)) {
    return false;
  }
  return evidence_rank(value) >= evidence_rank(max_evidence);
}

std::string AuthorityScope::render() const {
  std::string out = "classes=";
  if (classes.empty()) {
    out.append("none");
  } else {
    for (std::size_t i = 0; i < classes.size(); ++i) {
      if (i != 0) {
        out.push_back(',');
      }
      out.append(failure_domain_registry::to_string(classes[i]));
    }
  }
  out.append(";scope=");
  out.append(administrative_scope.empty() ? "*" : administrative_scope);
  out.append(";max-evidence=");
  out.append(failure_domain_registry::to_string(max_evidence));
  return out;
}

std::string_view to_string(FenceReason value) noexcept {
  switch (value) {
    case FenceReason::SessionLost: return "session-lost";
    case FenceReason::Reincarnated: return "reincarnated";
    case FenceReason::CoordinatorRestart: return "coordinator-restart";
    case FenceReason::Administrative: return "administrative";
    case FenceReason::Revoked: return "revoked";
    default: return "unknown";
  }
}

} // namespace failure_domain_registry
