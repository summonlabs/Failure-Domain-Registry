// Failure Domain Registry — independent containment-graph measurement for tests.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The registry enforces max_hierarchy_depth with its own longest-path walk. A
// test must not let that walk grade itself, so this header measures the same
// graph a second time from the public query API only, with a different
// algorithm: a Kahn topological pass over the CONTAINED_BY edges instead of a
// memoised depth-first walk. Nothing here can observe state the public API does
// not expose, and the caller's graph is expected to stay small (these are
// test-sized graphs, not production ones).

#ifndef FAILURE_DOMAIN_REGISTRY_TESTS_SUPPORT_CONTAINMENT_PROBE_HPP
#define FAILURE_DOMAIN_REGISTRY_TESTS_SUPPORT_CONTAINMENT_PROBE_HPP

#include <cstddef>
#include <map>
#include <vector>

#include "failure_domain_registry/failure_domain_registry.hpp"

namespace fdrtest {

using failure_domain_registry::DomainRelation;
using failure_domain_registry::DomainRelationType;
using failure_domain_registry::FailureDomain;
using failure_domain_registry::FailureDomainId;
using failure_domain_registry::Registry;

/// One CONTAINED_BY edge: `contained` is CONTAINED_BY `container`.
struct ContainmentEdge {
  FailureDomainId contained{};
  FailureDomainId container{};
};

/// Every CONTAINED_BY edge the registry holds, read back through relations_of().
inline std::vector<ContainmentEdge> containment_edges(const Registry& registry) {
  std::vector<ContainmentEdge> edges;
  for (const FailureDomain& domain : registry.domains(registry.domain_count() + 1)) {
    for (const DomainRelation& relation : registry.relations_of(domain.id)) {
      if (relation.type != DomainRelationType::ContainedBy) {
        continue;
      }
      // Each stored edge is returned from both endpoints; count it once.
      if (!(relation.source == domain.id)) {
        continue;
      }
      edges.push_back(ContainmentEdge{relation.source, relation.target});
    }
  }
  return edges;
}

namespace containment_detail {

/// Node -> successors in the requested direction.
inline std::map<FailureDomainId, std::vector<FailureDomainId>> adjacency(
    const std::vector<ContainmentEdge>& edges, bool towards_containers) {
  std::map<FailureDomainId, std::vector<FailureDomainId>> out;
  for (const ContainmentEdge& edge : edges) {
    if (towards_containers) {
      out[edge.contained].push_back(edge.container);
    } else {
      out[edge.container].push_back(edge.contained);
    }
  }
  return out;
}

/// Every node the measurement considers: the whole graph, or the subgraph
inline std::vector<FailureDomainId> graph_nodes(
    const std::map<FailureDomainId, std::vector<FailureDomainId>>& out,
    const FailureDomainId& start, bool entire_graph) {
  std::map<FailureDomainId, bool> seen;
  std::vector<FailureDomainId> nodes;
  const auto add = [&seen, &nodes](const FailureDomainId& id) {
    if (seen.find(id) == seen.end()) {
      seen[id] = true;
      nodes.push_back(id);
    }
  };
  if (entire_graph) {
    // Every domain with an outgoing edge is a key, and every domain with only an
    // incoming edge is a successor, so the two passes together cover the graph.
    for (const auto& entry : out) {
      add(entry.first);
    }
    for (const auto& entry : out) {
      for (const FailureDomainId& successor : entry.second) {
        add(successor);
      }
    }
    return nodes;
  }
  std::vector<FailureDomainId> frontier{start};
  add(start);
  while (!frontier.empty()) {
    const FailureDomainId current = frontier.back();
    frontier.pop_back();
    const auto it = out.find(current);
    if (it == out.end()) {
      continue;
    }
    for (const FailureDomainId& successor : it->second) {
      if (seen.find(successor) == seen.end()) {
        add(successor);
        frontier.push_back(successor);
      }
    }
  }
  return nodes;
}

/// The requested subgraph in reverse topological order, or an empty vector when
/// the subgraph holds a cycle (which Kahn detects as unprocessed nodes).
inline std::vector<FailureDomainId> reverse_topological_order(
    const std::map<FailureDomainId, std::vector<FailureDomainId>>& out,
    const FailureDomainId& start, bool entire_graph) {
  const std::vector<FailureDomainId> nodes = graph_nodes(out, start, entire_graph);
  std::map<FailureDomainId, std::size_t> position;
  for (std::size_t index = 0; index < nodes.size(); ++index) {
    position[nodes[index]] = index;
  }
  std::vector<std::size_t> incoming(nodes.size(), 0);
  for (const FailureDomainId& node : nodes) {
    const auto it = out.find(node);
    if (it == out.end()) {
      continue;
    }
    for (const FailureDomainId& successor : it->second) {
      incoming[position[successor]] += 1;
    }
  }
  std::vector<FailureDomainId> ready;
  for (const FailureDomainId& node : nodes) {
    if (incoming[position[node]] == 0) {
      ready.push_back(node);
    }
  }
  std::vector<FailureDomainId> order;
  while (!ready.empty()) {
    const FailureDomainId node = ready.back();
    ready.pop_back();
    order.push_back(node);
    const auto it = out.find(node);
    if (it == out.end()) {
      continue;
    }
    for (const FailureDomainId& successor : it->second) {
      std::size_t& degree = incoming[position[successor]];
      if (degree > 0) {
        --degree;
      }
      if (degree == 0) {
        ready.push_back(successor);
      }
    }
  }
  if (order.size() != nodes.size()) {
    return std::vector<FailureDomainId>{};
  }
  return order;
}

} // namespace containment_detail

/// The longest containment chain, in edges, that starts at one domain and walks
/// either towards its containers (true) or towards the domains it contains
/// (false). Exact for an acyclic graph; a cyclic graph returns the node count,
/// which no ceiling can admit, so a test that reaches it fails loudly.
inline std::size_t longest_chain(const std::vector<ContainmentEdge>& edges,
                                 const FailureDomainId& start, bool towards_containers) {
  const std::map<FailureDomainId, std::vector<FailureDomainId>> out =
      containment_detail::adjacency(edges, towards_containers);
  const std::vector<FailureDomainId> order =
      containment_detail::reverse_topological_order(out, start, /*entire_graph=*/false);
  if (order.empty()) {
    return edges.size() + 1;
  }
  std::map<FailureDomainId, std::size_t> depth;
  for (auto it = order.rbegin(); it != order.rend(); ++it) {
    std::size_t best = 0;
    const auto successors = out.find(*it);
    if (successors != out.end()) {
      for (const FailureDomainId& successor : successors->second) {
        const std::size_t candidate = depth[successor] + 1;
        if (candidate > best) {
          best = candidate;
        }
      }
    }
    depth[*it] = best;
  }
  return depth[start];
}

/// The longest containment chain anywhere in the graph.
inline std::size_t max_containment_depth(const std::vector<ContainmentEdge>& edges) {
  const std::map<FailureDomainId, std::vector<FailureDomainId>> out =
      containment_detail::adjacency(edges, /*towards_containers=*/true);
  const std::vector<FailureDomainId> order =
      containment_detail::reverse_topological_order(out, FailureDomainId{}, /*entire_graph=*/true);
  if (edges.empty()) {
    return 0;
  }
  if (order.empty()) {
    return edges.size() + 1;
  }
  std::map<FailureDomainId, std::size_t> depth;
  std::size_t best = 0;
  for (auto it = order.rbegin(); it != order.rend(); ++it) {
    std::size_t value = 0;
    const auto successors = out.find(*it);
    if (successors != out.end()) {
      for (const FailureDomainId& successor : successors->second) {
        const std::size_t candidate = depth[successor] + 1;
        if (candidate > value) {
          value = candidate;
        }
      }
    }
    depth[*it] = value;
    if (value > best) {
      best = value;
    }
  }
  return best;
}

/// True when the containment graph holds a cycle. Kahn leaves a node with an
/// unresolved predecessor exactly when it sits on a cycle.
inline bool containment_graph_has_cycle(const std::vector<ContainmentEdge>& edges) {
  if (edges.empty()) {
    return false;
  }
  const std::map<FailureDomainId, std::vector<FailureDomainId>> out =
      containment_detail::adjacency(edges, /*towards_containers=*/true);
  return containment_detail::reverse_topological_order(out, FailureDomainId{},
                                                       /*entire_graph=*/true)
      .empty();
}

/// True when the candidate edge (contained CONTAINED_BY container) would close a
/// containment cycle: exactly when the container can already reach the contained
/// domain by containment. This is the registry's own acyclicity question, asked
/// from the outside. A self edge is malformed rather than a cycle, so callers
/// filter it before asking.
inline bool would_close_cycle(const std::vector<ContainmentEdge>& edges,
                              const FailureDomainId& contained,
                              const FailureDomainId& container) {
  if (contained == container) {
    return true;
  }
  const std::map<FailureDomainId, std::vector<FailureDomainId>> out =
      containment_detail::adjacency(edges, /*towards_containers=*/true);
  std::map<FailureDomainId, bool> seen;
  std::vector<FailureDomainId> frontier{container};
  seen[container] = true;
  while (!frontier.empty()) {
    const FailureDomainId current = frontier.back();
    frontier.pop_back();
    const auto it = out.find(current);
    if (it == out.end()) {
      continue;
    }
    for (const FailureDomainId& successor : it->second) {
      if (successor == contained) {
        return true;
      }
      if (seen.find(successor) == seen.end()) {
        seen[successor] = true;
        frontier.push_back(successor);
      }
    }
  }
  return false;
}

/// The depth a candidate CONTAINED_BY edge would create: the longest chain above
/// the container, plus the new edge, plus the longest chain below the contained
/// domain.
inline std::size_t depth_through(const std::vector<ContainmentEdge>& edges,
                                 const FailureDomainId& contained,
                                 const FailureDomainId& container) {
  return longest_chain(edges, container, /*towards_containers=*/true) + 1 +
         longest_chain(edges, contained, /*towards_containers=*/false);
}

/// The number of domains reachable from one domain in one direction, which is
/// what ancestors() and descendants() must return when no walk truncates.
inline std::size_t reachable_count(const std::vector<ContainmentEdge>& edges,
                                   const FailureDomainId& start, bool towards_containers) {
  const std::map<FailureDomainId, std::vector<FailureDomainId>> out =
      containment_detail::adjacency(edges, towards_containers);
  std::map<FailureDomainId, bool> seen;
  std::vector<FailureDomainId> frontier{start};
  seen[start] = true;
  std::size_t count = 0;
  while (!frontier.empty()) {
    const FailureDomainId current = frontier.back();
    frontier.pop_back();
    const auto it = out.find(current);
    if (it == out.end()) {
      continue;
    }
    for (const FailureDomainId& successor : it->second) {
      if (seen.find(successor) == seen.end()) {
        seen[successor] = true;
        frontier.push_back(successor);
        ++count;
      }
    }
  }
  return count;
}

} // namespace fdrtest

#endif // FAILURE_DOMAIN_REGISTRY_TESTS_SUPPORT_CONTAINMENT_PROBE_HPP
