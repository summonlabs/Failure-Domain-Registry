// Failure Domain Registry — REAL multi-process proof.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Nothing in this file simulates a process. A real fdr-coordinator is started as
// a child process on a real loopback socket with its own durable image, two real
// fdr-publisher processes attach to it through the real framed protocol, one of
// them is killed with the operating system's forced-termination call, and a
// third publisher process with a fresh boot id recovers the classification.
// A second coordinator process is then started on the same image.
//
// The observation channel is a real failure_domain_registry::PublisherClient:
// it speaks the same framed protocol over its own socket, so every assertion
// below is made against the coordinator's live registry and not against a local
// reconstruction of it.
//
// One deliberate reading of the specification is recorded here, because the
// public surface forces a choice:
//
//   * Publisher A publishes its Rack domain and its membership with evidence
//     class ADMINISTRATIVE_DECLARATION, which is a durable class. The fence that
//     follows the kill therefore demotes A's membership to
//     REVALIDATION_REQUIRED while A's domain keeps classification authority, and
//     A' can re-publish and make the classification CURRENT again with the real
//     publisher command language.
//   * Publisher B publishes its Pdu domain with evidence class
//     DIRECT_HARDWARE_CONTROLLER, which is process bound. That is what proves the
//     process-bound rule: B's domain is CURRENT while B's process lives and is
//     demoted to REVALIDATION_REQUIRED once the coordinator fences B.
//
// A RevalidationRequired DOMAIN can only be moved back to Current by
// Registry::update_domain(transition = Current); neither the publisher command
// language nor PublisherClient exposes that operation, so the scenario below is
// the only shape in which a real publisher process can restore authority.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "failure_domain_registry/failure_domain_registry.hpp"
#include "support/test_harness.hpp"
#include "support/test_process.hpp"

namespace {

using namespace failure_domain_registry;


// ---------------------------------------------------------------------------
// Deterministic identities
// ---------------------------------------------------------------------------

template <class Id>
Id id_from(std::string_view label) {
  return Id::from_digest(sha256(label));
}

IdBytes entity_bytes_from(std::string_view label) {
  const DigestBytes digest = sha256(label);
  IdBytes bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    bytes[index] = digest[index];
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// The child processes
// ---------------------------------------------------------------------------

/// A bounded wait for a condition that only another process can satisfy. The
/// caller always asserts the result, so a false return is reported as a real
/// defect rather than swallowed.
template <class Predicate>
bool wait_for(Predicate predicate, long long budget_ms) {
  constexpr long long kPollMilliseconds = 10;
  for (long long waited = 0; waited <= budget_ms; waited += kPollMilliseconds) {
    if (predicate()) {
      return true;
    }
    fdrtest::sleep_milliseconds(kPollMilliseconds);
  }
  return predicate();
}

std::vector<std::string> result_lines(const std::string& text) {
  std::vector<std::string> lines;
  for (const std::string& line : fdrtest::split_lines(text)) {
    if (line.rfind("OK ", 0) == 0 || line.rfind("ERR ", 0) == 0) {
      lines.push_back(line);
    }
  }
  return lines;
}

/// Sends one command line to a publisher process and returns the deterministic
/// result line the process writes for it. The baseline is taken before the write
/// so an earlier command can never satisfy this one.
bool run_command(fdrtest::ChildProcess& child, const std::string& command, std::string* result,
                 std::string* why) {
  const std::size_t before = result_lines(child.output()).size();
  std::string error;
  if (!child.write_stdin(command + "\n", error)) {
    *why = "the command '" + command + "' could not be written: " + error;
    return false;
  }
  bool produced = false;
  const bool arrived = wait_for(
      [&]() { return result_lines(child.output()).size() > before; }, 30000);
  if (arrived) {
    const std::vector<std::string> lines = result_lines(child.output());
    if (lines.size() > before) {
      *result = lines[before];
      produced = true;
    }
  }
  if (!produced) {
    *why = "no result line arrived for '" + command + "'; captured output:\n" + child.output();
  }
  return produced;
}

/// Starts a child and waits for a line it must print before it is usable.
bool start_child(const std::string& program, const std::vector<std::string>& arguments,
                 const std::string& ready_needle, fdrtest::ChildProcess* child,
                 std::string* captured, std::string* why) {
  std::string error;
  std::optional<fdrtest::ChildProcess> spawned =
      fdrtest::ChildProcess::spawn(program, arguments, error);
  if (!spawned.has_value()) {
    *why = "spawning " + program + " failed: " + error;
    return false;
  }
  *child = std::move(*spawned);
  bool found = false;
  const std::string text = child->wait_for_output(ready_needle, 30000, found);
  if (captured != nullptr) {
    *captured = text;
  }
  if (!found) {
    *why = program + " never reported '" + ready_needle + "'; captured output:\n" + text;
    return false;
  }
  return true;
}

/// "listening 127.0.0.1:54321" -> the parseable endpoint.
std::optional<Endpoint> endpoint_from_listing(const std::string& output) {
  const std::string line = fdrtest::first_line_with_prefix(output, "listening ");
  if (line.empty()) {
    return std::nullopt;
  }
  return Endpoint::parse(line.substr(std::string("listening ").size()));
}

std::optional<CoordinatorEpoch> epoch_from_listing(const std::string& output) {
  const std::string line = fdrtest::first_line_with_prefix(output, "epoch ");
  if (line.empty()) {
    return std::nullopt;
  }
  return CoordinatorEpoch::parse(line.substr(std::string("epoch ").size()));
}

/// Reads "  fences           = 12" out of the status rendering.
std::size_t status_number(const std::string& rendered, const std::string& key) {
  for (const std::string& line : fdrtest::split_lines(rendered)) {
    if (line.find(key) == std::string::npos) {
      continue;
    }
    const std::size_t equals = line.find('=');
    if (equals == std::string::npos) {
      continue;
    }
    std::size_t index = equals + 1;
    while (index < line.size() && line[index] == ' ') {
      ++index;
    }
    std::size_t value = 0;
    bool any = false;
    while (index < line.size() && line[index] >= '0' && line[index] <= '9') {
      value = value * 10u + static_cast<std::size_t>(line[index] - '0');
      any = true;
      ++index;
    }
    if (any) {
      return value;
    }
  }
  return 0;
}

/// The trimmed value after the first '=' on the first line mentioning a key.
std::string field_of(const std::string& rendered, const std::string& key) {
  for (const std::string& line : fdrtest::split_lines(rendered)) {
    if (line.find(key) == std::string::npos) {
      continue;
    }
    const std::size_t equals = line.find('=');
    if (equals == std::string::npos) {
      continue;
    }
    std::size_t begin = equals + 1;
    while (begin < line.size() && line[begin] == ' ') {
      ++begin;
    }
    std::size_t end = line.size();
    while (end > begin && line[end - 1] == ' ') {
      --end;
    }
    return line.substr(begin, end - begin);
  }
  return std::string();
}

/// The membership lifecycle a member rendering reports for one entity.
std::string lifecycle_of_member(const std::string& rendered, const std::string& entity_text) {
  for (const std::string& line : fdrtest::split_lines(rendered)) {
    if (line.find(entity_text) == std::string::npos) {
      continue;
    }
    const std::size_t marker = line.find("lifecycle=");
    if (marker == std::string::npos) {
      continue;
    }
    return line.substr(marker + std::string("lifecycle=").size());
  }
  return std::string();
}

std::size_t count_member_lines(const std::string& rendered) {
  std::size_t count = 0;
  for (const std::string& line : fdrtest::split_lines(rendered)) {
    if (line.rfind("  ", 0) == 0 && line.find(" kind=") != std::string::npos) {
      ++count;
    }
  }
  return count;
}

/// True when the durable fence list holds one incarnation.
bool fence_recorded(const Registry& registry, const PublisherId& publisher,
                    const WorkerBootId& boot) {
  for (const FenceRecord& fence : registry.fences()) {
    if (fence.publisher == publisher && fence.worker_boot == boot) {
      return true;
    }
  }
  return false;
}

/// Loads a copy of the coordinator's durable image with the public API.
bool load_image(const std::string& path, Registry* registry, std::string* why) {
  PersistenceConfig config;
  config.path = path;
  const Outcome loaded = registry->load(config);
  if (!loaded.succeeded()) {
    *why = "the image at " + path + " could not be loaded: " + loaded.render();
    return false;
  }
  return true;
}

PublisherClientConfig observer_config(const Endpoint& endpoint, const PublisherId& publisher,
                                      const WorkerBootId& boot) {
  PublisherClientConfig config;
  config.endpoint = endpoint;
  config.publisher = publisher;
  config.worker_boot = boot;
  config.label = "fdr-test-observer";
  // Unknown evidence means "assert nothing", so the observer never needs an
  // evidence grant: it only reads.
  config.max_evidence = EvidenceClass::Unknown;
  return config;
}

} // namespace

FDR_TEST_CASE(multiprocess, real_processes_fence_reincarnate_and_recover) {
  const std::string coordinator_program = fdrtest::option("--coordinator");
  const std::string publisher_program = fdrtest::option("--publisher");
  FDR_CHECK_MSG(!coordinator_program.empty(),
                "the multiprocess suite needs --coordinator <path>");
  FDR_CHECK_MSG(!publisher_program.empty(), "the multiprocess suite needs --publisher <path>");

  const std::string directory = fdrtest::make_temporary_directory("multiprocess");
  FDR_CHECK_MSG(!directory.empty(), "the temporary directory could not be created");
  struct DirectoryGuard {
    std::string path;
    ~DirectoryGuard() { fdrtest::remove_directory(path); }
  } guard{directory};

  const std::string state_path = directory + "\\state.fdr";
  const std::string before_path = directory + "\\before.fdr";
  const std::string after_path = directory + "\\after.fdr";

  const PublisherId publisher_a = id_from<PublisherId>("fdr/test/multiprocess/publisher/a");
  const PublisherId publisher_b = id_from<PublisherId>("fdr/test/multiprocess/publisher/b");
  const PublisherId publisher_o = id_from<PublisherId>("fdr/test/multiprocess/publisher/o");
  const WorkerBootId boot_a = id_from<WorkerBootId>("fdr/test/multiprocess/boot/a/1");
  const WorkerBootId boot_a2 = id_from<WorkerBootId>("fdr/test/multiprocess/boot/a/2");
  const WorkerBootId boot_b = id_from<WorkerBootId>("fdr/test/multiprocess/boot/b/1");
  const WorkerBootId boot_o = id_from<WorkerBootId>("fdr/test/multiprocess/boot/o/1");
  // The observer's first incarnation is fenced when the first coordinator stops,
  // and a fence is durable, so the restarted coordinator needs a fresh one.
  const WorkerBootId boot_o2 = id_from<WorkerBootId>("fdr/test/multiprocess/boot/o/2");

  const EntityRef member_a(EntityClass::Switch, entity_bytes_from("fdr/test/member/a"),
                           EntityGeneration(1));
  const EntityRef member_b(EntityClass::Switch, entity_bytes_from("fdr/test/member/b"),
                           EntityGeneration(1));

  const std::vector<std::string> grants{
      "--grant", publisher_a.to_string() + ":rack:administrative-declaration:dc1",
      "--grant", publisher_b.to_string() + ":pdu:direct-hardware-controller:dc1",
      "--grant", publisher_o.to_string() + ":rack,pdu:administrative-declaration:dc1",
  };

  // -------------------------------------------------------------------------
  // 1. The coordinator is a real child process on a temporary state file.
  // -------------------------------------------------------------------------

  std::vector<std::string> coordinator_arguments{"--bind", "127.0.0.1", "--port", "0", "--state",
                                                 state_path};
  coordinator_arguments.insert(coordinator_arguments.end(), grants.begin(), grants.end());

  fdrtest::ChildProcess coordinator;
  std::string listing;
  std::string why;
  FDR_CHECK_MSG(start_child(coordinator_program, coordinator_arguments, "listening ", &coordinator,
                            &listing, &why),
                why);
  const std::optional<Endpoint> endpoint = endpoint_from_listing(listing);
  FDR_CHECK_MSG(endpoint.has_value(), "the coordinator did not report a parseable endpoint: " +
                                          listing);
  const std::optional<CoordinatorEpoch> first_epoch = epoch_from_listing(listing);
  FDR_CHECK_MSG(first_epoch.has_value(),
                "the coordinator did not report an epoch: " + listing);
  FDR_CHECK_MSG(first_epoch->value() >= 1u, "the first coordinator epoch must be established");
  FDR_CHECK_MSG(fdrtest::ChildProcess::wait_for_file(state_path, 30000),
                "the coordinator never wrote its state file");

  // 2. A real client connects over loopback. It is the observation channel.
  PublisherClient observer(observer_config(*endpoint, publisher_o, boot_o));
  {
    const Outcome attached = observer.connect();
    FDR_CHECK_MSG(attached.succeeded(),
                  "the observer could not attach: " + attached.render());
    FDR_CHECK_EQ(attached.epoch->value(), first_epoch->value());
  }
  std::string rendered;
  FDR_CHECK_EQ(observer.query_status(&rendered).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(status_number(rendered, "domains"), std::size_t{0});
  const std::size_t fences_before_kill = status_number(rendered, "fences");

  // -------------------------------------------------------------------------
  // 3./4. Two real publisher processes, each with its own publisher id and boot.
  // -------------------------------------------------------------------------

  const std::string endpoint_text = endpoint->to_string();
  fdrtest::ChildProcess publisher_a_process;
  FDR_CHECK_MSG(
      start_child(publisher_program,
                  {"--endpoint", endpoint_text, "--publisher", publisher_a.to_string(), "--boot",
                   boot_a.to_string(), "--label", "publisher-a", "--evidence",
                   "administrative-declaration"},
                  "OK CONNECTED", &publisher_a_process, nullptr, &why),
      why);
  fdrtest::ChildProcess publisher_b_process;
  FDR_CHECK_MSG(
      start_child(publisher_program,
                  {"--endpoint", endpoint_text, "--publisher", publisher_b.to_string(), "--boot",
                   boot_b.to_string(), "--label", "publisher-b", "--evidence",
                   "direct-hardware-controller"},
                  "OK CONNECTED", &publisher_b_process, nullptr, &why),
      why);

  // -------------------------------------------------------------------------
  // 5. A creates a Rack domain in scope dc1 and attaches a switch member.
  // -------------------------------------------------------------------------

  std::string result;
  FDR_CHECK_MSG(run_command(publisher_a_process, "create-domain-id rack dc1 rack-r7", &result, &why),
                why);
  FDR_CHECK_MSG(result.rfind("OK DOMAIN-ID ", 0) == 0,
                "create-domain-id answered: " + result);
  const std::optional<FailureDomainId> rack =
      FailureDomainId::parse(result.substr(std::string("OK DOMAIN-ID ").size()));
  FDR_CHECK_MSG(rack.has_value(), "the publisher printed an unparseable domain id: " + result);
  FDR_CHECK_EQ(*rack, domain_id_for("dc1", DomainClassRef(DomainClass::Rack), "rack-r7"));

  FDR_CHECK_MSG(run_command(publisher_a_process, "create rack dc1 rack-r7 rack-r7", &result, &why),
                why);
  FDR_CHECK_MSG(result.rfind("OK COMMITTED", 0) == 0, "create answered: " + result);
  FDR_CHECK_MSG(run_command(publisher_a_process,
                            "attach " + rack->to_string() + " " + member_a.to_string(), &result,
                            &why),
                why);
  FDR_CHECK_MSG(result.rfind("OK COMMITTED", 0) == 0, "attach answered: " + result);

  // -------------------------------------------------------------------------
  // 6. B creates an unrelated Pdu domain in the same scope and attaches an
  //    unrelated switch member.
  // -------------------------------------------------------------------------

  FDR_CHECK_MSG(run_command(publisher_b_process, "create-domain-id pdu dc1 pdu-p3-a", &result, &why),
                why);
  FDR_CHECK_MSG(result.rfind("OK DOMAIN-ID ", 0) == 0,
                "create-domain-id answered: " + result);
  const std::optional<FailureDomainId> pdu =
      FailureDomainId::parse(result.substr(std::string("OK DOMAIN-ID ").size()));
  FDR_CHECK_MSG(pdu.has_value(), "the publisher printed an unparseable domain id: " + result);
  FDR_CHECK_MSG(!(*pdu == *rack), "two different classes must address two different domains");

  FDR_CHECK_MSG(run_command(publisher_b_process, "create pdu dc1 pdu-p3-a pdu-p3-a", &result, &why),
                why);
  FDR_CHECK_MSG(result.rfind("OK COMMITTED", 0) == 0, "create answered: " + result);
  FDR_CHECK_MSG(run_command(publisher_b_process,
                            "attach " + pdu->to_string() + " " + member_b.to_string(), &result,
                            &why),
                why);
  FDR_CHECK_MSG(result.rfind("OK COMMITTED", 0) == 0, "attach answered: " + result);

  // -------------------------------------------------------------------------
  // 7. Both classifications are visible as CURRENT through real queries.
  // -------------------------------------------------------------------------

  FDR_CHECK_EQ(observer.query_domain(*rack, &rendered).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(field_of(rendered, "lifecycle"), std::string("CURRENT"));
  FDR_CHECK_EQ(observer.query_domain(*pdu, &rendered).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(field_of(rendered, "lifecycle"), std::string("CURRENT"));

  std::string members;
  FDR_CHECK_EQ(observer.query_domain_members(*rack, &members).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(count_member_lines(members), std::size_t{1});
  FDR_CHECK_EQ(lifecycle_of_member(members, member_a.to_string()), std::string("CURRENT"));
  FDR_CHECK_EQ(observer.query_domain_members(*pdu, &members).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(count_member_lines(members), std::size_t{1});
  FDR_CHECK_EQ(lifecycle_of_member(members, member_b.to_string()), std::string("CURRENT"));

  FDR_CHECK_EQ(observer.query_status(&rendered).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(status_number(rendered, "domains"), std::size_t{2});
  FDR_CHECK_EQ(status_number(rendered, "memberships"), std::size_t{2});
  FDR_CHECK_EQ(status_number(rendered, "fences"), fences_before_kill);

  // The membership identity is deterministic and does not depend on the
  // publisher, the incarnation or the arrival order.
  const MembershipId expected_membership = membership_id_for(
      MembershipKey{*rack, member_a.id(), member_a.generation(), MembershipKind::Direct});
  FDR_CHECK_MSG(fdrtest::ChildProcess::copy_file(state_path, before_path),
                "the pre-kill image could not be copied");
  {
    Registry image;
    std::string image_why;
    FDR_CHECK_MSG(load_image(before_path, &image, &image_why), image_why);
    const std::vector<Membership> memberships = image.members_of(*rack);
    FDR_CHECK_EQ(memberships.size(), std::size_t{1});
    FDR_CHECK_EQ(memberships.front().id, expected_membership);
    FDR_CHECK_EQ(memberships.front().lifecycle, MembershipLifecycle::Current);
  }

  // -------------------------------------------------------------------------
  // 8. A is killed for real. TerminateProcess runs no shutdown path in the
  //    child, so the coordinator only learns about it through the socket.
  // -------------------------------------------------------------------------

  {
    std::string error;
    FDR_CHECK_MSG(publisher_a_process.kill(error), "publisher A could not be killed: " + error);
    const int code = publisher_a_process.wait(error);
    FDR_CHECK_MSG(code != -1, "publisher A never exited: " + error);
    FDR_CHECK_MSG(!publisher_a_process.running(), "publisher A is still running after the kill");
  }

  // -------------------------------------------------------------------------
  // 9. The coordinator fences the dead incarnation through the real control
  //    path, and B's unrelated membership is untouched.
  // -------------------------------------------------------------------------

  const bool fenced =
      wait_for(
          [&]() {
            std::string status;
            if (!observer.query_status(&status).succeeded()) {
              return false;
            }
            return status_number(status, "fences") > fences_before_kill;
          },
          30000);
  FDR_CHECK_MSG(fenced,
                "the coordinator never recorded a fence for the killed incarnation");

  FDR_CHECK_EQ(observer.query_status(&rendered).code, OutcomeCode::Committed);
  const std::size_t fences_after_kill = status_number(rendered, "fences");
  FDR_CHECK_MSG(fences_after_kill > fences_before_kill,
               "the fence list did not grow: " + rendered);

  FDR_CHECK_EQ(observer.query_domain_members(*rack, &members).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(count_member_lines(members), std::size_t{1});
  FDR_CHECK_EQ(lifecycle_of_member(members, member_a.to_string()),
              std::string("REVALIDATION_REQUIRED"));
  FDR_CHECK_EQ(observer.query_domain_members(*pdu, &members).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(count_member_lines(members), std::size_t{1});
  FDR_CHECK_EQ(lifecycle_of_member(members, member_b.to_string()), std::string("CURRENT"));
  FDR_CHECK_EQ(observer.query_status(&rendered).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(status_number(rendered, "memberships"), std::size_t{2});

  // -------------------------------------------------------------------------
  // 10. Traffic from the dead incarnation and from a non-current epoch.
  // -------------------------------------------------------------------------

  {
    fdrtest::ChildProcess replay;
    FDR_CHECK_MSG(start_child(publisher_program,
                              {"--endpoint", endpoint_text, "--publisher", publisher_a.to_string(),
                               "--boot", boot_a.to_string(), "--label", "publisher-a",
                               "--evidence", "administrative-declaration"},
                              "ERR ", &replay, nullptr, &why),
                  why);
    std::string error;
    const int code = replay.wait(error);
    FDR_CHECK_MSG(code == 1, "a rejected attach must exit 1, saw " + std::to_string(code));
    FDR_CHECK_MSG(replay.output().find("ERR STALE_WORKER_BOOT") != std::string::npos,
                 "the fenced incarnation was not rejected: " + replay.output());
    FDR_CHECK_MSG(!replay.running(), "the replay process is still running");
  }

  {
    // Epoch zero is the epoch the registry held before any coordinator started,
    // so it is never the current one.
    fdrtest::ChildProcess stale_epoch;
    FDR_CHECK_MSG(start_child(publisher_program,
                              {"--endpoint", endpoint_text, "--publisher", publisher_b.to_string(),
                               "--boot", boot_b.to_string(), "--label", "publisher-b",
                               "--evidence", "direct-hardware-controller", "--fixed-epoch", "0"},
                              "ERR ", &stale_epoch, nullptr, &why),
                  why);
    std::string error;
    static_cast<void>(stale_epoch.wait(error));
    FDR_CHECK_MSG(stale_epoch.output().find("ERR STALE_EPOCH") != std::string::npos,
                 "a non-current epoch was not rejected: " + stale_epoch.output());
    FDR_CHECK_MSG(!stale_epoch.running(), "the stale-epoch process is still running");
  }

  // B kept its session and its authority throughout.
  FDR_CHECK_EQ(observer.query_domain_members(*pdu, &members).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(lifecycle_of_member(members, member_b.to_string()), std::string("CURRENT"));

  // -------------------------------------------------------------------------
  // 11. A' is a fresh incarnation of publisher A. It attaches, cannot revive
  //     the dead incarnation's evidence by replay, re-publishes, and does not
  //     create a second membership.
  // -------------------------------------------------------------------------

  fdrtest::ChildProcess publisher_a2;
  FDR_CHECK_MSG(
      start_child(publisher_program,
                  {"--endpoint", endpoint_text, "--publisher", publisher_a.to_string(), "--boot",
                   boot_a2.to_string(), "--label", "publisher-a", "--evidence",
                   "administrative-declaration"},
                  "OK CONNECTED", &publisher_a2, nullptr, &why),
      why);

  // A plain re-attach is idempotent: it does not restore authority to the
  // evidence the fenced incarnation published.
  FDR_CHECK_MSG(run_command(publisher_a2, "attach " + rack->to_string() + " " + member_a.to_string(),
                            &result, &why),
                why);
  FDR_CHECK_MSG(result.rfind("OK IDEMPOTENT", 0) == 0,
               "re-attaching an existing membership answered: " + result);
  FDR_CHECK_EQ(observer.query_domain_members(*rack, &members).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(lifecycle_of_member(members, member_a.to_string()),
              std::string("REVALIDATION_REQUIRED"));

  // Re-publishing the classification is what restores authority.
  FDR_CHECK_MSG(run_command(publisher_a2,
                            "publish incremental dc1 switch " + rack->to_string() + " " +
                                member_a.to_string(),
                            &result, &why),
                why);
  FDR_CHECK_MSG(result.rfind("OK COMMITTED", 0) == 0, "publish answered: " + result);

  FDR_CHECK_EQ(observer.query_domain_members(*rack, &members).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(count_member_lines(members), std::size_t{1});
  FDR_CHECK_EQ(lifecycle_of_member(members, member_a.to_string()), std::string("CURRENT"));
  FDR_CHECK_EQ(observer.query_status(&rendered).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(status_number(rendered, "memberships"), std::size_t{2});
  // Publisher A'' and publisher B are attached, and this observer is the third
  // live session. The dead incarnation''s session is gone.
  FDR_CHECK_EQ(status_number(rendered, "live-sessions"), std::size_t{3});

  FDR_CHECK_MSG(fdrtest::ChildProcess::copy_file(state_path, after_path),
                "the post-recovery image could not be copied");
  {
    Registry image;
    std::string image_why;
    FDR_CHECK_MSG(load_image(after_path, &image, &image_why), image_why);
    const std::vector<Membership> memberships = image.members_of(*rack);
    FDR_CHECK_EQ(memberships.size(), std::size_t{1});
    FDR_CHECK_EQ(memberships.front().id, expected_membership);
    FDR_CHECK_EQ(memberships.front().lifecycle, MembershipLifecycle::Current);
    FDR_CHECK_EQ(memberships.front().member, member_a);
    FDR_CHECK_MSG(image.live_sessions().empty(),
                  "a loaded image never restores a live session");
    FDR_CHECK_MSG(fence_recorded(image, publisher_a, boot_a),
                  "the dead incarnation is not in the durable fence list");
    FDR_CHECK_MSG(!fence_recorded(image, publisher_a, boot_a2),
                  "the fresh incarnation must not be fenced");
    std::string state_why;
    FDR_CHECK_MSG(image.validate_state(&state_why), "the recovered image is inconsistent: " + state_why);
  }

  // -------------------------------------------------------------------------
  // 12. The coordinator is restarted on the same durable image.
  // -------------------------------------------------------------------------

  {
    std::string error;
    FDR_CHECK_MSG(coordinator.write_stdin("stop\n", error),
                  "the coordinator stop command could not be sent: " + error);
    // Publisher A', publisher B and the observer are all still attached and idle
    // when stop() runs, so every session thread is parked in a blocking receive
    // and the shutdown still has to be prompt.
    const int code = coordinator.wait(error);
    FDR_CHECK_MSG(code == 0, "the coordinator exited with " + std::to_string(code) + ": " +
                                coordinator.output());
    FDR_CHECK_MSG(coordinator.output().find("stopped COMMITTED") != std::string::npos,
                 "the coordinator did not stop cleanly: " + coordinator.output());
    FDR_CHECK_MSG(!coordinator.running(), "the first coordinator is still running");
  }

  fdrtest::ChildProcess restarted;
  std::string restart_listing;
  FDR_CHECK_MSG(start_child(coordinator_program, coordinator_arguments, "listening ", &restarted,
                            &restart_listing, &why),
                why);
  const std::optional<Endpoint> restart_endpoint = endpoint_from_listing(restart_listing);
  FDR_CHECK_MSG(restart_endpoint.has_value(),
                "the restarted coordinator reported no endpoint: " + restart_listing);
  const std::optional<CoordinatorEpoch> second_epoch = epoch_from_listing(restart_listing);
  FDR_CHECK_MSG(second_epoch.has_value(), "the restarted coordinator reported no epoch");
  FDR_CHECK_EQ(second_epoch->value(), first_epoch->value() + 1u);

  PublisherClient restarted_observer(observer_config(*restart_endpoint, publisher_o, boot_o2));
  {
    const Outcome attached = restarted_observer.connect();
    FDR_CHECK_MSG(attached.succeeded(),
                  "the observer could not attach to the restarted coordinator: " +
                      attached.render());
    FDR_CHECK_EQ(attached.epoch->value(), second_epoch->value());
  }

  // No live session was restored: reading the image the restarted coordinator
  // wrote shows an empty session list, and the live status shows only the
  // observer's own connection.
  FDR_CHECK_MSG(fdrtest::ChildProcess::wait_for_file(state_path, 30000),
                "the restarted coordinator never wrote its state file");
  {
    Registry image;
    std::string image_why;
    FDR_CHECK_MSG(load_image(state_path, &image, &image_why), image_why);
    FDR_CHECK_MSG(image.live_sessions().empty(),
                 "a restart must not restore a live session");
    FDR_CHECK_EQ(image.epoch().value(), second_epoch->value());
    FDR_CHECK_MSG(image.validate_state(&image_why),
                 "the restarted image is inconsistent: " + image_why);
  }
  FDR_CHECK_EQ(restarted_observer.query_status(&rendered).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(status_number(rendered, "live-sessions"), std::size_t{1});

  // The durable classification survived the restart as authority.
  FDR_CHECK_EQ(restarted_observer.query_domain(*rack, &rendered).code, OutcomeCode::Committed);
  FDR_CHECK_MSG(rendered.find(rack->to_string()) != std::string::npos,
               "the rack domain did not survive the restart: " + rendered);
  FDR_CHECK_EQ(field_of(rendered, "lifecycle"), std::string("CURRENT"));

  // Process-bound classification did not: publisher B was fenced when the first
  // coordinator stopped, and its domain lost authority.
  FDR_CHECK_EQ(restarted_observer.query_domain(*pdu, &rendered).code, OutcomeCode::Committed);
  FDR_CHECK_MSG(field_of(rendered, "lifecycle") == std::string("REVALIDATION_REQUIRED"),
               "process-bound classification must not survive a coordinator restart: " + rendered);

  // Old-epoch traffic is rejected through the real control path.
  {
    fdrtest::ChildProcess stale_epoch;
    FDR_CHECK_MSG(
        start_child(publisher_program,
                    {"--endpoint", restart_endpoint->to_string(), "--publisher",
                     publisher_b.to_string(), "--boot", boot_b.to_string(), "--label",
                     "publisher-b", "--evidence", "direct-hardware-controller", "--fixed-epoch",
                     first_epoch->to_string()},
                    "ERR ", &stale_epoch, nullptr, &why),
        why);
    std::string error;
    static_cast<void>(stale_epoch.wait(error));
    FDR_CHECK_MSG(stale_epoch.output().find("ERR STALE_EPOCH") != std::string::npos,
                 "previous-epoch traffic was not rejected: " + stale_epoch.output());
    FDR_CHECK_MSG(!stale_epoch.running(), "the stale-epoch process is still running");
  }

  // A fresh incarnation at the current epoch still attaches and can act.
  {
    const WorkerBootId boot_b2 = id_from<WorkerBootId>("fdr/test/multiprocess/boot/b/2");
    fdrtest::ChildProcess fresh_b;
    FDR_CHECK_MSG(
        start_child(publisher_program,
                    {"--endpoint", restart_endpoint->to_string(), "--publisher",
                     publisher_b.to_string(), "--boot", boot_b2.to_string(), "--label",
                     "publisher-b", "--evidence", "direct-hardware-controller"},
                    "OK CONNECTED", &fresh_b, nullptr, &why),
        why);
    FDR_CHECK_MSG(run_command(fresh_b, "status", &result, &why), why);
    FDR_CHECK_MSG(result.rfind("OK STATUS", 0) == 0, "status answered: " + result);

    // -----------------------------------------------------------------------
    // Cleanup: every child is stopped, every handle is closed and no orphan is
    // left behind.
    // -----------------------------------------------------------------------

    std::string error;
    FDR_CHECK_MSG(restarted.write_stdin("stop\n", error),
                  "the restarted coordinator stop command could not be sent: " + error);
    const int code = restarted.wait(error);
    FDR_CHECK_MSG(code == 0, "the restarted coordinator exited with " + std::to_string(code));
    FDR_CHECK_MSG(!restarted.running(), "the restarted coordinator is still running");
    FDR_CHECK_MSG(fresh_b.kill(error), "the fresh publisher B could not be killed");
    static_cast<void>(fresh_b.wait(error));
    FDR_CHECK_MSG(!fresh_b.running(), "the fresh publisher B is still running");
    const Outcome restarted_detached = restarted_observer.close();
    FDR_CHECK_MSG(restarted_detached.succeeded(),
                  "the restarted observer could not detach: " + restarted_detached.render());
  }

  {
    std::string error;
    if (publisher_a2.running()) {
      static_cast<void>(publisher_a2.kill(error));
      static_cast<void>(publisher_a2.wait(error));
    }
    if (publisher_b_process.running()) {
      static_cast<void>(publisher_b_process.kill(error));
      static_cast<void>(publisher_b_process.wait(error));
    }
    FDR_CHECK_MSG(!publisher_a2.running(), "publisher A' is still running");
    FDR_CHECK_MSG(!publisher_b_process.running(), "publisher B is still running");
    FDR_CHECK_MSG(!publisher_a_process.running(), "the killed publisher A came back");
    FDR_CHECK_MSG(!coordinator.running(), "the first coordinator came back");
    FDR_CHECK_MSG(!restarted.running(), "the restarted coordinator came back");
  }

  {
    const Outcome detached = observer.close();
    FDR_CHECK_MSG(detached.succeeded(), "the observer could not detach: " + detached.render());
  }
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
