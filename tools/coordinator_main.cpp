// Failure Domain Registry - coordinator process.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Usage:
//   fdr-coordinator [--bind ADDRESS] [--port PORT] [--state PATH]
//                   [--grant PUBLISHER:CLASS[,CLASS...]:MAX-EVIDENCE[:SCOPE]]
//                   [--no-persist] [--endpoint-file PATH]
//
// The process reports its endpoint on stdout, then serves until its standard
// input reaches end of file or the process is terminated.

#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "failure_domain_registry/failure_domain_registry.hpp"

namespace {

void usage() {
  std::fputs(
      "usage: fdr-coordinator [--bind ADDRESS] [--port PORT] [--state PATH]\n"
      "                       [--grant PUBLISHER:CLASS[,CLASS...]:MAX-EVIDENCE[:SCOPE]]\n"
      "                       [--no-persist] [--endpoint-file PATH]\n",
      stderr);
}

bool split(const std::string& text, char separator, std::vector<std::string>* parts) {
  parts->clear();
  std::string current;
  for (char c : text) {
    if (c == separator) {
      parts->push_back(current);
      current.clear();
    } else {
      current.push_back(c);
    }
  }
  parts->push_back(current);
  return true;
}

} // namespace

int main(int argc, char** argv) {
  using namespace failure_domain_registry;

  CoordinatorConfig config;
  config.load_on_start = true;
  config.save_on_commit = true;
  std::string endpoint_file;

  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    const auto value_of = [&](const char* name) -> std::string {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "fdr-coordinator: %s requires a value\n", name);
        std::exit(2);
      }
      return argv[++i];
    };
    if (argument == "--bind") {
      config.bind_address = value_of("--bind");
    } else if (argument == "--port") {
      config.port = static_cast<std::uint16_t>(std::stoi(value_of("--port")));
    } else if (argument == "--state") {
      config.persistence.path = value_of("--state");
    } else if (argument == "--no-persist") {
      config.persistence.path.clear();
      config.save_on_commit = false;
    } else if (argument == "--endpoint-file") {
      endpoint_file = value_of("--endpoint-file");
    } else if (argument == "--grant") {
      const std::string text = value_of("--grant");
      std::vector<std::string> fields;
      split(text, ':', &fields);
      if (fields.size() < 3) {
        std::fputs("fdr-coordinator: --grant wants PUBLISHER:CLASS[,CLASS...]:MAX-EVIDENCE[:SCOPE]\n",
                   stderr);
        return 2;
      }
      const std::optional<PublisherId> publisher = PublisherId::parse(fields[0]);
      const std::optional<EvidenceClass> evidence = evidence_class_from_string(fields[2]);
      if (!publisher.has_value() || !evidence.has_value()) {
        std::fputs("fdr-coordinator: --grant carries a malformed publisher or evidence class\n",
                   stderr);
        return 2;
      }
      PublisherRegistration grant;
      grant.publisher = *publisher;
      grant.name = "grant";
      grant.scope.max_evidence = *evidence;
      std::vector<std::string> classes;
      split(fields[1], ',', &classes);
      for (const std::string& name : classes) {
        const std::optional<DomainClass> klass = domain_class_from_string(name);
        if (!klass.has_value()) {
          std::fprintf(stderr, "fdr-coordinator: unknown domain class '%s'\n", name.c_str());
          return 2;
        }
        grant.scope.classes.push_back(*klass);
      }
      if (fields.size() > 3) {
        grant.scope.administrative_scope = fields[3];
      }
      config.grants.push_back(std::move(grant));
    } else if (argument == "--help" || argument == "-h") {
      usage();
      return 0;
    } else {
      std::fprintf(stderr, "fdr-coordinator: unknown argument '%s'\n", argument.c_str());
      usage();
      return 2;
    }
  }

  if (config.persistence.path.empty()) {
    config.save_on_commit = false;
  }

  Coordinator coordinator(config);
  std::string endpoint;
  const Outcome started = coordinator.start(&endpoint);
  if (!started.committed()) {
    std::fprintf(stderr, "fdr-coordinator: cannot start: %s\n", started.render().c_str());
    return 1;
  }
  std::printf("listening %s\n", endpoint.c_str());
  std::printf("epoch %s\n", coordinator.epoch().to_string().c_str());
  std::fflush(stdout);
  if (!endpoint_file.empty()) {
    std::FILE* file = nullptr;
    if (::fopen_s(&file, endpoint_file.c_str(), "wb") == 0 && file != nullptr) {
      std::fwrite(endpoint.data(), 1, endpoint.size(), file);
      std::fclose(file);
    }
  }

  std::string line;
  bool stop_requested = false;
  while (std::getline(std::cin, line)) {
    if (line == "stop") {
      stop_requested = true;
      break;
    }
    if (line == "stats") {
      std::fputs(coordinator.stats().render().c_str(), stdout);
      std::fflush(stdout);
    }
  }
  // End of file on the console is not a stop request: the coordinator is a
  // service and keeps serving until it is told to stop or the process is
  // terminated.
  while (!stop_requested) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  const Outcome stopped = coordinator.stop();
  std::printf("stopped %s\n", to_string(stopped.code).data());
  std::fflush(stdout);
  return stopped.committed() || stopped.code == OutcomeCode::Idempotent ? 0 : 1;
}
