// Failure Domain Registry — minimal dependency-free test harness
// implementation.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "test_harness.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace fdrtest {

namespace {

struct Case {
  const char* suite;
  const char* name;
  TestFn fn;
};

// The registry is a function-local static so that a static initializer in any
// test translation unit can register without an initialization order hazard.
std::vector<Case>& registry() {
  static std::vector<Case> cases;
  return cases;
}

// Private failure signal: fail() throws it and run_all catches it, so a case
// aborts exactly at the failing check.
class CaseFailure final : public std::exception {
 public:
  const char* what() const noexcept override { return "fdrtest case failure"; }
};

struct CaseState {
  std::string message;
  bool failed = false;
};

CaseState& case_state() {
  static CaseState state;
  return state;
}

std::string qualified_name(const Case& test_case) {
  std::string name(test_case.suite);
  name.push_back('.');
  name.append(test_case.name);
  return name;
}

// Captured "--name value" arguments. Function-local static so a registration
// from another translation unit can never observe an uninitialized table.
std::map<std::string, std::string>& option_table() {
  static std::map<std::string, std::string> table;
  return table;
}

} // namespace

const std::string& option(const std::string& name) {
  static const std::string empty;
  const std::map<std::string, std::string>& table = option_table();
  const auto entry = table.find(name);
  return entry == table.end() ? empty : entry->second;
}

void set_option(const std::string& name, const std::string& value) { option_table()[name] = value; }

void register_case(const char* suite, const char* name, TestFn fn) {
  registry().push_back(Case{suite, name, fn});
}

void fail(const char* file, int line, const std::string& message) {
  CaseState& state = case_state();
  if (!state.failed) {
    state.failed = true;
    state.message.assign(file != nullptr ? file : "?");
    state.message.push_back(':');
    state.message.append(std::to_string(line));
    state.message.append(": ");
    state.message.append(message);
  }
  throw CaseFailure();
}

int run_all(int argc, char** argv) {
  // Capture every "--name value" pair first; the first remaining argument is the
  // suite filter. This lets a suite read external resources through option()
  // without any test executable defining its own main.
  std::string filter;
  bool list_only = false;
  for (int index = 1; index < argc && argv != nullptr; ++index) {
    if (argv[index] == nullptr) {
      break;
    }
    const std::string_view argument(argv[index]);
    const bool next_is_value =
        index + 1 < argc && argv[index + 1] != nullptr &&
        std::string_view(argv[index + 1]).rfind("--", 0) != 0;
    if (argument.rfind("--", 0) == 0 && argument != "--list" && next_is_value) {
      option_table()[std::string(argument)] = argv[index + 1];
      ++index;
      continue;
    }
    if (argument == "--list") {
      list_only = true;
      continue;
    }
    if (filter.empty()) {
      filter.assign(argument);
    }
  }

  if (list_only) {
    for (const Case& test_case : registry()) {
      std::printf("%s\n", qualified_name(test_case).c_str());
    }
    return 0;
  }

  int passed = 0;
  int failed = 0;
  for (const Case& test_case : registry()) {
    const std::string name = qualified_name(test_case);
    if (!filter.empty() && name.find(filter) == std::string::npos) {
      continue;
    }

    CaseState& state = case_state();
    state.message.clear();
    state.failed = false;
    try {
      test_case.fn();
    } catch (const CaseFailure&) {
      // fail() already recorded the reason; nothing is printed while unwinding.
    } catch (const std::exception& error) {
      state.failed = true;
      if (state.message.empty()) {
        state.message.assign("unexpected exception: ");
        state.message.append(error.what());
      }
    } catch (...) {
      state.failed = true;
      if (state.message.empty()) {
        state.message.assign("unexpected exception");
      }
    }

    if (state.failed) {
      ++failed;
      std::printf("%s: FAIL: %s\n", name.c_str(), state.message.c_str());
    } else {
      ++passed;
      std::printf("%s: PASS\n", name.c_str());
    }
  }

  std::printf("tests: %d passed, %d failed, %d total\n", passed, failed, passed + failed);
  return failed == 0 ? 0 : 1;
}

Rng::Rng(std::uint64_t seed) noexcept : state_(seed), seed_(seed) {}

std::uint64_t Rng::next_u64() noexcept {
  state_ += 0x9e3779b97f4a7c15ull;
  std::uint64_t value = state_;
  value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ull;
  value = (value ^ (value >> 27)) * 0x94d049bb133111ebull;
  return value ^ (value >> 31);
}

std::uint32_t Rng::next_u32() noexcept { return static_cast<std::uint32_t>(next_u64() >> 32); }

std::uint64_t Rng::below(std::uint64_t bound) noexcept {
  if (bound == 0) {
    return 0;
  }
  return next_u64() % bound;
}

std::int64_t Rng::in_range(std::int64_t lo, std::int64_t hi) noexcept {
  if (hi <= lo) {
    return lo;
  }
  const std::uint64_t span = static_cast<std::uint64_t>(hi) - static_cast<std::uint64_t>(lo);
  const std::uint64_t offset =
      span == ~static_cast<std::uint64_t>(0) ? next_u64() : below(span + 1u);
  return static_cast<std::int64_t>(static_cast<std::uint64_t>(lo) + offset);
}

bool Rng::chance(std::uint32_t percent) noexcept {
  if (percent == 0) {
    return false;
  }
  if (percent >= 100) {
    return true;
  }
  return below(100u) < percent;
}

std::uint64_t Rng::seed() const noexcept { return seed_; }

std::string random_text(Rng& rng, std::size_t length) {
  constexpr char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
  constexpr std::uint64_t kAlphabetSize = sizeof(kAlphabet) - 1u;
  std::string text;
  text.reserve(length);
  for (std::size_t i = 0; i < length; ++i) {
    text.push_back(kAlphabet[rng.below(kAlphabetSize)]);
  }
  return text;
}

} // namespace fdrtest
