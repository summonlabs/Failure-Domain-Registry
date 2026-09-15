// Failure Domain Registry — minimal dependency-free test harness.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every test translation unit includes this header; the definitions live in
// tests/support/test_harness.cpp. There is deliberately no dependency on any
// test framework: the harness is a case registry, a failure signal and a
// deterministic generator.

#ifndef FAILURE_DOMAIN_REGISTRY_TESTS_SUPPORT_TEST_HARNESS_HPP
#define FAILURE_DOMAIN_REGISTRY_TESTS_SUPPORT_TEST_HARNESS_HPP

#include <cstddef>
#include <cstdint>
#include <string>

namespace fdrtest {

using TestFn = void (*)();

/// Registers one case. Safe to call from a static initializer.
void register_case(const char* suite, const char* name, TestFn fn);

/// Records the failure of the running case and aborts it. Never returns.
void fail(const char* file, int line, const std::string& message);

/// Runs every registered case, or only the cases whose "suite.name" contains the
/// filter when one is given. "--list" prints the names instead. Returns zero
/// when no case failed.
///
/// Arguments of the form "--name value" are captured before the filter is
/// chosen, so a suite that needs external resources (the multiprocess suite
/// needs the paths of the coordinator and publisher executables) can read them
/// with option() without every test executable defining its own main.
int run_all(int argc, char** argv);

/// The value of a captured "--name value" argument, or the empty string.
const std::string& option(const std::string& name);

/// Records an option programmatically. Used by tests that build their own argv.
void set_option(const std::string& name, const std::string& value);

/// SplitMix64. Deterministic for a given seed.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) noexcept;

  std::uint64_t next_u64() noexcept;
  std::uint32_t next_u32() noexcept;
  /// Uniform value in [0, bound). The bound must be greater than zero.
  std::uint64_t below(std::uint64_t bound) noexcept;
  /// Uniform value in [lo, hi]. Returns lo when hi is not greater than lo.
  std::int64_t in_range(std::int64_t lo, std::int64_t hi) noexcept;
  /// True with probability percent/100; always false for 0 and true for 100.
  bool chance(std::uint32_t percent) noexcept;
  std::uint64_t seed() const noexcept;

 private:
  std::uint64_t state_;
  std::uint64_t seed_;
};

/// Deterministic lowercase alphanumeric text of exactly the requested length.
std::string random_text(Rng& rng, std::size_t length);

} // namespace fdrtest

/// Defines a test case and registers it at load time.
#define FDR_TEST_CASE(suite, name)                                                \
  static void fdrtest_case_##suite##_##name();                                    \
  namespace {                                                                     \
  const bool fdrtest_registered_##suite##_##name =                                \
      (::fdrtest::register_case(#suite, #name, &fdrtest_case_##suite##_##name),   \
       true);                                                                     \
  } /* namespace */                                                               \
  static void fdrtest_case_##suite##_##name()

/// Aborts the running case unless the expression is true.
#define FDR_CHECK(expr)                                            \
  do {                                                             \
    if (!(expr)) {                                                 \
      ::fdrtest::fail(__FILE__, __LINE__, "check failed: " #expr); \
      return;                                                      \
    }                                                              \
  } while (0)

/// Aborts the running case unless the two operands are equal.
#define FDR_CHECK_EQ(a, b)                                                \
  do {                                                                    \
    if (!((a) == (b))) {                                                  \
      ::fdrtest::fail(__FILE__, __LINE__, "check failed: " #a " == " #b); \
      return;                                                             \
    }                                                                     \
  } while (0)

/// Aborts the running case unless the expression is true, reporting a message.
#define FDR_CHECK_MSG(expr, msg)                 \
  do {                                           \
    if (!(expr)) {                               \
      ::fdrtest::fail(__FILE__, __LINE__, (msg)); \
      return;                                    \
    }                                            \
  } while (0)

/// Aborts the running case with a message.
#define FDR_FAIL(msg)                           \
  do {                                          \
    ::fdrtest::fail(__FILE__, __LINE__, (msg)); \
    return;                                     \
  } while (0)

#endif // FAILURE_DOMAIN_REGISTRY_TESTS_SUPPORT_TEST_HARNESS_HPP
