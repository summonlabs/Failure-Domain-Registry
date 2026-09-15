// Failure Domain Registry — real operating-system process control for tests.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The multiprocess proofs must kill real processes, so this helper starts a real
// child with an independent address space, holds its standard input open so a
// command language can be driven line by line, and terminates it with the
// operating system's own forced-termination call. Nothing here simulates
// process death.

#ifndef FAILURE_DOMAIN_REGISTRY_TESTS_SUPPORT_TEST_PROCESS_HPP
#define FAILURE_DOMAIN_REGISTRY_TESTS_SUPPORT_TEST_PROCESS_HPP

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace fdrtest {

/// A running child process with captured standard output.
class ChildProcess {
 public:
  ChildProcess() noexcept;
  ~ChildProcess();
  ChildProcess(ChildProcess&& other) noexcept;
  ChildProcess& operator=(ChildProcess&& other) noexcept;
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  /// Starts \`program\` with \`arguments\`. Standard output and standard error are
  /// captured into one pipe; standard input is a pipe the parent holds open.
  static std::optional<ChildProcess> spawn(const std::string& program,
                                           const std::vector<std::string>& arguments,
                                           std::string& error);

  bool running() const noexcept;
  std::uint64_t pid() const noexcept { return pid_; }

  /// Waits for the process to exit and returns its exit code, or -1 on failure.
  int wait(std::string& error);

  /// Terminates the process immediately. This is the operating system's forced
  /// termination: no graceful shutdown path in the child runs.
  bool kill(std::string& error);

  /// Writes \`text\` to the child's standard input.
  bool write_stdin(const std::string& text, std::string& error);

  /// Closes the parent's end of the child's standard input so a child that waits
  /// for end of input can stop gracefully.
  void close_stdin();

  /// Everything the child has written to standard output and standard error so
  /// far. Safe to call while the child is still running.
  std::string output() const;

  /// Waits until the captured output contains \`needle\`, or until \`budget_ms\`
  /// elapses. Returns the accumulated output either way; \`found\` reports
  /// whether the needle appeared. A caller always asserts \`found\`.
  std::string wait_for_output(const std::string& needle, long long budget_ms, bool& found);

  /// Waits until \`path\` exists and is non-empty. Returns true when it appeared.
  static bool wait_for_file(const std::string& path, long long budget_ms);

  /// Reads a whole file. Returns false when it cannot be read.
  static bool read_file(const std::string& path, std::string& out);

  /// Writes a whole file. Returns false on failure.
  static bool write_file(const std::string& path, const std::string& text);

  /// Copies a file. Returns false when the source cannot be read.
  static bool copy_file(const std::string& from, const std::string& to);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
  std::uint64_t pid_{0};
};

/// Suspends the calling thread.
void sleep_milliseconds(long long milliseconds);

/// Creates a unique temporary directory for one test and returns its path.
std::string make_temporary_directory(const std::string& label);

/// Removes a directory and everything in it.
void remove_directory(const std::string& path);

/// Splits captured child output into lines. Used by the multiprocess suite to
/// look for the deterministic result line of one command.
std::vector<std::string> split_lines(const std::string& text);

/// True when any line of \`text\` begins with \`prefix\`.
bool has_line_with_prefix(const std::string& text, const std::string& prefix);

/// The first line beginning with \`prefix\`, or the empty string.
std::string first_line_with_prefix(const std::string& text, const std::string& prefix);

} // namespace fdrtest

#endif // FAILURE_DOMAIN_REGISTRY_TESTS_SUPPORT_TEST_PROCESS_HPP
