// Failure Domain Registry — real operating-system process control for tests.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "test_process.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>

#if defined(_WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <csignal>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace fdrtest {

struct ChildProcess::Impl {
#if defined(_WIN32)
  HANDLE process{nullptr};
  HANDLE stdout_read{nullptr};
  HANDLE stdin_write{nullptr};
#else
  int pid{0};
  int stdout_read{-1};
  int stdin_write{-1};
#endif
  std::thread reader;
  mutable std::mutex output_mutex;
  std::string captured;
  std::atomic<bool> exited{false};
  int exit_code{-1};
};

void sleep_milliseconds(long long milliseconds) {
  if (milliseconds <= 0) {
    return;
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

#if defined(_WIN32)

namespace {

std::wstring widen(const std::string& text) {
  if (text.empty()) {
    return std::wstring();
  }
  const int size =
      MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
  std::wstring out(static_cast<std::size_t>(size), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), size);
  return out;
}

std::string quote_argument(const std::string& argument) {
  std::string out = "\"";
  for (char c : argument) {
    if (c == '"') {
      out += "\\\"";
    } else {
      out += c;
    }
  }
  out += "\"";
  return out;
}

} // namespace

ChildProcess::ChildProcess() noexcept : impl_(std::make_unique<Impl>()) {}

ChildProcess::~ChildProcess() {
  if (!impl_) {
    return;
  }
  if (impl_->process != nullptr) {
    std::string error;
    kill(error);
    wait(error);
  }
  if (impl_->reader.joinable()) {
    impl_->reader.join();
  }
  if (impl_->stdout_read != nullptr) {
    CloseHandle(impl_->stdout_read);
    impl_->stdout_read = nullptr;
  }
  if (impl_->stdin_write != nullptr) {
    CloseHandle(impl_->stdin_write);
    impl_->stdin_write = nullptr;
  }
}

ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : impl_(std::move(other.impl_)), pid_(other.pid_) {
  other.pid_ = 0;
}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
    pid_ = other.pid_;
    other.pid_ = 0;
  }
  return *this;
}

std::optional<ChildProcess> ChildProcess::spawn(const std::string& program,
                                                const std::vector<std::string>& arguments,
                                                std::string& error) {
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;

  HANDLE stdout_read = nullptr;
  HANDLE stdout_write = nullptr;
  HANDLE stdin_read = nullptr;
  HANDLE stdin_write = nullptr;
  if (CreatePipe(&stdout_read, &stdout_write, &attributes, 0) == 0) {
    error = "the child stdout pipe could not be created";
    return std::nullopt;
  }
  if (CreatePipe(&stdin_read, &stdin_write, &attributes, 0) == 0) {
    CloseHandle(stdout_read);
    CloseHandle(stdout_write);
    error = "the child stdin pipe could not be created";
    return std::nullopt;
  }
  SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);

  std::wstring command_line = widen(quote_argument(program));
  for (const std::string& argument : arguments) {
    command_line += L' ';
    command_line += widen(quote_argument(argument));
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = stdout_write;
  startup.hStdError = stdout_write;
  startup.hStdInput = stdin_read;
  PROCESS_INFORMATION information{};

  std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
  mutable_command.push_back(L'\0');

  const BOOL created = CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                                      CREATE_NO_WINDOW, nullptr, nullptr, &startup, &information);
  CloseHandle(stdout_write);
  CloseHandle(stdin_read);
  if (created == 0) {
    CloseHandle(stdout_read);
    CloseHandle(stdin_write);
    error = "the child process could not be created (windows error " +
            std::to_string(GetLastError()) + ")";
    return std::nullopt;
  }
  CloseHandle(information.hThread);

  ChildProcess child;
  child.impl_->process = information.hProcess;
  child.impl_->stdout_read = stdout_read;
  child.impl_->stdin_write = stdin_write;
  child.pid_ = static_cast<std::uint64_t>(information.dwProcessId);
  child.impl_->reader = std::thread([impl = child.impl_.get()]() {
    char buffer[4096];
    DWORD produced = 0;
    while (ReadFile(impl->stdout_read, buffer, sizeof(buffer), &produced, nullptr) != 0 &&
           produced != 0) {
      std::lock_guard<std::mutex> guard(impl->output_mutex);
      impl->captured.append(buffer, produced);
    }
  });
  return std::optional<ChildProcess>(std::move(child));
}

bool ChildProcess::running() const noexcept {
  if (!impl_ || impl_->process == nullptr) {
    return false;
  }
  return WaitForSingleObject(impl_->process, 0) == WAIT_TIMEOUT;
}

int ChildProcess::wait(std::string& error) {
  if (!impl_ || impl_->process == nullptr) {
    error = "the process has not been started";
    return -1;
  }
  if (WaitForSingleObject(impl_->process, INFINITE) != WAIT_OBJECT_0) {
    error = "waiting for the process failed";
    return -1;
  }
  DWORD code = 0;
  if (GetExitCodeProcess(impl_->process, &code) == 0) {
    error = "the process exit code could not be read";
    return -1;
  }
  if (impl_->reader.joinable()) {
    impl_->reader.join();
  }
  CloseHandle(impl_->process);
  impl_->process = nullptr;
  impl_->exit_code = static_cast<int>(code);
  return impl_->exit_code;
}

bool ChildProcess::kill(std::string& error) {
  if (!impl_ || impl_->process == nullptr) {
    error = "the process has not been started";
    return false;
  }
  if (TerminateProcess(impl_->process, 1) == 0) {
    const DWORD code = GetLastError();
    if (code != ERROR_ACCESS_DENIED) {
      error = "the process could not be terminated (windows error " + std::to_string(code) + ")";
      return false;
    }
  }
  return true;
}

bool ChildProcess::write_stdin(const std::string& text, std::string& error) {
  if (!impl_ || impl_->stdin_write == nullptr) {
    error = "the child standard input is not open";
    return false;
  }
  DWORD written = 0;
  if (WriteFile(impl_->stdin_write, text.data(), static_cast<DWORD>(text.size()), &written,
                nullptr) == 0 ||
      written != static_cast<DWORD>(text.size())) {
    error = "the child standard input could not be written";
    return false;
  }
  return true;
}

void ChildProcess::close_stdin() {
  if (impl_ && impl_->stdin_write != nullptr) {
    CloseHandle(impl_->stdin_write);
    impl_->stdin_write = nullptr;
  }
}

std::string ChildProcess::output() const {
  if (!impl_) {
    return std::string();
  }
  std::lock_guard<std::mutex> guard(impl_->output_mutex);
  return impl_->captured;
}

#else

ChildProcess::ChildProcess() noexcept : impl_(std::make_unique<Impl>()) {}

ChildProcess::~ChildProcess() {
  if (!impl_) {
    return;
  }
  if (impl_->pid > 0) {
    std::string error;
    kill(error);
    wait(error);
  }
  if (impl_->reader.joinable()) {
    impl_->reader.join();
  }
  if (impl_->stdout_read >= 0) {
    ::close(impl_->stdout_read);
  }
  if (impl_->stdin_write >= 0) {
    ::close(impl_->stdin_write);
  }
}

ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : impl_(std::move(other.impl_)), pid_(other.pid_) {
  other.pid_ = 0;
}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
    pid_ = other.pid_;
    other.pid_ = 0;
  }
  return *this;
}

std::optional<ChildProcess> ChildProcess::spawn(const std::string& program,
                                                const std::vector<std::string>& arguments,
                                                std::string& error) {
  int output_pipe[2] = {-1, -1};
  int input_pipe[2] = {-1, -1};
  if (::pipe(output_pipe) != 0 || ::pipe(input_pipe) != 0) {
    error = "the child pipes could not be created";
    return std::nullopt;
  }
  const pid_t pid = ::fork();
  if (pid < 0) {
    error = "the child process could not be forked";
    return std::nullopt;
  }
  if (pid == 0) {
    ::dup2(output_pipe[1], STDOUT_FILENO);
    ::dup2(output_pipe[1], STDERR_FILENO);
    ::dup2(input_pipe[0], STDIN_FILENO);
    ::close(output_pipe[0]);
    ::close(output_pipe[1]);
    ::close(input_pipe[0]);
    ::close(input_pipe[1]);
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(program.c_str()));
    for (const std::string& argument : arguments) {
      argv.push_back(const_cast<char*>(argument.c_str()));
    }
    argv.push_back(nullptr);
    ::execv(program.c_str(), argv.data());
    ::_exit(127);
  }
  ::close(output_pipe[1]);
  ::close(input_pipe[0]);
  ChildProcess child;
  child.impl_->pid = static_cast<int>(pid);
  child.impl_->stdout_read = output_pipe[0];
  child.impl_->stdin_write = input_pipe[1];
  child.pid_ = static_cast<std::uint64_t>(pid);
  child.impl_->reader = std::thread([impl = child.impl_.get()]() {
    char buffer[4096];
    for (;;) {
      const ssize_t produced = ::read(impl->stdout_read, buffer, sizeof(buffer));
      if (produced <= 0) {
        break;
      }
      std::lock_guard<std::mutex> guard(impl->output_mutex);
      impl->captured.append(buffer, static_cast<std::size_t>(produced));
    }
  });
  return std::optional<ChildProcess>(std::move(child));
}

bool ChildProcess::running() const noexcept {
  if (!impl_ || impl_->pid <= 0) {
    return false;
  }
  int status = 0;
  const pid_t result = ::waitpid(impl_->pid, &status, WNOHANG);
  return result == 0;
}

int ChildProcess::wait(std::string& error) {
  if (!impl_ || impl_->pid <= 0) {
    error = "the process has not been started";
    return -1;
  }
  int status = 0;
  if (::waitpid(impl_->pid, &status, 0) < 0) {
    error = "waiting for the process failed";
    return -1;
  }
  if (impl_->reader.joinable()) {
    impl_->reader.join();
  }
  impl_->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  impl_->pid = 0;
  return impl_->exit_code;
}

bool ChildProcess::kill(std::string& error) {
  if (!impl_ || impl_->pid <= 0) {
    error = "the process has not been started";
    return false;
  }
  if (::kill(impl_->pid, SIGKILL) != 0) {
    error = "the process could not be killed";
    return false;
  }
  return true;
}

bool ChildProcess::write_stdin(const std::string& text, std::string& error) {
  if (!impl_ || impl_->stdin_write < 0) {
    error = "the child standard input is not open";
    return false;
  }
  std::size_t written = 0;
  while (written < text.size()) {
    const ssize_t produced =
        ::write(impl_->stdin_write, text.data() + written, text.size() - written);
    if (produced <= 0) {
      error = "the child standard input could not be written";
      return false;
    }
    written += static_cast<std::size_t>(produced);
  }
  return true;
}

void ChildProcess::close_stdin() {
  if (impl_ && impl_->stdin_write >= 0) {
    ::close(impl_->stdin_write);
    impl_->stdin_write = -1;
  }
}

std::string ChildProcess::output() const {
  if (!impl_) {
    return std::string();
  }
  std::lock_guard<std::mutex> guard(impl_->output_mutex);
  return impl_->captured;
}

#endif

std::string ChildProcess::wait_for_output(const std::string& needle, long long budget_ms, bool& found) {
  found = false;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(budget_ms);
  for (;;) {
    const std::string captured = output();
    if (captured.find(needle) != std::string::npos) {
      found = true;
      return captured;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      return captured;
    }
    if (!running()) {
      return output();
    }
    sleep_milliseconds(10);
  }
}

bool ChildProcess::wait_for_file(const std::string& path, long long budget_ms) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(budget_ms);
  for (;;) {
    std::error_code error;
    if (std::filesystem::exists(path, error) && !error) {
      const std::uintmax_t size = std::filesystem::file_size(path, error);
      if (!error && size > 0) {
        return true;
      }
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      return false;
    }
    sleep_milliseconds(10);
  }
}

bool ChildProcess::read_file(const std::string& path, std::string& out) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return false;
  }
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  out = buffer.str();
  return true;
}

bool ChildProcess::write_file(const std::string& path, const std::string& text) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    return false;
  }
  stream << text;
  stream.flush();
  return static_cast<bool>(stream);
}

bool ChildProcess::copy_file(const std::string& from, const std::string& to) {
  std::string content;
  if (!read_file(from, content)) {
    return false;
  }
  return write_file(to, content);
}

std::string make_temporary_directory(const std::string& label) {
  const std::filesystem::path base = std::filesystem::temp_directory_path();
  static std::atomic<unsigned> counter{0};
  for (int attempt = 0; attempt < 1000; ++attempt) {
    const std::filesystem::path candidate =
        base / ("failure-domain-registry-test-" + label + "-" +
                std::to_string(counter.fetch_add(1)) + "-" + std::to_string(attempt));
    std::error_code error;
    if (std::filesystem::create_directories(candidate, error) && !error) {
      return candidate.string();
    }
  }
  return std::string();
}

void remove_directory(const std::string& path) {
  std::error_code error;
  std::filesystem::remove_all(path, error);
}

std::vector<std::string> split_lines(const std::string& text) {
  std::vector<std::string> lines;
  std::string current;
  for (char c : text) {
    if (c == '\n') {
      if (!current.empty() && current.back() == '\r') {
        current.pop_back();
      }
      lines.push_back(current);
      current.clear();
    } else {
      current.push_back(c);
    }
  }
  if (!current.empty()) {
    lines.push_back(current);
  }
  return lines;
}

bool has_line_with_prefix(const std::string& text, const std::string& prefix) {
  for (const std::string& line : split_lines(text)) {
    if (line.rfind(prefix, 0) == 0) {
      return true;
    }
  }
  return false;
}

std::string first_line_with_prefix(const std::string& text, const std::string& prefix) {
  for (const std::string& line : split_lines(text)) {
    if (line.rfind(prefix, 0) == 0) {
      return line;
    }
  }
  return std::string();
}

} // namespace fdrtest
