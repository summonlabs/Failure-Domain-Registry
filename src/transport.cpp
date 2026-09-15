// Failure Domain Registry - loopback TCP transport.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Teardown is deliberately explicit. A blocking recv() is woken by
// shutdown(both) on every stack this build supports; the handle is then closed
// by the thread that owns it, never while another thread is still inside
// recv(). That ordering is what keeps shutdown free of self-join and of
// use-after-close.

#include "failure_domain_registry/transport.hpp"

#include <cstring>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace failure_domain_registry {
namespace {

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;

struct WinsockGuard {
  WinsockGuard() {
    WSADATA data;
    started = WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }
  ~WinsockGuard() {
    if (started) {
      WSACleanup();
    }
  }
  bool started{false};
};

bool ensure_winsock() {
  static WinsockGuard guard;
  return guard.started;
}

void close_socket(NativeSocket socket) { ::closesocket(socket); }
int last_error() { return WSAGetLastError(); }
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;

bool ensure_winsock() { return true; }
void close_socket(NativeSocket socket) { ::close(socket); }
int last_error() { return errno; }
#endif

std::string describe_error(int code) {
  return "socket error " + std::to_string(code);
}

/// True when a failed receive means "no data arrived inside the receive
/// timeout" rather than "the transport is broken".
bool is_receive_timeout(int code) {
#ifdef _WIN32
  return code == WSAETIMEDOUT || code == WSAEWOULDBLOCK;
#else
  return code == EAGAIN || code == EWOULDBLOCK || code == EINTR;
#endif
}

} // namespace

struct TcpSocket::Native {
  NativeSocket handle{kInvalidSocket};
  std::string peer;
};

struct TcpListener::Native {
  NativeSocket handle{kInvalidSocket};
  std::uint16_t bound_port{0};
};

TcpSocket::TcpSocket() noexcept : native_(std::make_unique<Native>()) {}

TcpSocket::~TcpSocket() {
  if (native_ && native_->handle != kInvalidSocket) {
    close_socket(native_->handle);
    native_->handle = kInvalidSocket;
  }
}

TcpSocket::TcpSocket(TcpSocket&& other) noexcept : native_(std::move(other.native_)) {
  if (!native_) {
    native_ = std::make_unique<Native>();
  }
}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
  if (this != &other) {
    if (native_ && native_->handle != kInvalidSocket) {
      close_socket(native_->handle);
    }
    native_ = std::move(other.native_);
    if (!native_) {
      native_ = std::make_unique<Native>();
    }
  }
  return *this;
}

bool TcpSocket::valid() const noexcept {
  return native_ && native_->handle != kInvalidSocket;
}

Outcome TcpSocket::send_all(std::string_view bytes) {
  if (!valid()) {
    return Outcome::make(OutcomeCode::TransportFailure, "the socket is not connected");
  }
  std::size_t sent = 0;
  while (sent < bytes.size()) {
    const std::size_t remaining = bytes.size() - sent;
    const int chunk = static_cast<int>(remaining > 262144u ? 262144u : remaining);
    const int written = ::send(native_->handle, bytes.data() + sent, chunk, 0);
    if (written <= 0) {
      return Outcome::make(OutcomeCode::TransportFailure,
                           "send failed: " + describe_error(last_error()));
    }
    sent += static_cast<std::size_t>(written);
  }
  return Outcome::make(OutcomeCode::Committed, "sent");
}

Outcome TcpSocket::recv_exact(std::size_t size, std::string* out) {
  // The destination string is the receive buffer: no large stack frame and no
  // second copy.
  out->clear();
  out->resize(size);
  std::size_t filled = 0;
  while (filled < size) {
    const std::size_t remaining = size - filled;
    const int chunk = static_cast<int>(remaining > 262144u ? 262144u : remaining);
    const int got = ::recv(native_->handle, out->data() + filled, chunk, 0);
    if (got == 0) {
      out->clear();
      return Outcome::make(OutcomeCode::TransportFailure, "the peer closed the connection");
    }
    if (got < 0) {
      const int code = last_error();
      if (is_receive_timeout(code)) {
        continue;
      }
      out->clear();
      return Outcome::make(OutcomeCode::TransportFailure,
                           "receive failed: " + describe_error(code));
    }
    filled += static_cast<std::size_t>(got);
  }
  return Outcome::make(OutcomeCode::Committed, "received");
}

Outcome TcpSocket::recv_some(std::size_t max_bytes, std::string* out, bool* closed) {
  *closed = false;
  out->clear();
  const std::size_t want = max_bytes > 262144u ? 262144u : max_bytes;
  out->resize(want);
  const int got = ::recv(native_->handle, out->data(), static_cast<int>(want), 0);
  if (got == 0) {
    out->clear();
    *closed = true;
    return Outcome::make(OutcomeCode::Committed, "the peer closed the connection");
  }
  if (got < 0) {
    const int code = last_error();
    out->clear();
    if (is_receive_timeout(code)) {
      // No data arrived inside the receive timeout. That is not a failure: the
      // caller re-checks its stop flag and receives again.
      return Outcome::make(OutcomeCode::Committed, "no data inside the receive timeout");
    }
    return Outcome::make(OutcomeCode::TransportFailure,
                         "receive failed: " + describe_error(code));
  }
  out->resize(static_cast<std::size_t>(got));
  return Outcome::make(OutcomeCode::Committed, "received");
}

Outcome TcpSocket::set_receive_timeout(std::uint32_t milliseconds) {
  if (!valid()) {
    return Outcome::make(OutcomeCode::TransportFailure, "the socket is not connected");
  }
#ifdef _WIN32
  const DWORD value = static_cast<DWORD>(milliseconds);
  if (::setsockopt(native_->handle, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
    return Outcome::make(OutcomeCode::TransportFailure,
                         "cannot set the receive timeout: " + describe_error(last_error()));
  }
#else
  timeval value{};
  value.tv_sec = static_cast<long>(milliseconds / 1000u);
  value.tv_usec = static_cast<long>((milliseconds % 1000u) * 1000u);
  if (::setsockopt(native_->handle, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value)) != 0) {
    return Outcome::make(OutcomeCode::TransportFailure,
                         "cannot set the receive timeout: " + describe_error(last_error()));
  }
#endif
  return Outcome::make(OutcomeCode::Committed, "receive timeout set");
}

void TcpSocket::shutdown_both() noexcept {
  if (valid()) {
#ifdef _WIN32
    ::shutdown(native_->handle, SD_BOTH);
#else
    ::shutdown(native_->handle, SHUT_RDWR);
#endif
  }
}

void TcpSocket::close() noexcept {
  if (valid()) {
    close_socket(native_->handle);
    native_->handle = kInvalidSocket;
  }
}

std::string TcpSocket::peer_text() const {
  return native_ ? native_->peer : std::string();
}

TcpListener::TcpListener() noexcept : native_(std::make_unique<Native>()) {}

TcpListener::~TcpListener() {
  if (native_ && native_->handle != kInvalidSocket) {
    close_socket(native_->handle);
    native_->handle = kInvalidSocket;
  }
}

TcpListener::TcpListener(TcpListener&& other) noexcept : native_(std::move(other.native_)) {
  if (!native_) {
    native_ = std::make_unique<Native>();
  }
}

TcpListener& TcpListener::operator=(TcpListener&& other) noexcept {
  if (this != &other) {
    if (native_ && native_->handle != kInvalidSocket) {
      close_socket(native_->handle);
    }
    native_ = std::move(other.native_);
    if (!native_) {
      native_ = std::make_unique<Native>();
    }
  }
  return *this;
}

bool TcpListener::valid() const noexcept {
  return native_ && native_->handle != kInvalidSocket;
}

Outcome TcpListener::accept(TcpSocket* accepted, bool* got_connection, std::uint32_t poll_ms) {
  *got_connection = false;
  if (!valid()) {
    return Outcome::make(OutcomeCode::TransportFailure, "the listener is not open");
  }
  fd_set read_set;
  FD_ZERO(&read_set);
  FD_SET(native_->handle, &read_set);
  timeval timeout{};
  timeout.tv_sec = static_cast<long>(poll_ms / 1000u);
  timeout.tv_usec = static_cast<long>((poll_ms % 1000u) * 1000u);
#ifdef _WIN32
  const int ready = ::select(0, &read_set, nullptr, nullptr, &timeout);
#else
  const int ready = ::select(native_->handle + 1, &read_set, nullptr, nullptr, &timeout);
#endif
  if (ready == 0) {
    return Outcome::make(OutcomeCode::Committed, "no connection pending");
  }
  if (ready < 0) {
    return Outcome::make(OutcomeCode::TransportFailure,
                         "accept poll failed: " + describe_error(last_error()));
  }
  sockaddr_storage address{};
#ifdef _WIN32
  int address_length = static_cast<int>(sizeof(address));
#else
  socklen_t address_length = static_cast<socklen_t>(sizeof(address));
#endif
  const NativeSocket handle =
      ::accept(native_->handle, reinterpret_cast<sockaddr*>(&address), &address_length);
  if (handle == kInvalidSocket) {
    return Outcome::make(OutcomeCode::TransportFailure,
                         "accept failed: " + describe_error(last_error()));
  }
  accepted->close();
  accepted->native_->handle = handle;
  char text[64] = {};
  if (address.ss_family == AF_INET) {
    const auto* v4 = reinterpret_cast<const sockaddr_in*>(&address);
    ::inet_ntop(AF_INET, &v4->sin_addr, text, sizeof(text));
    accepted->native_->peer = std::string(text);
  } else if (address.ss_family == AF_INET6) {
    const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&address);
    ::inet_ntop(AF_INET6, &v6->sin6_addr, text, sizeof(text));
    accepted->native_->peer = std::string(text);
  } else {
    accepted->native_->peer = "unknown";
  }
  *got_connection = true;
  return Outcome::make(OutcomeCode::Committed, "connection accepted");
}

void TcpListener::shutdown_listen() noexcept {
  if (valid()) {
#ifdef _WIN32
    ::shutdown(native_->handle, SD_BOTH);
#else
    ::shutdown(native_->handle, SHUT_RDWR);
#endif
  }
}

void TcpListener::close() noexcept {
  if (valid()) {
    close_socket(native_->handle);
    native_->handle = kInvalidSocket;
  }
}

std::uint16_t TcpListener::bound_port() const noexcept {
  return native_ ? native_->bound_port : 0;
}

Outcome connect_to(const Endpoint& endpoint, std::uint32_t timeout_ms, TcpSocket* out) {
  if (!ensure_winsock()) {
    return Outcome::make(OutcomeCode::TransportFailure, "the socket library is unavailable");
  }
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  const std::string port_text = std::to_string(endpoint.port);
  addrinfo* results = nullptr;
  const int resolved =
      ::getaddrinfo(endpoint.host.empty() ? "127.0.0.1" : endpoint.host.c_str(),
                    port_text.c_str(), &hints, &results);
  if (resolved != 0 || results == nullptr) {
    return Outcome::make(OutcomeCode::TransportFailure, "cannot resolve the endpoint");
  }
  Outcome result = Outcome::make(OutcomeCode::TransportFailure, "no address could be reached");
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    const NativeSocket handle =
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (handle == kInvalidSocket) {
      continue;
    }
    bool connected = false;
    if (::connect(handle, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) == 0) {
      connected = true;
    } else {
      fd_set write_set;
      FD_ZERO(&write_set);
      FD_SET(handle, &write_set);
      timeval timeout{};
      timeout.tv_sec = static_cast<long>(timeout_ms / 1000u);
      timeout.tv_usec = static_cast<long>((timeout_ms % 1000u) * 1000u);
      const int selected = ::select(0, nullptr, &write_set, nullptr, &timeout);
      connected = selected > 0;
    }
    if (!connected) {
      close_socket(handle);
      continue;
    }
    out->close();
    out->native_->handle = handle;
    out->native_->peer = endpoint.to_string();
    result = Outcome::make(OutcomeCode::Committed, "connected");
    break;
  }
  ::freeaddrinfo(results);
  return result;
}

Outcome listen_on(const std::string& bind_address, std::uint16_t port, std::size_t backlog,
                  TcpListener* out) {
  if (!ensure_winsock()) {
    return Outcome::make(OutcomeCode::TransportFailure, "the socket library is unavailable");
  }
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  const std::string port_text = std::to_string(port);
  const std::string host = bind_address.empty() ? std::string("127.0.0.1") : bind_address;
  addrinfo* results = nullptr;
  const int resolved = ::getaddrinfo(host.c_str(), port_text.c_str(), &hints, &results);
  if (resolved != 0 || results == nullptr) {
    return Outcome::make(OutcomeCode::TransportFailure, "cannot resolve the bind address");
  }
  Outcome result = Outcome::make(OutcomeCode::TransportFailure, "cannot bind the address");
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    const NativeSocket handle =
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (handle == kInvalidSocket) {
      continue;
    }
    int reuse = 1;
    ::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&reuse), sizeof(reuse));
    if (::bind(handle, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) != 0) {
      close_socket(handle);
      continue;
    }
    if (::listen(handle, static_cast<int>(backlog)) != 0) {
      close_socket(handle);
      continue;
    }
    sockaddr_storage address{};
#ifdef _WIN32
    int address_length = static_cast<int>(sizeof(address));
#else
    socklen_t address_length = static_cast<socklen_t>(sizeof(address));
#endif
    std::uint16_t chosen_port = port;
    if (::getsockname(handle, reinterpret_cast<sockaddr*>(&address), &address_length) == 0 &&
        address.ss_family == AF_INET) {
      chosen_port = ntohs(reinterpret_cast<const sockaddr_in*>(&address)->sin_port);
    }
    out->close();
    out->native_->handle = handle;
    out->native_->bound_port = chosen_port;
    result = Outcome::make(OutcomeCode::Committed, "listening");
    break;
  }
  ::freeaddrinfo(results);
  return result;
}

std::optional<Endpoint> Endpoint::parse(std::string_view text) {
  if (text.empty()) {
    return std::nullopt;
  }
  const std::size_t colon = text.rfind(':');
  Endpoint endpoint;
  if (colon == std::string_view::npos) {
    endpoint.host = "127.0.0.1";
    const std::optional<std::uint64_t> port =
        static_cast<std::optional<std::uint64_t>>(std::nullopt);
    (void)port;
    std::uint64_t value = 0;
    for (char c : text) {
      if (c < '0' || c > '9') {
        return std::nullopt;
      }
      value = value * 10u + static_cast<std::uint64_t>(c - '0');
      if (value > 65535u) {
        return std::nullopt;
      }
    }
    if (value == 0) {
      return std::nullopt;
    }
    endpoint.port = static_cast<std::uint16_t>(value);
    return endpoint;
  }
  endpoint.host.assign(text.substr(0, colon));
  const std::string_view port_text = text.substr(colon + 1);
  if (port_text.empty() || port_text.size() > 5) {
    return std::nullopt;
  }
  std::uint64_t value = 0;
  for (char c : port_text) {
    if (c < '0' || c > '9') {
      return std::nullopt;
    }
    value = value * 10u + static_cast<std::uint64_t>(c - '0');
  }
  if (value == 0 || value > 65535u) {
    return std::nullopt;
  }
  endpoint.port = static_cast<std::uint16_t>(value);
  return endpoint;
}

std::string Endpoint::to_string() const {
  return host + ":" + std::to_string(port);
}

} // namespace failure_domain_registry
