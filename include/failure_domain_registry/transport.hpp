// Failure Domain Registry — loopback TCP transport.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The control path is framed TCP. On Windows, shutdown(both) does not wake a
// pending blocking recv() in every stack state - a measured case left the
// receive blocked for 120 seconds until the peer closed. Every orderly teardown
// here therefore combines two mechanisms:
//
//   shutdown(both)                 the fast path: recv returns zero
//   SO_RCVTIMEO on the session     the guaranteed bound: recv returns
//                                  WSAETIMEDOUT, which is reported as "no data
//                                  yet" rather than as a failure, so the owning
//                                  thread re-checks its stop flag
//
// The socket is never closed while another thread is inside recv() on it: the
// owner observes the stop flag and closes its own handle.

#ifndef FAILURE_DOMAIN_REGISTRY_TRANSPORT_HPP
#define FAILURE_DOMAIN_REGISTRY_TRANSPORT_HPP

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "failure_domain_registry/errors.hpp"
#include "failure_domain_registry/export.hpp"

namespace failure_domain_registry {

/// A parsed "host:port" or "port" endpoint.
struct Endpoint {
  std::string host;
  std::uint16_t port{0};

  static std::optional<Endpoint> parse(std::string_view text);
  std::string to_string() const;
  friend bool operator==(const Endpoint&, const Endpoint&) = default;
};

/// A connected, blocking TCP socket. Move-only. Every operation is safe to call
/// from one thread at a time; a socket is owned by exactly one reader thread.
class FDR_API TcpSocket {
public:
  TcpSocket() noexcept;
  ~TcpSocket();
  TcpSocket(TcpSocket&& other) noexcept;
  TcpSocket& operator=(TcpSocket&& other) noexcept;
  TcpSocket(const TcpSocket&) = delete;
  TcpSocket& operator=(const TcpSocket&) = delete;

  bool valid() const noexcept;

  /// Writes every byte or reports the failure.
  Outcome send_all(std::string_view bytes);
  /// Reads exactly `size` bytes. Returns TransportFailure with an empty buffer
  /// when the peer closed cleanly before sending anything.
  Outcome recv_exact(std::size_t size, std::string* out);
  /// Reads whatever is available, up to `max_bytes`. Returns an empty string on
  /// orderly close.
  Outcome recv_some(std::size_t max_bytes, std::string* out, bool* closed);

  /// Bounds how long a blocking receive may wait for data. A receive that
  /// expires is reported as "no data yet", not as a failure, so a reader can
  /// re-check a stop flag instead of blocking indefinitely.
  Outcome set_receive_timeout(std::uint32_t milliseconds);

  /// Requests shutdown of both directions. Does not close the handle and does
  /// not block. On Windows this is the fast path and is not by itself a
  /// guarantee that a pending blocking receive returns, which is why session
  /// sockets also carry a receive timeout.
  void shutdown_both() noexcept;
  /// Closes the handle. Must only be called by the owning thread, after every
  /// other thread has left recv()/send().
  void close() noexcept;

  std::string peer_text() const;

private:
  friend FDR_API Outcome connect_to(const Endpoint& endpoint,
                                    std::uint32_t timeout_ms,
                                    TcpSocket* out);
  friend class TcpListener;
  struct Native;
  std::unique_ptr<Native> native_;
};

/// A listening socket. Move-only.
class FDR_API TcpListener {
public:
  TcpListener() noexcept;
  ~TcpListener();
  TcpListener(TcpListener&& other) noexcept;
  TcpListener& operator=(TcpListener&& other) noexcept;
  TcpListener(const TcpListener&) = delete;
  TcpListener& operator=(const TcpListener&) = delete;

  bool valid() const noexcept;
  /// Blocks until a connection arrives, the listener is shut down, or the poll
  /// interval expires. `accepted` is cleared when nothing arrived.
  Outcome accept(TcpSocket* accepted, bool* got_connection, std::uint32_t poll_ms);
  void shutdown_listen() noexcept;
  void close() noexcept;
  std::uint16_t bound_port() const noexcept;

  struct Native;

private:
  friend FDR_API Outcome listen_on(const std::string& bind_address, std::uint16_t port,
                                   std::size_t backlog, TcpListener* out);
  std::unique_ptr<Native> native_;
};

/// Connects to a loopback or explicit endpoint.
FDR_API Outcome connect_to(const Endpoint& endpoint, std::uint32_t timeout_ms, TcpSocket* out);

/// Binds `bind_address`:`port` (port 0 selects an ephemeral port).
FDR_API Outcome listen_on(const std::string& bind_address,
                          std::uint16_t port,
                          std::size_t backlog,
                          TcpListener* out);

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_TRANSPORT_HPP
