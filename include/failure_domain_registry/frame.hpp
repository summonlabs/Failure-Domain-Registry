// Failure Domain Registry — the framed control protocol.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A frame is:
//
//   magic      u32    0x46445231 ("FDR1")
//   version    u16    protocol version, currently 1
//   type       u16    message type
//   flags      u32    reserved, must be zero on the wire
//   payload    u32    payload length in bytes
//   sequence   u64    per connection, strictly increasing
//   integrity  u32    first four bytes of SHA-256 over the payload
//   payload    N      message body
//
// The header is exactly 28 bytes. No raw C++ object layout crosses the wire:
// payloads are written field by field by the message codec, with explicit
// widths and a trailing-byte check when a payload is decoded.

#ifndef FAILURE_DOMAIN_REGISTRY_FRAME_HPP
#define FAILURE_DOMAIN_REGISTRY_FRAME_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "failure_domain_registry/errors.hpp"
#include "failure_domain_registry/export.hpp"
#include "failure_domain_registry/limits.hpp"

namespace failure_domain_registry {

inline constexpr std::uint32_t kFrameMagic = 0x46445231u;
inline constexpr std::size_t kFrameHeaderBytes = 28;

/// Message types. The values are part of the wire protocol and never change.
enum class MessageType : std::uint16_t {
  Unknown = 0,
  /// client -> coordinator: attach this incarnation.
  Hello = 1,
  /// coordinator -> client: attach accepted or rejected.
  HelloAck = 2,
  /// client -> coordinator: a mutation request.
  Mutate = 3,
  /// client -> coordinator: a read-only query.
  Query = 4,
  /// coordinator -> client: the outcome of a mutation or query.
  Response = 5,
  /// either direction: liveness.
  Heartbeat = 6,
  /// client -> coordinator: orderly detach.
  Bye = 7,
};

FDR_API std::string_view to_string(MessageType value) noexcept;
FDR_API bool is_valid_message_type(MessageType value) noexcept;

struct FrameHeader {
  std::uint32_t magic{kFrameMagic};
  std::uint16_t version{1};
  MessageType type{MessageType::Unknown};
  std::uint32_t flags{0};
  std::uint32_t payload_bytes{0};
  std::uint64_t sequence{0};
  std::uint32_t integrity{0};
};

/// Computes the frame integrity value of a payload.
FDR_API std::uint32_t frame_integrity(std::string_view payload) noexcept;

/// Encodes one frame into `out`. Rejects payloads above `max_payload`.
FDR_API Outcome encode_frame(MessageType type,
                             std::uint64_t sequence,
                             std::string_view payload,
                             std::size_t max_payload,
                             std::string& out);

/// Decodes one frame header from the front of `bytes`.
FDR_API Outcome decode_frame_header(std::string_view bytes,
                                    const FrameLimits& limits,
                                    FrameHeader* header);

/// Decodes one complete frame. `consumed` receives the total frame size.
FDR_API Outcome decode_frame(std::string_view bytes,
                             const FrameLimits& limits,
                             FrameHeader* header,
                             std::string_view* payload,
                             std::size_t* consumed);

} // namespace failure_domain_registry

#endif // FAILURE_DOMAIN_REGISTRY_FRAME_HPP
