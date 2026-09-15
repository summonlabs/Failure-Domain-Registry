// Failure Domain Registry - the framed control protocol codec.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "failure_domain_registry/frame.hpp"

#include "byte_codec.hpp"
#include "failure_domain_registry/digest.hpp"
#include "failure_domain_registry/version.hpp"

namespace failure_domain_registry {

std::string_view to_string(MessageType value) noexcept {
  switch (value) {
    case MessageType::Hello: return "hello";
    case MessageType::HelloAck: return "hello-ack";
    case MessageType::Mutate: return "mutate";
    case MessageType::Query: return "query";
    case MessageType::Response: return "response";
    case MessageType::Heartbeat: return "heartbeat";
    case MessageType::Bye: return "bye";
    default: return "unknown";
  }
}

bool is_valid_message_type(MessageType value) noexcept {
  return value != MessageType::Unknown &&
         static_cast<std::uint16_t>(value) <= static_cast<std::uint16_t>(MessageType::Bye);
}

std::uint32_t frame_integrity(std::string_view payload) noexcept {
  const DigestBytes digest = sha256(payload);
  return static_cast<std::uint32_t>(digest[0]) | (static_cast<std::uint32_t>(digest[1]) << 8) |
         (static_cast<std::uint32_t>(digest[2]) << 16) |
         (static_cast<std::uint32_t>(digest[3]) << 24);
}

Outcome encode_frame(MessageType type, std::uint64_t sequence, std::string_view payload,
                     std::size_t max_payload, std::string& out) {
  if (!is_valid_message_type(type)) {
    return Outcome::make(OutcomeCode::ProtocolViolation, "message type is not valid");
  }
  if (payload.size() > max_payload || payload.size() > hard_limits::kMaxFramePayloadBytes) {
    return Outcome::make(OutcomeCode::ResourceLimit, "frame payload exceeds the configured bound");
  }
  codec::Writer header;
  header.u32(kFrameMagic);
  header.u16(static_cast<std::uint16_t>(kWireProtocolVersion));
  header.u16(static_cast<std::uint16_t>(type));
  header.u32(0);
  header.u32(static_cast<std::uint32_t>(payload.size()));
  header.u64(sequence);
  header.u32(frame_integrity(payload));
  if (header.size() != kFrameHeaderBytes) {
    return Outcome::make(OutcomeCode::InternalFailure, "frame header width is wrong");
  }
  out.assign(header.buffer());
  out.append(payload.data(), payload.size());
  return Outcome::make(OutcomeCode::Committed, "frame encoded");
}

Outcome decode_frame_header(std::string_view bytes, const FrameLimits& limits, FrameHeader* header) {
  if (bytes.size() < kFrameHeaderBytes) {
    return Outcome::make(OutcomeCode::ProtocolViolation, "frame header is incomplete");
  }
  codec::Reader reader(bytes.substr(0, kFrameHeaderBytes));
  std::uint32_t magic = 0;
  std::uint16_t version = 0;
  std::uint16_t type = 0;
  std::uint32_t flags = 0;
  std::uint32_t payload_bytes = 0;
  std::uint64_t sequence = 0;
  std::uint32_t integrity = 0;
  if (!reader.u32(&magic) || !reader.u16(&version) || !reader.u16(&type) || !reader.u32(&flags) ||
      !reader.u32(&payload_bytes) || !reader.u64(&sequence) || !reader.u32(&integrity)) {
    return Outcome::make(OutcomeCode::ProtocolViolation, "frame header is truncated");
  }
  if (magic != kFrameMagic) {
    return Outcome::make(OutcomeCode::ProtocolViolation, "frame magic does not match");
  }
  if (version != static_cast<std::uint16_t>(kWireProtocolVersion)) {
    return Outcome::make(OutcomeCode::ProtocolViolation, "wire protocol version is not supported");
  }
  if (flags != 0) {
    return Outcome::make(OutcomeCode::ProtocolViolation, "frame declares reserved flags");
  }
  if (!is_valid_message_type(static_cast<MessageType>(type))) {
    return Outcome::make(OutcomeCode::ProtocolViolation, "frame message type is not valid");
  }
  if (static_cast<std::size_t>(payload_bytes) > limits.max_payload_bytes ||
      static_cast<std::size_t>(payload_bytes) > hard_limits::kMaxFramePayloadBytes) {
    return Outcome::make(OutcomeCode::ResourceLimit, "frame declares an oversized payload");
  }
  header->magic = magic;
  header->version = version;
  header->type = static_cast<MessageType>(type);
  header->flags = flags;
  header->payload_bytes = payload_bytes;
  header->sequence = sequence;
  header->integrity = integrity;
  return Outcome::make(OutcomeCode::Committed, "frame header decoded");
}

Outcome decode_frame(std::string_view bytes, const FrameLimits& limits, FrameHeader* header,
                     std::string_view* payload, std::size_t* consumed) {
  Outcome header_result = decode_frame_header(bytes, limits, header);
  if (!header_result.committed()) {
    return header_result;
  }
  const std::size_t total = kFrameHeaderBytes + static_cast<std::size_t>(header->payload_bytes);
  if (bytes.size() < total) {
    return Outcome::make(OutcomeCode::ProtocolViolation, "frame payload is incomplete");
  }
  const std::string_view body = bytes.substr(kFrameHeaderBytes,
                                              static_cast<std::size_t>(header->payload_bytes));
  if (frame_integrity(body) != header->integrity) {
    return Outcome::make(OutcomeCode::IntegrityFailure, "frame integrity check failed");
  }
  *payload = body;
  *consumed = total;
  return Outcome::make(OutcomeCode::Committed, "frame decoded");
}

} // namespace failure_domain_registry
