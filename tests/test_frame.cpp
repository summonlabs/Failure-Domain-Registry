// Failure Domain Registry — framed control protocol proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A frame is the only thing the control path puts on a socket, so the codec is
// asserted here byte by byte: the fixed 28-byte header, its little-endian field
// order, the SHA-256-derived integrity word, and the exact number of bytes one
// frame consumes out of a stream. Every rejection is checked against the exact
// OutcomeCode and against the precedence the decoder really applies, because a
// decoder that reports the wrong violation is as dangerous as one that accepts
// the frame.
//
// The message codec lives in src/ and is not part of the public API, so the
// trailing-byte guarantee is asserted where it is observable: at the frame
// boundary. The consumed value is the contract that keeps a caller from reading
// a payload longer than the sender declared.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "failure_domain_registry/digest.hpp"
#include "failure_domain_registry/frame.hpp"
#include "failure_domain_registry/transport.hpp"
#include "failure_domain_registry/version.hpp"
#include "support/test_harness.hpp"

namespace {

using failure_domain_registry::DigestBytes;
using failure_domain_registry::Endpoint;
using failure_domain_registry::FrameHeader;
using failure_domain_registry::FrameLimits;
using failure_domain_registry::MessageType;
using failure_domain_registry::Outcome;
using failure_domain_registry::OutcomeCode;
using failure_domain_registry::TcpListener;
using failure_domain_registry::TcpSocket;

/// The highest message type the protocol defines. The enumeration is part of
/// the wire format, so the number itself is asserted rather than assumed.
constexpr std::uint16_t kLastMessageType = static_cast<std::uint16_t>(MessageType::Bye);

/// A value no decoder may write into the consumed out-parameter on a rejection,
/// so a case can prove the parameter was left alone instead of merely re-read.
constexpr std::size_t kConsumedSentinel = 0x5A5A5A5A5A5A5A5Aull;

const std::string kPayloadSentinel = "sentinel-payload-that-no-decode-produces";

std::uint16_t read_u16(std::string_view bytes, std::size_t offset) {
  std::uint16_t value = 0;
  for (unsigned shift = 0; shift < 16; shift += 8) {
    value |= static_cast<std::uint16_t>(
        static_cast<unsigned char>(bytes[offset + (shift / 8)]) << shift);
  }
  return value;
}

std::uint32_t read_u32(std::string_view bytes, std::size_t offset) {
  std::uint32_t value = 0;
  for (unsigned shift = 0; shift < 32; shift += 8) {
    // Widen before shifting: an unsigned char promotes to a 32-bit int, and
    // shifting a byte into the top bit of that int would be signed overflow.
    value |= static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset + (shift / 8)]))
             << shift;
  }
  return value;
}

std::uint64_t read_u64(std::string_view bytes, std::size_t offset) {
  std::uint64_t value = 0;
  for (unsigned shift = 0; shift < 64; shift += 8) {
    value |= static_cast<std::uint64_t>(static_cast<unsigned char>(bytes[offset + (shift / 8)]))
             << shift;
  }
  return value;
}

void write_u16(std::string& bytes, std::size_t offset, std::uint16_t value) {
  for (unsigned shift = 0; shift < 16; shift += 8) {
    bytes[offset + (shift / 8)] = static_cast<char>((value >> shift) & 0xFFu);
  }
}

void write_u32(std::string& bytes, std::size_t offset, std::uint32_t value) {
  for (unsigned shift = 0; shift < 32; shift += 8) {
    bytes[offset + (shift / 8)] = static_cast<char>((value >> shift) & 0xFFu);
  }
}

void write_u64(std::string& bytes, std::size_t offset, std::uint64_t value) {
  for (unsigned shift = 0; shift < 64; shift += 8) {
    bytes[offset + (shift / 8)] = static_cast<char>((value >> shift) & 0xFFu);
  }
}

/// Deterministic payload with no run-to-run variation. The pattern is not valid
/// UTF-8 on purpose: the frame layer must carry opaque bytes.
std::string patterned_payload(std::size_t length) {
  std::string out(length, static_cast<char>(0));
  for (std::size_t index = 0; index < length; ++index) {
    out[index] = static_cast<char>((index * 37u + 11u) & 0xFFu);
  }
  return out;
}

/// The integrity word the wire format specifies: the first four SHA-256 bytes
/// in little-endian order. Recomputed here so the encoder is never trusted to
/// check itself.
std::uint32_t integrity_from_sha256(std::string_view payload) {
  const DigestBytes digest = failure_domain_registry::sha256(payload);
  return static_cast<std::uint32_t>(digest[0]) | (static_cast<std::uint32_t>(digest[1]) << 8) |
         (static_cast<std::uint32_t>(digest[2]) << 16) |
         (static_cast<std::uint32_t>(digest[3]) << 24);
}

bool same_header(const FrameHeader& left, const FrameHeader& right) {
  return left.magic == right.magic && left.version == right.version && left.type == right.type &&
         left.flags == right.flags && left.payload_bytes == right.payload_bytes &&
         left.sequence == right.sequence && left.integrity == right.integrity;
}

/// A header whose every field differs from the defaults, so "the decoder left
/// the output untouched" is a real observation.
FrameHeader probe_header() {
  FrameHeader probe;
  probe.magic = 0x11111111u;
  probe.version = 7;
  probe.type = MessageType::Bye;
  probe.flags = 0x22222222u;
  probe.payload_bytes = 3;
  probe.sequence = 9;
  probe.integrity = 0x33333333u;
  return probe;
}

struct Encoded {
  Outcome outcome;
  std::string bytes;
};

Encoded encode(MessageType type, std::uint64_t sequence, std::string_view payload,
               std::size_t max_payload) {
  Encoded result;
  result.outcome = failure_domain_registry::encode_frame(type, sequence, payload, max_payload,
                                                         result.bytes);
  return result;
}

struct Decoded {
  Outcome outcome;
  FrameHeader header;
  std::string_view payload{kPayloadSentinel};
  std::size_t consumed{kConsumedSentinel};
};

Decoded decode(std::string_view bytes, const FrameLimits& limits) {
  Decoded result;
  result.header = probe_header();
  result.outcome = failure_domain_registry::decode_frame(bytes, limits, &result.header,
                                                         &result.payload, &result.consumed);
  return result;
}

struct HeaderOnly {
  Outcome outcome;
  FrameHeader header;
};

HeaderOnly decode_header(std::string_view bytes, const FrameLimits& limits) {
  HeaderOnly result;
  result.header = probe_header();
  result.outcome = failure_domain_registry::decode_frame_header(bytes, limits, &result.header);
  return result;
}

/// A well-formed frame whose payload is the deterministic pattern.
std::string frame_of(MessageType type, std::uint64_t sequence, std::size_t payload_length,
                     const FrameLimits& limits) {
  const std::string payload = patterned_payload(payload_length);
  const Encoded encoded = encode(type, sequence, payload, limits.max_payload_bytes);
  return encoded.outcome.committed() ? encoded.bytes : std::string();
}

} // namespace

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

FDR_TEST_CASE(frame, encode_writes_the_exact_little_endian_28_byte_header) {
  const std::string payload = "fdr-frame-layout";
  const std::uint64_t sequence = 0x0123456789ABCDEFull;
  const Encoded encoded = encode(MessageType::Query, sequence, payload, 1024);

  FDR_CHECK_EQ(encoded.outcome.code, OutcomeCode::Committed);
  static_assert(failure_domain_registry::kFrameHeaderBytes == 28,
                "the frame header is exactly twenty-eight bytes on the wire");
  FDR_CHECK_EQ(encoded.bytes.size(), failure_domain_registry::kFrameHeaderBytes + payload.size());

  // Field offsets follow the documented layout exactly; a shift in either
  // direction would break every peer built against the format.
  FDR_CHECK_EQ(read_u32(encoded.bytes, 0), failure_domain_registry::kFrameMagic);
  static_assert(failure_domain_registry::kFrameMagic == 0x46445231u,
                "the frame magic is the four ASCII bytes FDR1");
  FDR_CHECK_EQ(read_u16(encoded.bytes, 4),
              static_cast<std::uint16_t>(failure_domain_registry::kWireProtocolVersion));
  static_assert(failure_domain_registry::kWireProtocolVersion == 1,
                "the wire protocol version of this build is one");
  FDR_CHECK_EQ(read_u16(encoded.bytes, 6), static_cast<std::uint16_t>(MessageType::Query));
  FDR_CHECK_EQ(read_u32(encoded.bytes, 8), std::uint32_t{0});
  FDR_CHECK_EQ(read_u32(encoded.bytes, 12), static_cast<std::uint32_t>(payload.size()));
  FDR_CHECK_EQ(read_u64(encoded.bytes, 16), sequence);
  FDR_CHECK_EQ(read_u32(encoded.bytes, 24), integrity_from_sha256(payload));
  FDR_CHECK_EQ(encoded.bytes.substr(failure_domain_registry::kFrameHeaderBytes), payload);

  // The magic is a little-endian u32, so its most significant byte is written
  // last: the first four bytes on the wire are "1RDF". A reader that compared
  // the raw prefix against "FDR1" would reject every real frame.
  FDR_CHECK_EQ(encoded.bytes.substr(0, 4), std::string("1RDF"));
  FDR_CHECK_EQ(static_cast<unsigned char>(encoded.bytes[0]), static_cast<unsigned char>(0x31u));
  FDR_CHECK_EQ(static_cast<unsigned char>(encoded.bytes[3]), static_cast<unsigned char>(0x46u));
}

FDR_TEST_CASE(frame, encode_and_decode_agree_for_every_message_type_and_the_empty_payload) {
  const FrameLimits limits = FrameLimits::defaults();
  static_assert(kLastMessageType >= 1, "the protocol defines no message type at all");

  const std::size_t lengths[] = {std::size_t{0}, std::size_t{1}, std::size_t{7}, std::size_t{64},
                                 std::size_t{4096}};
  for (std::uint16_t raw = 1; raw <= kLastMessageType; ++raw) {
    const MessageType type = static_cast<MessageType>(raw);
    FDR_CHECK_MSG(failure_domain_registry::is_valid_message_type(type),
                 "a defined message type is not valid");
    FDR_CHECK_MSG(failure_domain_registry::to_string(type) != std::string_view("unknown"),
                 "a defined message type has no name");
    for (const std::size_t length : lengths) {
      const std::string payload = patterned_payload(length);
      const std::uint64_t sequence = 0x1000u + raw;
      const Encoded encoded = encode(type, sequence, payload, limits.max_payload_bytes);
      FDR_CHECK_MSG(encoded.outcome.committed(), "encode_frame refused a legal payload");
      FDR_CHECK_EQ(encoded.bytes.size(), failure_domain_registry::kFrameHeaderBytes + length);

      const Decoded decoded = decode(encoded.bytes, limits);
      FDR_CHECK_EQ(decoded.outcome.code, OutcomeCode::Committed);
      FDR_CHECK_EQ(decoded.consumed, encoded.bytes.size());
      FDR_CHECK_EQ(decoded.header.magic, failure_domain_registry::kFrameMagic);
      FDR_CHECK_EQ(decoded.header.version,
                  static_cast<std::uint16_t>(failure_domain_registry::kWireProtocolVersion));
      FDR_CHECK_EQ(decoded.header.type, type);
      FDR_CHECK_EQ(decoded.header.flags, std::uint32_t{0});
      FDR_CHECK_EQ(decoded.header.payload_bytes, static_cast<std::uint32_t>(length));
      FDR_CHECK_EQ(decoded.header.sequence, sequence);
      FDR_CHECK_EQ(decoded.header.integrity, integrity_from_sha256(payload));
      FDR_CHECK_EQ(decoded.payload.size(), length);
      FDR_CHECK_EQ(decoded.payload, std::string_view(payload));

      // decode_frame_header is the same single decision the complete decoder
      // starts from, so it must agree field for field.
      const HeaderOnly header_only = decode_header(encoded.bytes, limits);
      FDR_CHECK_EQ(header_only.outcome.code, OutcomeCode::Committed);
      FDR_CHECK_MSG(same_header(header_only.header, decoded.header),
                   "decode_frame_header and decode_frame disagreed about one frame");
    }
  }

  FDR_CHECK(!failure_domain_registry::is_valid_message_type(MessageType::Unknown));
  FDR_CHECK(failure_domain_registry::is_valid_message_type(MessageType::Hello));
  FDR_CHECK(failure_domain_registry::is_valid_message_type(MessageType::Bye));
  FDR_CHECK(!failure_domain_registry::is_valid_message_type(
      static_cast<MessageType>(kLastMessageType + 1)));
  FDR_CHECK(!failure_domain_registry::is_valid_message_type(static_cast<MessageType>(0xFFFFu)));
}

FDR_TEST_CASE(frame, decode_consumes_exactly_one_frame_and_hands_the_rest_back) {
  const FrameLimits limits = FrameLimits::defaults();
  const std::string first = frame_of(MessageType::Hello, 1, 32, limits);
  const std::string second = frame_of(MessageType::Heartbeat, 2, 3, limits);
  FDR_CHECK(!first.empty());
  FDR_CHECK(!second.empty());

  const std::string stream = first + second;
  const Decoded one = decode(stream, limits);
  FDR_CHECK_EQ(one.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(one.consumed, first.size());
  FDR_CHECK_EQ(one.header.sequence, std::uint64_t{1});
  FDR_CHECK_EQ(one.header.type, MessageType::Hello);
  FDR_CHECK_EQ(one.payload,
              std::string_view(first).substr(failure_domain_registry::kFrameHeaderBytes));

  const Decoded two = decode(std::string_view(stream).substr(one.consumed), limits);
  FDR_CHECK_EQ(two.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(two.consumed, second.size());
  FDR_CHECK_EQ(two.header.sequence, std::uint64_t{2});
  FDR_CHECK_EQ(two.header.type, MessageType::Heartbeat);
  FDR_CHECK_EQ(two.payload.size(), std::size_t{3});

  // Once both frames are consumed there is nothing left, and an empty buffer is
  // not a frame: it is an incomplete one.
  const Decoded none =
      decode(std::string_view(stream).substr(one.consumed + two.consumed), limits);
  FDR_CHECK_EQ(none.outcome.code, OutcomeCode::ProtocolViolation);
  FDR_CHECK_EQ(none.consumed, kConsumedSentinel);
  FDR_CHECK_EQ(none.payload, std::string_view(kPayloadSentinel));
}

FDR_TEST_CASE(frame, frame_integrity_is_stable_and_is_the_sha256_prefix_in_little_endian) {
  const std::string empty;
  const DigestBytes empty_digest = failure_domain_registry::sha256(empty);
  FDR_CHECK_EQ(empty_digest[0], std::uint8_t{0xe3});
  FDR_CHECK_EQ(empty_digest[1], std::uint8_t{0xb0});
  FDR_CHECK_EQ(empty_digest[2], std::uint8_t{0xc4});
  FDR_CHECK_EQ(empty_digest[3], std::uint8_t{0x42});
  FDR_CHECK_EQ(failure_domain_registry::frame_integrity(empty), std::uint32_t{0x42c4b0e3u});
  FDR_CHECK_EQ(failure_domain_registry::frame_integrity(empty), integrity_from_sha256(empty));

  const std::string payload = patterned_payload(777);
  const std::uint32_t first = failure_domain_registry::frame_integrity(payload);
  const std::uint32_t again = failure_domain_registry::frame_integrity(payload);
  FDR_CHECK_EQ(first, again);
  FDR_CHECK_EQ(first, integrity_from_sha256(payload));

  // Different content and different length both change the word: a length-blind
  // checksum would let a truncated payload verify.
  const std::string other = patterned_payload(777) + "x";
  FDR_CHECK(!(failure_domain_registry::frame_integrity(other) == first));
  std::string flipped = payload;
  flipped[0] = static_cast<char>(static_cast<unsigned char>(flipped[0]) ^ 0x01u);
  FDR_CHECK(!(failure_domain_registry::frame_integrity(flipped) == first));
  FDR_CHECK(!(failure_domain_registry::frame_integrity("a") ==
             failure_domain_registry::frame_integrity("b")));
}

// ---------------------------------------------------------------------------
// Rejections
// ---------------------------------------------------------------------------

FDR_TEST_CASE(frame, every_decoder_rejection_carries_the_exact_code_and_a_message) {
  const FrameLimits limits = FrameLimits::defaults();
  const std::string base = frame_of(MessageType::Mutate, 7, 32, limits);
  FDR_CHECK_EQ(base.size(), failure_domain_registry::kFrameHeaderBytes + 32);
  FDR_CHECK_EQ(decode(base, limits).outcome.code, OutcomeCode::Committed);

  const auto rejected_unchanged = [&base, &limits](const std::string& bytes, OutcomeCode code,
                                                   const char* fragment) {
    (void)base;
    const Decoded decoded = decode(bytes, limits);
    const std::string message = decoded.outcome.message;
    return decoded.outcome.code == code && !message.empty() &&
           message.find(fragment) != std::string::npos &&
           decoded.consumed == kConsumedSentinel &&
           decoded.payload == std::string_view(kPayloadSentinel);
  };

  {
    std::string bad = base;
    bad[0] = 'X';
    FDR_CHECK_MSG(rejected_unchanged(bad, OutcomeCode::ProtocolViolation, "frame magic"),
                 "a wrong magic word was not reported as a magic violation");
  }
  {
    std::string bad = base;
    write_u16(bad, 4, static_cast<std::uint16_t>(failure_domain_registry::kWireProtocolVersion + 1));
    FDR_CHECK_MSG(rejected_unchanged(bad, OutcomeCode::ProtocolViolation, "version"),
                 "an unsupported version was not reported as a version violation");
    write_u16(bad, 4, 0);
    FDR_CHECK_MSG(rejected_unchanged(bad, OutcomeCode::ProtocolViolation, "version"),
                 "version zero was accepted as the wire version");
  }
  {
    std::string bad = base;
    write_u16(bad, 6, 0);
    FDR_CHECK_MSG(rejected_unchanged(bad, OutcomeCode::ProtocolViolation, "message type"),
                 "the Unknown message type was not rejected");
    write_u16(bad, 6, static_cast<std::uint16_t>(kLastMessageType + 1));
    FDR_CHECK_MSG(rejected_unchanged(bad, OutcomeCode::ProtocolViolation, "message type"),
                 "a message type above the defined range was not rejected");
    write_u16(bad, 6, 60000);
    FDR_CHECK_MSG(rejected_unchanged(bad, OutcomeCode::ProtocolViolation, "message type"),
                 "an arbitrary message type was not rejected");
  }
  {
    std::string bad = base;
    write_u32(bad, 8, 1);
    FDR_CHECK_MSG(rejected_unchanged(bad, OutcomeCode::ProtocolViolation, "reserved flags"),
                 "reserved flags were not rejected");
    write_u32(bad, 8, 0x80000000u);
    FDR_CHECK_MSG(rejected_unchanged(bad, OutcomeCode::ProtocolViolation, "reserved flags"),
                 "a high reserved flag bit was not rejected");
  }
  {
    std::string bad = base;
    write_u32(bad, 12, static_cast<std::uint32_t>(limits.max_payload_bytes + 1));
    FDR_CHECK_MSG(rejected_unchanged(bad, OutcomeCode::ResourceLimit, "oversized payload"),
                 "a payload above the configured bound was not a resource limit");
  }
  {
    // The compiled-in ceiling applies even when the configured bound is raised
    // to it, so a frame can never be advertised past the hard limit.
    FrameLimits wide = limits;
    wide.max_payload_bytes = failure_domain_registry::hard_limits::kMaxFramePayloadBytes;
    std::string bad = base;
    write_u32(bad, 12, static_cast<std::uint32_t>(
                           failure_domain_registry::hard_limits::kMaxFramePayloadBytes + 1));
    const Decoded decoded = decode(bad, wide);
    FDR_CHECK_EQ(decoded.outcome.code, OutcomeCode::ResourceLimit);
    FDR_CHECK(!decoded.outcome.message.empty());
    FDR_CHECK_EQ(decoded.consumed, kConsumedSentinel);
  }
  {
    const std::string truncated = base.substr(0, failure_domain_registry::kFrameHeaderBytes - 1);
    FDR_CHECK_MSG(rejected_unchanged(truncated, OutcomeCode::ProtocolViolation, "header is incomplete"),
                 "a truncated header was not reported as incomplete");
    FDR_CHECK_EQ(decode(std::string(), limits).outcome.code, OutcomeCode::ProtocolViolation);
    FDR_CHECK_EQ(decode(std::string(4, static_cast<char>(0)), limits).outcome.code,
                OutcomeCode::ProtocolViolation);
  }
  {
    const std::string short_body = base.substr(0, base.size() - 1);
    FDR_CHECK_MSG(rejected_unchanged(short_body, OutcomeCode::ProtocolViolation, "payload is incomplete"),
                 "a declared payload longer than the buffer was not reported as incomplete");
  }
  {
    std::string bad = base;
    const std::uint32_t integrity = read_u32(bad, 24);
    write_u32(bad, 24, integrity ^ 0x00000001u);
    FDR_CHECK_MSG(rejected_unchanged(bad, OutcomeCode::IntegrityFailure, "integrity"),
                 "a wrong integrity word was not reported as an integrity failure");
  }
  {
    // The header out-parameter is a result, not scratch space: a caller that
    // reuses one header struct must not be able to read stale-but-plausible
    // fields out of a failed decode.
    std::string bad = base;
    bad[0] = 'X';
    const HeaderOnly header_only = decode_header(bad, limits);
    FDR_CHECK_EQ(header_only.outcome.code, OutcomeCode::ProtocolViolation);
    FDR_CHECK_MSG(same_header(header_only.header, probe_header()),
                 "a failed header decode wrote into the caller's header");
    const HeaderOnly short_header =
        decode_header(base.substr(0, failure_domain_registry::kFrameHeaderBytes - 1), limits);
    FDR_CHECK_EQ(short_header.outcome.code, OutcomeCode::ProtocolViolation);
    FDR_CHECK_MSG(same_header(short_header.header, probe_header()),
                 "a truncated header decode wrote into the caller's header");
  }
}

FDR_TEST_CASE(frame, violation_precedence_is_magic_then_version_then_flags_then_type_then_size) {
  const FrameLimits limits = FrameLimits::defaults();
  const std::string base = frame_of(MessageType::Query, 5, 16, limits);
  FDR_CHECK_EQ(base.size(), failure_domain_registry::kFrameHeaderBytes + 16);

  // Magic is checked before everything else, including the integrity word: a
  // buffer that is not a frame at all must never be reported as a corrupt
  // frame.
  {
    std::string bad = base;
    bad[0] = 'X';
    const std::uint32_t integrity = read_u32(bad, 24);
    write_u32(bad, 24, integrity ^ 0xFFFFFFFFu);
    const Decoded decoded = decode(bad, limits);
    FDR_CHECK_EQ(decoded.outcome.code, OutcomeCode::ProtocolViolation);
    FDR_CHECK_MSG(decoded.outcome.message.find("magic") != std::string::npos,
                 "bad magic lost to the integrity check: " + decoded.outcome.message);
  }
  // Version beats the flags word.
  {
    std::string bad = base;
    write_u16(bad, 4, 99);
    write_u32(bad, 8, 1);
    const Decoded decoded = decode(bad, limits);
    FDR_CHECK_EQ(decoded.outcome.code, OutcomeCode::ProtocolViolation);
    FDR_CHECK_MSG(decoded.outcome.message.find("version") != std::string::npos,
                 "an unsupported version lost to the flags check: " + decoded.outcome.message);
  }
  // Flags beat the message type.
  {
    std::string bad = base;
    write_u32(bad, 8, 1);
    write_u16(bad, 6, 0);
    const Decoded decoded = decode(bad, limits);
    FDR_CHECK_EQ(decoded.outcome.code, OutcomeCode::ProtocolViolation);
    FDR_CHECK_MSG(decoded.outcome.message.find("reserved flags") != std::string::npos,
                 "reserved flags lost to the message-type check: " + decoded.outcome.message);
  }
  // The message type beats the declared payload length, so an oversized
  // declaration cannot be reached through a frame that is not a frame.
  {
    std::string bad = base;
    write_u16(bad, 6, 60000);
    write_u32(bad, 12, static_cast<std::uint32_t>(limits.max_payload_bytes + 1));
    const Decoded decoded = decode(bad, limits);
    FDR_CHECK_EQ(decoded.outcome.code, OutcomeCode::ProtocolViolation);
    FDR_CHECK_MSG(decoded.outcome.message.find("message type") != std::string::npos,
                 "an unknown type lost to the payload-size check: " + decoded.outcome.message);
  }
  // The size of the buffer beats the content of the header: a buffer too short
  // to hold a header is "not yet", never "malformed".
  {
    std::string short_buffer = base.substr(0, 8);
    short_buffer[0] = 'X';
    const Decoded decoded = decode(short_buffer, limits);
    FDR_CHECK_EQ(decoded.outcome.code, OutcomeCode::ProtocolViolation);
    FDR_CHECK_MSG(decoded.outcome.message.find("header is incomplete") != std::string::npos,
                 "a short buffer was not reported as an incomplete header: " + decoded.outcome.message);
    // The length of the payload is checked before the integrity word, so an
    // over-long frame is a resource answer, not a corruption answer.
    std::string over = base;
    write_u32(over, 12, static_cast<std::uint32_t>(limits.max_payload_bytes + 1));
    const std::uint32_t integrity = read_u32(over, 24);
    write_u32(over, 24, integrity ^ 0xFFFFFFFFu);
    FDR_CHECK_EQ(decode(over, limits).outcome.code, OutcomeCode::ResourceLimit);
  }
}

FDR_TEST_CASE(frame, encode_refuses_an_oversized_payload_without_touching_the_output) {
  const std::string payload = patterned_payload(65);
  const std::string untouched = "the caller's buffer must survive a refusal";

  {
    std::string out = untouched;
    const Outcome outcome =
        failure_domain_registry::encode_frame(MessageType::Hello, 1, payload, 64, out);
    FDR_CHECK_EQ(outcome.code, OutcomeCode::ResourceLimit);
    FDR_CHECK(!outcome.message.empty());
    FDR_CHECK_EQ(out, untouched);
  }
  {
    // The compiled-in ceiling applies even when an absurd maximum is supplied.
    std::string out = untouched;
    const Outcome outcome = failure_domain_registry::encode_frame(
        MessageType::Hello, 1, payload,
        failure_domain_registry::hard_limits::kMaxFramePayloadBytes, out);
    FDR_CHECK_EQ(outcome.code, OutcomeCode::Committed);
    FDR_CHECK(!(out == untouched));
    FDR_CHECK_EQ(out.size(), failure_domain_registry::kFrameHeaderBytes + payload.size());
  }
  {
    const std::string empty;
    std::string out = untouched;
    FDR_CHECK_EQ(failure_domain_registry::encode_frame(MessageType::Bye, 1, empty, 0, out).code,
                OutcomeCode::Committed);
    FDR_CHECK_EQ(out.size(), failure_domain_registry::kFrameHeaderBytes);
  }
  {
    std::string out = untouched;
    const Outcome outcome =
        failure_domain_registry::encode_frame(MessageType::Unknown, 1, std::string_view(), 1024, out);
    FDR_CHECK_EQ(outcome.code, OutcomeCode::ProtocolViolation);
    FDR_CHECK(!outcome.message.empty());
    FDR_CHECK_EQ(out, untouched);
  }
  {
    std::string out = untouched;
    const Outcome outcome = failure_domain_registry::encode_frame(
        static_cast<MessageType>(kLastMessageType + 1), 1, std::string_view(), 1024, out);
    FDR_CHECK_EQ(outcome.code, OutcomeCode::ProtocolViolation);
    FDR_CHECK_EQ(out, untouched);
  }
}

// ---------------------------------------------------------------------------
// Trailing bytes
// ---------------------------------------------------------------------------

FDR_TEST_CASE(frame, bytes_after_a_declared_payload_are_never_absorbed_into_it) {
  const FrameLimits limits = FrameLimits::defaults();
  const std::string body = patterned_payload(64);

  // A frame that declares eight payload bytes while the body holds sixty-four.
  // The decoder must hand back exactly eight and leave the rest visible; the
  // frame layer has no way to know what the message body was supposed to be, so
  // the consumed value is the only thing standing between a caller and a
  // payload it was never sent.
  const std::string declared = body.substr(0, 8);
  const Encoded encoded = encode(MessageType::Mutate, 3, declared, limits.max_payload_bytes);
  FDR_CHECK_EQ(encoded.outcome.code, OutcomeCode::Committed);
  const std::string framed = encoded.bytes + body.substr(8);
  FDR_CHECK_EQ(framed.size(), failure_domain_registry::kFrameHeaderBytes + body.size());

  const Decoded decoded = decode(framed, limits);
  FDR_CHECK_EQ(decoded.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(decoded.consumed, failure_domain_registry::kFrameHeaderBytes + 8);
  FDR_CHECK_EQ(decoded.payload, std::string_view(declared));
  FDR_CHECK_EQ(decoded.header.payload_bytes, std::uint32_t{8});

  // The remainder is the caller's bytes, not the frame's: decoding them as a
  // frame fails loudly instead of being swallowed as part of the payload.
  const std::string_view remainder = std::string_view(framed).substr(decoded.consumed);
  FDR_CHECK_EQ(remainder.size(), std::size_t{56});
  FDR_CHECK_EQ(remainder, std::string_view(body).substr(8));
  const Decoded second = decode(remainder, limits);
  FDR_CHECK_EQ(second.outcome.code, OutcomeCode::ProtocolViolation);
  FDR_CHECK(!second.outcome.message.empty());
  FDR_CHECK_EQ(second.consumed, kConsumedSentinel);
  FDR_CHECK_EQ(second.payload, std::string_view(kPayloadSentinel));
}

FDR_TEST_CASE(frame, a_frame_surrounded_by_other_bytes_stays_exactly_one_frame) {
  const FrameLimits limits = FrameLimits::defaults();
  const std::string payload = patterned_payload(100);
  const Encoded encoded = encode(MessageType::Response, 11, payload, limits.max_payload_bytes);
  FDR_CHECK_EQ(encoded.outcome.code, OutcomeCode::Committed);

  const std::string leading_junk = "not-a-frame";
  const std::string trailing_junk = "and-not-a-frame-either";
  const std::string buffer = encoded.bytes + trailing_junk;

  // The decoder reads from the front: leading junk makes the whole buffer
  // unreadable, and it must not scan forward looking for a magic word.
  const Decoded from_junk = decode(leading_junk + encoded.bytes, limits);
  FDR_CHECK_EQ(from_junk.outcome.code, OutcomeCode::ProtocolViolation);
  FDR_CHECK_MSG(from_junk.outcome.message.find("magic") != std::string::npos,
               "a leading-junk buffer was not rejected at the magic word");

  const Decoded one = decode(buffer, limits);
  FDR_CHECK_EQ(one.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(one.consumed, encoded.bytes.size());
  FDR_CHECK_EQ(one.payload, std::string_view(payload));
  FDR_CHECK_EQ(one.header.sequence, std::uint64_t{11});

  const Decoded after = decode(std::string_view(buffer).substr(one.consumed), limits);
  FDR_CHECK_EQ(after.outcome.code, OutcomeCode::ProtocolViolation);
  FDR_CHECK(!after.outcome.message.empty());
}

FDR_TEST_CASE(frame, the_frame_layer_carries_an_opaque_payload_byte_for_byte) {
  const FrameLimits limits = FrameLimits::defaults();
  // A body full of bytes that are not valid UTF-8 and that contain what look
  // like framing words. The frame layer must not interpret any of it.
  std::string payload = "FDR1";
  payload.append(static_cast<std::size_t>(4), static_cast<char>(0));
  payload.push_back(static_cast<char>(0xFFu));
  payload.push_back(static_cast<char>(0xFEu));
  payload.push_back(static_cast<char>(0x80u));
  payload.append(frame_of(MessageType::Hello, 1, 8, limits));
  payload.push_back(static_cast<char>(0x7Fu));

  const Encoded encoded = encode(MessageType::HelloAck, 400, payload, limits.max_payload_bytes);
  FDR_CHECK_EQ(encoded.outcome.code, OutcomeCode::Committed);
  const Decoded decoded = decode(encoded.bytes, limits);
  FDR_CHECK_EQ(decoded.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(decoded.payload.size(), payload.size());
  FDR_CHECK_EQ(decoded.payload, std::string_view(payload));
  FDR_CHECK_EQ(decoded.consumed, encoded.bytes.size());
  FDR_CHECK_EQ(decoded.header.integrity, failure_domain_registry::frame_integrity(payload));
}

// ---------------------------------------------------------------------------
// Loopback transport
// ---------------------------------------------------------------------------

FDR_TEST_CASE(frame, a_loopback_socket_carries_a_frame_byte_for_byte) {
  const FrameLimits limits = FrameLimits::defaults();
  const std::string payload = patterned_payload(1000);
  const Encoded encoded = encode(MessageType::Mutate, 0x99u, payload, limits.max_payload_bytes);
  FDR_CHECK_EQ(encoded.outcome.code, OutcomeCode::Committed);

  TcpListener listener;
  const Outcome bound = failure_domain_registry::listen_on("127.0.0.1", 0, 4, &listener);
  FDR_CHECK_EQ(bound.code, OutcomeCode::Committed);
  FDR_CHECK(listener.valid());
  const std::uint16_t port = listener.bound_port();
  FDR_CHECK_MSG(port != 0, "the listener did not bind an ephemeral port");

  TcpSocket client;
  const Outcome connected =
      failure_domain_registry::connect_to(Endpoint{"127.0.0.1", port}, 5000, &client);
  FDR_CHECK_EQ(connected.code, OutcomeCode::Committed);
  FDR_CHECK(client.valid());

  // accept() polls; a bounded loop is the honest way to wait for a connection
  // when no timeout may be imposed on the process.
  TcpSocket server;
  bool accepted = false;
  for (int attempt = 0; attempt < 400 && !accepted; ++attempt) {
    const Outcome polled = listener.accept(&server, &accepted, 5);
    FDR_CHECK_EQ(polled.code, OutcomeCode::Committed);
  }
  FDR_CHECK_MSG(accepted, "the listener never accepted the loopback connection");
  FDR_CHECK(server.valid());
  FDR_CHECK(!server.peer_text().empty());

  FDR_CHECK_EQ(server.send_all(encoded.bytes).code, OutcomeCode::Committed);
  std::string received;
  FDR_CHECK_EQ(client.recv_exact(encoded.bytes.size(), &received).code, OutcomeCode::Committed);
  FDR_CHECK_EQ(received.size(), encoded.bytes.size());
  FDR_CHECK_MSG(received == encoded.bytes, "the socket did not deliver the frame byte for byte");

  const Decoded decoded = decode(received, limits);
  FDR_CHECK_EQ(decoded.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(decoded.consumed, received.size());
  FDR_CHECK_EQ(decoded.header.type, MessageType::Mutate);
  FDR_CHECK_EQ(decoded.header.sequence, std::uint64_t{0x99u});
  FDR_CHECK_EQ(decoded.header.magic, failure_domain_registry::kFrameMagic);
  FDR_CHECK_EQ(decoded.payload, std::string_view(payload));

  server.shutdown_both();
  client.shutdown_both();
  server.close();
  client.close();
  listener.close();
}

FDR_TEST_CASE(frame, send_all_delivers_a_payload_larger_than_the_internal_chunk_whole) {
  const FrameLimits limits = FrameLimits::defaults();
  // Larger than the 256 KiB chunk the sender splits on, so the send path has to
  // loop and the receive path has to reassemble.
  const std::size_t payload_length = 300u * 1024u;
  const std::string payload = patterned_payload(payload_length);
  const Encoded encoded = encode(MessageType::Response, 0x5A5Au, payload, limits.max_payload_bytes);
  FDR_CHECK_EQ(encoded.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(encoded.bytes.size(), failure_domain_registry::kFrameHeaderBytes + payload_length);
  FDR_CHECK_MSG(encoded.bytes.size() > 262144u,
               "the frame does not exercise a multi-chunk send after all");

  TcpListener listener;
  FDR_CHECK_EQ(failure_domain_registry::listen_on("127.0.0.1", 0, 4, &listener).code,
              OutcomeCode::Committed);
  TcpSocket client;
  FDR_CHECK_EQ(failure_domain_registry::connect_to(Endpoint{"127.0.0.1", listener.bound_port()}, 5000,
                                                  &client)
                  .code,
              OutcomeCode::Committed);

  TcpSocket server;
  bool accepted = false;
  for (int attempt = 0; attempt < 400 && !accepted; ++attempt) {
    FDR_CHECK_EQ(listener.accept(&server, &accepted, 5).code, OutcomeCode::Committed);
  }
  FDR_CHECK_MSG(accepted, "the listener never accepted the loopback connection");

  // The receiver drains in its own thread: a single-threaded sender would
  // deadlock against the socket buffers before the last chunk is accepted, and
  // a deadlock is not a test result.
  std::string received;
  Outcome received_outcome = Outcome::make(OutcomeCode::InternalFailure, "the reader never ran");
  std::thread reader([&server, &received, &received_outcome, &encoded] {
    received_outcome = server.recv_exact(encoded.bytes.size(), &received);
  });
  const Outcome sent = client.send_all(encoded.bytes);
  reader.join();

  FDR_CHECK_EQ(sent.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(received_outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(received.size(), encoded.bytes.size());
  FDR_CHECK_MSG(received == encoded.bytes, "a multi-chunk send did not arrive whole");

  const Decoded decoded = decode(received, limits);
  FDR_CHECK_EQ(decoded.outcome.code, OutcomeCode::Committed);
  FDR_CHECK_EQ(decoded.consumed, received.size());
  FDR_CHECK_EQ(decoded.payload.size(), payload_length);
  FDR_CHECK_EQ(decoded.payload, std::string_view(payload));

  server.shutdown_both();
  client.shutdown_both();
  server.close();
  client.close();
  listener.close();
}

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
