#ifndef OVERLAY_FRAME_H
#define OVERLAY_FRAME_H

/*
 * overlay_frame.h — LPX2 wire format for the multi-hop overlay (B2).
 *
 * DESIGN — "onion-lite" source-routed envelopes:
 *
 *   Origin picks a path R1..Rn -> Dest. For each hop it builds a sealed-box
 *   instruction (libsodium crypto_box_seal) that ONLY that hop can open:
 *
 *     hop_i_body = seal(pk_i, { kind, next_peer, inner })
 *       where inner = hop_{i+1}_body ... innermost = seal(pk_dest, payload)
 *
 *   Properties:
 *     - Every relay learns only (previous hop, next hop) — never both endpoints.
 *     - The destination payload is sealed to the destination's static key;
 *       relays cannot read application data.
 *     - Relays keep NO per-circuit state: any relay crash only kills the one
 *       attempt; the origin re-routes on a fresh path. Stateless relays are
 *       dramatically more rugged on churn-heavy hostile networks than
 *       circuit-based designs.
 *     - INET destinations do not exist in LPX2 (peer destinations only), so an
 *       overlay relay can never be abused as an open internet proxy.
 *
 *   Loop/routing protection:
 *     - frame_id: 16 random bytes; each node keeps a bounded LRU of seen ids
 *       and drops duplicates (loop detection).
 *     - ttl: decremented by every relay; frames die at 0.
 *     - The innermost payload carries a timestamp inside the sealed blob, so
 *       stale frames cannot be replayed by an adversary holding captured
 *       traffic.
 *
 * Frame layout (all integers little-endian):
 *   [0..3]  magic "LPX2"
 *   [4]     version (=1)
 *   [5]     flags  (see OverlayFlags)
 *   [6]     ttl    (remaining hops; relays decrement)
 *   [7]     reserved (0)
 *   [8..23] frame_id (16 bytes)
 *   [24..]  body (a sealed hop instruction for the receiving node)
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace overlay {

inline constexpr char kLpx2Magic[4] = {'L', 'P', 'X', '2'};
inline constexpr uint8_t kLpx2Version = 2;  // v2: padding field + signed payloads
inline constexpr size_t kLpx2HeaderSize = 24;              // magic..frame_id
inline constexpr size_t kFrameIdSize = 16;

// NOTE: an LPX2 frame must stay below one UDP datagram so it rides the same
// transport paths as every other engine message. Three sealed layers (~80 B
// each) + header + a small payload fit comfortably.
inline constexpr size_t kMaxOverlayFrameSize = 1100;

enum OverlayFlags : uint8_t {
    kFlagNone          = 0x00,
    kFlagMailboxStore  = 0x01,  // final hop: store sealed blob in mailbox
    kFlagMailboxPickup = 0x02,  // request: return stored blobs for me
    kFlagAck           = 0x04,  // innermost payload is an ACK record
    kFlagRelayAdvert   = 0x08,  // relay-role advertisement (unsealed body)
    kFlagWantAck       = 0x10,  // destination should ACK this frame
    kFlagRelayPex      = 0x20,  // relay-list exchange (unsealed body; public)
};

// Instruction kinds inside a sealed hop body.
enum class HopKind : uint8_t {
    Forward       = 1,  // forward `inner` to next_peer (I am a relay on the path)
    Deliver       = 2,  // I am the destination; `inner` is sealed for me
    MailboxStore  = 3,  // I am the mailbox relay; store `inner` for mailbox_key
    MailboxPickup = 4,  // I am the mailbox relay; send stored blobs to me
    Cover         = 5,  // cover-traffic filler; open and discard silently
};

// Cover traffic: random-size buckets and random padding force the wire
// distribution to hide real message sizes; idle cover frames obscure silence
// (see OverlayRouter::Config::cover_interval_ms).
inline constexpr size_t kPadFieldSize = 2;      // u16 pad_len after the header

// ---------------------------------------------------------------------------
// Byte-level (de)serialization helpers shared by codec and tests.
// ---------------------------------------------------------------------------
void put_u16_le(std::string& out, uint16_t v);
void put_u32_le(std::string& out, uint32_t v);
void put_u64_le(std::string& out, uint64_t v);
void put_str(std::string& out, const std::string& s);   // u16 length + bytes
bool get_u16_le(std::string_view in, size_t& off, uint16_t& v);
bool get_u32_le(std::string_view in, size_t& off, uint32_t& v);
bool get_u64_le(std::string_view in, size_t& off, uint64_t& v);
bool get_str(std::string_view in, size_t& off, std::string& v);

// ---------------------------------------------------------------------------
// Sealed hop instruction (crypto_box_seal to the hop's static key).
// ---------------------------------------------------------------------------
struct HopInstruction {
    HopKind kind{HopKind::Forward};
    std::string next_peer;     // Forward only
    std::string mailbox_key;   // MailboxStore/MailboxPickup only
    std::string inner;         // nested instruction, or sealed final payload
};

// Serialize + seal to `hop_public_key` (32-byte Curve25519 static key).
// Returns empty string on failure.
std::string seal_hop(const std::vector<uint8_t>& hop_public_key,
                     const HopInstruction& instr);

// Attempt to open a sealed hop body with our static keypair.
// Returns false if the body is not for us / malformed.
bool open_hop(const std::vector<uint8_t>& local_public_key,
              const std::vector<uint8_t>& local_secret_key,
              std::string_view body, HopInstruction& out);

// ---------------------------------------------------------------------------
// Final payload (innermost blob, sealed to the destination).
// ---------------------------------------------------------------------------
struct FinalPayload {
    std::string origin_peer_id;
    uint64_t created_ts_ms{0};
    uint16_t flags{0};            // kFlagWantAck / kFlagAck / kFlagMailboxStore
    std::string app_payload;      // application bytes
    std::string ack_of;           // when kFlagAck: frame_id being acknowledged (hex)
    // The ORIGIN's frame id for this message. The destination ACKs this id so
    // the origin can correlate (critical for mailbox delivery, where the
    // destination sees a DIFFERENT outer frame id on the pickup response).
    std::string message_frame_id_hex;
    std::vector<std::string> reply_relays;  // trusted relays for the reverse path

    // ---- Origin authentication (Phase B, roadmap §8 item 7) ----
    // Ed25519 signature over the serialized unsigned portion of this payload.
    // When empty the payload is UNSIGNED (older peers / tests). The router
    // signs always when signing keys are configured, and may enforce
    // signatures via OverlayRouter::Config::require_origin_auth.
    std::string signer_pk;        // 32-byte Ed25519 public key (raw)
    std::string signature;        // 64-byte Ed25519 signature (raw)

    // SECURITY NOTE (resolved by signing when enabled):
    // An unsigned origin_peer_id is NOT cryptographically authenticated. With
    // Ed25519 signing enabled and peer signing keys registered, the origin is
    // bound to a stable identity; without registration the signature still
    // guarantees tamper-proof integrity (the attacker cannot alter payload,
    // timestamp, or claimed origin without breaking the signature).
};

// Serialize + seal to `dest_public_key`. When `sign_sk`/`sign_pk` are provided
// (32-byte Ed25519 secret + public), the payload is signed; signature and
// signer public key travel inside the sealed box (tamper-proof end-to-end).
std::string seal_final(const std::vector<uint8_t>& dest_public_key,
                       const FinalPayload& payload,
                       const uint8_t* sign_sk = nullptr,
                       const uint8_t* sign_pk = nullptr);
bool open_final(const std::vector<uint8_t>& local_public_key,
                const std::vector<uint8_t>& local_secret_key,
                std::string_view body, FinalPayload& out);

// Verify the Ed25519 signature embedded in an opened FinalPayload.
// Returns true when the payload is unsigned OR the signature validates against
// `expected_signer_pk` (pass an empty vector to validate against the payload's
// own embedded key — integrity only, not identity binding).
bool verify_final_signature(const FinalPayload& payload,
                            const std::vector<uint8_t>& expected_signer_pk);

// ---------------------------------------------------------------------------
// Relay advertisement (NOT sealed — relay role is public information).
// Body layout: [peer_id str][capacity u16][max_hops u8]
// ---------------------------------------------------------------------------
std::string encode_relay_advert(const std::string& peer_id,
                                uint16_t capacity, uint8_t max_hops);
bool decode_relay_advert(std::string_view body, std::string& peer_id,
                         uint16_t& capacity, uint8_t& max_hops);

// ---------------------------------------------------------------------------
// Relay-list exchange (PEX; unsealed — public routing metadata).
// Body layout: [count u16][peer_id str]...
// ---------------------------------------------------------------------------
std::string encode_relay_pex(const std::vector<std::string>& relay_ids);
bool decode_relay_pex(std::string_view body, std::vector<std::string>& out);

// ---------------------------------------------------------------------------
// Outer frame encode/decode.
//
// Wire layout (all integers little-endian):
//   [0..3]  magic "LPX2"
//   [4]     version (=2)
//   [5]     flags
//   [6]     ttl
//   [7]     reserved (0)
//   [8..23] frame_id (16 bytes)
//   [24..25] pad_len (u16)  <-- cover-traffic padding (Phase B)
//   [26..]  body (sealed hop instruction for the receiving node)
//   [26+len .. 26+len+pad_len]  random pad bytes (dropped by decode_frame)
// ---------------------------------------------------------------------------
struct OverlayFrameHeader {
    uint8_t version{0};
    uint8_t flags{0};
    uint8_t ttl{0};
    uint8_t reserved{0};
    uint8_t frame_id[kFrameIdSize]{};
    size_t pad_len{0};
};

std::string encode_frame(uint8_t flags, uint8_t ttl,
                         const uint8_t frame_id[kFrameIdSize], std::string_view body);
bool decode_frame(std::string_view data, OverlayFrameHeader& hdr,
                  std::string_view& body);

// Cover traffic: (re)pad an encoded frame to the next multiple of `bucket`
// bytes (0 = strip padding). Uses fresh random pad bytes each call. Relays
// re-pad on forward so all hops stay within the same size distribution.
void pad_wire_frame(std::string& wire, size_t bucket);

// ---------------------------------------------------------------------------
// Obfuscated transport (Phase B, DPI resistance).
//
// Wraps an LPX2 frame in an envelope that does NOT reveal the "LPX2" magic:
//   [magic "OBF1"][sender_pk 32][nonce 24][pad_len u16]
//   [secretbox(ciphertext+MAC)][pad bytes pad_len]
// The shared key is derived with X25519 (crypto_box_beforenm) between the
// sender's STATIC secret key and the RECEIVER's static public key — no new key
// exchange is needed; the same Noise static keys already exchanged are reused.
// `pad_to_bucket`: 0 = no padding, else the TOTAL envelope length is padded to
// the next bucket multiple so the wire distribution hides message sizes. The
// padding sits OUTSIDE the AEAD so the plaintext length is preserved exactly.
// ---------------------------------------------------------------------------
std::string obfuscate_wrap(const std::vector<uint8_t>& receiver_public_key,
                           const std::vector<uint8_t>& local_secret_key,
                           std::string_view plaintext, size_t pad_to_bucket = 0);
// Returns false if the envelope is malformed / not addressed to `local_sk`.
bool obfuscate_unwrap(const std::vector<uint8_t>& local_public_key,
                      const std::vector<uint8_t>& local_secret_key,
                      std::string_view envelope, std::string& plaintext);

void random_frame_id(uint8_t out[kFrameIdSize]);
std::string frame_id_to_hex(const uint8_t id[kFrameIdSize]);

} // namespace overlay

#endif // OVERLAY_FRAME_H
