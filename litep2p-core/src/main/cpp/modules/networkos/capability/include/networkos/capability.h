#pragma once

// Network OS — Capability negotiation (master doc §39, §40; Phase 2).
//
// On session setup each peer exchanges a small capability document so both
// sides negotiate the highest compatible wire protocol version and know what
// the peer supports (transports, chunking, receipts, carrier service, …).
//
// Privacy rule (§50): the document contains NO battery level, NO device model,
// NO identifying metadata beyond the peer id already exchanged. The binary
// codec is bounded (max 1024 bytes) and len-prefixed so unknown optional
// fields added by newer peers are skipped safely by older ones.

#include <cstdint>
#include <string>
#include <vector>

namespace networkos {

// Wire protocol versions (master doc §40). v1 = current session framing.
inline constexpr uint8_t kWireProtocolMin = 1;
inline constexpr uint8_t kWireProtocolMax = 1;

// Transport capability flags (mirrors TransportCapability in ITransport.h).
enum WireTransportFlags : uint16_t {
    kWireTcp       = 1u << 0,
    kWireUdp       = 1u << 1,
    kWireQuic      = 1u << 2,
    kWireObscured  = 1u << 3,   // OBF1/padding/cover
    kWireNat       = 1u << 4,
    kWireRelay     = 1u << 5,
};

// Security suites (bitmask).
enum WireSecuritySuites : uint16_t {
    kSecNoiseNK     = 1u << 0,
    kSecXChaCha20   = 1u << 1,
};

// Feature flags (bitmask).
enum WireFeatureFlags : uint8_t {
    kFeatCarrier    = 1u << 0,  // willing/able to store-and-forward for others
    kFeatChunking   = 1u << 1,  // supports large-object chunking (Phase 10)
    kFeatReceipts   = 1u << 2,  // supports signed delivery receipts (Phase 5)
    kFeatCompression = 1u << 3,
};

// Logical multiplexed stream ids (§18). Control always wins.
enum StreamId : uint8_t {
    kStreamControl = 0,     // connection/security control
    kStreamCritical = 1,    // high-priority (delivery, receipts)
    kStreamReceipt = 2,
    kStreamInventory = 3,   // anti-entropy (Phase 6)
    kStreamObject = 4,      // object transfer (Phase 3+)
    kStreamApplication = 5, // plain application direct stream
    kStreamBulk = 6,        // background/bulk (Phase 10)
    kStreamMax = 7,
};

// Carrier capacity class (§11): how strong a carrier a peer can be.
enum class CarrierCapacityClass : uint8_t {
    kNone = 0,        // not a carrier
    kMinimal = 1,     // low storage / battery-constrained
    kStandard = 2,    // normal phone
    kHigh = 3,        // charging/always-on capable
};

struct CapabilityDocument {
    uint8_t protocol_min{kWireProtocolMin};
    uint8_t protocol_max{kWireProtocolMax};
    uint16_t transports{kWireUdp | kWireTcp};
    uint32_t max_frame_size{10u * 1024u * 1024u};  // matches wire_codec kMaxMessageSize
    uint64_t max_object_size{64u * 1024u * 1024u};
    uint8_t features{kFeatCarrier | kFeatReceipts};
    CarrierCapacityClass carrier_class{CarrierCapacityClass::kStandard};
    uint16_t security_suites{kSecNoiseNK | kSecXChaCha20};

    // Registered namespaces (Phase 12 registers app namespaces here).
    std::vector<std::string> namespaces;

    // Result of negotiation with a peer.
    struct Negotiated {
        bool compatible{false};
        uint8_t protocol_version{0};   // highest common
        uint8_t merged_transports{0};
        uint8_t merged_features{0};
    };
    Negotiated negotiated_with(const CapabilityDocument& remote) const;
};

// Binary codec. encode returns empty on failure; decode returns false on a
// malformed doc. Both bounded: encode refuses docs over 1024 bytes, decode
// refuses oversized input. Unknown optional fields are skipped (len-prefixed).
namespace cap {
inline constexpr size_t kMaxDocBytes = 1024;
std::string encode(const CapabilityDocument& doc);
bool decode(const std::string& bytes, CapabilityDocument& out);
// Base64 variants used on the wire (CONTROL_CONNECT payload field).
std::string encodeB64(const CapabilityDocument& doc);
bool decodeB64(const std::string& b64, CapabilityDocument& out);
} // namespace cap

} // namespace networkos
