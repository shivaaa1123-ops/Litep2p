// envelope.cpp — Network Object envelope codec + Ed25519 origin signature.

#include "networkos/object/envelope.h"

#include <sodium.h>

#include <cstring>

namespace networkos {
namespace obj {

namespace {

constexpr size_t kMaxEnvelopeBytes = 16u * 1024u * 1024u;  // payload bound
constexpr size_t kMaxStrField = 4096;                       // per-string field

inline void put_u16(std::string& out, uint16_t v) {
    out.push_back(static_cast<char>(v & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
}
inline void put_u32(std::string& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}
inline void put_u64(std::string& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}
inline void put_i64(std::string& out, int64_t v) {
    put_u64(out, static_cast<uint64_t>(v));
}
inline void put_str(std::string& out, const std::string& s) {
    put_u16(out, static_cast<uint16_t>(s.size()));  // caller bounds-checks
    out.append(s);
}

inline bool get_u16(const std::string& in, size_t& off, uint16_t& out) {
    if (off + 2 > in.size()) return false;
    out = static_cast<uint16_t>(static_cast<uint8_t>(in[off])) |
          static_cast<uint16_t>(static_cast<uint8_t>(in[off + 1]) << 8);
    off += 2;
    return true;
}
inline bool get_u32(const std::string& in, size_t& off, uint32_t& out) {
    if (off + 4 > in.size()) return false;
    out = 0;
    for (int i = 0; i < 4; ++i) out |= static_cast<uint32_t>(static_cast<uint8_t>(in[off + i])) << (8 * i);
    off += 4;
    return true;
}
inline bool get_u64(const std::string& in, size_t& off, uint64_t& out) {
    if (off + 8 > in.size()) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) out |= static_cast<uint64_t>(static_cast<uint8_t>(in[off + i])) << (8 * i);
    off += 8;
    return true;
}
inline bool get_i64(const std::string& in, size_t& off, int64_t& out) {
    uint64_t v;
    if (!get_u64(in, off, v)) return false;
    out = static_cast<int64_t>(v);
    return true;
}
inline bool get_str(const std::string& in, size_t& off, size_t bound, std::string& out) {
    uint16_t len;
    if (!get_u16(in, off, len)) return false;
    if (len > bound) return false;
    if (off + len > in.size()) return false;
    out.assign(in.data() + off, len);
    off += len;
    return true;
}

} // namespace

std::string origin_canonical_bytes(const OriginHeader& h) {
    std::string b;
    b.reserve(128);
    b.push_back(h.protocol_version);
    put_str(b, h.network_id);
    put_str(b, h.namespace_id);
    put_str(b, h.object_id_hex);
    put_str(b, h.origin);
    put_str(b, h.destination);
    put_str(b, h.object_type);
    put_i64(b, h.created_at_ms);
    put_i64(b, h.ttl_ms);
    b.push_back(h.priority);
    b.push_back(h.delivery_class);
    b.push_back(h.max_hops);
    b.push_back(h.hop_count);
    put_u64(b, h.payload_size);
    put_str(b, h.payload_hash);
    b.push_back(h.security_flags);
    return b;
}


std::string serialize(const NetworkObject& obj) {
    if (obj.payload.size() > kMaxEnvelopeBytes) return {};
    if (obj.origin.object_id_hex.size() > kMaxStrField ||
        obj.origin.network_id.size() > kMaxStrField ||
        obj.origin.namespace_id.size() > kMaxStrField ||
        obj.origin.origin.size() > kMaxStrField ||
        obj.origin.destination.size() > kMaxStrField ||
        obj.origin.object_type.size() > kMaxStrField ||
        obj.origin.payload_hash.size() > 64) {
        return {};
    }
    if (obj.forwarding.previous_peer.size() > kMaxStrField ||
        obj.forwarding.routing_hints.size() > kMaxStrField ||
        obj.forwarding.lease_info.size() > kMaxStrField) {
        return {};
    }

    std::string out;
    out.reserve(256 + obj.payload.size());
    out.append("NTO1", 4);

    // Forwarding header (mutable, not signed).
    out.push_back(obj.forwarding.hop_count);
    put_str(out, obj.forwarding.previous_peer);
    put_str(out, obj.forwarding.routing_hints);
    put_str(out, obj.forwarding.lease_info);

    // Origin header (immutable, signed).
    const OriginHeader& h = obj.origin;
    out.push_back(h.protocol_version);
    put_str(out, h.network_id);
    put_str(out, h.namespace_id);
    put_str(out, h.object_id_hex);
    put_str(out, h.origin);
    put_str(out, h.destination);
    put_str(out, h.object_type);
    put_i64(out, h.created_at_ms);
    put_i64(out, h.ttl_ms);
    out.push_back(h.priority);
    out.push_back(h.delivery_class);
    out.push_back(h.max_hops);
    out.push_back(h.hop_count);
    put_u64(out, h.payload_size);
    put_str(out, h.payload_hash);
    out.push_back(h.security_flags);

    // Payload.
    put_u32(out, static_cast<uint32_t>(obj.payload.size()));
    out.append(obj.payload);

    // Signature.
    if (obj.origin_signature.size() > 64) return {};
    out.push_back(static_cast<char>(obj.origin_signature.size()));
    out.append(obj.origin_signature);

    // Recipient-wrapped content keys.
    if (obj.recipient_keys.size() > 256) return {};
    put_u16(out, static_cast<uint16_t>(obj.recipient_keys.size()));
    for (const auto& kv : obj.recipient_keys) {
        if (kv.first.size() > kMaxStrField || kv.second.size() > 128) return {};
        put_str(out, kv.first);
        out.push_back(static_cast<char>(kv.second.size()));
        out.append(kv.second);
    }

    // Optional unknown-fields section (v1: none).
    put_u16(out, 0);

    if (out.size() > kMaxEnvelopeBytes) return {};
    return out;
}


bool deserialize(const std::string& in, NetworkObject& out) {
    if (in.size() < 4 || in.size() > kMaxEnvelopeBytes) return false;
    if (in.compare(0, 4, "NTO1") != 0) return false;
    size_t off = 4;

    // Forwarding header.
    if (off + 1 > in.size()) return false;
    out.forwarding.hop_count = static_cast<uint8_t>(in[off++]);
    if (!get_str(in, off, kMaxStrField, out.forwarding.previous_peer)) return false;
    if (!get_str(in, off, kMaxStrField, out.forwarding.routing_hints)) return false;
    if (!get_str(in, off, kMaxStrField, out.forwarding.lease_info)) return false;

    // Origin header.
    OriginHeader& h = out.origin;
    if (off + 1 > in.size()) return false;
    h.protocol_version = static_cast<uint8_t>(in[off++]);
    if (!get_str(in, off, kMaxStrField, h.network_id)) return false;
    if (!get_str(in, off, kMaxStrField, h.namespace_id)) return false;
    if (!get_str(in, off, kMaxStrField, h.object_id_hex)) return false;
    if (!get_str(in, off, kMaxStrField, h.origin)) return false;
    if (!get_str(in, off, kMaxStrField, h.destination)) return false;
    if (!get_str(in, off, kMaxStrField, h.object_type)) return false;
    if (!get_i64(in, off, h.created_at_ms)) return false;
    if (!get_i64(in, off, h.ttl_ms)) return false;
    if (off + 4 > in.size()) return false;
    h.priority = static_cast<uint8_t>(in[off++]);
    h.delivery_class = static_cast<uint8_t>(in[off++]);
    h.max_hops = static_cast<uint8_t>(in[off++]);
    h.hop_count = static_cast<uint8_t>(in[off++]);
    if (!get_u64(in, off, h.payload_size)) return false;
    if (!get_str(in, off, 64, h.payload_hash)) return false;
    if (off + 1 > in.size()) return false;
    h.security_flags = static_cast<uint8_t>(in[off++]);

    // Payload.
    uint32_t plen;
    if (!get_u32(in, off, plen)) return false;
    if (off + plen > in.size()) return false;
    out.payload.assign(in.data() + off, plen);
    off += plen;

    // Signature.
    if (off + 1 > in.size()) return false;
    const uint8_t sig_len = static_cast<uint8_t>(in[off++]);
    if (sig_len > 64 || off + sig_len > in.size()) return false;
    out.origin_signature.assign(in.data() + off, sig_len);
    off += sig_len;

    // Recipient-wrapped content keys.
    uint16_t rcount;
    if (!get_u16(in, off, rcount)) return false;
    out.recipient_keys.clear();
    for (uint16_t i = 0; i < rcount; ++i) {
        std::string id, key;
        if (!get_str(in, off, kMaxStrField, id)) return false;
        if (off + 1 > in.size()) return false;
        const uint8_t klen = static_cast<uint8_t>(in[off++]);
        if (off + klen > in.size()) return false;
        key.assign(in.data() + off, klen);
        off += klen;
        out.recipient_keys.emplace_back(std::move(id), std::move(key));
    }

    // Optional unknown-fields section: len-prefixed, skipped.
    uint16_t opt_count;
    if (!get_u16(in, off, opt_count)) return false;
    for (uint16_t i = 0; i < opt_count; ++i) {
        if (off + 3 > in.size()) return false;
        ++off;  // key
        uint16_t vlen;
        if (!get_u16(in, off, vlen)) return false;
        if (off + vlen > in.size()) return false;
        off += vlen;
    }

    return off == in.size();
}

bool sign_object(NetworkObject& obj, const uint8_t sk[64], const uint8_t pk[32]) {
    (void)pk;
    if (!sk) return false;
    const std::string canonical = origin_canonical_bytes(obj.origin);
    std::string sig(64, '\0');
    if (crypto_sign_detached(reinterpret_cast<unsigned char*>(&sig[0]), nullptr,
                             reinterpret_cast<const unsigned char*>(canonical.data()),
                             canonical.size(), sk) != 0) {
        return false;
    }
    obj.origin_signature = std::move(sig);
    return true;
}

bool verify_object(const NetworkObject& obj, const uint8_t pk[32]) {
    // Step 3.3 /§29: the origin signature authenticates the origin header AND
    // the payload hash; the hash authenticates the payload. Both must hold —
    // a tampered payload (without a matching hash) must fail verification.
    if (!pk || obj.origin_signature.size() != 64) return false;
    const std::string canonical = origin_canonical_bytes(obj.origin);
    if (crypto_sign_verify_detached(
            reinterpret_cast<const unsigned char*>(obj.origin_signature.data()),
            reinterpret_cast<const unsigned char*>(canonical.data()),
            canonical.size(), pk) != 0) {
        return false;
    }
    // Payload integrity: if a payload is present, its hash must match the
    // signed origin header hash.
    if (obj.origin.payload_hash.empty()) {
        return obj.payload.empty();
    }
    const std::string actual = compute_payload_hash(obj.payload);
    return actual == obj.origin.payload_hash;
}

std::string compute_payload_hash(const std::string& payload) {
    std::string hash(32, '\0');
    crypto_generichash(reinterpret_cast<unsigned char*>(&hash[0]), 32,
                       reinterpret_cast<const unsigned char*>(payload.data()),
                       payload.size(), nullptr, 0);
    return hash;
}

} // namespace obj
} // namespace networkos
