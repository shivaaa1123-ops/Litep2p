// capability.cpp — binary codec + negotiation for the capability document.

#include "networkos/capability.h"

#include <algorithm>
#include <cstdint>
#include <cstring>

namespace networkos {

namespace {

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

constexpr char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string b64_encode(const std::string& in) {
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= in.size()) {
        const uint32_t n = (static_cast<uint8_t>(in[i]) << 16) |
                           (static_cast<uint8_t>(in[i + 1]) << 8) |
                           static_cast<uint8_t>(in[i + 2]);
        out.push_back(kB64[(n >> 18) & 63]);
        out.push_back(kB64[(n >> 12) & 63]);
        out.push_back(kB64[(n >> 6) & 63]);
        out.push_back(kB64[n & 63]);
        i += 3;
    }
    const size_t rem = in.size() - i;
    if (rem == 1) {
        const uint32_t n = static_cast<uint8_t>(in[i]) << 16;
        out.push_back(kB64[(n >> 18) & 63]);
        out.push_back(kB64[(n >> 12) & 63]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2) {
        const uint32_t n = (static_cast<uint8_t>(in[i]) << 16) |
                           (static_cast<uint8_t>(in[i + 1]) << 8);
        out.push_back(kB64[(n >> 18) & 63]);
        out.push_back(kB64[(n >> 12) & 63]);
        out.push_back(kB64[(n >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
bool b64_decode(const std::string& in, std::string& out) {
    out.clear();
    uint32_t buf = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        const int v = b64_val(c);
        if (v < 0) return false;
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buf >> bits) & 0xFF));
        }
    }
    return true;
}

} // namespace


CapabilityDocument::Negotiated CapabilityDocument::negotiated_with(
    const CapabilityDocument& remote) const {
    Negotiated n;
    const uint8_t lo = std::max(protocol_min, remote.protocol_min);
    const uint8_t hi = std::min(protocol_max, remote.protocol_max);
    if (lo > hi) return n;  // incompatible
    n.compatible = true;
    n.protocol_version = hi;
    n.merged_transports = static_cast<uint8_t>(transports & remote.transports);
    n.merged_features = features & remote.features;
    return n;
}

namespace cap {

std::string encode(const CapabilityDocument& doc) {
    // [docver:1][pmin:1][pmax:1][transport:2][maxframe:4][maxobj:8][flags:1][class:1][sec:2]
    // [ns_count:1][ns...: len(1)+bytes][opt_count:2]
    std::string out;
    out.reserve(64 + doc.namespaces.size() * 8);
    out.push_back(1);                            // doc format version
    out.push_back(doc.protocol_min);
    out.push_back(doc.protocol_max);
    put_u16(out, doc.transports);
    put_u32(out, doc.max_frame_size);
    put_u64(out, doc.max_object_size);
    out.push_back(doc.features);
    out.push_back(static_cast<uint8_t>(doc.carrier_class));
    put_u16(out, doc.security_suites);
    if (doc.namespaces.size() > 255) return {};
    out.push_back(static_cast<char>(doc.namespaces.size()));
    for (const auto& ns : doc.namespaces) {
        if (ns.size() > 255) return {};
        out.push_back(static_cast<char>(ns.size()));
        out.append(ns);
    }
    put_u16(out, 0);                             // no optional fields yet
    if (out.size() > kMaxDocBytes) return {};
    return out;
}


bool decode(const std::string& in, CapabilityDocument& out) {
    if (in.empty() || in.size() > kMaxDocBytes) return false;
    size_t off = 0;
    const uint8_t docver = static_cast<uint8_t>(in[off++]);
    if (docver != 1) return false;
    if (off + 1 > in.size()) return false;
    out.protocol_min = static_cast<uint8_t>(in[off++]);
    if (off + 1 > in.size()) return false;
    out.protocol_max = static_cast<uint8_t>(in[off++]);
    uint16_t t; uint32_t f; uint64_t o;
    if (!get_u16(in, off, t)) return false;
    out.transports = t;
    if (!get_u32(in, off, f)) return false;
    out.max_frame_size = f;
    if (!get_u64(in, off, o)) return false;
    out.max_object_size = o;
    if (off + 1 > in.size()) return false;
    out.features = static_cast<uint8_t>(in[off++]);
    if (off + 1 > in.size()) return false;
    out.carrier_class = static_cast<CarrierCapacityClass>(in[off++]);
    uint16_t s;
    if (!get_u16(in, off, s)) return false;
    out.security_suites = s;
    if (off + 1 > in.size()) return false;
    const uint8_t ns_count = static_cast<uint8_t>(in[off++]);
    out.namespaces.clear();
    for (uint8_t i = 0; i < ns_count; ++i) {
        if (off + 1 > in.size()) return false;
        const uint8_t len = static_cast<uint8_t>(in[off++]);
        if (off + len > in.size()) return false;
        out.namespaces.emplace_back(in.substr(off, len));
        off += len;
    }
    uint16_t opt_count;
    if (!get_u16(in, off, opt_count)) return false;
    // Optional fields: [key:1][len:2][value]. Unknown keys are skipped.
    for (uint16_t i = 0; i < opt_count; ++i) {
        if (off + 3 > in.size()) return false;
        ++off;                                   // key (unknown -> skip)
        const uint16_t vlen = static_cast<uint16_t>(static_cast<uint8_t>(in[off])) |
                              static_cast<uint16_t>(static_cast<uint8_t>(in[off + 1]) << 8);
        off += 2;
        if (off + vlen > in.size()) return false;
        off += vlen;
    }
    return off == in.size();
}

std::string encodeB64(const CapabilityDocument& doc) {
    const std::string raw = encode(doc);
    if (raw.empty()) return {};
    return b64_encode(raw);
}

bool decodeB64(const std::string& b64, CapabilityDocument& out) {
    std::string raw;
    if (!b64_decode(b64, raw)) return false;
    return decode(raw, out);
}

} // namespace cap

} // namespace networkos
