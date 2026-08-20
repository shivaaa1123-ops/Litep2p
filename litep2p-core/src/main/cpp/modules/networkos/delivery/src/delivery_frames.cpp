// delivery_frames.cpp — Phase 5 delivery frame + receipt codec (bounded).

#include "networkos/delivery/delivery_frames.h"

#include <cstring>
#include <string>

namespace networkos {
namespace delivery {

namespace {

constexpr size_t kMaxIdLen = 600;       // ObjectId hex upper bound
constexpr size_t kMaxStringLen = 2048;  // peer/namespace ids
constexpr size_t kMaxHashHex = 128;     // payload_hash hex (<=64) + slack
constexpr size_t kMaxSigLen = 64 + 4;   // 64-byte Ed25519 sig

class Writer {
public:
    void u8(uint8_t v) { b.push_back(static_cast<char>(v)); }
    void i64(int64_t v) {
        const uint64_t u = static_cast<uint64_t>(v);
        for (int shift = 56; shift >= 0; shift -= 8) {
            b.push_back(static_cast<char>((u >> shift) & 0xFF));
        }
    }
    void u32(uint32_t v) {
        for (int shift = 24; shift >= 0; shift -= 8) {
            b.push_back(static_cast<char>((v >> shift) & 0xFF));
        }
    }
    void str(const std::string& s) {
        u32(static_cast<uint32_t>(s.size()));
        b.append(s.data(), s.size());
    }
    std::string take() { return std::move(b); }
private:
    std::string b;
};

class Reader {
public:
    explicit Reader(const std::string& data) : m_data(data), m_pos(0) {}
    bool u8(uint8_t& out) {
        if (m_pos + 1 > m_data.size()) return false;
        out = static_cast<uint8_t>(m_data[m_pos++]);
        return true;
    }
    bool i64(int64_t& out) {
        if (m_pos + 8 > m_data.size()) return false;
        uint64_t u = 0;
        for (int i = 0; i < 8; ++i) u = (u << 8) | static_cast<uint8_t>(m_data[m_pos++]);
        out = static_cast<int64_t>(u);
        return true;
    }
    bool u32(uint32_t& out) {
        if (m_pos + 4 > m_data.size()) return false;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v = (v << 8) | static_cast<uint8_t>(m_data[m_pos++]);
        out = v;
        return true;
    }
    bool str(std::string& out, size_t max_len) {
        uint32_t n;
        if (!u32(n)) return false;
        if (n > max_len) return false;
        if (m_pos + n > m_data.size()) return false;
        out.assign(m_data.data() + m_pos, n);
        m_pos += n;
        return true;
    }
    bool at_end() const { return m_pos == m_data.size(); }
private:
    const std::string& m_data;
    size_t m_pos{0};
};

} // namespace

const char* receipt_type_name(uint8_t t) {
    switch (t) {
        case kReceived: return "RECEIVED";
        case kProcessed: return "PROCESSED";
        case kRead: return "READ";
        case kRejected: return "REJECTED";
    }
    return "UNKNOWN";
}

const char* failure_class_name(uint8_t c) {
    switch (c) {
        case kFailTransient: return "TRANSIENT";
        case kFailTerminal: return "TERMINAL";
        case kFailPolicy: return "POLICY";
        case kFailSecurity: return "SECURITY";
        case kFailNone: return "NONE";
    }
    return "UNKNOWN";
}

std::string encode_received_ack(const ReceivedAckFrame& f) {
    Writer w;
    w.str(f.object_id_hex);
    w.str(f.destination);
    w.i64(f.received_at_ms);
    w.u8(f.receipt_type);
    return w.take();
}

bool decode_received_ack(const std::string& data, ReceivedAckFrame& out) {
    Reader r(data);
    if (!r.str(out.object_id_hex, kMaxIdLen) ||
        !r.str(out.destination, kMaxStringLen) ||
        !r.i64(out.received_at_ms) ||
        !r.u8(out.receipt_type)) {
        return false;
    }
    return r.at_end();
}

std::string canonical_receipt_bytes(const std::string& object_id_hex,
                                    const std::string& object_hash_hex,
                                    const std::string& origin,
                                    const std::string& destination,
                                    int64_t received_at_ms,
                                    uint8_t receipt_type) {
    Writer w;
    w.str(object_id_hex);
    w.str(object_hash_hex);
    w.str(origin);
    w.str(destination);
    w.i64(received_at_ms);
    w.u8(receipt_type);
    return w.take();
}

std::string encode_receipt(const ReceiptPayload& r) {
    Writer w;
    w.str(r.object_id_hex);
    w.str(r.object_hash_hex);
    w.str(r.origin);
    w.str(r.destination);
    w.i64(r.received_at_ms);
    w.u8(r.receipt_type);
    w.i64(r.object_created_at_ms);
    w.str(r.signature);
    w.str(r.signer_pk_hex);
    return w.take();
}

bool decode_receipt(const std::string& data, ReceiptPayload& out) {
    Reader r(data);
    if (!r.str(out.object_id_hex, kMaxIdLen) ||
        !r.str(out.object_hash_hex, kMaxHashHex) ||
        !r.str(out.origin, kMaxStringLen) ||
        !r.str(out.destination, kMaxStringLen) ||
        !r.i64(out.received_at_ms) ||
        !r.u8(out.receipt_type) ||
        !r.i64(out.object_created_at_ms) ||
        !r.str(out.signature, kMaxSigLen) ||
        !r.str(out.signer_pk_hex, 128)) {
        return false;
    }
    return r.at_end();
}

} // namespace delivery
} // namespace networkos