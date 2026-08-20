// handoff_frames.cpp — Phase 4 handoff frame codec (bounded, validated).

#include "networkos/handoff/handoff_frames.h"

#include <cstring>
#include <limits>
#include <vector>

namespace networkos {
namespace handoff {

namespace {

// Hard bounds (defense in depth; wire_codec already caps at 10 MB total).
constexpr size_t kMaxIdLen = 600;        // ObjectId hex upper bound
constexpr size_t kMaxStringLen = 2048;   // namespace/destination/carrier ids
constexpr size_t kMaxEnvelopeLen = 16ull * 1024ull * 1024ull;  // obj envelope cap

class Writer {
public:
    void u8(uint8_t v) { b.push_back(static_cast<char>(v)); }
    void i64(int64_t v) {
        const uint64_t u = static_cast<uint64_t>(v);
        for (int shift = 56; shift >= 0; shift -= 8) {
            b.push_back(static_cast<char>((u >> shift) & 0xFF));
        }
    }
    void u64(uint64_t v) { i64(static_cast<int64_t>(v)); }
    void str(const std::string& s) {
        u32(static_cast<uint32_t>(s.size()));
        b.append(s.data(), s.size());
    }
    void raw(const std::string& s) { b.append(s.data(), s.size()); }
    std::string take() { return std::move(b); }
private:
    void u32(uint32_t v) {
        for (int shift = 24; shift >= 0; shift -= 8) {
            b.push_back(static_cast<char>((v >> shift) & 0xFF));
        }
    }
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
        for (int i = 0; i < 8; ++i) {
            u = (u << 8) | static_cast<uint8_t>(m_data[m_pos++]);
        }
        out = static_cast<int64_t>(u);
        return true;
    }
    bool u64(uint64_t& out) { return i64(reinterpret_cast<int64_t&>(out)); }
    bool str(std::string& out, size_t max_len) {
        uint32_t n;
        if (!u32(n)) return false;
        if (n > max_len) return false;
        if (m_pos + n > m_data.size()) return false;
        out.assign(m_data.data() + m_pos, n);
        m_pos += n;
        return true;
    }
    bool raw_tail(std::string& out, size_t max_len) {
        const size_t remaining = m_data.size() - m_pos;
        if (remaining > max_len) return false;
        out.assign(m_data.data() + m_pos, remaining);
        m_pos = m_data.size();
        return true;
    }
    bool at_end() const { return m_pos == m_data.size(); }
private:
    bool u32(uint32_t& out) {
        if (m_pos + 4 > m_data.size()) return false;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            v = (v << 8) | static_cast<uint8_t>(m_data[m_pos++]);
        }
        out = v;
        return true;
    }
    const std::string& m_data;
    size_t m_pos{0};
};

} // namespace
const char* reject_reason_name(uint8_t reason) {
    switch (reason) {
        case kRejectedAuth: return "REJECTED_AUTH";
        case kRejectedPolicy: return "REJECTED_POLICY";
        case kRejectedQuota: return "REJECTED_QUOTA";
        case kBusy: return "BUSY";
        case kRetryAfter: return "RETRY_AFTER";
    }
    return "UNKNOWN";
}

std::string encode_offer(const OfferFrame& f) {
    Writer w;
    w.str(f.object_id_hex);
    w.str(f.namespace_id);
    w.str(f.origin);
    w.str(f.destination);
    w.u64(f.size_bytes);
    w.str(f.payload_hash_hex);
    w.i64(f.expires_at_ms);
    w.i64(f.requested_storage_class);
    w.i64(f.requested_lease_ms);
    return w.take();
}

bool decode_offer(const std::string& data, OfferFrame& out) {
    Reader r(data);
    if (!r.str(out.object_id_hex, kMaxIdLen) ||
        !r.str(out.namespace_id, kMaxStringLen) ||
        !r.str(out.origin, kMaxStringLen) ||
        !r.str(out.destination, kMaxStringLen) ||
        !r.u64(out.size_bytes) ||
        !r.str(out.payload_hash_hex, 128) ||
        !r.i64(out.expires_at_ms) ||
        !r.i64(out.requested_storage_class) ||
        !r.i64(out.requested_lease_ms)) {
        return false;
    }
    return r.at_end();
}

std::string encode_accept(const AcceptFrame& f) {
    Writer w;
    w.str(f.object_id_hex);
    w.i64(f.accepted_until_ms);
    w.i64(f.storage_class);
    w.str(f.carrier_id);
    return w.take();
}

bool decode_accept(const std::string& data, AcceptFrame& out) {
    Reader r(data);
    if (!r.str(out.object_id_hex, kMaxIdLen) ||
        !r.i64(out.accepted_until_ms) ||
        !r.i64(out.storage_class) ||
        !r.str(out.carrier_id, kMaxStringLen)) {
        return false;
    }
    return r.at_end();
}

std::string encode_reject(const RejectFrame& f) {
    Writer w;
    w.str(f.object_id_hex);
    w.u8(f.reason);
    w.i64(f.retry_after_ms);
    return w.take();
}

bool decode_reject(const std::string& data, RejectFrame& out) {
    Reader r(data);
    if (!r.str(out.object_id_hex, kMaxIdLen) ||
        !r.u8(out.reason) ||
        !r.i64(out.retry_after_ms)) {
        return false;
    }
    return r.at_end();
}

std::string encode_data(const DataFrame& f) {
    Writer w;
    w.str(f.object_id_hex);
    w.str(f.envelope);
    return w.take();
}

bool decode_data(const std::string& data, DataFrame& out) {
    Reader r(data);
    if (!r.str(out.object_id_hex, kMaxIdLen) ||
        !r.str(out.envelope, kMaxEnvelopeLen)) {
        return false;
    }
    return r.at_end();
}

std::string encode_stored_ack(const StoredAckFrame& f) {
    Writer w;
    w.str(f.object_id_hex);
    w.str(f.carrier_id);
    w.i64(f.accepted_until_ms);
    w.i64(f.storage_class);
    w.str(f.signature);
    w.str(f.carrier_pk_hex);
    return w.take();
}

bool decode_stored_ack(const std::string& data, StoredAckFrame& out) {
    Reader r(data);
    if (!r.str(out.object_id_hex, kMaxIdLen) ||
        !r.str(out.carrier_id, kMaxStringLen) ||
        !r.i64(out.accepted_until_ms) ||
        !r.i64(out.storage_class) ||
        !r.str(out.signature, 128) ||
        !r.str(out.carrier_pk_hex, 128)) {
        return false;
    }
    return r.at_end();
}

std::string canonical_lease_bytes(const std::string& object_id_hex,
                                  const std::string& carrier_id,
                                  int64_t accepted_until_ms,
                                  int64_t storage_class) {
    Writer w;
    w.str(object_id_hex);
    w.str(carrier_id);
    w.i64(accepted_until_ms);
    w.i64(storage_class);
    return w.take();
}

} // namespace handoff
} // namespace networkos

