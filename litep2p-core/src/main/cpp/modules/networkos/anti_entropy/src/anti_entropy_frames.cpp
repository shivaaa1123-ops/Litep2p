// anti_entropy_frames.cpp — Phase 6 anti-entropy frame codec (bounded).

#include "networkos/anti_entropy/anti_entropy_frames.h"

#include <cstring>

namespace networkos {
namespace anti_entropy {

namespace {

constexpr size_t kMaxIdLen = 600;   // ObjectId hex upper bound

class Writer {
public:
    void u8(uint8_t v) { b.push_back(static_cast<char>(v)); }
    void u64(uint64_t v) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            b.push_back(static_cast<char>((v >> shift) & 0xFF));
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
    bool u64(uint64_t& out) {
        if (m_pos + 8 > m_data.size()) return false;
        uint64_t u = 0;
        for (int i = 0; i < 8; ++i) u = (u << 8) | static_cast<uint8_t>(m_data[m_pos++]);
        out = u;
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

std::string encode_inventory(const InventoryFrame& f) {
    Writer w;
    w.u8(f.format);
    w.u32(f.count);
    for (uint32_t i = 0; i < f.count && i < f.entries.size(); ++i) {
        const InventoryEntry& e = f.entries[i];
        w.str(e.object_id_hex);
        w.u8(e.state);
        w.u64(static_cast<uint64_t>(e.created_at_ms));
    }
    return w.take();
}

bool decode_inventory(const std::string& data, InventoryFrame& out) {
    Reader r(data);
    if (!r.u8(out.format)) return false;
    if (!r.u32(out.count)) return false;
    if (out.count > kMaxInventoryEntries) return false;   // bounded (§12)
    out.entries.clear();
    out.entries.reserve(out.count);
    for (uint32_t i = 0; i < out.count; ++i) {
        InventoryEntry e;
        if (!r.str(e.object_id_hex, kMaxIdLen)) return false;
        if (!r.u8(e.state)) return false;
        uint64_t ts;
        if (!r.u64(ts)) return false;
        e.created_at_ms = static_cast<int64_t>(ts);
        out.entries.push_back(std::move(e));
    }
    return r.at_end();
}

std::string encode_object_want(const ObjectWantFrame& f) {
    Writer w;
    w.u32(static_cast<uint32_t>(f.object_id_hexes.size()));
    for (const auto& id : f.object_id_hexes) w.str(id);
    w.u32(static_cast<uint32_t>(f.already_held.size()));
    for (const auto& id : f.already_held) w.str(id);
    return w.take();
}

bool decode_object_want(const std::string& data, ObjectWantFrame& out) {
    Reader r(data);
    uint32_t n_want = 0, n_held = 0;
    if (!r.u32(n_want)) return false;
    if (n_want > kMaxWantIds) return false;   // bounded
    out.object_id_hexes.clear();
    out.object_id_hexes.reserve(n_want);
    for (uint32_t i = 0; i < n_want; ++i) {
        std::string id;
        if (!r.str(id, kMaxIdLen)) return false;
        out.object_id_hexes.push_back(std::move(id));
    }
    if (!r.u32(n_held)) return false;
    if (n_held > kMaxWantIds) return false;
    out.already_held.clear();
    out.already_held.reserve(n_held);
    for (uint32_t i = 0; i < n_held; ++i) {
        std::string id;
        if (!r.str(id, kMaxIdLen)) return false;
        out.already_held.push_back(std::move(id));
    }
    return r.at_end();
}

} // namespace anti_entropy
} // namespace networkos