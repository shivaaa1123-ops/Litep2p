// largeobject.cpp — Network OS Phase 10 large object layer.

#include "networkos/largeobject/largeobject.h"

#include "networkos/object/envelope.h"   // canonical content hash

#include <cstring>

namespace networkos {
namespace largeobject {

namespace {

// Bounded binary writer/reader (same strict style as the other frame codecs).
class Writer {
public:
    void u8(uint8_t v) { b.push_back(static_cast<char>(v)); }
    void u32(uint32_t v) {
        for (int s = 24; s >= 0; s -= 8) b.push_back(static_cast<char>((v >> s) & 0xFF));
    }
    void u64(uint64_t v) {
        for (int s = 56; s >= 0; s -= 8) b.push_back(static_cast<char>((v >> s) & 0xFF));
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
    explicit Reader(const std::string& d) : m_d(d), m_p(0) {}
    bool u8(uint8_t& o) {
        if (m_p + 1 > m_d.size()) return false;
        o = static_cast<uint8_t>(m_d[m_p++]);
        return true;
    }
    bool u32(uint32_t& o) {
        if (m_p + 4 > m_d.size()) return false;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v = (v << 8) | static_cast<uint8_t>(m_d[m_p++]);
        o = v;
        return true;
    }
    bool u64(uint64_t& o) {
        if (m_p + 8 > m_d.size()) return false;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | static_cast<uint8_t>(m_d[m_p++]);
        o = v;
        return true;
    }
    bool str(std::string& o, size_t max_len) {
        uint32_t n;
        if (!u32(n)) return false;
        if (n > max_len) return false;
        if (m_p + n > m_d.size()) return false;
        o.assign(m_d.data() + m_p, n);
        m_p += n;
        return true;
    }
    bool at_end() const { return m_p == m_d.size(); }
private:
    const std::string& m_d;
    size_t m_p;
};

constexpr size_t kMaxHashLen = 256;
constexpr size_t kMaxMetaLen = 4096;
constexpr uint32_t kMaxChunks = 1u << 20;   // hard cap before allocation (§29)

} // namespace

// ---- Manifest codec --------------------------------------------------------
std::string encode_manifest(const Manifest& m) {
    Writer w;
    w.str(m.content_hash);
    w.u64(m.total_size);
    w.u32(m.chunk_size);
    w.u32(static_cast<uint32_t>(m.chunk_hashes.size()));
    for (const auto& h : m.chunk_hashes) w.str(h);
    w.str(m.encryption_metadata);
    w.str(m.source_info);
    w.u8(m.availability_policy);
    w.u64(static_cast<uint64_t>(m.ttl_ms));
    return w.take();
}

bool decode_manifest(const std::string& data, Manifest& out) {
    Reader r(data);
    if (!r.str(out.content_hash, kMaxHashLen)) return false;
    if (!r.u64(out.total_size)) return false;
    if (!r.u32(out.chunk_size)) return false;
    uint32_t n = 0;
    if (!r.u32(n)) return false;
    if (n > kMaxChunks) return false;   // bounded before allocation
    out.chunk_hashes.clear();
    out.chunk_hashes.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        std::string h;
        if (!r.str(h, kMaxHashLen)) return false;
        out.chunk_hashes.push_back(std::move(h));
    }
    if (!r.str(out.encryption_metadata, kMaxMetaLen)) return false;
    if (!r.str(out.source_info, kMaxMetaLen)) return false;
    if (!r.u8(out.availability_policy)) return false;
    uint64_t ttl = 0;
    if (!r.u64(ttl)) return false;
    out.ttl_ms = static_cast<int64_t>(ttl);
    return r.at_end();
}

// ---- Chunk IDs (§5 content-addressed) --------------------------------------
std::string chunk_object_id(const std::string& content_hash, uint32_t index) {
    return content_hash + ":" + std::to_string(index);
}

// ---- ChunkTransfer ---------------------------------------------------------
ChunkTransfer::ChunkTransfer(Manifest manifest, Config cfg)
    : m_manifest(std::move(manifest)), m_cfg(cfg),
      m_states(m_manifest.chunk_count(), ChunkState::kPending) {}

std::vector<uint32_t> ChunkTransfer::nextChunksToRequest(size_t max) const {
    std::vector<uint32_t> out;
    uint32_t in_flight = chunksInFlight();
    // Resume from the first unverified chunk; bounded by the sliding window.
    for (uint32_t i = 0; i < m_states.size() && out.size() < max; ++i) {
        if (in_flight >= m_cfg.max_chunks_in_flight) break;
        if (m_states[i] == ChunkState::kPending) {
            out.push_back(i);
            ++in_flight;
        }
    }
    return out;
}

bool ChunkTransfer::markChunkVerified(uint32_t index, const std::string& chunk_data) {
    if (index >= m_states.size()) return false;
    if (index >= m_manifest.chunk_hashes.size()) return false;
    // Tamper/corruption detection: the chunk must hash to the manifest entry.
    const std::string h = obj::compute_payload_hash(chunk_data);
    if (h != m_manifest.chunk_hashes[index]) return false;
    m_states[index] = ChunkState::kVerified;
    return true;
}

bool ChunkTransfer::markChunkCommitted(uint32_t index) {
    if (index >= m_states.size()) return false;
    if (m_states[index] != ChunkState::kVerified) return false;  // commit after verify
    m_states[index] = ChunkState::kCommitted;
    return true;
}

ChunkState ChunkTransfer::chunkState(uint32_t index) const {
    if (index >= m_states.size()) return ChunkState::kPending;
    return m_states[index];
}

bool ChunkTransfer::isComplete() const {
    for (auto s : m_states) if (s != ChunkState::kCommitted) return false;
    return true;
}

size_t ChunkTransfer::verifiedCount() const {
    size_t n = 0;
    for (auto s : m_states) if (s >= ChunkState::kVerified) ++n;
    return n;
}

size_t ChunkTransfer::committedCount() const {
    size_t n = 0;
    for (auto s : m_states) if (s == ChunkState::kCommitted) ++n;
    return n;
}

uint8_t ChunkTransfer::progressPercent() const {
    if (m_states.empty()) return 100;
    return static_cast<uint8_t>((committedCount() * 100) / m_states.size());
}

size_t ChunkTransfer::maxInFlightBytes() const {
    return static_cast<size_t>(m_cfg.max_chunks_in_flight) *
           static_cast<size_t>(m_cfg.chunk_size);
}

uint32_t ChunkTransfer::chunksInFlight() const {
    uint32_t n = 0;
    for (auto s : m_states) {
        if (s == ChunkState::kInFlight || s == ChunkState::kReceived) ++n;
    }
    return n;
}

bool ChunkTransfer::shouldProceedBulk(bool wifi, bool charging, bool metered) const {
    if (metered && !m_cfg.allow_metered) return false;   // defer on metered (§5.4)
    if (m_cfg.prefer_charging && !wifi && !charging) return false;
    return true;
}

// ---- BulkScheduler ---------------------------------------------------------
namespace {
constexpr size_t kNumClasses = 5;
}

void BulkScheduler::enqueue(TransferClass cls, const std::string& id) {
    const size_t c = static_cast<size_t>(cls);
    if (c >= kNumClasses) return;
    auto& q = m_queues[c];
    for (const auto& e : q) if (e == id) return;   // idempotent per (class,id)
    q.push_back(id);
}

bool BulkScheduler::nextSlot(Slot& out) {
    // Higher priority (lower class value) always drains first; bulk last.
    for (size_t c = 0; c < kNumClasses; ++c) {
        if (!m_queues[c].empty()) {
            out.cls = static_cast<TransferClass>(c);
            out.id = m_queues[c].front();
            m_queues[c].erase(m_queues[c].begin());
            return true;
        }
    }
    return false;
}

size_t BulkScheduler::pending(TransferClass cls) const {
    const size_t c = static_cast<size_t>(cls);
    return c < kNumClasses ? m_queues[c].size() : 0;
}

size_t BulkScheduler::pendingAll() const {
    size_t n = 0;
    for (const auto& q : m_queues) n += q.size();
    return n;
}

bool BulkScheduler::hasHigherPriorityWork(TransferClass below) const {
    const size_t c = static_cast<size_t>(below);
    for (size_t i = 0; i < c && i < kNumClasses; ++i) {
        if (!m_queues[i].empty()) return true;
    }
    return false;
}

// ---- Admission & backpressure (§68) ----------------------------------------
Admission admitChunk(bool storage_pressure, size_t queue_depth, size_t queue_cap) {
    if (storage_pressure) return Admission::kRejectedQuota;
    if (queue_cap > 0 && queue_depth >= queue_cap) return Admission::kBusy;
    if (queue_cap > 0 && queue_depth * 4 >= queue_cap * 3) return Admission::kDefer;  // 75%
    return Admission::kAccept;
}

} // namespace largeobject
} // namespace networkos