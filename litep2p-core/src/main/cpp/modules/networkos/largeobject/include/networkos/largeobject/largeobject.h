#pragma once

// Network OS Phase 10 — Large Object Layer (master doc §32 large objects,
// §33 low-copy data path, §34 memory budget, §67 priority inversion, §68
// congestion, §69 compression, §89 Phase 10).
//
// Multi-megabyte content travels as a small MANIFEST + content-addressed
// CHUNK objects, never as one giant mailbox object. Transfers are resumable
// (checkpointed per chunk; verified chunks are never re-sent), memory-bounded
// (chunk-sized working window, no whole-file buffering), and scheduled as a
// separate low-priority bulk class that never blocks control/receipts/chat.

#include "networkos/Runtime.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace networkos {
namespace largeobject {

// Default chunk size matches the existing file_transfer engine (32 KB).
constexpr uint32_t kDefaultChunkSize = 32u * 1024u;
// Sliding window cap (mirrors file_transfer MAX_CHUNKS_IN_FLIGHT=16).
constexpr uint32_t kDefaultMaxChunksInFlight = 16u;

// ---------------------------------------------------------------------------
// Manifest (§32). A SMALL object that travels the normal durable network.
// ---------------------------------------------------------------------------
struct Manifest {
    std::string content_hash;              // whole-content hash (hex)
    uint64_t total_size{0};
    uint32_t chunk_size{kDefaultChunkSize};
    std::vector<std::string> chunk_hashes; // per-chunk hash (hex), index order
    std::string encryption_metadata;       // opaque (wrapped keys / nonce)
    std::string source_info;
    uint8_t availability_policy{0};        // bulk class / policy tag
    int64_t ttl_ms{0};

    uint32_t chunk_count() const {
        return static_cast<uint32_t>(chunk_hashes.size());
    }
};

// Strict, bounded codec. Rejects oversized / trailing bytes (§29).
std::string encode_manifest(const Manifest& m);
bool decode_manifest(const std::string& data, Manifest& out);

// ---------------------------------------------------------------------------
// Chunk IDs (§5): content-addressed. Deterministic from content_hash + index.
// ---------------------------------------------------------------------------
std::string chunk_object_id(const std::string& content_hash, uint32_t index);

// Per-chunk transfer state (§5.2 resume/checkpoint).
enum class ChunkState : uint8_t {
    kPending = 0,
    kInFlight = 1,
    kReceived = 2,
    kVerified = 3,     // hash-checked
    kCommitted = 4,    // durably stored
};

// ---------------------------------------------------------------------------
// ChunkTransfer — resumable, checkpointed, memory-bounded transfer tracker.
// Extends the file_transfer sliding-window/checkpoint semantics to the generic
// object model (manifest + chunk objects), reusing its invariants (§decision 9).
// ---------------------------------------------------------------------------
class ChunkTransfer {
public:
    struct Config {
        uint32_t chunk_size{kDefaultChunkSize};
        uint32_t max_chunks_in_flight{kDefaultMaxChunksInFlight};
        bool allow_metered{false};    // bulk defers on metered (§5.4)
        bool prefer_charging{true};   // bulk prefers Wi-Fi + charging
    };

    ChunkTransfer(Manifest manifest, Config cfg);

    const Manifest& manifest() const { return m_manifest; }

    // Resume: the next chunk indices to request, starting at the first
    // unverified chunk, bounded by the sliding window + `max`.
    std::vector<uint32_t> nextChunksToRequest(size_t max) const;

    // Record a chunk received + hash-verified. Returns false on hash mismatch
    // (tamper / corruption) and leaves the chunk pending for retransmit.
    bool markChunkVerified(uint32_t index, const std::string& chunk_data);
    bool markChunkCommitted(uint32_t index);
    ChunkState chunkState(uint32_t index) const;

    bool isComplete() const;              // all chunks committed
    size_t verifiedCount() const;
    size_t committedCount() const;
    uint8_t progressPercent() const;

    // Memory bound (§34): never more than max_chunks_in_flight chunk buffers.
    size_t maxInFlightBytes() const;
    uint32_t chunksInFlight() const;

    // Bulk scheduling (§5.4): proceed only when the resource context allows.
    bool shouldProceedBulk(bool wifi, bool charging, bool metered) const;

private:
    Manifest m_manifest;
    Config m_cfg;
    std::vector<ChunkState> m_states;
};

// ---------------------------------------------------------------------------
// Priority classes (§67/§71): control > critical > receipts > normal > bulk.
// Lower numeric value = higher priority.
// ---------------------------------------------------------------------------
enum class TransferClass : uint8_t {
    kControl = 0,
    kCritical = 1,
    kReceipt = 2,
    kNormal = 3,
    kBulk = 4,
};

// ---------------------------------------------------------------------------
// BulkScheduler — separate per-class queues with fair scheduling. A large
// bulk transfer must never block a higher-priority class (priority inversion
// protection, §67): bulk only gets a slot when no higher-class work is pending.
// ---------------------------------------------------------------------------
class BulkScheduler {
public:
    struct Slot {
        TransferClass cls{TransferClass::kNormal};
        std::string id;
    };

    // Enqueue work for a class (idempotent per (class,id)).
    void enqueue(TransferClass cls, const std::string& id);
    // Pop the next slot. Higher classes always drain before bulk; within a
    // class it is FIFO. Returns false when no work is pending.
    bool nextSlot(Slot& out);
    size_t pending(TransferClass cls) const;
    size_t pendingAll() const;
    bool hasHigherPriorityWork(TransferClass below) const;

private:
    // One FIFO queue per class (control/critical/receipt/normal/bulk).
    std::array<std::vector<std::string>, 5> m_queues;
};

// ---------------------------------------------------------------------------
// Admission & backpressure (§68): decide whether to accept a chunk offer.
// Never silently drop; overloaded receivers return BUSY/REJECTED_QUOTA and the
// sender defers with backoff.
// ---------------------------------------------------------------------------
enum class Admission : uint8_t {
    kAccept = 0,
    kBusy = 1,
    kRejectedQuota = 2,
    kDefer = 3,
};

Admission admitChunk(bool storage_pressure, size_t queue_depth, size_t queue_cap);

} // namespace largeobject
} // namespace networkos