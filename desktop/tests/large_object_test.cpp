// large_object_test.cpp — Network OS Phase 10 verification suite.
//
// Covers (phase file §9): manifest encode/decode (strict, tamper rejected),
// content-addressed chunk ID derivation, per-chunk hash verification + tamper
// detection, resumable transfer (verified chunks never re-sent), memory bound
// (chunk-sized window, no whole-file buffering), bulk scheduling policy
// (metered deferral, Wi-Fi/charging preferred), priority inversion protection
// (control/receipts drain before bulk), and backpressure/admission.

#include "networkos/largeobject/largeobject.h"
#include "networkos/object/envelope.h"

#include <iostream>
#include <string>
#include <vector>

namespace {

int g_failures = 0;
int g_checks = 0;

#define TEST_ASSERT(cond, msg)                                        \
    do {                                                              \
        ++g_checks;                                                   \
        if (!(cond)) {                                                \
            std::cerr << "FAIL: " << msg << " (line " << __LINE__ << ")\n"; \
            ++g_failures;                                             \
        }                                                             \
    } while (0)

using namespace networkos::largeobject;
using networkos::obj::compute_payload_hash;

// Build a manifest for `num_chunks` chunks of `chunk_size`, with real hashes.
Manifest makeManifest(uint32_t num_chunks, uint32_t chunk_size,
                      const std::vector<std::string>& chunk_data) {
    Manifest m;
    m.content_hash = compute_payload_hash("whole-content");
    m.chunk_size = chunk_size;
    m.encryption_metadata = "meta";
    m.source_info = "peer-src";
    m.availability_policy = 1;   // bulk
    m.ttl_ms = 7LL * 24 * 3600 * 1000;
    uint64_t total = 0;
    for (uint32_t i = 0; i < num_chunks; ++i) {
        m.chunk_hashes.push_back(compute_payload_hash(chunk_data[i]));
        total += chunk_data[i].size();
    }
    m.total_size = total;
    return m;
}

std::vector<std::string> makeChunkData(uint32_t n, uint32_t size) {
    std::vector<std::string> out;
    for (uint32_t i = 0; i < n; ++i) {
        out.push_back(std::string(size, static_cast<char>('a' + (i % 26))));
    }
    return out;
}

// ---------------------------------------------------------------------------
// 1. Manifest codec: round-trip + strict decode (trailing/tamper rejected).
// ---------------------------------------------------------------------------
static void test_manifest_codec() {
    auto data = makeChunkData(4, 64);
    Manifest m = makeManifest(4, 64, data);
    const std::string enc = encode_manifest(m);
    TEST_ASSERT(!enc.empty(), "manifest encodes");

    Manifest dec;
    TEST_ASSERT(decode_manifest(enc, dec), "manifest decodes");
    TEST_ASSERT(dec.content_hash == m.content_hash, "content_hash round-trips");
    TEST_ASSERT(dec.total_size == m.total_size, "total_size round-trips");
    TEST_ASSERT(dec.chunk_size == 64, "chunk_size round-trips");
    TEST_ASSERT(dec.chunk_hashes.size() == 4, "4 chunk hashes");
    TEST_ASSERT(dec.chunk_hashes[2] == m.chunk_hashes[2], "chunk hash round-trips");
    TEST_ASSERT(dec.availability_policy == 1, "policy round-trips");

    // Strict: trailing bytes rejected.
    std::string trailing = enc + "xx";
    Manifest t;
    TEST_ASSERT(!decode_manifest(trailing, t), "trailing bytes rejected");
    // Strict: truncation rejected.
    Manifest tr;
    TEST_ASSERT(!decode_manifest(enc.substr(0, enc.size() / 2), tr), "truncated rejected");
    // Empty rejected.
    Manifest e;
    TEST_ASSERT(!decode_manifest("", e), "empty rejected");
    std::cout << "manifest codec ok: round-trip + strict decode\n";
}

// ---------------------------------------------------------------------------
// 2. Chunk ID derivation (§5): content-addressed + deterministic.
// ---------------------------------------------------------------------------
static void test_chunk_id() {
    const std::string h = "deadbeef";
    TEST_ASSERT(chunk_object_id(h, 0) == "deadbeef:0", "chunk 0 id");
    TEST_ASSERT(chunk_object_id(h, 5) == "deadbeef:5", "chunk 5 id");
    TEST_ASSERT(chunk_object_id(h, 0) != chunk_object_id(h, 1), "distinct per index");
    TEST_ASSERT(chunk_object_id(h, 3) == chunk_object_id("deadbeef", 3),
                "deterministic for same content+index");
    std::cout << "chunk id ok: content-addressed + deterministic\n";
}

// ---------------------------------------------------------------------------
// 3. Per-chunk hash verification + tamper detection.
// ---------------------------------------------------------------------------
static void test_hash_tamper() {
    auto data = makeChunkData(3, 32);
    Manifest m = makeManifest(3, 32, data);
    ChunkTransfer::Config cfg;
    ChunkTransfer xfer(m, cfg);

    TEST_ASSERT(xfer.markChunkVerified(0, data[0]), "correct chunk verifies");
    TEST_ASSERT(xfer.markChunkVerified(1, data[1]), "chunk 1 verifies");
    // Tamper: corrupt one byte -> hash mismatch -> rejected.
    std::string corrupt = data[2];
    corrupt[0] ^= 0x01;
    TEST_ASSERT(!xfer.markChunkVerified(2, corrupt), "tampered chunk rejected");
    TEST_ASSERT(xfer.chunkState(2) == ChunkState::kPending, "tampered stays pending");
    // Correct data then verifies.
    TEST_ASSERT(xfer.markChunkVerified(2, data[2]), "correct data verifies after retry");
    // Out-of-range index rejected.
    TEST_ASSERT(!xfer.markChunkVerified(99, data[0]), "out-of-range rejected");
    std::cout << "hash verification + tamper detection ok\n";
}

// ---------------------------------------------------------------------------
// 4. Resumable transfer: verified chunks are NEVER re-requested (no re-send),
//    resume starts at the first unverified chunk.
// ---------------------------------------------------------------------------
static void test_resume_no_resend() {
    auto data = makeChunkData(8, 16);
    Manifest m = makeManifest(8, 16, data);
    ChunkTransfer::Config cfg;
    cfg.max_chunks_in_flight = 16;
    ChunkTransfer xfer(m, cfg);

    // Verify + commit the first 3 chunks (simulating progress before a crash).
    for (uint32_t i = 0; i < 3; ++i) {
        TEST_ASSERT(xfer.markChunkVerified(i, data[i]), "verify chunk");
        TEST_ASSERT(xfer.markChunkCommitted(i), "commit chunk");
    }
    TEST_ASSERT(xfer.committedCount() == 3, "3 committed");

    // Resume: next requests start at chunk 3 (first unverified), never 0..2.
    auto next = xfer.nextChunksToRequest(10);
    bool resend_verified = false;
    for (auto idx : next) if (idx < 3) resend_verified = true;
    TEST_ASSERT(!resend_verified, "verified chunks never re-requested");
    TEST_ASSERT(!next.empty() && next[0] == 3, "resume from first unverified (3)");
    TEST_ASSERT(xfer.progressPercent() == 37, "progress ~37%");   // 3/8 = 37
    TEST_ASSERT(!xfer.isComplete(), "not complete yet");

    // Commit the rest -> complete.
    for (uint32_t i = 3; i < 8; ++i) {
        xfer.markChunkVerified(i, data[i]);
        xfer.markChunkCommitted(i);
    }
    TEST_ASSERT(xfer.isComplete(), "complete after all committed");
    TEST_ASSERT(xfer.progressPercent() == 100, "progress 100%");
    TEST_ASSERT(xfer.nextChunksToRequest(10).empty(), "nothing left to request");
    std::cout << "resume ok: verified chunks never re-sent\n";
}

// ---------------------------------------------------------------------------
// 5. Memory bound (§34): working memory bounded by window x chunk size.
// ---------------------------------------------------------------------------
static void test_memory_bound() {
    auto data = makeChunkData(100, 1024);   // 100 KB total
    Manifest m = makeManifest(100, 1024, data);
    ChunkTransfer::Config cfg;
    cfg.chunk_size = 1024;
    cfg.max_chunks_in_flight = 4;            // small window
    ChunkTransfer xfer(m, cfg);

    TEST_ASSERT(xfer.maxInFlightBytes() == 4 * 1024,
                "max in-flight bytes = window x chunk size");
    // Sliding window: nextChunksToRequest bounded by window even with max=100.
    auto next = xfer.nextChunksToRequest(100);
    TEST_ASSERT(next.size() <= 4, "window bounds in-flight requests");
    std::cout << "memory bound ok: chunk-sized window, no whole-file buffering\n";
}

// ---------------------------------------------------------------------------
// 6. Bulk scheduling policy (§5.4): defer on metered; prefer Wi-Fi/charging.
// ---------------------------------------------------------------------------
static void test_bulk_scheduling() {
    auto data = makeChunkData(2, 8);
    Manifest m = makeManifest(2, 8, data);
    ChunkTransfer::Config cfg;
    cfg.allow_metered = false;
    cfg.prefer_charging = true;
    ChunkTransfer xfer(m, cfg);

    TEST_ASSERT(xfer.shouldProceedBulk(true, false, false), "Wi-Fi => proceed");
    TEST_ASSERT(xfer.shouldProceedBulk(true, true, false), "Wi-Fi+charging => proceed");
    TEST_ASSERT(!xfer.shouldProceedBulk(false, false, true), "metered => defer");
    TEST_ASSERT(!xfer.shouldProceedBulk(false, false, false),
                "no wifi/no charging => defer (prefer_charging)");
    TEST_ASSERT(xfer.shouldProceedBulk(false, true, false), "charging => proceed");
    std::cout << "bulk scheduling ok: metered defers, Wi-Fi/charging proceed\n";
}

// ---------------------------------------------------------------------------
// 7. Priority inversion protection (§67): control/receipts drain BEFORE bulk.
// ---------------------------------------------------------------------------
static void test_priority_inversion() {
    BulkScheduler sched;
    // Bulk enqueued FIRST, then higher-priority work arrives.
    sched.enqueue(TransferClass::kBulk, "bulk-chunk-0");
    sched.enqueue(TransferClass::kBulk, "bulk-chunk-1");
    sched.enqueue(TransferClass::kReceipt, "receipt-1");
    sched.enqueue(TransferClass::kControl, "control-1");
    sched.enqueue(TransferClass::kNormal, "chat-1");

    TEST_ASSERT(sched.pendingAll() == 5, "5 slots pending");
    TEST_ASSERT(sched.hasHigherPriorityWork(TransferClass::kBulk),
                "higher-priority work pending above bulk");

    // Drain order must be control > receipt > normal > bulk.
    BulkScheduler::Slot s;
    TEST_ASSERT(sched.nextSlot(s) && s.cls == TransferClass::kControl, "control first");
    TEST_ASSERT(sched.nextSlot(s) && s.cls == TransferClass::kReceipt, "receipt second");
    TEST_ASSERT(sched.nextSlot(s) && s.cls == TransferClass::kNormal, "normal third");
    TEST_ASSERT(sched.nextSlot(s) && s.cls == TransferClass::kBulk, "bulk fourth");
    TEST_ASSERT(sched.nextSlot(s) && s.cls == TransferClass::kBulk, "bulk fifth");
    TEST_ASSERT(!sched.nextSlot(s), "drained");
    std::cout << "priority inversion ok: bulk never blocks control/receipts\n";
}

// ---------------------------------------------------------------------------
// 8. Backpressure / admission (§68): BUSY/REJECTED_QUOTA under load.
// ---------------------------------------------------------------------------
static void test_backpressure() {
    // Healthy: accept.
    TEST_ASSERT(admitChunk(false, 0, 100) == Admission::kAccept, "healthy => accept");
    // Approaching capacity (>=75%): defer.
    TEST_ASSERT(admitChunk(false, 80, 100) == Admission::kDefer, "75%+ => defer");
    // Full: busy.
    TEST_ASSERT(admitChunk(false, 100, 100) == Admission::kBusy, "full => busy");
    TEST_ASSERT(admitChunk(false, 150, 100) == Admission::kBusy, "over cap => busy");
    // Storage pressure: reject quota (never silently drop).
    TEST_ASSERT(admitChunk(true, 0, 100) == Admission::kRejectedQuota,
                "storage pressure => rejected_quota");
    std::cout << "backpressure ok: accept/defer/busy/reject_quota\n";
}

} // namespace

int main() {
    test_manifest_codec();
    test_chunk_id();
    test_hash_tamper();
    test_resume_no_resend();
    test_memory_bound();
    test_bulk_scheduling();
    test_priority_inversion();
    test_backpressure();
    std::cout << (g_failures == 0 ? "PASS" : "FAIL") << ": " << g_checks
              << " checks, " << g_failures << " failure(s)\n";
    return g_failures == 0 ? 0 : 1;
}