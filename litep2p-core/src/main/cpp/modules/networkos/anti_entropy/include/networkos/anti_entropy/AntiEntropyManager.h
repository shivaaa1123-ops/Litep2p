#pragma once

// Network OS Phase 6 — AntiEntropyManager (master doc §12/§59/§60/§65/§82,
// phase file 06). Pull-heavy reconciliation: on a useful peer connection the
// two peers exchange compact inventory summaries and WANT only the objects
// they are missing — no blind resend.
//
// Session order (§59):
//   1. authenticate (Phase 2 secure session)        [already established]
//   2. negotiate capabilities (Phase 2)             [already established]
//   3. exchange inventory summaries                 <-- this module
//   4. deliver objects directly addressed to this peer   (Phase 5)
//   5. exchange receipts                                  (Phase 5)
//   6. repair high-priority replica deficits (Phase 7)    [stub hook]
//   7. low-priority anti-entropy                         <-- this module
//   8. close when no useful work remains
//
// This module implements steps 3/7 (inventory + want/transfer) and exposes the
// Phase 7 repair-request hook as a no-op stub. Work is PRIORITIZED (§60) and
// BOUNDED per session (§6.5): per-session object/byte/time caps; remaining work
// is deferred (event-triggered resumption), never polled. Pull-first: sessions
// are only ever started on an existing connected session (event-triggered), so
// an idle runtime makes no reconciliation traffic (no gossip timers).

#include "networkos/Runtime.h"
#include "networkos/anti_entropy/anti_entropy_frames.h"
#include "networkos/objectstore/ObjectStore.h"

#include "message_types.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace networkos {
namespace anti_entropy {

// Step 6.1 — inventory source seam. The reconciliation session flow calls this
// to get THIS peer's summary; the encoding format (exact list v0 now, Bloom
// filter v1 later) is decided here, so the session flow never changes when the
// format evolves.
class IInventorySource {
public:
    virtual ~IInventorySource() = default;
    // Build the bounded inventory summary this peer casts now.
    virtual InventoryFrame buildInventory(uint32_t limit) = 0;
    // True if `object_id_hex` is held locally (dedup context, §65).
    virtual bool holds(const std::string& object_id_hex) = 0;
};

class AntiEntropyManager {
public:
    struct Config {
        bool enabled{true};
        uint32_t inventory_limit{kMaxInventoryEntries};  // bounded
        uint32_t max_objects_per_session{256};           // §6.5 cap
        uint64_t max_bytes_per_session{4ull * 1024 * 1024};
        int64_t session_deadline_ms{20000};              // §6.5 time budget
        std::string local_peer_id;
    };

    using SendFn = std::function<bool(const std::string& peer_id, MessageType type,
                                      const std::string& payload)>;
    using GetEnvelopeFn = std::function<Result(const ObjectId&, std::string& envelope)>;
    using EventFn = std::function<void(const std::string& kind, const std::string& payload)>;

    explicit AntiEntropyManager(ObjectStore* store, const Config& cfg);
    ~AntiEntropyManager();

    void setSendFn(SendFn fn);
    void setEventFn(EventFn fn);
    // Provide local envelope lookup for transfer (default: from the store).
    void setEnvelopeFn(GetEnvelopeFn fn);

    // Step 6.3/6.7 — a peer came online: kick a reconciliation session
    // (pull-first). Never launches from a timer.
    void onPeerReady(const std::string& peer_id);

    // Receive path (via the runtime typed-frame hook). Never blocks.
    void onFrame(const std::string& peer_id, MessageType type,
                 const std::string& payload);

    // Step 6.8 — structured counters.
    struct Counters {
        uint64_t inventories_sent{0};
        uint64_t inventories_received{0};
        uint64_t wants_sent{0};
        uint64_t wants_received{0};
        uint64_t objects_transferred{0};
        uint64_t bytes_reconciled{0};
        uint64_t duplicate_hits{0};        // dedup, not a re-send
        uint64_t sessions{0};
        int64_t last_session_duration_ms{0};
    };
    Counters counters() const;
    std::string telemetryJson() const;

    // Repair hook for Phase 7 (Step 6.3 #6): no-op stub now.
    size_t runRepairHook(const std::string& peer_id);

private:
    // Build + send this peer's inventory to `peer_id` (§12).
    void sendInventory_(const std::string& peer_id);
    // Compute missing ids (ours absent) + WANT them (§59/§65) — pull-first.
    void handleInventory_(const std::string& peer_id, const InventoryFrame& f);
    // Responder: transfer the WANTed objects we hold, skipping already-held +
    // honoring per-session caps (§65/§6.5).
    void handleWant_(const std::string& peer_id, const ObjectWantFrame& f);

    Result sendEnvelope_(const std::string& peer_id, const ObjectId& id,
                         const std::string& envelope);

    void emit_(const std::string& kind, const std::string& payload);
    bool send_(const std::string& peer_id, MessageType type, const std::string& payload);
    static int64_t now_ms_();

    ObjectStore* m_store{nullptr};
    Config m_cfg;
    mutable std::mutex m_mu;
    SendFn m_send;
    EventFn m_event;
    GetEnvelopeFn m_envelope_fn;
    std::unique_ptr<IInventorySource> m_inventory;
    Counters m_ctr;
    // Active session budgets per peer (reset on each onPeerReady). §6.5.
    struct SessionBudget {
        uint32_t objects_transferred{0};
        uint64_t bytes_transferred{0};
        int64_t deadline_ms{0};
    };
    std::unordered_map<std::string, SessionBudget> m_sessions;
};

std::unique_ptr<AntiEntropyManager> createAntiEntropyManager(
    ObjectStore* store, const AntiEntropyManager::Config& cfg);

} // namespace anti_entropy
} // namespace networkos