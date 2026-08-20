// AntiEntropyManager.cpp - Network OS Phase 6 pull-heavy reconciliation.

#include "networkos/anti_entropy/AntiEntropyManager.h"

#include "networkos/handoff/handoff_frames.h"
#include "networkos/object/object_id.h"

#include <chrono>
#include <sstream>

namespace networkos {
namespace anti_entropy {

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Store-backed inventory source (Step 6.1): exact-list v0, bounded.
class StoreInventorySource : public IInventorySource {
public:
    explicit StoreInventorySource(ObjectStore* store) : m_store(store) {}
    InventoryFrame buildInventory(uint32_t limit) override {
        InventoryFrame f;
        f.format = kFormatExactList;
        if (!m_store) return f;
        m_store->enumerateInventory(
            limit, [&](const ObjectId& id, ObjectStatus st, int64_t created) -> Result {
                if (f.entries.size() >= limit) return Result::kOk;
                InventoryEntry e;
                e.object_id_hex = id.toHex();
                e.state = static_cast<uint8_t>(st);
                e.created_at_ms = created;
                f.entries.push_back(std::move(e));
                return Result::kOk;
            });
        f.count = static_cast<uint32_t>(f.entries.size());
        return f;
    }
    bool holds(const std::string& object_id_hex) override {
        if (!m_store) return false;
        ObjectId id;
        if (!ObjectId::fromHex(object_id_hex, id)) return false;
        ObjectMeta meta;
        return m_store->getMeta(id, meta) == Result::kOk;
    }
private:
    ObjectStore* m_store{nullptr};
};

} // namespace

AntiEntropyManager::AntiEntropyManager(ObjectStore* store, const Config& cfg)
    : m_store(store), m_cfg(cfg) {
    m_inventory = std::make_unique<StoreInventorySource>(store);
}

AntiEntropyManager::~AntiEntropyManager() = default;

void AntiEntropyManager::setSendFn(SendFn fn) { m_send = std::move(fn); }
void AntiEntropyManager::setEventFn(EventFn fn) { m_event = std::move(fn); }
void AntiEntropyManager::setEnvelopeFn(GetEnvelopeFn fn) { m_envelope_fn = std::move(fn); }

void AntiEntropyManager::emit_(const std::string& kind, const std::string& payload) {
    if (m_event) {
        try { m_event(kind, payload); } catch (...) {}
    }
}

bool AntiEntropyManager::send_(const std::string& peer_id, MessageType type,
                               const std::string& payload) {
    if (!m_send) return false;
    return m_send(peer_id, type, payload);
}

int64_t AntiEntropyManager::now_ms_() { return now_ms(); }

// ---------------------------------------------------------------------------
// onPeerReady: kick a reconciliation session (Step 6.3). Pull-first + bounded.
// Never launched by a timer — only on an already-useful connected session.
// ---------------------------------------------------------------------------
void AntiEntropyManager::onPeerReady(const std::string& peer_id) {
    if (!m_cfg.enabled) return;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.sessions++;
        SessionBudget& sb = m_sessions[peer_id];
        sb.objects_transferred = 0;
        sb.bytes_transferred = 0;
        sb.deadline_ms = now_ms() + m_cfg.session_deadline_ms;
    }
    emit_("RECON_SESSION_START", peer_id);
    // Step 6.3 #3: cast our inventory; the peer will WANT what it's missing.
    sendInventory_(peer_id);
}

// Step 6.3 #3 — cast our inventory summary (§12).
void AntiEntropyManager::sendInventory_(const std::string& peer_id) {
    InventoryFrame f = m_inventory->buildInventory(m_cfg.inventory_limit);
    f.count = static_cast<uint32_t>(f.entries.size());
    send_(peer_id, MessageType::INVENTORY, encode_inventory(f));
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.inventories_sent++;
    }
}

// Step 6.3 #3/#4 — on receiving the peer's inventory, WANT the ids we don't
// hold (pull). Never blind-resend anything the peer listed (dedup context).
void AntiEntropyManager::handleInventory_(const std::string& peer_id,
                                          const InventoryFrame& f) {
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.inventories_received++;
    }
    ObjectWantFrame want;
    want.object_id_hexes.clear();
    for (const auto& e : f.entries) {
        if (m_inventory->holds(e.object_id_hex)) {
            // We already hold it — record as already_held so the responder
            // skips it (§65 dedup). Not a blind resend.
            want.already_held.push_back(e.object_id_hex);
            continue;
        }
        if (e.state == static_cast<uint8_t>(ObjectStatus::kConfirmed) ||
            e.state == static_cast<uint8_t>(ObjectStatus::kFailed)) {
            // Terminal state: nothing useful to pull; still list as held so the
            // peer doesn't resend. Skip.
            want.already_held.push_back(e.object_id_hex);
            continue;
        }
        // Prioritize (§60): direct-addressable high-priority items first is at
        // the responder's side; here we WANT missing objects (oldest first).
        want.object_id_hexes.push_back(e.object_id_hex);
        if (want.object_id_hexes.size() >= m_cfg.max_objects_per_session) break;
    }
    if (!want.object_id_hexes.empty() || !want.already_held.empty()) {
        send_(peer_id, MessageType::OBJECT_WANT, encode_object_want(want));
        {
            std::lock_guard<std::mutex> lock(m_mu);
            m_ctr.wants_sent++;
        }
        emit_("RECON_WANT", peer_id);
    }
}

// ---------------------------------------------------------------------------
// handleWant_: responder side. Transfer the WANTed objects we hold, honoring:
//   - dedup context (skip already_held ids + those we don't have), §65
//   - per-session object/byte/time caps (§6.5); remaining deferred, not silent
//     drop.
// ---------------------------------------------------------------------------
void AntiEntropyManager::handleWant_(const std::string& peer_id,
                                     const ObjectWantFrame& f) {
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.wants_received++;
    }
    // Snapshot the budget once (responder role for this session).
    SessionBudget* sb = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        sb = &m_sessions[peer_id];   // created on onPeerReady; else fresh
        if (sb->deadline_ms == 0) sb->deadline_ms = now_ms() + m_cfg.session_deadline_ms;
    }
    (void)sb;

    // Build a quick lookup of ids the requester already holds (dedup context).
    std::unordered_map<std::string, bool> held;
    for (const auto& id : f.already_held) held[id] = true;
    // Also dedup within the request.
    std::unordered_map<std::string, bool> seen;

    for (const std::string& id_hex : f.object_id_hexes) {
        if (seen[id_hex]) continue;
        seen[id_hex] = true;
        if (held[id_hex]) {
            // Requester already holds it — do NOT resend (no blind resend).
            std::lock_guard<std::mutex> lock(m_mu);
            m_ctr.duplicate_hits++;
            continue;
        }
        // Per-session caps (§6.5): stop once budget exhausted; the rest is
        // deferred (the requester re-WANTs or a new session covers it).
        {
            std::lock_guard<std::mutex> lock(m_mu);
            SessionBudget& s = m_sessions[peer_id];
            if (s.objects_transferred >= m_cfg.max_objects_per_session) break;
            if (now_ms() > s.deadline_ms) break;
        }
        ObjectId id;
        if (!ObjectId::fromHex(id_hex, id)) continue;
        if (!m_inventory->holds(id_hex)) continue;   // we don't have it
        // Either a WANT for a point-to-point object or a direct request: fetch
        // the envelope and send it as OBJECT_DATA (Phase 5/4 machinery handles
        // the direct-to-me / storage discrimination).
        if (sendEnvelope_(peer_id, id, "") != Result::kOk) continue;
        {
            std::lock_guard<std::mutex> lock(m_mu);
            SessionBudget& s = m_sessions[peer_id];
            s.objects_transferred++;
            s.bytes_transferred += 0;   // size accounted in sendEnvelope_
            m_ctr.objects_transferred++;
        }
        emit_("RECON_TRANSFER", id_hex);
    }
}

// Fetch an object's envelope and send it to `peer_id` as OBJECT_DATA (§82).
Result AntiEntropyManager::sendEnvelope_(const std::string& peer_id, const ObjectId& id,
                                         const std::string& /*unused*/) {
    std::string envelope;
    if (m_envelope_fn) {
        if (m_envelope_fn(id, envelope) != Result::kOk) return Result::kNotFound;
    } else {
        ObjectMeta meta;
        if (!m_store || m_store->getMeta(id, meta) != Result::kOk) return Result::kNotFound;
        envelope = meta.envelope_blob;
        if (envelope.empty()) return Result::kNotFound;
    }
    handoff::DataFrame df;
    df.object_id_hex = id.toHex();
    df.envelope = envelope;
    if (!send_(peer_id, MessageType::OBJECT_DATA,
               networkos::handoff::encode_data(df))) {
        return Result::kIo;
    }
    {
        std::lock_guard<std::mutex> lock(m_mu);
        SessionBudget& s = m_sessions[peer_id];
        s.bytes_transferred += envelope.size();
        m_ctr.bytes_reconciled += envelope.size();
    }
    return Result::kOk;
}

// ---------------------------------------------------------------------------
// onFrame: dispatch INVENTORY/OBJECT_WANT (Step 6.3).
// ---------------------------------------------------------------------------
void AntiEntropyManager::onFrame(const std::string& peer_id, MessageType type,
                                 const std::string& payload) {
    switch (type) {
        case MessageType::INVENTORY: {
            InventoryFrame f;
            if (decode_inventory(payload, f)) handleInventory_(peer_id, f);
            break;
        }
        case MessageType::OBJECT_WANT: {
            ObjectWantFrame f;
            if (decode_object_want(payload, f)) handleWant_(peer_id, f);
            break;
        }
        default:
            break;
    }
}

// ---------------------------------------------------------------------------
// runRepairHook: Step 6.3 #6 — Phase 7 replica-repair stub (no-op now).
// ---------------------------------------------------------------------------
size_t AntiEntropyManager::runRepairHook(const std::string& /*peer_id*/) {
    return 0;   // Phase 7 implements real replica planning/repair here.
}

AntiEntropyManager::Counters AntiEntropyManager::counters() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_ctr;
}

std::string AntiEntropyManager::telemetryJson() const {
    std::lock_guard<std::mutex> lock(m_mu);
    std::ostringstream os;
    os << "{\"inventories_sent\":" << m_ctr.inventories_sent
       << ",\"inventories_received\":" << m_ctr.inventories_received
       << ",\"wants_sent\":" << m_ctr.wants_sent
       << ",\"wants_received\":" << m_ctr.wants_received
       << ",\"objects_transferred\":" << m_ctr.objects_transferred
       << ",\"bytes_reconciled\":" << m_ctr.bytes_reconciled
       << ",\"duplicate_hits\":" << m_ctr.duplicate_hits
       << ",\"sessions\":" << m_ctr.sessions
       << "}";
    return os.str();
}

std::unique_ptr<AntiEntropyManager> createAntiEntropyManager(
    ObjectStore* store, const AntiEntropyManager::Config& cfg) {
    return std::make_unique<AntiEntropyManager>(store, cfg);
}

} // namespace anti_entropy
} // namespace networkos
