#include "overlay_router.h"
#include "logger.h"
#include "telemetry.h"

#include <sodium.h>

#include <algorithm>
#include <random>

namespace overlay {

namespace {

uint64_t steady_now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

uint64_t wall_now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

// Pickup key for a mailbox: blake2b-128 of the destination peer id, hex.
// Both origin (addressing) and relay (indexing) derive it identically; the
// relay learns only this opaque digest, never the peer id itself.
std::string mailbox_key_for(const std::string& peer_id) {
    unsigned char out[crypto_generichash_BYTES_MIN];
    crypto_generichash(out, sizeof(out),
                       reinterpret_cast<const unsigned char*>(peer_id.data()),
                       peer_id.size(), nullptr, 0);
    static const char* hexd = "0123456789abcdef";
    std::string hex;
    hex.reserve(sizeof(out) * 2);
    for (unsigned char b : out) {
        hex.push_back(hexd[b >> 4]);
        hex.push_back(hexd[b & 0xF]);
    }
    return hex;
}

} // namespace

// ---------------------------------------------------------------------------
// Construction / wiring / lifecycle
// ---------------------------------------------------------------------------

OverlayRouter::OverlayRouter() : OverlayRouter(Config()) {}

OverlayRouter::OverlayRouter(const Config& cfg)
    : m_cfg(cfg), m_relay_enabled(cfg.relay_enabled), m_mailbox(OverlayMailbox::Config{}) {}

OverlayRouter::~OverlayRouter() { stop(); }

void OverlayRouter::set_send_fn(SendFn fn) { m_send = std::move(fn); }
void OverlayRouter::set_connect_fn(ConnectFn fn) { m_connect = std::move(fn); }
void OverlayRouter::set_is_connected_fn(IsConnectedFn fn) { m_is_connected = std::move(fn); }
void OverlayRouter::set_deliver_fn(DeliverFn fn) { m_deliver = std::move(fn); }
void OverlayRouter::set_delivery_cb(DeliveryCb cb) { m_delivery_cb = std::move(cb); }

void OverlayRouter::set_local_identity(const std::string& peer_id,
                                       const std::vector<uint8_t>& public_key,
                                       const std::vector<uint8_t>& secret_key) {
    std::lock_guard<std::mutex> lock(m_mu);
    m_local_id = peer_id;
    m_local_pk = public_key;
    m_local_sk = secret_key;
}

void OverlayRouter::set_peer_key_fn(
    std::function<std::vector<uint8_t>(const std::string&)> fn) {
    m_peer_key_fn = std::move(fn);
}

void OverlayRouter::set_local_signing_keys(const std::vector<uint8_t>& public_key,
                                           const std::vector<uint8_t>& secret_key) {
    std::lock_guard<std::mutex> lock(m_mu);
    m_local_sign_pk = public_key;
    m_local_sign_sk = secret_key;
}

void OverlayRouter::set_peer_signing_key_fn(
    std::function<std::vector<uint8_t>(const std::string&)> fn) {
    m_peer_sign_fn = std::move(fn);
}

void OverlayRouter::start() {
    if (m_running.exchange(true)) return;
    LOG_INFO("OVL: overlay router started (relay=" +
             std::string(m_relay_enabled.load() ? "on" : "off") +
             ", hops=" + std::to_string(m_cfg.default_hops) + ")");
    m_tick_thread = std::thread([this] { tick_loop_(); });
}

void OverlayRouter::stop() {
    if (!m_running.exchange(false)) return;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_tick_cv.notify_all();
    }
    if (m_tick_thread.joinable()) m_tick_thread.join();
    // Fail any still-pending reliable sends.
    std::vector<std::string> doomed;
    DeliveryCb cb_copy;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        for (auto& kv : m_pending) doomed.push_back(kv.second.frame_id_hex);
        m_pending.clear();
        cb_copy = m_delivery_cb;
    }
    if (cb_copy) {
        for (const auto& id : doomed) cb_copy(id, DeliveryStatus::Failed);
    }
    LOG_INFO("OVL: overlay router stopped");
}

uint64_t OverlayRouter::steady_ms_() { return steady_now_ms(); }

void OverlayRouter::tick_loop_() {
    while (m_running.load()) {
        std::unique_lock<std::mutex> lock(m_mu);
        m_tick_cv.wait_for(lock, std::chrono::milliseconds(m_cfg.tick_interval_ms),
                           [this] { return !m_running.load(); });
        if (!m_running.load()) break;
        lock.unlock();

        do_tick_(steady_now_ms());
    }
}

// ---------------------------------------------------------------------------
// Origin: path selection + frame construction
// ---------------------------------------------------------------------------

std::vector<std::string> OverlayRouter::pick_path_(size_t hop_count,
                                                   const std::string& exclude1,
                                                   const std::string& exclude2) const {
    // Score relays: freshness, spare capacity, success history. Deliberately
    // randomized among the top candidates so successive sends do not funnel
    // through identical paths (traffic-analysis resistance + load spreading).
    struct Cand {
        const RelayInfo* info;
        double score;
    };
    std::vector<Cand> cands;
    const uint64_t now = steady_now_ms();
    for (const auto& kv : m_relays) {
        const RelayInfo& r = kv.second;
        if (r.peer_id == exclude1 || r.peer_id == exclude2 || r.peer_id == m_local_id) continue;
        if (!r.persistent && now - r.last_seen_ms > m_cfg.relay_ad_ttl_ms) continue;
        double score = 0.0;
        score += static_cast<double>(r.success_score);
        if (r.forward_load < r.capacity) {
            score += 50.0 * (1.0 - static_cast<double>(r.forward_load) / r.capacity);
        }
        if (now > r.last_seen_ms) {
            const double age_s = static_cast<double>(now - r.last_seen_ms) / 1000.0;
            score -= std::min(40.0, age_s / 5.0);
        }
        cands.push_back({&r, score});
    }
    if (cands.empty()) return {};

    std::sort(cands.begin(), cands.end(),
              [](const Cand& a, const Cand& b) { return a.score > b.score; });

    // Keep the healthy half, shuffle, take hop_count.
    const size_t keep = std::max<size_t>(1, cands.size() / 2);
    thread_local std::mt19937 rng(std::random_device{}());
    std::shuffle(cands.begin(), cands.begin() + static_cast<long>(std::min(keep, cands.size())), rng);

    std::vector<std::string> path;
    for (size_t i = 0; i < cands.size() && path.size() < hop_count; ++i) {
        path.push_back(cands[i].info->peer_id);
    }
    return path;
}

OverlayRouter::SendResult OverlayRouter::dispatch_frame_(
    const std::string& dest_peer_id, const std::string& payload,
    bool want_ack, bool via_mailbox, uint8_t /*attempts_hint*/,
    std::string& out_frame_id_hex, const uint8_t frame_id[kFrameIdSize]) {

    // Caller holds NO lock. Resolve keys first.
    if (m_local_pk.empty() || m_local_sk.empty()) return SendResult::Internal;
    std::vector<uint8_t> dest_pk;
    if (m_peer_key_fn) dest_pk = m_peer_key_fn(dest_peer_id);
    if (dest_pk.empty()) return SendResult::NoKey;

    // Choose the relay path. For mailbox sends the LAST relay doubles as the
    // mailbox holder; for direct sends the path is all relays and the
    // destination is the terminal hop.
    std::vector<std::string> path;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        path = pick_path_(m_cfg.default_hops, dest_peer_id, m_local_id);
    }
    if (path.empty()) return SendResult::NoRelays;

    // ---- Build the sealed layers (innermost first) ------------------------
    FinalPayload fp;
    fp.origin_peer_id = m_local_id;
    fp.created_ts_ms = wall_now_ms();
    fp.flags = 0;
    if (want_ack) fp.flags |= kFlagWantAck;
    if (via_mailbox) fp.flags |= kFlagMailboxStore;
    fp.app_payload = payload;
    fp.message_frame_id_hex = frame_id_to_hex(frame_id);  // origin's id for ACK correlation
    {
        // Reply hint: relays we recently saw advertising.
        std::lock_guard<std::mutex> lock(m_mu);
        size_t n = 0;
        for (const auto& kv : m_relays) {
            if (n >= 3) break;
            fp.reply_relays.push_back(kv.second.peer_id);
            ++n;
        }
    }

    // Phase B: sign the payload with our Ed25519 keypair when configured.
    const uint8_t* sign_sk = m_local_sign_sk.empty() ? nullptr : m_local_sign_sk.data();
    const uint8_t* sign_pk = m_local_sign_pk.empty() ? nullptr : m_local_sign_pk.data();
    std::string innermost = seal_final(dest_pk, fp, sign_sk, sign_pk);
    if (innermost.empty()) return SendResult::Internal;

    std::string body;
    std::string terminal;  // peer that terminates the path (after the last Forward)
    if (via_mailbox) {
        terminal = path.back();  // last relay holds the mailbox entry
        std::vector<uint8_t> mb_pk;
        if (m_peer_key_fn) mb_pk = m_peer_key_fn(terminal);
        if (mb_pk.empty()) return SendResult::NoKey;

        HopInstruction mb_hop;
        mb_hop.kind = HopKind::MailboxStore;
        mb_hop.mailbox_key = mailbox_key_for(dest_peer_id);
        mb_hop.inner = innermost;
        body = seal_hop(mb_pk, mb_hop);
        path.pop_back();
        if (body.empty()) return SendResult::Internal;
    } else {
        terminal = dest_peer_id;
        HopInstruction dest_hop;
        dest_hop.kind = HopKind::Deliver;
        dest_hop.inner = innermost;
        body = seal_hop(dest_pk, dest_hop);
        if (body.empty()) return SendResult::Internal;
    }

    // Wrap each relay from last to first. The last Forward hop points at the
    // terminal peer (destination, or mailbox relay for mailbox sends).
    for (size_t ii = path.size(); ii-- > 0;) {
        std::vector<uint8_t> hop_pk;
        if (m_peer_key_fn) hop_pk = m_peer_key_fn(path[ii]);
        if (hop_pk.empty()) return SendResult::NoKey;

        HopInstruction fwd;
        fwd.kind = HopKind::Forward;
        fwd.next_peer = (ii + 1 < path.size()) ? path[ii + 1] : terminal;
        fwd.inner = body;
        body = seal_hop(hop_pk, fwd);
        if (body.empty()) return SendResult::Internal;
    }

    uint8_t flags = 0;
    if (want_ack) flags |= kFlagWantAck;
    if (via_mailbox) flags |= kFlagMailboxStore;

    // frame_id is provided by the caller (already registered in m_pending for
    // reliable sends — the ACK may arrive synchronously during dispatch).
    const std::string wire = encode_frame(flags, m_cfg.max_hops, frame_id, body);
    if (wire.size() > kMaxOverlayFrameSize) return SendResult::TooLarge;

    // ---- Hand the first hop to the transport -------------------------------
    // NOTE: send_or_queue_ takes m_mu itself (and may invoke session
    // callbacks), so it MUST be called without holding m_mu.
    const std::string first_hop = path.front();
    send_or_queue_(first_hop, wire, steady_now_ms());
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_stats.sent_total += 1;
    }

    out_frame_id_hex = frame_id_to_hex(frame_id);
    return SendResult::Ok;
}

OverlayRouter::SendResult OverlayRouter::send(const std::string& dest_peer_id,
                                              const std::string& payload,
                                              bool want_ack, bool via_mailbox,
                                              std::string& out_frame_id_hex) {
    out_frame_id_hex.clear();
    if (!m_running.load()) return SendResult::NotStarted;
    // Payload budget: 3 sealed layers + header must stay under one datagram.
    if (payload.empty() || payload.size() > 640) return SendResult::TooLarge;
    if (dest_peer_id.empty() || dest_peer_id == m_local_id) {
        return SendResult::Internal;
    }

    // Pre-generate the frame id and REGISTER the pending entry BEFORE the
    // frame is dispatched: the ACK can legitimately arrive synchronously
    // during dispatch (e.g., in-memory transport, or a fast first hop), and
    // an unregistered id would silently drop the Delivered notification.
    uint8_t frame_id[kFrameIdSize];
    random_frame_id(frame_id);
    out_frame_id_hex = frame_id_to_hex(frame_id);
    if (want_ack) {
        std::lock_guard<std::mutex> lock(m_mu);
        if (m_pending.size() >= m_cfg.max_pending_sends) return SendResult::Busy;
        PendingSend p;
        p.dest_peer_id = dest_peer_id;
        p.payload = payload;
        p.via_mailbox = via_mailbox;
        p.attempts = 1;
        const uint64_t now = steady_now_ms();
        p.next_retry_ms = now + static_cast<uint64_t>(m_cfg.ack_timeout_ms);
        p.deadline_ms = now + static_cast<uint64_t>(m_cfg.ack_timeout_ms) * m_cfg.max_send_attempts;
        p.frame_id_hex = out_frame_id_hex;
        m_pending[p.frame_id_hex] = std::move(p);
    }

    const SendResult rc = dispatch_frame_(dest_peer_id, payload, want_ack, via_mailbox,
                                          0, out_frame_id_hex, frame_id);
    if (rc != SendResult::Ok) {
        out_frame_id_hex.clear();
        if (want_ack) {
            std::lock_guard<std::mutex> lock(m_mu);
            m_pending.erase(frame_id_to_hex(frame_id));
        }
        return rc;
    }
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_stats.sent_ok_total += 1;
    }
    Telemetry::getInstance().inc_counter("overlay_tx_total");
    return SendResult::Ok;
}

// ---------------------------------------------------------------------------
// Input: called by the session on every OVERLAY_FRAME wire message.
// ---------------------------------------------------------------------------

void OverlayRouter::on_frame(const std::string& from_peer_id,
                             const std::string& frame_bytes) {
    // Phase B: optional obfuscated transport — peel the OBF1 envelope first so
    // the LPX2 magic is never seen on the wire. Mismatched configs drop here.
    std::string payload = frame_bytes;
    if (m_cfg.obfuscate_transport) {
        std::string plain;
        if (!obfuscate_unwrap(m_local_pk, m_local_sk, frame_bytes, plain)) {
            std::lock_guard<std::mutex> lock(m_mu);
            m_stats.obf_fail_total += 1;
            return;
        }
        payload = std::move(plain);
        std::lock_guard<std::mutex> lock(m_mu);
        m_stats.obf_ok_total += 1;
    }

    OverlayFrameHeader hdr;
    std::string_view body;
    if (!decode_frame(payload, hdr, body)) {
        LOG_DEBUG("OVL: malformed frame from " + from_peer_id);
        return;
    }

    // Relay advertisements and PEX travel unsealed (public routing metadata).
    if (hdr.flags & kFlagRelayAdvert) {
        handle_relay_advert_(from_peer_id, body);
        return;
    }
    if (hdr.flags & kFlagRelayPex) {
        handle_relay_pex_(body);
        return;
    }

    // Loop/dupe detection: every node remembers seen frame ids.
    if (seen_frame_(hdr.frame_id)) {
        std::lock_guard<std::mutex> lock(m_mu);
        m_stats.dedup_drops_total += 1;
        return;
    }
    if (hdr.ttl == 0) {
        std::lock_guard<std::mutex> lock(m_mu);
        m_stats.ttl_drops_total += 1;
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (m_local_pk.empty() || m_local_sk.empty()) return;
    }
    HopInstruction hop;
    if (!open_hop(m_local_pk, m_local_sk, body, hop)) {
        // Not addressed to us (we are not on this path) or corrupt.
        std::lock_guard<std::mutex> lock(m_mu);
        m_stats.unseal_fail_total += 1;
        return;
    }

    switch (hop.kind) {
        case HopKind::Forward:
            handle_forward_(from_peer_id, hop, hdr.flags, hdr.ttl, hdr.frame_id);
            break;
        case HopKind::Deliver:
            handle_deliver_(hop, hdr.flags, hdr.frame_id);
            break;
        case HopKind::MailboxStore:
            handle_mailbox_store_(from_peer_id, hop);
            break;
        case HopKind::MailboxPickup:
            handle_mailbox_pickup_(from_peer_id);
            break;
        case HopKind::Cover:
            // Cover-traffic filler: consumed silently. Indistinguishable from
            // real frames to a passive observer.
            {
                std::lock_guard<std::mutex> lock(m_mu);
                m_stats.cover_rx_total += 1;
            }
            Telemetry::getInstance().inc_counter("overlay_cover_rx_total");
            break;
    }
}

void OverlayRouter::handle_relay_advert_(const std::string& from_peer,
                                         std::string_view body) {
    std::string adv_peer;
    uint16_t capacity = 0;
    uint8_t max_hops = 0;
    if (!decode_relay_advert(body, adv_peer, capacity, max_hops)) return;
    if (adv_peer != from_peer) return;  // do not learn third-party adverts yet

    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_stats.adverts_rx_total += 1;
        auto& r = m_relays[adv_peer];
        r.peer_id = adv_peer;
        r.capacity = capacity ? capacity : 32;
        r.max_hops = max_hops ? max_hops : m_cfg.max_hops;
        r.last_seen_ms = steady_now_ms();
        if (m_relays.size() > m_cfg.relay_table_max) {
            // Evict stalest non-persistent entry.
            std::string stalest;
            uint64_t best_age = 0;
            const uint64_t now = steady_now_ms();
            for (const auto& kv : m_relays) {
                if (kv.second.persistent) continue;
                const uint64_t age = now - kv.second.last_seen_ms;
                if (age > best_age) { best_age = age; stalest = kv.first; }
            }
            if (!stalest.empty()) m_relays.erase(stalest);
        }
    }

    // Phase B (B5): a relay advertisement is also a discovery opportunity —
    // answer with our known relay list so relay knowledge spreads peer to peer.
    send_relay_pex_(from_peer, steady_now_ms());
}

void OverlayRouter::send_relay_pex_(const std::string& to_peer, uint64_t now_ms) {
    std::vector<std::string> ids;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        for (const auto& kv : m_relays) ids.push_back(kv.first);
    }
    if (ids.empty()) return;

    const std::string body = encode_relay_pex(ids);
    uint8_t fid[kFrameIdSize];
    random_frame_id(fid);
    const std::string wire = encode_frame(kFlagRelayPex, 255, fid, body);
    send_frame_(to_peer, wire, now_ms);

    std::lock_guard<std::mutex> lock(m_mu);
    m_stats.pex_tx_total += 1;
    m_last_pex_ms.store(now_ms, std::memory_order_relaxed);
}

void OverlayRouter::handle_relay_pex_(std::string_view body) {
    std::vector<std::string> ids;
    if (!decode_relay_pex(body, ids)) return;

    std::lock_guard<std::mutex> lock(m_mu);
    m_stats.pex_rx_total += 1;
    for (const auto& id : ids) {
        if (id.empty() || id == m_local_id) continue;
        if (m_relays.count(id) == 0 && m_relays.size() >= m_cfg.relay_table_max) {
            continue;  // full: only refresh existing entries
        }
        RelayInfo& r = m_relays[id];
        r.peer_id = id;
        r.last_seen_ms = steady_now_ms();
    }
}

void OverlayRouter::handle_forward_(const std::string& from_peer,
                                    const HopInstruction& hop,
                                    uint8_t flags, uint8_t ttl,
                                    const uint8_t frame_id[kFrameIdSize]) {
    if (!m_relay_enabled.load(std::memory_order_relaxed)) {
        // Not volunteering as a relay — silently drop. (Never NAK: leaking
        // relay policy to arbitrary senders aids network mapping.)
        (void)from_peer;
        return;
    }
    if (hop.next_peer.empty() || hop.next_peer == m_local_id) return;

    // Re-encode for the next hop: same id/flags, TTL-1, body = inner.
    const uint8_t next_ttl = static_cast<uint8_t>(ttl - 1);
    const std::string wire = encode_frame(flags, next_ttl, frame_id, hop.inner);

    send_or_queue_(hop.next_peer, wire, steady_now_ms());

    std::lock_guard<std::mutex> lock(m_mu);
    m_stats.relayed_total += 1;
    Telemetry::getInstance().inc_counter("overlay_relayed_total");
    auto it = m_relays.find(from_peer);
    if (it != m_relays.end()) it->second.last_seen_ms = steady_now_ms();
}

void OverlayRouter::handle_deliver_(const HopInstruction& hop, uint8_t flags,
                                    const uint8_t frame_id[kFrameIdSize]) {
    FinalPayload fp;
    if (!open_final(m_local_pk, m_local_sk, hop.inner, fp)) {
        std::lock_guard<std::mutex> lock(m_mu);
        m_stats.unseal_fail_total += 1;
        return;
    }

    // Replay protection: sealed payload must be recent.
    if (!check_replay_(fp.created_ts_ms, wall_now_ms())) {
        LOG_WARN("OVL: dropped replayed/stale sealed payload");
        return;
    }

    // ---- Origin authentication (Phase B) -------------------------------
    // Verify the embedded Ed25519 signature. When we have a REGISTERED
    // signing key for the claimed origin, it must match the embedded signer —
    // otherwise this is a forgery or key-mismatch and the frame is dropped.
    std::vector<uint8_t> registered_pk =
        m_peer_sign_fn ? m_peer_sign_fn(fp.origin_peer_id) : std::vector<uint8_t>{};
    if (!verify_final_signature(fp, registered_pk)) {
        std::lock_guard<std::mutex> lock(m_mu);
        m_stats.auth_fail_total += 1;
        Telemetry::getInstance().inc_counter("overlay_auth_fail_total");
        LOG_WARN("OVL: dropped frame with invalid/mismatched origin signature from " +
                 fp.origin_peer_id);
        return;
    }
    if (m_cfg.require_origin_auth && fp.signature.empty()) {
        std::lock_guard<std::mutex> lock(m_mu);
        m_stats.auth_fail_total += 1;
        Telemetry::getInstance().inc_counter("overlay_auth_fail_total");
        LOG_WARN("OVL: require_origin_auth, dropping unsigned payload from " +
                 fp.origin_peer_id);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_stats.auth_ok_total += 1;
    }

    // ACK frames close out our pending sends. The user-visible callback is
    // invoked OUTSIDE the lock (it may call send_overlay() itself).
    if ((flags & kFlagAck) || (fp.flags & kFlagAck)) {
        std::string delivered_id;
        DeliveryCb cb;
        {
            std::lock_guard<std::mutex> lock(m_mu);
            m_stats.acked_total += 1;
            auto it = m_pending.find(fp.ack_of);
            if (it != m_pending.end()) {
                delivered_id = it->second.frame_id_hex;
                cb = m_delivery_cb;
                m_pending.erase(it);
            }
        }
        if (cb && !delivered_id.empty()) {
            cb(delivered_id, DeliveryStatus::Delivered);
        }
        return;
    }

    // Application delivery carries the ORIGIN's peer id.
    if (m_deliver) {
        m_deliver(fp.origin_peer_id, fp.app_payload);
    }
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_stats.delivered_total += 1;
    }
    Telemetry::getInstance().inc_counter("overlay_delivered_total");

    // ACK the ORIGIN's message id: on direct paths this equals the outer
    // frame id (unchanged through relays), but on mailbox pickup the
    // destination sees a different outer frame id — the sealed payload
    // carries the original id so the origin's pending entry resolves.
    const std::string ack_id =
        fp.message_frame_id_hex.empty() ? frame_id_to_hex(frame_id) : fp.message_frame_id_hex;
    if ((flags & kFlagWantAck) || (fp.flags & kFlagWantAck)) {
        send_ack_(fp, ack_id);
    }
}

void OverlayRouter::handle_mailbox_store_(const std::string& from_peer,
                                          const HopInstruction& hop) {
    if (!m_relay_enabled.load(std::memory_order_relaxed)) return;
    if (hop.mailbox_key.empty()) return;

    const bool ok = m_mailbox.store(hop.mailbox_key, from_peer, hop.inner, steady_now_ms());
    if (ok) {
        std::lock_guard<std::mutex> lock(m_mu);
        m_stats.mailbox_stored_total += 1;
        Telemetry::getInstance().inc_counter("overlay_mailbox_stored_total");
    }
}

void OverlayRouter::handle_mailbox_pickup_(const std::string& from_peer) {
    if (!m_relay_enabled.load(std::memory_order_relaxed)) return;

    // The requester IS the destination; blobs were sealed to its key by the
    // origin, so we hand them over without ever seeing plaintext.
    auto blobs = m_mailbox.pickup(mailbox_key_for(from_peer),
                                  m_cfg.mailbox_pickup_batch, steady_now_ms());
    for (auto& blob : blobs) {
        const std::vector<uint8_t> to_pk =
            m_peer_key_fn ? m_peer_key_fn(from_peer) : std::vector<uint8_t>{};
        if (to_pk.empty()) break;

        HopInstruction deliver;
        deliver.kind = HopKind::Deliver;
        deliver.inner = blob;  // sealed to the destination by the origin
        const std::string body = seal_hop(to_pk, deliver);
        if (body.empty()) break;

        uint8_t fid[kFrameIdSize];
        random_frame_id(fid);
        const std::string wire = encode_frame(0, m_cfg.max_hops, fid, body);
        send_or_queue_(from_peer, wire, steady_now_ms());

        std::lock_guard<std::mutex> lock(m_mu);
        m_stats.mailbox_picked_total += 1;
    }
    Telemetry::getInstance().inc_counter("overlay_mailbox_picked_total");
}

// ---------------------------------------------------------------------------
// ACKs, forwarding queue, dedup
// ---------------------------------------------------------------------------

void OverlayRouter::send_ack_(const FinalPayload& delivered, std::string acked_id_hex) {
    // The ACK is its own tiny overlay frame back to the origin, preferring the
    // reply-relay hint the origin embedded in the sealed payload. If no relay
    // is known, the ACK degrades to a 0-hop direct frame — better a linkable
    // ACK than a lost message.
    if (delivered.origin_peer_id.empty()) return;
    std::vector<uint8_t> origin_pk;
    if (m_peer_key_fn) origin_pk = m_peer_key_fn(delivered.origin_peer_id);
    if (origin_pk.empty()) return;  // unknown origin -> cannot ACK

    std::vector<std::string> path;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        for (const auto& r : delivered.reply_relays) {
            RelayInfo& ri = m_relays[r];  // create-or-refresh from the hint
            ri.peer_id = r;
            ri.last_seen_ms = steady_now_ms();
        }
        path = pick_path_(m_cfg.default_hops, delivered.origin_peer_id, m_local_id);
    }

    FinalPayload ack;
    ack.origin_peer_id = m_local_id;
    ack.created_ts_ms = wall_now_ms();
    ack.flags = kFlagAck;
    ack.ack_of = std::move(acked_id_hex);

    // ACKs are signed too: without a signature a malicious relay could forge
    // "delivered" notifications. The origin verifies against our registered key.
    const uint8_t* sign_sk = m_local_sign_sk.empty() ? nullptr : m_local_sign_sk.data();
    const uint8_t* sign_pk = m_local_sign_pk.empty() ? nullptr : m_local_sign_pk.data();
    const std::string inner = seal_final(origin_pk, ack, sign_sk, sign_pk);
    if (inner.empty()) return;

    HopInstruction term;
    term.kind = HopKind::Deliver;
    term.inner = inner;
    std::string body = seal_hop(origin_pk, term);
    if (body.empty()) return;

    // Keep only relays whose static keys we can resolve, THEN wrap the whole
    // path. Wrapping must never degrade mid-loop: a partially wrapped envelope
    // redirected to a shorter path would still contain layers sealed for
    // relays that are no longer on it — undecryptable at the terminal.
    const std::string terminal = delivered.origin_peer_id;
    std::vector<std::string> usable;
    usable.reserve(path.size());
    for (const auto& rid : path) {
        std::vector<uint8_t> k = m_peer_key_fn ? m_peer_key_fn(rid) : std::vector<uint8_t>{};
        if (!k.empty()) usable.push_back(rid);
    }
    for (size_t ii = usable.size(); ii-- > 0;) {
        std::vector<uint8_t> hop_pk;
        if (m_peer_key_fn) hop_pk = m_peer_key_fn(usable[ii]);
        if (hop_pk.empty()) return;  // raced away between filter and wrap: skip ACK
        HopInstruction fwd;
        fwd.kind = HopKind::Forward;
        fwd.next_peer = (ii + 1 < usable.size()) ? usable[ii + 1] : terminal;
        fwd.inner = body;
        body = seal_hop(hop_pk, fwd);
        if (body.empty()) return;
    }

    uint8_t fid[kFrameIdSize];
    random_frame_id(fid);
    // ACK frames set kFlagAck; they never request their own ACK (no loops).
    const std::string wire = encode_frame(kFlagAck, m_cfg.max_hops, fid, body);
    send_or_queue_(usable.empty() ? terminal : usable.front(), wire, steady_now_ms());
    Telemetry::getInstance().inc_counter("overlay_ack_tx_total");
}

void OverlayRouter::send_frame_(const std::string& peer_id,
                                const std::string& wire_frame, uint64_t now_ms) {
    // Single choke point for every frame that leaves this router: applies
    // cover-traffic padding and the optional obfuscation envelope, then hands
    // the frame to the transport. Callers may hold no lock (we take it only
    // for timestamp bookkeeping, and never while invoking m_send).
    if (!m_send) return;

    std::string out = wire_frame;
    if (m_cfg.obfuscate_transport) {
        // Wrap FIRST so the "LPX2" magic never appears on the wire. Padding
        // happens inside the envelope (uniform ciphertext sizes).
        std::vector<uint8_t> peer_pk =
            m_peer_key_fn ? m_peer_key_fn(peer_id) : std::vector<uint8_t>{};
        if (peer_pk.empty()) return;  // cannot wrap without the peer's static key
        const std::string wrapped =
            overlay::obfuscate_wrap(peer_pk, m_local_sk, out, m_cfg.padding_bucket);
        if (wrapped.empty()) return;
        out = std::move(wrapped);
    } else if (m_cfg.padding_bucket > 1) {
        overlay::pad_wire_frame(out, m_cfg.padding_bucket);
    }

    m_last_tx_ms.store(now_ms, std::memory_order_relaxed);
    m_send(peer_id, out);
}

void OverlayRouter::send_or_queue_(const std::string& peer_id,
                                   const std::string& wire_frame, uint64_t now_ms) {
    // Fast path: connected -> send immediately (outside the lock).
    if (m_is_connected && m_is_connected(peer_id)) {
        send_frame_(peer_id, wire_frame, now_ms);
        return;
    }
    if (m_connect) {
        m_connect(peer_id);  // connect-on-demand (rugged churn handling)
    }

    // Queue the RAW frame; on flush send_frame_ applies fresh padding/wrap.
    std::lock_guard<std::mutex> lock(m_mu);
    auto& q = m_forward_wait[peer_id];
    if (q.size() >= m_cfg.max_forward_queue) {
        q.erase(q.begin());  // drop oldest — bounded memory under partition
    }
    ForwardWait w;
    w.wire_frame = wire_frame;
    w.expires_ms = now_ms + 15000;  // 15s connect budget
    q.push_back(std::move(w));
}

bool OverlayRouter::seen_frame_(const uint8_t frame_id[kFrameIdSize]) {
    const std::string hex = frame_id_to_hex(frame_id);
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_dedup_it.count(hex)) {
        m_dedup_lru.splice(m_dedup_lru.end(), m_dedup_lru, m_dedup_it[hex]);
        return true;
    }
    m_dedup_lru.push_back(hex);
    m_dedup_it[hex] = std::prev(m_dedup_lru.end());
    while (m_dedup_lru.size() > m_cfg.dedup_cache_size) {
        m_dedup_it.erase(m_dedup_lru.front());
        m_dedup_lru.pop_front();
    }
    return false;
}

bool OverlayRouter::check_replay_(uint64_t created_ts_ms, uint64_t now_ms) const {
    if (created_ts_ms == 0) return false;
    if (now_ms + 60000 < created_ts_ms) return false;                      // far-future
    if (now_ms > created_ts_ms + m_cfg.replay_window_ms) return false;     // stale
    return true;
}

void OverlayRouter::pickup_mailbox(const std::string& relay_peer_id) {
    if (!m_running.load() || relay_peer_id.empty()) return;
    if (relay_peer_id == m_local_id) return;

    std::vector<uint8_t> relay_pk =
        m_peer_key_fn ? m_peer_key_fn(relay_peer_id) : std::vector<uint8_t>{};
    if (relay_pk.empty()) return;

    HopInstruction req;
    req.kind = HopKind::MailboxPickup;
    const std::string body = seal_hop(relay_pk, req);
    if (body.empty()) return;

    uint8_t fid[kFrameIdSize];
    random_frame_id(fid);
    const std::string wire = encode_frame(kFlagMailboxPickup, 2, fid, body);
    send_or_queue_(relay_peer_id, wire, steady_now_ms());
}

// ---------------------------------------------------------------------------
// Housekeeping tick
// ---------------------------------------------------------------------------

void OverlayRouter::do_tick_(uint64_t now_ms) {
    // 1) Mailbox purge.
    m_mailbox.purge(now_ms);

    DeliveryCb cb;
    std::vector<PendingSend> retries;
    std::vector<std::string> failures;
    std::vector<std::pair<std::string, std::string>> flushes;

    {
        std::lock_guard<std::mutex> lock(m_mu);
        cb = m_delivery_cb;

        // 2) Reliable-send deadline handling.
        for (auto it = m_pending.begin(); it != m_pending.end();) {
            PendingSend& p = it->second;
            if (now_ms >= p.deadline_ms || p.attempts >= m_cfg.max_send_attempts) {
                failures.push_back(p.frame_id_hex);
                m_stats.failed_total += 1;
                it = m_pending.erase(it);
                continue;
            }
            if (now_ms >= p.next_retry_ms) {
                p.attempts += 1;
                p.next_retry_ms = now_ms + static_cast<uint64_t>(m_cfg.ack_timeout_ms);
                retries.push_back(p);
                it = m_pending.erase(it);  // re-added with a fresh frame id
                continue;
            }
            ++it;
        }

        // 3) Flush connect-wait queues for peers that came online.
        for (auto qit = m_forward_wait.begin(); qit != m_forward_wait.end();) {
            auto& q = qit->second;
            q.erase(std::remove_if(q.begin(), q.end(),
                                   [&](const ForwardWait& w) { return now_ms >= w.expires_ms; }),
                    q.end());
            if (q.empty()) {
                qit = m_forward_wait.erase(qit);
                continue;
            }
            if (m_is_connected && m_is_connected(qit->first) && m_send) {
                for (auto& w : q) flushes.emplace_back(qit->first, w.wire_frame);
                qit = m_forward_wait.erase(qit);
                continue;
            }
            ++qit;
        }

        // 4) Age out stale relay advertisements.
        for (auto it = m_relays.begin(); it != m_relays.end();) {
            if (!it->second.persistent &&
                now_ms - it->second.last_seen_ms > m_cfg.relay_ad_ttl_ms * 3) {
                it = m_relays.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Callbacks and sends happen outside the lock.
    if (cb) {
        for (const auto& f : failures) cb(f, DeliveryStatus::Failed);
    }
    for (auto& p : retries) {
        // Same ordering rule as send(): register the NEW pending entry (fresh
        // frame id) before dispatching, then clean up on failure.
        uint8_t fid[kFrameIdSize];
        random_frame_id(fid);
        const std::string fid_hex = frame_id_to_hex(fid);

        {
            std::lock_guard<std::mutex> lock(m_mu);
            PendingSend np = p;
            np.attempts = p.attempts;
            np.frame_id_hex = fid_hex;
            np.next_retry_ms = now_ms + static_cast<uint64_t>(m_cfg.ack_timeout_ms);
            np.deadline_ms = now_ms + static_cast<uint64_t>(m_cfg.ack_timeout_ms) *
                              (m_cfg.max_send_attempts - p.attempts + 1);
            m_pending[fid_hex] = std::move(np);
            m_stats.retries_total += 1;
        }

        std::string dispatched_hex = fid_hex;
        const SendResult rc = dispatch_frame_(p.dest_peer_id, p.payload, true, p.via_mailbox,
                                              p.attempts, dispatched_hex, fid);
        if (rc != SendResult::Ok) {
            std::lock_guard<std::mutex> lock(m_mu);
            m_pending.erase(fid_hex);
            m_stats.failed_total += 1;
            if (cb) cb(fid_hex, DeliveryStatus::Failed);
        }
    }
    for (auto& pr : flushes) {
        send_frame_(pr.first, pr.second, now_ms);
    }

    // Phase B: periodic relay-list exchange (B5).
    if (m_cfg.pex_interval_ms && now_ms - m_last_pex_ms.load() >= m_cfg.pex_interval_ms) {
        std::vector<std::string> targets;
        {
            std::lock_guard<std::mutex> lock(m_mu);
            for (const auto& kv : m_relays) targets.push_back(kv.first);
        }
        for (const auto& t : targets) send_relay_pex_(t, now_ms);
    }

    // Phase B: idle cover frames (obscures silence/presence).
    maybe_send_cover_(now_ms);

    advertise_if_due_();
}

// ---------------------------------------------------------------------------
// Management & stats
// ---------------------------------------------------------------------------

void OverlayRouter::maybe_send_cover_(uint64_t now_ms) {
    // Cover traffic: when the link has been idle for cover_interval_ms, emit a
    // sealed Cover frame to a random known relay. Sizes and timing mimic real
    // traffic, so silence/presence patterns are hidden from a passive observer.
    if (m_cfg.cover_interval_ms == 0 || !m_relay_enabled.load(std::memory_order_relaxed)) {
        return;
    }
    if (!m_send) return;

    const uint64_t last_any =
        std::max(m_last_tx_ms.load(std::memory_order_relaxed),
                 m_last_cover_ms.load(std::memory_order_relaxed));
    if (last_any != 0 && now_ms - last_any < m_cfg.cover_interval_ms) return;

    std::vector<std::string> targets;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        for (const auto& kv : m_relays) targets.push_back(kv.first);
    }
    if (targets.empty()) {
        // No relay to cover toward; remember the attempt so we don't busy-loop.
        m_last_cover_ms.store(now_ms, std::memory_order_relaxed);
        return;
    }

    thread_local std::mt19937 rng(std::random_device{}());
    const std::string& target = targets[rng() % targets.size()];
    std::vector<uint8_t> target_pk =
        m_peer_key_fn ? m_peer_key_fn(target) : std::vector<uint8_t>{};
    if (target_pk.empty()) {
        m_last_cover_ms.store(now_ms, std::memory_order_relaxed);
        return;
    }

    HopInstruction cover;
    cover.kind = HopKind::Cover;
    const std::string body = seal_hop(target_pk, cover);
    if (body.empty()) return;

    uint8_t fid[kFrameIdSize];
    random_frame_id(fid);
    const std::string wire = encode_frame(kFlagNone, m_cfg.max_hops, fid, body);
    send_frame_(target, wire, now_ms);

    std::lock_guard<std::mutex> lock(m_mu);
    m_stats.cover_tx_total += 1;
    m_last_cover_ms.store(now_ms, std::memory_order_relaxed);
    Telemetry::getInstance().inc_counter("overlay_cover_tx_total");
}

void OverlayRouter::advertise_if_due_() {
    // Advertise relay role to connected known peers (public metadata).
    if (!m_relay_enabled.load(std::memory_order_relaxed) || !m_cfg.advertise_relay || !m_send) return;

    std::vector<std::string> targets;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        for (const auto& kv : m_relays) targets.push_back(kv.first);
    }
    for (const auto& t : targets) {
        if (m_is_connected && m_is_connected(t)) {
            uint8_t fid[kFrameIdSize];
            random_frame_id(fid);
            const std::string body = encode_relay_advert(m_local_id, 32, m_cfg.max_hops);
            const std::string wire = encode_frame(kFlagRelayAdvert, 255, fid, body);
            send_frame_(t, wire, steady_now_ms());
            std::lock_guard<std::mutex> lock(m_mu);
            m_stats.adverts_tx_total += 1;
        }
    }
}

void OverlayRouter::set_relay_enabled(bool enabled) {
    m_relay_enabled.store(enabled, std::memory_order_relaxed);
    LOG_INFO(std::string("OVL: relay role ") + (enabled ? "ENABLED" : "disabled"));
}

void OverlayRouter::register_relay_candidate(const std::string& peer_id, uint16_t capacity,
                                             uint8_t max_hops, bool persistent) {
    std::lock_guard<std::mutex> lock(m_mu);
    RelayInfo& r = m_relays[peer_id];
    r.peer_id = peer_id;
    r.capacity = capacity ? capacity : 32;
    r.max_hops = max_hops ? max_hops : m_cfg.max_hops;
    r.persistent = persistent;
    r.last_seen_ms = steady_now_ms();
}

std::vector<std::string> OverlayRouter::relay_candidates() const {
    std::lock_guard<std::mutex> lock(m_mu);
    std::vector<std::string> out;
    out.reserve(m_relays.size());
    for (const auto& kv : m_relays) out.push_back(kv.first);
    return out;
}

OverlayRouter::Stats OverlayRouter::stats() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_stats;
}

std::string OverlayRouter::stats_json() const {
    const Stats s = stats();
    std::string json = "{";
    json += "\"sent_total\":" + std::to_string(s.sent_total);
    json += ",\"sent_ok_total\":" + std::to_string(s.sent_ok_total);
    json += ",\"retries_total\":" + std::to_string(s.retries_total);
    json += ",\"failed_total\":" + std::to_string(s.failed_total);
    json += ",\"acked_total\":" + std::to_string(s.acked_total);
    json += ",\"relayed_total\":" + std::to_string(s.relayed_total);
    json += ",\"delivered_total\":" + std::to_string(s.delivered_total);
    json += ",\"dedup_drops_total\":" + std::to_string(s.dedup_drops_total);
    json += ",\"ttl_drops_total\":" + std::to_string(s.ttl_drops_total);
    json += ",\"unseal_fail_total\":" + std::to_string(s.unseal_fail_total);
    json += ",\"mailbox_stored_total\":" + std::to_string(s.mailbox_stored_total);
    json += ",\"mailbox_picked_total\":" + std::to_string(s.mailbox_picked_total);
    json += ",\"adverts_tx_total\":" + std::to_string(s.adverts_tx_total);
    json += ",\"adverts_rx_total\":" + std::to_string(s.adverts_rx_total);
    json += ",\"pex_tx_total\":" + std::to_string(s.pex_tx_total);
    json += ",\"pex_rx_total\":" + std::to_string(s.pex_rx_total);
    json += ",\"cover_tx_total\":" + std::to_string(s.cover_tx_total);
    json += ",\"cover_rx_total\":" + std::to_string(s.cover_rx_total);
    json += ",\"auth_ok_total\":" + std::to_string(s.auth_ok_total);
    json += ",\"auth_fail_total\":" + std::to_string(s.auth_fail_total);
    json += ",\"obf_ok_total\":" + std::to_string(s.obf_ok_total);
    json += ",\"obf_fail_total\":" + std::to_string(s.obf_fail_total);
    json += "}";
    return json;
}

} // namespace overlay
