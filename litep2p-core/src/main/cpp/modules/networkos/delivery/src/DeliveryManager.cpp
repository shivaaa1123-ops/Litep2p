// DeliveryManager.cpp - Network OS Phase 5 direct delivery + signed receipts.

#include "networkos/delivery/DeliveryManager.h"

#include "networkos/object/object_id.h"

#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <sstream>

namespace networkos {
namespace delivery {

namespace {

struct SodiumInitGuard {
    SodiumInitGuard() { (void)sodium_init(); }
};
const SodiumInitGuard k_sodium_init;

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string to_hex(const std::string& raw) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(raw.size() * 2);
    for (unsigned char c : raw) {
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0x0F]);
    }
    return out;
}

bool is_hex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

} // namespace

DeliveryManager::DeliveryManager(ObjectStore* store, const Config& cfg)
    : m_store(store), m_cfg(cfg) {}

DeliveryManager::~DeliveryManager() = default;

void DeliveryManager::setSendFn(SendFn fn) { m_send = std::move(fn); }
void DeliveryManager::setConnectedPeersFn(ConnectedPeersFn fn) { m_connected = std::move(fn); }
void DeliveryManager::setSigningKeysFns(LocalSignKeysFn local, PeerSignKeyFn peer) {
    m_local_keys = std::move(local);
    m_peer_key = std::move(peer);
}
void DeliveryManager::setEventFn(EventFn fn) { m_event = std::move(fn); }

void DeliveryManager::emit_(const std::string& kind, const std::string& payload) {
    if (m_event) {
        try { m_event(kind, payload); } catch (...) {}
    }
}

bool DeliveryManager::send_(const std::string& peer_id, MessageType type,
                            const std::string& payload) {
    if (!m_send) return false;
    return m_send(peer_id, type, payload);
}

std::vector<std::string> DeliveryManager::peers_() const {
    if (m_connected) return m_connected();
    return {};
}

int64_t DeliveryManager::now_ms_() { return now_ms(); }

// ---------------------------------------------------------------------------
// storeAndDeliver: the single object-delivery entry point.
//   1. Durable local commit (QUEUED_LOCAL).
//   2. Cheapest-path dispatch (§57): direct to destination if connected, else
//      store-and-forward to carriers. RECEIVED_ACK / STORED_ACK drive the
//      state machine; the signed receipt is issued on the reverse path.
// ---------------------------------------------------------------------------
DeliveryManager::Outcome DeliveryManager::storeAndDeliver(
    const ObjectMeta& meta, const std::string& envelope_blob, int64_t requested_lease_ms) {
    Outcome out;
    if (!m_store) { out = {Result::kInvalidState, kFailNone, false, 0, "NO_STORE"}; return out; }
    if (!m_cfg.delivery_enabled) { out = {Result::kInvalidState, kFailPolicy, false, 0, "POLICY"}; return out; }

    ObjectStore::Outcome oc;
    ObjectMeta m = meta;
    m.status = ObjectStatus::kQueuedLocal;
    m.envelope_blob = envelope_blob;
    const Result rc = m_store->putWithOutcome(m, "", oc);
    if (rc != Result::kOk) {
        out = {rc, kFailTransient, (oc == ObjectStore::Outcome::Busy), 0, "LOCAL_COMMIT_FAILED"};
        emit_("DELIVERY_LOCAL_COMMIT_FAILED", meta.id.toHex());
        return out;
    }
    emit_("OBJECT_CREATED", meta.id.toHex());
    emit_("LOCAL_COMMIT", meta.id.toHex());

    const std::string dest = meta.destination.value_or("");
    const auto peers = peers_();
    const bool dest_connected =
        !dest.empty() && std::find(peers.begin(), peers.end(), dest) != peers.end();

    if (m_cfg.direct_delivery_enabled && dest_connected && !dest.empty()) {
        handoff::OfferFrame offer;
        offer.object_id_hex = meta.id.toHex();
        offer.namespace_id = meta.namespace_id;
        offer.origin = meta.origin;
        offer.destination = dest;
        offer.size_bytes = meta.payload_size;
        offer.payload_hash_hex = meta.payload_hash.size() == 32 ? to_hex(meta.payload_hash) : "";
        offer.expires_at_ms = meta.ttl_ms > 0 ? meta.created_at_ms + meta.ttl_ms : 0;
        offer.requested_storage_class = handoff::kStorageStandard;
        offer.requested_lease_ms = requested_lease_ms;
        {
            std::lock_guard<std::mutex> lock(m_mu);
            m_ctr.direct_deliveries++;
            m_direct_pending[meta.id.toHex()] = envelope_blob;
        }
        emit_("DESTINATION_DISCOVERED", meta.id.toHex());
        emit_("DELIVERY_STARTED", meta.id.toHex());
        send_(dest, MessageType::OBJECT_OFFER, encode_offer(offer));
        m_store->markDeliveryAttempted(meta.id);
        return out;
    }

    if (!m_cfg.store_and_forward_enabled) {
        out = {Result::kOk, kFailNone, false, 0, "NO_CARRIER"};
        m_ctr.no_carrier++;
        emit_("DELIVERY_NO_CARRIER", meta.id.toHex());
        return out;
    }
    handoff::OfferFrame offer;
    offer.object_id_hex = meta.id.toHex();
    offer.namespace_id = meta.namespace_id;
    offer.origin = meta.origin;
    offer.destination = "";
    offer.size_bytes = meta.payload_size;
    offer.payload_hash_hex = meta.payload_hash.size() == 32 ? to_hex(meta.payload_hash) : "";
    offer.expires_at_ms = meta.ttl_ms > 0 ? meta.created_at_ms + meta.ttl_ms : 0;
    offer.requested_storage_class = handoff::kStorageStandard;
    offer.requested_lease_ms = requested_lease_ms;

    std::vector<std::pair<std::string, std::string>> offers;
    for (const auto& p : peers) {
        if (p.empty() || p == m_cfg.local_peer_id || p == dest) continue;
        offers.emplace_back(p, encode_offer(offer));
    }
    if (offers.empty()) {
        out = {Result::kOk, kFailTransient, true, 5000, "NO_CARRIER"};
        m_ctr.no_carrier++;
        emit_("DELIVERY_NO_CARRIER", meta.id.toHex());
        return out;
    }
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.store_and_forwards++;
    }
    for (const auto& s : offers) send_(s.first, MessageType::OBJECT_OFFER, s.second);
    emit_("REMOTE_STORAGE_REQUEST", meta.id.toHex());
    return out;
}

// ---------------------------------------------------------------------------
// forwardPending: carrier role. Push stored-but-undeclivered objects to a
// destination that just connected, so B can commit and return a receipt.
// ---------------------------------------------------------------------------
size_t DeliveryManager::forwardPending(const std::string& destination) {
    if (!m_store) return 0;
    std::vector<networkos::ObjectId> undelivered;
    if (m_store->forEachUndelivered(destination,
                                    [&](const ObjectId& id) -> Result {
                                        undelivered.push_back(id);
                                        return Result::kOk;
                                    }) != Result::kOk) {
        return 0;
    }
    size_t sent = 0;
    for (const auto& id : undelivered) {
        ObjectMeta meta;
        if (m_store->getMeta(id, meta) != Result::kOk) continue;
        if (meta.envelope_blob.empty()) continue;
        if (meta.status != ObjectStatus::kStored &&
            meta.status != ObjectStatus::kDurabilityReached) {
            continue;
        }
        handoff::OfferFrame offer;
        offer.object_id_hex = id.toHex();
        offer.namespace_id = meta.namespace_id;
        offer.origin = meta.origin;
        offer.destination = destination;
        offer.size_bytes = meta.payload_size;
        offer.payload_hash_hex = meta.payload_hash.size() == 32 ? to_hex(meta.payload_hash) : "";
        offer.expires_at_ms = meta.ttl_ms > 0 ? meta.created_at_ms + meta.ttl_ms : 0;
        offer.requested_storage_class = handoff::kStorageStandard;
        if (!send_(destination, MessageType::OBJECT_OFFER, encode_offer(offer))) continue;
        m_store->markDeliveryAttempted(id);
        ++sent;
        emit_("DELIVERY_STARTED", id.toHex());
    }
    return sent;
}

// ---------------------------------------------------------------------------
// sweepReplicas: replica release (§64). Only DELIVERED replicas (there is
// delivery proof) past their retention window are garbage-collected. A
// still-queued / not-yet-delivered replica is NEVER removed merely because
// bytes hit a socket (last-useful-replica rule).
// ---------------------------------------------------------------------------
size_t DeliveryManager::sweepReplicas(int64_t now_ms_value) {
    if (!m_store) return 0;
    const int64_t before = now_ms_value - m_cfg.replica_retention_window_ms;
    std::vector<networkos::ObjectId> candidates;
    if (m_store->forEachDeliveredReplica(before, [&](const ObjectId& id) -> Result {
            candidates.push_back(id);
            return Result::kOk;
        }) != Result::kOk) {
        return 0;
    }
    size_t freed = 0;
    for (const auto& id : candidates) {
        // Safety: only remove if the object is still marked DELIVERED (it may
        // have been upgraded to CONFIRMED or failed since; those are kept).
        ObjectStatus status;
        if (m_store->deliveryReadout(id, &status, nullptr, nullptr, nullptr) !=
            Result::kOk) {
            continue;
        }
        if (status != ObjectStatus::kDelivered) continue;
        if (m_store->remove(id) != Result::kOk) continue;
        ++freed;
        {
            std::lock_guard<std::mutex> lock(m_mu);
            m_ctr.delivered_replicas_released++;
        }
        emit_("REPLICA_RELEASED", id.toHex());
    }
    return freed;
}

// ---------------------------------------------------------------------------
// onFrame: receive path. i_am_destination is true when the runtime resolved
// that the object's destination field names this peer.
// ---------------------------------------------------------------------------
void DeliveryManager::onFrame(const std::string& peer_id, MessageType type,
                              const std::string& payload, bool i_am_destination) {
    switch (type) {
        case MessageType::OBJECT_OFFER: {
            if (!i_am_destination) break;  // storage handoff -> HandoffManager
            handoff::OfferFrame f;
            if (decode_offer(payload, f)) handleOfferMe_(peer_id, f);
            break;
        }
        case MessageType::OBJECT_ACCEPT: {
            // A destination (or carrier) accepted our DIRECT offer: answer with
            // OBJECT_DATA. (Store-and-forward accepts are handled by HandoffManager.)
            handoff::AcceptFrame f;
            if (decode_accept(payload, f)) handleAcceptDirect_(peer_id, f);
            break;
        }
        case MessageType::OBJECT_DATA: {
            if (!i_am_destination) break;  // storage handoff -> HandoffManager
            handoff::DataFrame f;
            if (decode_data(payload, f)) handleDataMe_(peer_id, f);
            break;
        }
        case MessageType::RECEIVED_ACK: {
            ReceivedAckFrame f;
            if (decode_received_ack(payload, f)) handleReceivedAck_(peer_id, f);
            break;
        }
        default:
            break;
    }
}

// ---------------------------------------------------------------------------
// DESTINATION side
// ---------------------------------------------------------------------------
void DeliveryManager::handleOfferMe_(const std::string& peer_id, const handoff::OfferFrame& f) {
    if (!m_store) return;
    networkos::ObjectId id;
    if (!networkos::ObjectId::fromHex(f.object_id_hex, id)) return;
    if (!is_hex64(f.payload_hash_hex)) return;
    if (f.size_bytes > m_store->options().max_object_bytes) return;
    // Accept anything addressed to us (optional trust filter on origin).
    if (!m_cfg.trusted_origins.empty()) {
        bool ok = false;
        for (const auto& t : m_cfg.trusted_origins) if (t == f.origin) ok = true;
        if (!ok) return;  // silently ignore (we are not a storage carrier)
    }
    handoff::AcceptFrame af;
    af.object_id_hex = f.object_id_hex;
    af.accepted_until_ms = f.expires_at_ms;   // ack carries no lease; mirrors offer
    af.storage_class = handoff::kStorageStandard;
    af.carrier_id = m_cfg.local_peer_id;
    send_(peer_id, MessageType::OBJECT_ACCEPT, encode_accept(af));
}

void DeliveryManager::handleDataMe_(const std::string& peer_id, const handoff::DataFrame& f) {
    if (!m_store) return;
    networkos::ObjectId id;
    if (!networkos::ObjectId::fromHex(f.object_id_hex, id)) return;
    if (f.envelope.empty()) return;

    obj::NetworkObject obj;
    if (!obj::deserialize(f.envelope, obj)) {
        emit_("DESTINATION_COMMIT_INVALID", f.object_id_hex);
        return;
    }
    if (obj.origin.object_id_hex != f.object_id_hex) return;

    // Verify the ORIGIN signature (§29 verify before work), when configured.
    if (m_cfg.require_destination_signature) {
        const std::vector<uint8_t> origin_pk =
            m_peer_key ? m_peer_key(obj.origin.origin) : std::vector<uint8_t>{};
        if (origin_pk.size() != 32 || !obj::verify_object(obj, origin_pk.data())) {
            m_ctr.auth_failed++;
            emit_("AUTH_FAILED", f.object_id_hex);
            return;
        }
    }

    // Idempotent commit: if already delivered, re-ACK the same receipt; never
    // a second application event (invariant 3, 18).
    {
        ObjectStore::ReceiptRow existing;
        if (m_store->getReceipt(f.object_id_hex, existing) == Result::kOk) {
            m_ctr.duplicate_data_rejected++;
            // Re-send RECEIVED_ACK idempotently (Step 5.4).
            ReceivedAckFrame ack;
            ack.object_id_hex = f.object_id_hex;
            ack.destination = m_cfg.local_peer_id;
            ack.received_at_ms = existing.received_at_ms;
            ack.receipt_type = existing.receipt_type;
            send_(peer_id, MessageType::RECEIVED_ACK, encode_received_ack(ack));
            return;
        }
    }

    // Durable commit (store the envelope; dedup ensures one copy).
    ObjectMeta meta;
    meta.id = id;
    meta.namespace_id = obj.origin.namespace_id;
    meta.origin = obj.origin.origin;
    if (!obj.origin.destination.empty()) meta.destination = obj.origin.destination;
    meta.object_type = obj.origin.object_type;
    meta.created_at_ms = obj.origin.created_at_ms;
    meta.ttl_ms = obj.origin.ttl_ms;
    meta.priority = obj.origin.priority;
    meta.payload_size = obj.payload.size();
    meta.payload_hash = obj.origin.payload_hash;
    meta.envelope_blob = f.envelope;
    meta.status = ObjectStatus::kStored;
    ObjectStore::Outcome oc;
    if (m_store->putWithOutcome(meta, obj.payload, oc) != Result::kOk) {
        emit_("DESTINATION_COMMIT_FAILED", f.object_id_hex);
        return;
    }
    emit_("DESTINATION_COMMIT", f.object_id_hex);

    // RECEIVED_ACK only after the durable commit (invariant 2).
    const int64_t received_at = now_ms();
    ReceivedAckFrame ack;
    ack.object_id_hex = f.object_id_hex;
    ack.destination = m_cfg.local_peer_id;
    ack.received_at_ms = received_at;
    ack.receipt_type = delivery::kReceived;
    send_(peer_id, MessageType::RECEIVED_ACK, encode_received_ack(ack));
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.received_acks++;
    }

    // Sign + route a receipt back to the origin (Step 5.2/5.3). A delivered
    // OBJECT may itself BE a receipt (the reverse hop to the origin): in that
    // case consume it (upgrade to CONFIRMED) instead of issuing a new receipt.
    if (obj.origin.object_type == "receipt") {
        handleReceipt_(obj.origin.origin, obj, true);
        return;
    }
    issueReceipt_(meta.id.toHex(), meta);
}

// ---------------------------------------------------------------------------
// ORIGIN side: a destination accepted our direct offer — send OBJECT_DATA.
// ---------------------------------------------------------------------------
void DeliveryManager::handleAcceptDirect_(const std::string& peer_id,
                                          const handoff::AcceptFrame& f) {
    std::string envelope;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        auto it = m_direct_pending.find(f.object_id_hex);
        if (it == m_direct_pending.end()) return;
        envelope = it->second;
        m_direct_pending.erase(it);   // one-shot direct delivery
    }
    handoff::DataFrame df;
    df.object_id_hex = f.object_id_hex;
    df.envelope = envelope;
    send_(peer_id, MessageType::OBJECT_DATA, encode_data(df));
}

// ---------------------------------------------------------------------------
// ORIGIN side: RECEIVED_ACK marks DELIVERED; the signed receipt (Step 5.2)
// upgrades to CONFIRMED (Step 5.6). Both transitions are idempotent.
// ---------------------------------------------------------------------------
void DeliveryManager::handleReceivedAck_(const std::string& peer_id, const ReceivedAckFrame& f) {
    if (!m_store) return;
    networkos::ObjectId id;
    if (!networkos::ObjectId::fromHex(f.object_id_hex, id)) return;
    ObjectMeta meta;
    if (m_store->getMeta(id, meta) != Result::kOk) return;
    m_store->markDelivered(id, f.received_at_ms);
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.received_acks++;
        m_direct_pending.erase(f.object_id_hex);
    }
    emit_("DESTINATION_COMMIT", f.object_id_hex);
    emit_("RECEIVED_ACK", f.object_id_hex);
}

// ---------------------------------------------------------------------------
// issueReceipt_: the destination builds a signed receipt NetworkObject and
// routes it back toward the origin (Step 5.2/5.3).
// ---------------------------------------------------------------------------
bool DeliveryManager::issueReceipt_(const std::string& delivered_object_id_hex,
                                    const ObjectMeta& delivered_meta) {
    if (!m_local_keys) return false;
    if (delivered_meta.payload_hash.size() != 32) return false;  // need real hash

    const auto keys = m_local_keys();
    if (keys.second.size() != 64) return false;   // no signing key

    // Build the receipt object: a system-namespace NetworkObject whose payload
    // is the signed ReceiptPayload.
    networkos::ObjectId rec_id =
        networkos::ObjectId::generate("system-receipt", m_cfg.local_peer_id);
    ReceiptPayload receipt;
    receipt.object_id_hex = delivered_object_id_hex;
    receipt.object_hash_hex = to_hex(delivered_meta.payload_hash);
    receipt.origin = delivered_meta.origin;
    receipt.destination = m_cfg.local_peer_id;
    receipt.received_at_ms = now_ms();
    receipt.receipt_type = kReceived;
    receipt.object_created_at_ms = delivered_meta.created_at_ms;

    const std::string canon = canonical_receipt_bytes(
        receipt.object_id_hex, receipt.object_hash_hex, receipt.origin,
        receipt.destination, receipt.received_at_ms, receipt.receipt_type);
    std::string sig(64, '\0');
    crypto_sign_detached(reinterpret_cast<unsigned char*>(&sig[0]), nullptr,
                         reinterpret_cast<const unsigned char*>(canon.data()),
                         canon.size(), keys.second.data());
    receipt.signature = sig;
    receipt.signer_pk_hex = to_hex(std::string(keys.first.begin(), keys.first.end()));

    const std::string receipt_payload = encode_receipt(receipt);

    // Wrap in a signed NetworkObject (origin = us, destination = origin peer).
    obj::NetworkObject robj;
    robj.origin.network_id = "system";
    robj.origin.namespace_id = "system";
    robj.origin.object_id_hex = rec_id.toHex();
    robj.origin.origin = m_cfg.local_peer_id;         // we (B) signed it
    robj.origin.destination = delivered_meta.origin;  // route to original origin A
    robj.origin.object_type = "receipt";
    robj.origin.created_at_ms = receipt.received_at_ms;
    robj.origin.ttl_ms = m_cfg.receipt_ttl_ms;
    robj.origin.priority = m_cfg.receipt_priority;
    robj.origin.payload_size = receipt_payload.size();
    robj.origin.payload_hash = obj::compute_payload_hash(receipt_payload);
    robj.payload = receipt_payload;
    if (!obj::sign_object(robj, keys.second.data(), keys.first.data())) return false;

    // Persist the linkage + the receipt object itself (durable on B).
    ObjectStore::ReceiptRow row;
    row.delivered_object_id_hex = delivered_object_id_hex;
    row.receipt_object_id_hex = rec_id.toHex();
    row.origin = delivered_meta.origin;
    row.destination = m_cfg.local_peer_id;
    row.receipt_type = kReceived;
    row.received_at_ms = receipt.received_at_ms;
    row.object_hash_hex = receipt.object_hash_hex;
    row.signature = sig;
    row.signer_pk_hex = receipt.signer_pk_hex;
    m_store->recordReceipt(row);

    ObjectMeta rmeta;
    rmeta.id = rec_id;
    rmeta.namespace_id = "system";
    rmeta.origin = m_cfg.local_peer_id;
    rmeta.destination = delivered_meta.origin;
    rmeta.object_type = "receipt";
    rmeta.created_at_ms = receipt.received_at_ms;
    rmeta.ttl_ms = m_cfg.receipt_ttl_ms;
    rmeta.priority = m_cfg.receipt_priority;
    rmeta.payload_size = receipt_payload.size();
    rmeta.payload_hash = robj.origin.payload_hash;
    rmeta.status = ObjectStatus::kDelivered;   // we have it durably; route now
    rmeta.envelope_blob = obj::serialize(robj);
    ObjectStore::Outcome oc;
    m_store->putWithOutcome(rmeta, receipt_payload, oc);
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.receipts_created++;
    }
    emit_("RECEIPT_CREATED", delivered_object_id_hex);

    // Reverse delivery: direct if origin connected, else store-and-forward.
    routeReceipt_(rmeta, rmeta.envelope_blob);
    return true;
}

// ---------------------------------------------------------------------------
// routeReceipt_: reverse receipt delivery (Step 5.3). Direct to origin if
// connected; else store-and-forward via carriers (Phase 4 machinery, no
// special-casing) so CONFIRMED survives process death on every hop.
// ---------------------------------------------------------------------------
Result DeliveryManager::routeReceipt_(const ObjectMeta& receipt_meta,
                                      const std::string& receipt_envelope) {
    const std::string origin = receipt_meta.destination.value_or("");
    if (origin.empty()) { return Result::kOk; }   // no origin to route to
    const auto peers = peers_();
    const bool connected =
        std::find(peers.begin(), peers.end(), origin) != peers.end();
    if (connected) {
        // Direct reverse delivery: record the receipt so an OBJECT_ACCEPT from
        // the origin is answered with OBJECT_DATA (Step 5.3).
        {
            std::lock_guard<std::mutex> lock(m_mu);
            m_direct_pending[receipt_meta.id.toHex()] = receipt_envelope;
        }
        handoff::OfferFrame offer;
        offer.object_id_hex = receipt_meta.id.toHex();
        offer.namespace_id = "system";
        offer.origin = receipt_meta.origin;
        offer.destination = origin;
        offer.size_bytes = receipt_meta.payload_size;
        offer.payload_hash_hex = to_hex(receipt_meta.payload_hash);
        offer.expires_at_ms = receipt_meta.ttl_ms > 0
                                  ? receipt_meta.created_at_ms + receipt_meta.ttl_ms
                                  : 0;
        send_(origin, MessageType::OBJECT_OFFER, encode_offer(offer));
        return Result::kOk;
    }
    // Store-and-forward: hand the envelope to a carrier for the reverse hop.
    for (const auto& p : peers) {
        if (p.empty() || p == m_cfg.local_peer_id || p == origin) continue;
        send_(p, MessageType::OBJECT_OFFER,
              encode_offer([&] {
                  handoff::OfferFrame o;
                  o.object_id_hex = receipt_meta.id.toHex();
                  o.namespace_id = "system";
                  o.origin = receipt_meta.origin;
                  o.destination = "";   // storage offer; destination will pull
                  o.size_bytes = receipt_meta.payload_size;
                  o.payload_hash_hex = to_hex(receipt_meta.payload_hash);
                  o.expires_at_ms = receipt_meta.ttl_ms > 0
                                        ? receipt_meta.created_at_ms + receipt_meta.ttl_ms
                                        : 0;
                  return o;
              }()));
        return Result::kOk;
    }
    // No path right now: leave the receipt durably stored; retryPending() or
    // a later peer_ready delivers it. Not an error.
    return Result::kOk;
}

// ---------------------------------------------------------------------------
// verifyReceipt_: the origin checks the destination's Ed25519 signature over
// the canonical receipt bytes (using the destination's registered key).
// ---------------------------------------------------------------------------
bool DeliveryManager::verifyReceipt_(const ReceiptPayload& receipt) const {
    if (receipt.signature.size() != 64) return false;
    const std::vector<uint8_t> pk =
        m_peer_key ? m_peer_key(receipt.destination) : std::vector<uint8_t>{};
    if (pk.size() != 32) return false;   // no registered trust anchor
    const std::string canon = canonical_receipt_bytes(
        receipt.object_id_hex, receipt.object_hash_hex, receipt.origin,
        receipt.destination, receipt.received_at_ms, receipt.receipt_type);
    return crypto_sign_verify_detached(
               reinterpret_cast<const unsigned char*>(receipt.signature.data()),
               reinterpret_cast<const unsigned char*>(canon.data()),
               canon.size(), pk.data()) == 0;
}

// ---------------------------------------------------------------------------
// handleReceipt_: the origin consumes a verified signed receipt and upgrades
// the delivered object's state to CONFIRMED (idempotent, Step 5.6).
// ---------------------------------------------------------------------------
void DeliveryManager::handleReceipt_(const std::string& origin,
                                     const obj::NetworkObject& receipt_obj,
                                     bool /*reachable*/) {
    if (!m_store) return;
    ReceiptPayload receipt;
    if (!decode_receipt(receipt_obj.payload, receipt)) return;
    // Only the object's origin should accept the receipt; do not trust the
    // receipt's own origin field blindly.
    if (receipt.origin != m_cfg.local_peer_id) return;
    if (!verifyReceipt_(receipt)) {
        m_ctr.auth_failed++;
        emit_("RECEIPT_INVALID", receipt.object_id_hex);
        return;
    }
    networkos::ObjectId delivered_id;
    if (!networkos::ObjectId::fromHex(receipt.object_id_hex, delivered_id)) return;
    if (m_store->confirmObject(delivered_id, receipt.received_at_ms) != Result::kOk) return;
    // Persist the linkage on the origin too, so `CONFIRMED` is durable proof
    // that survives process death (invariant 4/17-18).
    {
        ObjectStore::ReceiptRow row;
        row.delivered_object_id_hex = receipt.object_id_hex;
        row.receipt_object_id_hex = receipt_obj.origin.object_id_hex;
        row.origin = receipt.origin;
        row.destination = receipt.destination;
        row.receipt_type = receipt.receipt_type;
        row.received_at_ms = receipt.received_at_ms;
        row.object_hash_hex = receipt.object_hash_hex;
        row.signature = receipt.signature;
        row.signer_pk_hex = receipt.signer_pk_hex;
        m_store->recordReceipt(row);
    }
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.receipts_verified++;
        m_ctr.confirmed_objects++;
        m_ctr.receipts_delivered++;
    }
    emit_("RECEIPT_RECEIVED", receipt.object_id_hex);
    emit_("CONFIRMED", receipt.object_id_hex);
}

// ---------------------------------------------------------------------------
// retryPending: re-offer objects that are still queued (no reachable
// destination / no carrier accepted) to newly-available peers. Idempotent.
// ---------------------------------------------------------------------------
size_t DeliveryManager::retryPending(int64_t /*now_ms_value*/,
                                     const std::vector<std::string>& new_peers) {
    if (!m_store) return 0;
    if (new_peers.empty()) return 0;
    size_t sent = 0;
    // A freshly-reachable destination may have queued/undelivered objects.
    for (const auto& peer : new_peers) {
        sent += forwardPending(peer);
    }
    return sent;
}

DeliveryManager::Counters DeliveryManager::counters() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_ctr;
}

std::string DeliveryManager::telemetryJson() const {
    std::lock_guard<std::mutex> lock(m_mu);
    std::ostringstream os;
    os << "{\"direct_deliveries\":" << m_ctr.direct_deliveries
       << ",\"store_and_forwards\":" << m_ctr.store_and_forwards
       << ",\"received_acks\":" << m_ctr.received_acks
       << ",\"receipts_created\":" << m_ctr.receipts_created
       << ",\"receipts_delivered\":" << m_ctr.receipts_delivered
       << ",\"receipts_verified\":" << m_ctr.receipts_verified
       << ",\"confirmed_objects\":" << m_ctr.confirmed_objects
       << ",\"duplicate_data_rejected\":" << m_ctr.duplicate_data_rejected
       << ",\"no_carrier\":" << m_ctr.no_carrier
       << ",\"ttl_expired\":" << m_ctr.ttl_expired
       << "}";
    return os.str();
}

std::unique_ptr<DeliveryManager> createDeliveryManager(ObjectStore* store,
                                                       const DeliveryManager::Config& cfg) {
    return std::make_unique<DeliveryManager>(store, cfg);
}

} // namespace delivery
} // namespace networkos
