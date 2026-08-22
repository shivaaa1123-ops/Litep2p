#pragma once

// Network OS Phase 13 — Push bridge (signalling.md §3 Phase 1/§5 JNI
// dispatcher). Mirrors the Android WakeBridge pattern: the C++ core never
// touches Firebase. The JNI layer registers an emitter; the engine calls it
// when it needs an out-of-band push wake to a peer (cascade tier 3), and the
// app forwards inbound FCM payloads back through litep2p_push_payload().

#include <cstdint>
#include <string>
#include <vector>

namespace networkos {
namespace gossip {

// Emitted when the engine wants the host app to deliver an FCM data message
// to `peer_id`. candidates_json: flat JSON array of candidate endpoints.
using PushTriggerFn = void (*)(const char* peer_id, const char* candidates_json);

void setPushTriggerBridge(PushTriggerFn fn);
PushTriggerFn pushTriggerBridge();

// ---- Inbound FCM payload schema (strict) -----------------------------------
// {"type":"candidates","peer_id":"<hex>","nonce":<u32>,
//  "candidates":["ip:port", ...]}
// {"type":"wake","peer_id":"<hex>"}
struct PushPayload {
    enum class Type { kCandidates, kWake } type{Type::kWake};
    std::string peer_id;
    uint32_t nonce{0};
    std::vector<std::string> candidates;  // <=8 entries, each <=128 chars
};

bool parse_push_payload(const std::string& json, PushPayload& out);

}  // namespace gossip
}  // namespace networkos