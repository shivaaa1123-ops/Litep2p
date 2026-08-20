#pragma once

// Network OS Phase 6 — anti-entropy reconciliation frames (master doc §82 typed
// frames, §12 inventory, §59 reconciliation, §65 dedup).
//
// Pull-heavy primitive: two peers on a useful connection exchange compact
// summaries of the objects they hold and explicitly WANT only the objects they
// are missing — no blind resend.
//
//   INVENTORY   (0x3A) — sender's held-object summary. `format` selects the
//                        encoding: v0 = exact compact ID list (id + short state
//                        tag). Bloom-filter summaries (v1) are deferred behind
//                        the IInventorySource interface.
//   OBJECT_WANT (0x3B) — explicit request for specific object_ids, with the
//                        requesting peer's dedup context (ids it already holds)
//                        so the responder can skip already-seen objects.
//
// Both frames are bounded: the codec caps the number of entries and the total
// wire length BEFORE allocation (§29); oversized requests are rejected. The
// decoder is STRICT (trailing/unknown fields rejected) like every networkos
// frame.

#include <cstdint>
#include <string>
#include <vector>

namespace networkos {
namespace anti_entropy {

// Inventory encoding formats (§12). v0 is the compact exact list implemented
// now; v1 (Bloom filter) is a designed extension behind IInventorySource.
enum InventoryFormat : uint8_t {
    kFormatExactList = 0,
};

// One inventory entry: object id + a short state tag (ObjectStatus byte). Used
// by the responder to prioritize and to skip already-seen/already-terminal ids.
struct InventoryEntry {
    std::string object_id_hex;   // canonical ObjectId hex (dedup key)
    uint8_t state{0};            // ObjectStatus
    int64_t created_at_ms{0};    // for priority/time ordering
};

struct InventoryFrame {
    uint8_t format{kFormatExactList};
    uint32_t count{0};
    std::vector<InventoryEntry> entries;
};

struct ObjectWantFrame {
    std::vector<std::string> object_id_hexes;   // ids this peer is missing
    std::vector<std::string> already_held;      // dedup context (responder skips these)
};

// Hard cap on serialized inventory entries — §12: bounded serialization,
// never an unbounded message. (Phase-3 pool sized pools; Bloom filter is the
// growth path when pools exceed this.)
constexpr uint32_t kMaxInventoryEntries = 2000;
constexpr uint32_t kMaxWantIds = 2000;

std::string encode_inventory(const InventoryFrame& f);
bool decode_inventory(const std::string& data, InventoryFrame& out);

std::string encode_object_want(const ObjectWantFrame& f);
bool decode_object_want(const std::string& data, ObjectWantFrame& out);

} // namespace anti_entropy
} // namespace networkos