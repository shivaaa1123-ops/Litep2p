#pragma once

// Network OS — stable public C++ interfaces (Phase 1).
//
// These headers are the seam every later phase plugs into (object store P3,
// sessions P2, resource manager P8, discovery P9). They intentionally hide
// socket/session internals; only the C ABI (include/litep2p.h) is a stable
// *public* contract — the C++ ABI is free to change between releases.

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace networkos {

class SessionFacade;   // declared in networkos/session/SessionFacade.h
class ObjectStore;     // declared in networkos/objectstore/ObjectStore.h

namespace handoff { class HandoffManager; }  // declared in networkos/handoff/HandoffManager.h
namespace delivery { class DeliveryManager; }  // declared in networkos/delivery/DeliveryManager.h
namespace anti_entropy { class AntiEntropyManager; }  // networkos/anti_entropy/AntiEntropyManager.h
namespace replication { class ReplicaPlanner; }  // networkos/replication/ReplicaPlanner.h

// ---------------------------------------------------------------------------
// Result codes (engine-internal; the C ABI keeps its own litep2p_result_t).
// ---------------------------------------------------------------------------
enum class Result {
    kOk = 0,
    kInvalidArg,
    kInvalidState,
    kBusy,
    kNotFound,
    kIo,
    kTimeout,
    kInterrupted,
    kNotImplemented,
};

inline const char* result_name(Result r) {
    switch (r) {
        case Result::kOk: return "OK";
        case Result::kInvalidArg: return "INVALID_ARG";
        case Result::kInvalidState: return "INVALID_STATE";
        case Result::kBusy: return "BUSY";
        case Result::kNotFound: return "NOT_FOUND";
        case Result::kIo: return "IO";
        case Result::kTimeout: return "TIMEOUT";
        case Result::kInterrupted: return "INTERRUPTED";
        case Result::kNotImplemented: return "NOT_IMPLEMENTED";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// Runtime lifecycle state (mirrors the C ABI's STOPPED/STARTING/RUNNING/
// STOPPING machine; RESTORING is internal to NetworkRuntime::restore()).
// ---------------------------------------------------------------------------
enum class RuntimeState {
    kStopped,
    kStarting,
    kRunning,
    kStopping,
    kRestoring,
    kFailed,
};

class RuntimeEventSink;  // declared below (pointer member in RuntimeConfig)

// ---------------------------------------------------------------------------
// Runtime events (event bus / §35 single dispatch boundary).
// ---------------------------------------------------------------------------
enum class RuntimeEventType {
    kLifecycle,
    kPeerState,
    kMessage,
    kDelivery,
    kPlatform,   // connectivity/battery/foreground changes from the adapter
};

struct RuntimeEvent {
    RuntimeEventType type{RuntimeEventType::kLifecycle};
    // Human-readable kind, e.g. "started", "peer_ready", "connectivity".
    std::string kind;
    // Optional peer id / message payload.
    std::string peer_id;
    std::string payload;
    int64_t at_ms{0};
};

class RuntimeEventSink {
public:
    virtual ~RuntimeEventSink() = default;
    virtual void onRuntimeEvent(const RuntimeEvent& event) = 0;
};


// ---------------------------------------------------------------------------
// Runtime configuration — everything a consumer may set before start().
// Field semantics mirror the C ABI's litep2p_config_t (api-spec.md §3.4).
// ---------------------------------------------------------------------------
struct RuntimeConfig {
    // Stable identity. Empty = resolve via IIdentityStore (create-once and
    // persist), so PeerID is identical across restarts and IP changes (§12).
    std::string peer_id;

    // Communication mode: "UDP" | "TCP" | "HYBRID" (see CommsMode).
    std::string comms_mode = "UDP";

    int listen_port = 30001;

    // App-private writable directory (Android filesDir / desktop CWD).
    std::string files_dir;

    // Optional config.json path (auto-discovered under files_dir otherwise).
    std::string config_path;

    bool enable_encryption = true;
    bool enable_discovery = true;
    bool single_thread_mode = false;

    // Event sink receives runtime lifecycle + peer events. A single sink is
    // the ONE dispatch boundary (§35) — no arbitrary callbacks from many
    // native threads.
    std::shared_ptr<RuntimeEventSink> event_sink;

    std::string ToString() const {
        std::string s = "comms=" + comms_mode + " port=" + std::to_string(listen_port) +
                        " enc=" + (enable_encryption ? "1" : "0") +
                        " disc=" + (enable_discovery ? "1" : "0") +
                        " single=" + (single_thread_mode ? "1" : "0") +
                        " files=" + files_dir + " cfg=" + config_path;
        if (!peer_id.empty()) s += " peer=" + peer_id;
        return s;
    }
};

// ---------------------------------------------------------------------------
// Runtime facade (master doc §7 lifecycle, §89 Phase 1).
// ---------------------------------------------------------------------------
class Runtime {
public:
    virtual ~Runtime() = default;

    // start() order: load config -> open identity -> open transports ->
    // restore durable state -> notify scheduler -> begin event loop.
    virtual Result start(const RuntimeConfig& cfg) = 0;

    // stop() order is the reverse of start(); clean shutdown, no blocked
    // threads left.
    virtual Result stop() = 0;

    // Reconstruct the same logical state from persistence after process death
    // (or after the engine was stopped). Logs every restore path.
    virtual Result restore() = 0;

    virtual RuntimeState state() const = 0;
    virtual Result stateName(std::string& out) const = 0;

    // The resolved (persisted) peer id; empty until start()/restore().
    virtual std::string peerId() const = 0;

    // Raw send over the session path (plain fire-and-forget, same semantics
    // as litep2p_send). The object-delivery path arrives in Phase 5.
    virtual Result sendMessage(const std::string& peer_id,
                               const std::string& payload) = 0;

    // Phase 2: session facade owned by the runtime (bounds, capabilities,
    // telemetry). Default: none (runtimes without a session layer return null).
    virtual SessionFacade* sessionFacade() { return nullptr; }

    // Phase 3: durable object store owned by the runtime (SQLite/WAL).
    // Default: none (runtimes without files_dir / without SQLite).
    virtual ObjectStore* objectStore() { return nullptr; }

    // Phase 4: two-phase durable handoff manager owned by the runtime
    // (signed replica leases). Valid only while running and only when the
    // object store is present. Default: none.
    virtual handoff::HandoffManager* handoff() { return nullptr; }

    // Phase 5: direct-delivery + signed-receipt manager owned by the runtime.
    // Valid only while running and only when the object store is present.
    // Default: none.
    virtual delivery::DeliveryManager* delivery() { return nullptr; }

    // Phase 6: pull-heavy anti-entropy reconciliation manager owned by the
    // runtime. Valid only while running and only when the object store is
    // present. Default: none.
    virtual anti_entropy::AntiEntropyManager* antiEntropy() { return nullptr; }

    // Phase 7: target-driven adaptive replication + peer scoring planner owned
    // by the runtime. Valid only while running and only when the object store
    // is present. Default: none.
    virtual replication::ReplicaPlanner* replication() { return nullptr; }

    // Poke the runtime with an event (used by the platform adapter and
    // external triggers, e.g. network change -> scheduler wakeup).
    virtual Result onPlatformSignal(const std::string& signal,
                                    const std::string& value) = 0;
};

// Factory (defined in NetworkRuntime.cpp). Returns a new facade instance.
std::unique_ptr<Runtime> createRuntime();

} // namespace networkos
