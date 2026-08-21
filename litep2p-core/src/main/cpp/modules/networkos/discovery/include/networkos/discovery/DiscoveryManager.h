#pragma once

// Network OS Phase 9 — DiscoveryManager (master doc §14 discovery architecture,
// §15 optional infrastructure, §73 NAT/internet reachability layering, §79 HA
// peers, §52 carrier willingness, §50 privacy, §72 no premature DHT, §89 P9).
//
// Modular discovery with explicit graceful degradation. Backends (LAN,
// known-peer reconnect, peer exchange, optional bootstrap/rendezvous, optional
// relay) register behind a common interface; the manager coordinates them,
// scales intensity with the resource profile (Phase 8), and never refuses to
// operate when optional infrastructure is absent (invariant 19).

#include "networkos/Runtime.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace networkos {
namespace discovery {

// Discovery backend kinds (Step 5.1). Future BLE / Wi-Fi Direct / DHT plug in
// here without touching the core.
enum class BackendKind : uint8_t {
    kLan = 0,
    kKnownPeer = 1,
    kPeerExchange = 2,
    kBootstrap = 3,      // optional signaling/rendezvous server
    kRelay = 4,          // optional NAT relay
};

// NAT/internet reachability layers (§73).
enum class ReachPath : uint8_t {
    kDirect = 0,
    kNatTraversal = 1,
    kRelay = 2,
    kStoreAndForward = 3,
};

// A peer discovered by some backend, with carrier/HA capability (§52/§79).
struct DiscoveredPeer {
    std::string peer_id;
    BackendKind source{BackendKind::kLan};
    int64_t last_seen_ms{0};
    bool storage_carrier{true};   // willing to carry third-party data (§52)
    bool ha_node{false};          // high-availability peer (§79)
    bool relay_capable{false};
    bool direct_reachable{false}; // has a usable direct endpoint (§73)
    bool nat_traversable{false};
};

// Backend interface. Implementations wrap the existing discovery plugin (LAN,
// signaling) or test mocks. The manager owns lifetime via unique_ptr.
class IDiscoveryBackend {
public:
    virtual ~IDiscoveryBackend() = default;
    virtual BackendKind kind() const = 0;
    virtual std::string name() const = 0;
    // Whether the backend is currently usable (e.g. server reachable).
    virtual bool available() const = 0;
    // Optional infrastructure (§15): may disappear without breaking the net.
    virtual bool optional() const { return false; }
    virtual void setEnabled(bool e) = 0;
    virtual bool enabled() const = 0;
    // Discover up to `max` peers this scan. Bounded.
    virtual std::vector<DiscoveredPeer> discover(int max) = 0;
};

class DiscoveryManager {
public:
    struct Config {
        bool enabled{true};
        uint8_t intensity{100};            // 0..100, from resource profile (P8)
        size_t peer_exchange_max{32};      // bounded peer-exchange (§50)
        bool peer_exchange_enabled{true};
        int64_t presence_window_ms{5 * 60 * 1000};  // "seen within" => present
        std::string local_peer_id;
    };

    explicit DiscoveryManager(const Config& cfg);
    ~DiscoveryManager();

    // ---- Backend registration / control (Step 5.1) -------------------------
    void registerBackend(std::unique_ptr<IDiscoveryBackend> backend);
    void setBackendEnabled(BackendKind kind, bool enabled);
    bool backendEnabled(BackendKind kind) const;
    bool backendAvailable(BackendKind kind) const;
    size_t backendCount() const;

    // ---- Intensity scaling with resource profile (Phase 8) -----------------
    void setIntensity(uint8_t intensity);
    uint8_t intensity() const;

    // ---- Discovery across enabled backends (bounded) -----------------------
    std::vector<DiscoveredPeer> discover();

    // ---- Graceful degradation (§15, invariant 19) --------------------------
    // True if the network still functions with only non-optional backends.
    bool functionalWithoutOptional() const;
    // Count of enabled+available non-optional backends.
    size_t coreBackendCount() const;

    // ---- NAT/internet reachability layering (§73) --------------------------
    ReachPath choosePath(const DiscoveredPeer& peer) const;
    static const char* pathName(ReachPath p);

    // ---- Carrier willingness + HA capabilities (§52/§79) -------------------
    void setLocalCapabilities(bool storage_carrier, bool ha, bool relay_capable);
    DiscoveredPeer localCapabilities() const;

    // ---- Peer exchange (bounded, dedup) (Step 5.1) --------------------------
    // Merge incoming peer info with our known set; never flood, dedup by id.
    std::vector<DiscoveredPeer> peerExchange(const std::vector<DiscoveredPeer>& incoming);

    // ---- Serverless presence + alias fallback (Step 5.7, decision 11) -------
    void notePeerSeen(const std::string& peer_id, int64_t at_ms);
    bool isPeerPresent(const std::string& peer_id, int64_t now_ms) const;
    void setAlias(const std::string& alias, const std::string& peer_id);
    // Resolution order: server directory (optional) then peer/known fallback.
    std::string resolveAlias(const std::string& alias) const;

    // ---- Telemetry ----------------------------------------------------------
    std::string telemetryJson() const;

private:
    IDiscoveryBackend* find_(BackendKind kind) const;
    // Lock-free core-backend count (caller must hold m_mu).
    size_t coreBackendCountUnlocked_() const;

    Config m_cfg;
    std::vector<std::unique_ptr<IDiscoveryBackend>> m_backends;
    // Known-peer table: peer_id -> last info (bounded, aged §75).
    std::unordered_map<std::string, DiscoveredPeer> m_known;
    std::unordered_map<std::string, std::string> m_alias;   // alias -> peer_id
    std::unordered_map<std::string, int64_t> m_last_seen;   // peer_id -> ms
    DiscoveredPeer m_local;
    mutable std::mutex m_mu;
};

std::unique_ptr<DiscoveryManager> createDiscoveryManager(const DiscoveryManager::Config& cfg);

} // namespace discovery
} // namespace networkos