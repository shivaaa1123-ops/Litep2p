#pragma once

// Network OS Phase 8 — ResourceManager (master doc §8 central scheduling,
// §9 radio/battery, §42 ResourceManager, §43 profiles, §77 wakeup budget,
// §78 background reality, §88 targets, §89 Phase 8).
//
// Converts abstract platform signals into concrete resource budgets the rest
// of the engine consumes (connection budget, replication budget, bandwidth,
// CPU, discovery intensity, storage acceptance, maintenance allowance, lease
// duration hint). Profiles (ECO/BALANCED/RELIABLE/CRITICAL) trade energy for
// liveness; hard safety limits are never violated (§85).
//
// Also owns the wakeup-budget metric (§77): every wakeup is attributed to a
// subsystem and counted, so tests can assert "no unattributed wakeups" and
// "idle produces near-zero periodic wakeups".
//
// The C++ core consumes abstract signals from IPlatformAdapter; the Android
// adapter obtains them from Android. Desktop uses the same engine logic.

#include "networkos/IPlatformAdapter.h"
#include "networkos/Runtime.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace networkos {
namespace resources {

// Resource profiles (§43). ECO trades liveness for maximum battery; RELIABLE
// and CRITICAL spend more to guarantee durability/latency.
enum class ResourceProfile : uint8_t {
    kEco = 0,
    kBalanced = 1,
    kReliable = 2,
    kCritical = 3,
};

// Discrete connectivity classes derived from PlatformSignal::kConnectivity.
enum class NetworkClass : uint8_t {
    kUnknown = 0,
    kNone,       // offline / Doze
    kWifi,
    kCellular,   // unmetered? tracked separately via metered flag
    kEthernet,
};

// Concrete budget outputs (§42) — the single source of truth the engine reads.
struct ResourceBudget {
    size_t connection_budget{8};        // concurrent sessions permitted
    size_t replication_budget{8};       // handoffs per maintenance tick
    uint64_t bandwidth_bytes_per_sec{0};
    uint32_t cpu_quota_percent{100};    // 0..100
    uint8_t discovery_intensity{100};   // 0..100 (on-demand vs aggressive)
    bool accept_storage{true};          // accept inbound carrier offers
    int64_t lease_duration_hint_ms{6LL * 3600 * 1000};  // carrier lease offer (§11)
    int64_t maintenance_allowance_ms{0}; // ms of work we may do this window
    bool foreground{false};              // app visible / user communicating
};

// Wakeup accounting (§77): every wakeup attributed to a subsystem.
struct WakeupSample {
    std::string source;    // e.g. "reconcile", "repair", "discovery", "delivery"
    int64_t duration_ms{0};
    int64_t at_ms{0};
};

class ResourceManager {
public:
    ResourceManager();

    // ---- Inputs (from IPlatformAdapter pushSignal) -------------------------
    // A full input set beyond the Phase-4 stub: battery, charging, metered,
    // connectivity, storage, foreground, thermal, data-saver, OS scheduling.
    void onSignal(PlatformSignal signal, const std::string& value);

    // ---- Profiles (§43) -----------------------------------------------------
    void setProfile(ResourceProfile profile);
    ResourceProfile profile() const;

    // ---- Outputs ------------------------------------------------------------
    ResourceBudget budget() const;
    // Convenience booleans for integration (replication/reconciliation gating).
    bool isBackground() const;                 // opportunistic or dormant
    bool canDoBackgroundWork() const;          // opportunistic window open
    bool canAcceptStorage() const;             // storage acceptance flag

    // ---- Wakeup budget (§77) ------------------------------------------------
    void noteWakeup(const std::string& source, int64_t duration_ms);
    size_t wakeupCount(const std::string& source = "") const;   // "" = all
    std::vector<WakeupSample> wakeups() const;
    // Total wakeups unattributed to a known subsystem (should stay ~0).
    size_t unattributedWakeups() const;

    // ---- Lifecycle / dormant persistence (§7, invariant 11/17) -------------
    // Serialize the resource state (profile + budget) so restore() can rebuild
    // without re-deriving. Small, bounded JSON.
    std::string snapshot() const;
    bool restore(const std::string& json);

    // ---- Telemetry ----------------------------------------------------------
    std::string budgetJson() const;
    std::string profileName() const;

    // Test hook: deterministic clock.
    void setNowMs(int64_t now_ms);

private:
    void recomputeBudget_();
    NetworkClass netClass_() const;

    ResourceProfile m_profile{ResourceProfile::kBalanced};
    ResourceBudget m_budget;
    PlatformInfo m_info;

    std::vector<WakeupSample> m_wakeups;
    size_t m_unattributed{0};

    mutable std::mutex m_mu;
    int64_t m_now_ms{0};          // 0 => use real clock
};

std::unique_ptr<ResourceManager> createResourceManager();

} // namespace resources
} // namespace networkos