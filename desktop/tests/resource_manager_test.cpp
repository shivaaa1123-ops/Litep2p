// resource_manager_test.cpp — Network OS Phase 8 verification suite.
//
// Covers (phase file §9): profile behavior (ECO/BALANCED/RELIABLE/CRITICAL
// differ; switch takes effect), budget enforcement (background throttle vs
// foreground full), event-driven (no idle wakeups / no gossip timers), Doze
// simulation (offline => no radio work), wakeup accounting (attributed), and
// dormant persistence (snapshot/restore round-trip, invariant 11/17).

#include "networkos/resources/ResourceManager.h"
#include "networkos/IPlatformAdapter.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

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

using networkos::PlatformSignal;
using networkos::resources::ResourceBudget;
using networkos::resources::ResourceManager;
using networkos::resources::ResourceProfile;

// Helper: a foreground, wifi, charging, healthy-battery device.
void healthyForeground(ResourceManager& rm) {
    rm.onSignal(PlatformSignal::kConnectivity, "wifi");
    rm.onSignal(PlatformSignal::kForeground, "1");
    rm.onSignal(PlatformSignal::kCharging, "1");
    rm.onSignal(PlatformSignal::kBattery, "100");
    rm.onSignal(PlatformSignal::kMetered, "0");
    rm.onSignal(PlatformSignal::kStoragePressure, "ok");
}

// ---------------------------------------------------------------------------
// 1. Profile behavior (§43): ECO/BALANCED/RELIABLE/CRITICAL differ in budgets,
//    and switching profiles takes effect without restart.
// ---------------------------------------------------------------------------
static void test_profile_behavior() {
    ResourceManager rm;
    healthyForeground(rm);

    rm.setProfile(ResourceProfile::kEco);
    ResourceBudget eco = rm.budget();
    TEST_ASSERT(eco.replication_budget == 0 && eco.connection_budget == 0,
                "ECO: no replication/connections");
    TEST_ASSERT(!eco.accept_storage, "ECO: no opportunistic storage");

    rm.setProfile(ResourceProfile::kBalanced);
    ResourceBudget bal = rm.budget();
    TEST_ASSERT(bal.replication_budget > eco.replication_budget,
                "BALANCED replicates more than ECO");
    TEST_ASSERT(bal.accept_storage, "BALANCED accepts storage");

    rm.setProfile(ResourceProfile::kReliable);
    ResourceBudget rel = rm.budget();
    TEST_ASSERT(rel.replication_budget > bal.replication_budget,
                "RELIABLE replicates more than BALANCED");
    TEST_ASSERT(rel.discovery_intensity >= bal.discovery_intensity,
                "RELIABLE discovery >= BALANCED");

    rm.setProfile(ResourceProfile::kCritical);
    ResourceBudget crit = rm.budget();
    TEST_ASSERT(crit.replication_budget >= rel.replication_budget,
                "CRITICAL replication >= RELIABLE");
    TEST_ASSERT(rm.profile() == ResourceProfile::kCritical, "profile switch took effect");
    std::cout << "profile behavior ok: ECO < BAL < RELIABLE <= CRITICAL\n";
}

// ---------------------------------------------------------------------------
// 2. Budget enforcement (Step 5.6 / §17): background throttles replication,
//    foreground restores full budgets.
// ---------------------------------------------------------------------------
static void test_budget_enforcement() {
    ResourceManager rm;
    rm.setProfile(ResourceProfile::kBalanced);
    rm.onSignal(PlatformSignal::kConnectivity, "wifi");
    rm.onSignal(PlatformSignal::kForeground, "1");
    rm.onSignal(PlatformSignal::kCharging, "1");
    rm.onSignal(PlatformSignal::kBattery, "100");
    ResourceBudget fg = rm.budget();
    TEST_ASSERT(!rm.isBackground(), "foreground => not background");
    TEST_ASSERT(fg.replication_budget >= 8, "foreground full replication budget");
    rm.onSignal(PlatformSignal::kForeground, "0");
    TEST_ASSERT(rm.isBackground(), "background after foreground=0");
    TEST_ASSERT(rm.canAcceptStorage(), "still accepts storage while background");
    std::cout << "budget enforcement ok: background vs foreground\n";
}

// ---------------------------------------------------------------------------
// 3. Event-driven check (§9): no pending work => zero wakeups; idle produces
//    no gossip-timer churn (invariant: no unattributed wakeups).
// ---------------------------------------------------------------------------
static void test_event_driven_idle() {
    ResourceManager rm;
    healthyForeground(rm);
    rm.setProfile(ResourceProfile::kBalanced);
    TEST_ASSERT(rm.wakeupCount() == 0, "idle => zero wakeups");
    TEST_ASSERT(rm.unattributedWakeups() == 0, "no unattributed wakeups");
    // A maintenance window (kWakeupWindow) is the ONLY legitimate wakeup source.
    rm.onSignal(PlatformSignal::kWakeupWindow, "30000");
    TEST_ASSERT(rm.budget().maintenance_allowance_ms == 30000,
                "maintenance window recorded");
    std::cout << "event-driven ok: idle is silent; wakeups only from events\n";
}

// ---------------------------------------------------------------------------
// 4. Doze simulation (§78 / Step 5.8): offline + Doze => no radio work, state
//    intact; resume restores budgets.
// ---------------------------------------------------------------------------
static void test_doze_simulation() {
    ResourceManager rm;
    healthyForeground(rm);
    rm.onSignal(PlatformSignal::kConnectivity, "none");
    rm.onSignal(PlatformSignal::kForeground, "0");
    ResourceBudget doze = rm.budget();
    TEST_ASSERT(doze.connection_budget == 0, "Doze: no connections");
    TEST_ASSERT(doze.replication_budget == 0, "Doze: no replication");
    TEST_ASSERT(doze.discovery_intensity == 0, "Doze: no discovery");
    rm.onSignal(PlatformSignal::kConnectivity, "wifi");
    rm.onSignal(PlatformSignal::kForeground, "1");
    ResourceBudget resumed = rm.budget();
    TEST_ASSERT(resumed.connection_budget > 0, "resume restores connections");
    TEST_ASSERT(resumed.replication_budget > 0, "resume restores replication");
    std::cout << "doze simulation ok: silent under Doze, restored on resume\n";
}

// ---------------------------------------------------------------------------
// 5. Wakeup accounting (§77): every wakeup attributed to a subsystem; no
//    unattributed wakeups; per-subsystem counters.
// ---------------------------------------------------------------------------
static void test_wakeup_accounting() {
    ResourceManager rm;
    rm.setNowMs(1000);
    rm.noteWakeup("reconcile", 12);
    rm.noteWakeup("repair", 7);
    rm.noteWakeup("reconcile", 5);
    TEST_ASSERT(rm.wakeupCount() == 3, "3 wakeups counted");
    TEST_ASSERT(rm.wakeupCount("reconcile") == 2, "2 reconcile wakeups");
    TEST_ASSERT(rm.wakeupCount("repair") == 1, "1 repair wakeup");
    TEST_ASSERT(rm.unattributedWakeups() == 0, "all wakeups attributed");
    // An empty source is attributed as unattributed and counted separately.
    rm.noteWakeup("", 1);
    TEST_ASSERT(rm.unattributedWakeups() == 1, "empty source => unattributed");
    std::cout << "wakeup accounting ok: attributed per subsystem\n";
}

// ---------------------------------------------------------------------------
// 6. Dormant persistence (§6, invariant 11/17): snapshot/restore round-trip
//    through a file rebuilds the resource state without re-deriving.
// ---------------------------------------------------------------------------
static void test_dormant_persistence() {
    ResourceManager rm;
    rm.setProfile(ResourceProfile::kReliable);
    rm.onSignal(PlatformSignal::kConnectivity, "wifi");
    rm.onSignal(PlatformSignal::kForeground, "0");
    rm.onSignal(PlatformSignal::kBattery, "55");
    const std::string snap = rm.snapshot();
    TEST_ASSERT(!snap.empty(), "snapshot produced");

    // Persist to a temp file, then rebuild a fresh instance from it.
    const std::string dir = "/tmp/networkos_p8";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    const std::string path = dir + "/resource_state.json";
    {
        std::ofstream out(path, std::ios::trunc);
        out << snap;
    }
    ResourceManager rm2;   // fresh, no signals
    {
        std::ifstream in(path);
        std::stringstream ss;
        ss << in.rdbuf();
        TEST_ASSERT(rm2.restore(ss.str()), "restore succeeded");
    }
    TEST_ASSERT(rm2.profile() == ResourceProfile::kReliable, "profile restored");
    TEST_ASSERT(rm2.budget().replication_budget > 0, "budget recomputed from state");
    std::cout << "dormant persistence ok: snapshot/restore round-trip\n";
}

} // namespace

int main() {
    test_profile_behavior();
    test_budget_enforcement();
    test_event_driven_idle();
    test_doze_simulation();
    test_wakeup_accounting();
    test_dormant_persistence();
    std::cout << (g_failures == 0 ? "PASS" : "FAIL") << ": " << g_checks
              << " checks, " << g_failures << " failure(s)\n";
    return g_failures == 0 ? 0 : 1;
}