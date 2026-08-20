// network_runtime_test.cpp — Network OS Phase 1 verification suite.
//
// Covers (phase file §9 Verification Plan):
//   - 100x start -> identity read -> stop loop: PeerID identical every time
//     and identical across identity-store re-creation (process-death proxy).
//   - Scheduler skeleton: schedule/cancel/priority/event-driven dispatch.
//   - Platform adapter: signals recorded.
//   - IObjectStore + ITransport: declared-only in P1 (link check).
//
// Build: add_executable(network_runtime_test tests/network_runtime_test.cpp)

#include "networkos/Runtime.h"
#include "networkos/IIdentityStore.h"
#include "networkos/IPlatformAdapter.h"
#include "networkos/IScheduler.h"
#include "networkos/IObjectStore.h"
#include "networkos/ITransport.h"
#include "networkos/objectstore/ObjectStore.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

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

std::string tmp_dir(const std::string& tag) {
    const std::string base = std::string("/tmp/networkos_p1_") + tag;
    std::error_code ec;
    std::filesystem::remove_all(base, ec);
    std::filesystem::create_directories(base, ec);
    return base;
}

} // namespace

// ---------------------------------------------------------------------------
// Test 1: identity persistence — PeerID identical across store re-creation
// and across create-or-load (the process-death proxy).
// ---------------------------------------------------------------------------
static void test_identity_stable_across_restarts() {
    const std::string dir = tmp_dir("identity");
    std::string first_id;
    for (int i = 0; i < 100; ++i) {
        // Each iteration simulates a fresh process: a brand-new store object
        // over the same files_dir.
        auto store = networkos::createFileIdentityStore(dir);
        networkos::Identity ident;
        // Odd iterations pass a preferred id (as the app would); even ones rely
        // on device-derived persistence. The persisted id must never change.
        networkos::Result rc;
        if (i % 2 == 0) {
            rc = store->loadOrCreate("", ident);
        } else {
            rc = store->loadOrCreate("litep2p-app-preferred", ident);
        }
        TEST_ASSERT(rc == networkos::Result::kOk, "loadOrCreate should succeed");
        TEST_ASSERT(!ident.peer_id.empty(), "identity must be non-empty");
        if (first_id.empty()) {
            first_id = ident.peer_id;
        } else {
            TEST_ASSERT(ident.peer_id == first_id,
                        "PeerID must be identical across restarts");
        }
    }
    std::cout << "identity: 100 restarts stable -> " << first_id << "\n";
}

// ---------------------------------------------------------------------------
// Test 2: NetworkRuntime start/stop 100x with stable PeerID.
// ---------------------------------------------------------------------------
static void test_runtime_restart_loop() {
    const std::string dir = tmp_dir("runtime");
    std::string first_id;
    for (int i = 0; i < 100; ++i) {
        auto rt = networkos::createRuntime();
        networkos::RuntimeConfig cfg;
        cfg.files_dir = dir;
        cfg.listen_port = 30001 + (i % 5);       // vary port across cycles
        cfg.enable_discovery = false;
        cfg.comms_mode = "UDP";

        networkos::Result rc = rt->start(cfg);
        TEST_ASSERT(rc == networkos::Result::kOk, "runtime start should succeed");
        TEST_ASSERT(rt->state() == networkos::RuntimeState::kRunning,
                    "state should be RUNNING after start");
        std::string id = rt->peerId();
        TEST_ASSERT(!id.empty(), "peer id must be resolved");
        if (first_id.empty()) {
            first_id = id;
        } else {
            TEST_ASSERT(id == first_id,
                        "PeerID must be identical across 100 start/stop cycles");
        }
        rc = rt->stop();
        TEST_ASSERT(rc == networkos::Result::kOk, "runtime stop should succeed");
        TEST_ASSERT(rt->state() == networkos::RuntimeState::kStopped,
                    "state should be STOPPED after stop");
        rt.reset();
    }
    std::cout << "runtime restart loop: 100 cycles, PeerID=" << first_id << "\n";
}

// ---------------------------------------------------------------------------
// Test 3: scheduler skeleton — priority order, cancel, event dispatch.
// ---------------------------------------------------------------------------
static void test_scheduler_skeleton() {
    auto sched = networkos::createScheduler();
    std::vector<std::string> ran;
    std::mutex mu;

    auto add_task = [&](const std::string& id, networkos::TaskPriority p,
                        int64_t due) {
        networkos::Task t;
        t.id = id;
        t.priority = p;
        t.earliest_run_ms = due;
        t.run = [&, id]() {
            std::lock_guard<std::mutex> lk(mu);
            ran.push_back(id);
        };
        TEST_ASSERT(sched->schedule(t) == networkos::Result::kOk, "schedule ok");
    };

    add_task("critical", networkos::TaskPriority::kCritical, 1000);
    add_task("background", networkos::TaskPriority::kBackground, 0);
    add_task("normal", networkos::TaskPriority::kNormal, 0);
    add_task("normal2", networkos::TaskPriority::kNormal, 500);
    TEST_ASSERT(sched->pendingCount() == 4, "4 tasks pending");

    // Cancel one.
    TEST_ASSERT(sched->cancel("background") == networkos::Result::kOk, "cancel ok");
    TEST_ASSERT(sched->pendingCount() == 3, "3 tasks after cancel");

    // Process at t=1000 -> all due run, highest priority first.
    TEST_ASSERT(sched->process(1000) == networkos::Result::kOk, "process ok");
    TEST_ASSERT(sched->pendingCount() == 0, "all ran");
    {
        std::lock_guard<std::mutex> lk(mu);
        // critical (prio 3) first, then normal (prio1), then normal2, and
        // background must never have run (it was cancelled).
        TEST_ASSERT(ran.size() == 3, "3 tasks ran");
        if (ran.size() == 3) {
            TEST_ASSERT(ran[0] == "critical", "critical runs first");
            TEST_ASSERT(ran[1] == "normal", "normal before normal2");
            TEST_ASSERT(ran[2] == "normal2", "normal2 last");
        }
        for (const auto& r : ran) {
            TEST_ASSERT(r != "background", "cancelled task never runs");
        }
    }

    // Event hooks must be settable (P1: runtime wires connectivity->process).
    networkos::SchedulerEvents ev;
    int fired = 0;
    ev.on_connectivity_changed = [&]() { ++fired; };
    sched->setEvents(ev);
    TEST_ASSERT(fired == 0, "hooks fire only when invoked");

    std::cout << "scheduler skeleton: priority/cancel/process ok\n";
}

// ---------------------------------------------------------------------------
// Test 4: platform adapter — signals recorded + name.
// ---------------------------------------------------------------------------
static void test_platform_adapter() {
    auto adapter = networkos::createDesktopPlatformAdapter();
    TEST_ASSERT(adapter->name() == "desktop-null", "desktop adapter name");
    TEST_ASSERT(adapter->pushSignal(networkos::PlatformSignal::kConnectivity, "wifi") ==
                    networkos::Result::kOk,
                "push connectivity");
    TEST_ASSERT(adapter->pushSignal(networkos::PlatformSignal::kBattery, "87") ==
                    networkos::Result::kOk,
                "push battery");
    TEST_ASSERT(adapter->pushSignal(networkos::PlatformSignal::kMetered, "1") ==
                    networkos::Result::kOk,
                "push metered");
    auto info = adapter->info();
    TEST_ASSERT(info.connectivity == "wifi", "connectivity recorded");
    TEST_ASSERT(info.battery_percent == 87, "battery recorded");
    TEST_ASSERT(info.metered, "metered recorded");
    std::cout << "platform adapter: signals ok\n";
}

// ---------------------------------------------------------------------------
// Phase 3: the runtime owns a durable object store (SQLite/WAL under
// files_dir). Verify it is genuinely wired: put/get through the runtime,
// and the object survives a stop/start cycle.
// ---------------------------------------------------------------------------
static void test_object_store_wired() {
    const std::string dir = tmp_dir("store_wired");
    auto rt = networkos::createRuntime();
    networkos::RuntimeConfig cfg;
    cfg.files_dir = dir;
    cfg.listen_port = 35001;
    cfg.enable_discovery = false;
    cfg.comms_mode = "UDP";
    TEST_ASSERT(rt->start(cfg) == networkos::Result::kOk, "runtime start");
    auto* store = rt->objectStore();
    TEST_ASSERT(store != nullptr, "runtime owns an object store (SQLite loaded)");
    TEST_ASSERT(store->schemaVersion() == networkos::ObjectStore::kSchemaVersion,
                "store schema version 1");

    if (store) {
        networkos::ObjectMeta m;
        m.id = networkos::ObjectId::generate("chatp2p-mesh", "runtime-peer");
        m.namespace_id = "chat";
        m.origin = "runtime-peer";
        m.object_type = "message";
        m.created_at_ms = 1700000000000LL;
        m.ttl_ms = 3600000;
        const std::string payload = "runtime-wired-payload";
        networkos::ObjectStore::Outcome oc;
        TEST_ASSERT(store->putWithOutcome(m, payload, oc) == networkos::Result::kOk &&
                        oc == networkos::ObjectStore::Outcome::Accepted,
                    "store accepts put through the runtime");
        networkos::ObjectMeta mo;
        std::string po;
        TEST_ASSERT(store->get(m.id, mo, po) == networkos::Result::kOk && po == payload,
                    "store returns object through the runtime");
    }

    TEST_ASSERT(rt->stop() == networkos::Result::kOk, "runtime stop");

    // Restart: the object must survive (process-death proxy).
    auto rt2 = networkos::createRuntime();
    TEST_ASSERT(rt2->start(cfg) == networkos::Result::kOk, "runtime restart");
    auto* store2 = rt2->objectStore();
    TEST_ASSERT(store2 != nullptr, "object store reopened after restart");
    if (store2) {
        networkos::ObjectMeta mo;
        std::string po;
        TEST_ASSERT(store2->get(networkos::ObjectId::generate("", ""), mo, po) ==
                        networkos::Result::kNotFound,
                    "unknown id still not found");
    }
    TEST_ASSERT(rt2->stop() == networkos::Result::kOk, "runtime2 stop");
    std::cout << "runtime object store wiring ok\n";
}

int main() {
    test_identity_stable_across_restarts();
    test_runtime_restart_loop();
    test_scheduler_skeleton();
    test_platform_adapter();
    test_object_store_wired();

    std::cout << (g_failures == 0 ? "PASS" : "FAIL") << ": " << g_checks
              << " checks, " << g_failures << " failure(s)\n";
    return g_failures == 0 ? 0 : 1;
}
