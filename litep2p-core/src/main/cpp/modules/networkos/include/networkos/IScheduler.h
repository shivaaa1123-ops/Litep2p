#pragma once

// Network OS — IScheduler (master doc §8 central scheduler, §37 threading,
// §89 Phase 1).
//
// Rule (P1): NO subsystem owns an independent timer. Every piece of deferred
// work is a Task; the scheduler dispatches tasks only when an event triggers
// processing. In Phase 1 the scheduler owns no thread (idle-thread budget,
// Gate B); the Runtime calls process(now) at event boundaries.

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>

#include "Runtime.h"

namespace networkos {

enum class TaskPriority : uint8_t {
    kBackground = 0,
    kNormal = 1,
    kHigh = 2,
    kCritical = 3,
};

// Task metadata — the scheduler uses these fields to decide WHEN work runs.
// Prefer triggers over timers: earliest_run + deadline bound the window,
// the flags describe the resource requirements.
struct Task {
    std::string id;
    std::string kind;                    // e.g. "retry", "reconcile", "repair"
    std::function<void()> run;           // the work (must be cheap; no blocking I/O)
    TaskPriority priority{TaskPriority::kNormal};

    int64_t earliest_run_ms{0};          // epoch ms; 0 = as soon as possible
    int64_t deadline_ms{0};              // epoch ms; 0 = no hard deadline
    bool requires_network{false};
    bool requires_unmetered{false};
    bool requires_charging{false};
    bool can_batch{true};
    uint64_t estimated_bytes{0};
    uint64_t estimated_cpu_us{0};

    // Event triggers that wake this task early (network change, peer
    // available, foreground, maintenance window, charging).
    bool wake_on_connectivity{false};
    bool wake_on_peer_available{false};
    bool wake_on_foreground{false};
    bool wake_on_maintenance{false};
    bool wake_on_charging{false};
};

// Event hooks the runtime calls when platform/peer signals arrive.
struct SchedulerEvents {
    std::function<void()> on_connectivity_changed;
    std::function<void()> on_app_foreground;
    std::function<void()> on_maintenance_window;
    std::function<void()> on_peer_available;
};

class IScheduler {
public:
    virtual ~IScheduler() = default;

    virtual Result schedule(Task task) = 0;
    virtual Result cancel(const std::string& id) = 0;

    // Set the event hooks (called on the caller's thread; must be cheap).
    virtual void setEvents(const SchedulerEvents& events) = 0;

    // Dispatch any due tasks now. Called by the Runtime at event boundaries —
    // never from a scheduler-owned timer in Phase 1.
    virtual Result process(int64_t now_ms) = 0;

    virtual size_t pendingCount() const = 0;
};

// Skeleton scheduler implementation (Scheduler.cpp).
std::unique_ptr<IScheduler> createScheduler();

} // namespace networkos
