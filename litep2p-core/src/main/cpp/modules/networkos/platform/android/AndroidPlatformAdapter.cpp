// AndroidPlatformAdapter.cpp — Network OS Phase 1 Android adapter stub.
//
// Phase 1 ships the adapter seam on Android; real Android signals
// (ConnectivityManager, BatteryManager, ActivityManager, WorkManager) are
// pushed from the Kotlin side via JNI in Phase 8. This stub records signals
// exactly like the desktop adapter so both flavors behave identically.
//
// The engine never calls Android APIs directly — only this file may (guarded
// by HAVE_JNI); everything else consumes IPlatformAdapter signals.

#include "AndroidPlatformAdapter.h"

#include "networkos/IPlatformAdapter.h"

#include <mutex>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Wakeup bridge (Phase 8). The JNI layer registers an emitter via
// networkos::android::setWakeBridge(); requestWakeup() forwards through it.
// Wakeups requested before registration are queued and flushed later so an
// early scheduler deadline is never dropped during engine boot.
// ---------------------------------------------------------------------------
namespace networkos {

constexpr size_t kMaxPendingWakeups = 8;
constexpr int64_t kMaxWakeupDelayMs = 15 * 60 * 1000;  // clamp: 15 minutes

struct PendingWakeup {
    std::string reason;
    int64_t delay_ms;
};

std::mutex g_bridge_mu;
android::WakeBridgeFn g_wake_bridge = nullptr;
std::vector<PendingWakeup> g_pending_wakeups;

namespace android {

void setWakeBridge(WakeBridgeFn fn) {
    std::vector<PendingWakeup> to_flush;
    {
        std::lock_guard<std::mutex> lock(g_bridge_mu);
        g_wake_bridge = fn;
        if (fn) {
            to_flush.swap(g_pending_wakeups);
        } else {
            g_pending_wakeups.clear();
        }
    }
    // Invoke outside the lock: the emitter enters JNI and must not deadlock
    // against a concurrent requestWakeup() on another engine thread.
    for (const PendingWakeup& w : to_flush) {
        fn(w.reason.c_str(), w.delay_ms);
    }
}

}  // namespace android

namespace {

class AndroidPlatformAdapter : public IPlatformAdapter {
public:
    Result pushSignal(PlatformSignal signal, const std::string& value) override {
        std::lock_guard<std::mutex> lock(m_mu);
        switch (signal) {
            case PlatformSignal::kConnectivity: m_info.connectivity = value.empty() ? "none" : value; break;
            case PlatformSignal::kMetered: m_info.metered = (value == "1"); break;
            case PlatformSignal::kBattery:
                try { m_info.battery_percent = std::stoi(value); } catch (...) {}
                break;
            case PlatformSignal::kCharging: m_info.charging = (value == "1"); break;
            case PlatformSignal::kStoragePressure: m_info.storage_pressure = value.empty() ? "ok" : value; break;
            case PlatformSignal::kForeground: m_info.foreground = (value != "0"); break;
            case PlatformSignal::kWakeupWindow: break;
        }
        return Result::kOk;
    }

    PlatformInfo info() const override {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_info;
    }

    // Phase 8 lifecycle bridge: forward to WorkManager via the JNI-registered
    // emitter (WorkManager jobs survive process death + Doze batching).
    // Without a bridge (desktop-style tests, pre-JNI boot) the request is
    // retained bounded/coalesced and flushed once the bridge registers.
    Result requestWakeup(const std::string& reason, int64_t in_ms) override {
        PendingWakeup w;
        w.reason = reason.empty() ? "unspecified" : reason;
        if (in_ms < 0) in_ms = 0;
        if (in_ms > kMaxWakeupDelayMs) in_ms = kMaxWakeupDelayMs;
        w.delay_ms = in_ms;

        android::WakeBridgeFn fn = nullptr;
        {
            std::lock_guard<std::mutex> lock(g_bridge_mu);
            fn = g_wake_bridge;
            if (!fn) {
                bool coalesced = false;
                for (PendingWakeup& p : g_pending_wakeups) {
                    if (p.reason == w.reason) {
                        if (w.delay_ms < p.delay_ms) p.delay_ms = w.delay_ms;
                        coalesced = true;
                        break;
                    }
                }
                if (!coalesced) {
                    if (g_pending_wakeups.size() >= kMaxPendingWakeups) {
                        g_pending_wakeups.erase(g_pending_wakeups.begin());
                    }
                    g_pending_wakeups.push_back(std::move(w));
                }
            }
        }
        if (fn) fn(w.reason.c_str(), w.delay_ms);
        return Result::kOk;
    }

    std::string name() const override { return "android"; }

private:
    mutable std::mutex m_mu;
    PlatformInfo m_info;
};

} // namespace

std::unique_ptr<IPlatformAdapter> createAndroidPlatformAdapter() {
    return std::make_unique<AndroidPlatformAdapter>();
}

} // namespace networkos
