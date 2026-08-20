// AndroidPlatformAdapter.cpp — Network OS Phase 1 Android adapter stub.
//
// Phase 1 ships the adapter seam on Android; real Android signals
// (ConnectivityManager, BatteryManager, ActivityManager, WorkManager) are
// pushed from the Kotlin side via JNI in Phase 8. This stub records signals
// exactly like the desktop adapter so both flavors behave identically.
//
// The engine never calls Android APIs directly — only this file may (guarded
// by HAVE_JNI); everything else consumes IPlatformAdapter signals.

#include "networkos/IPlatformAdapter.h"

#include <mutex>
#include <string>

namespace networkos {

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

    // Phase 8: map to WorkManager constraints (network/unmetered/charging).
    Result requestWakeup(const std::string&, int64_t) override {
        return Result::kNotImplemented;  // wired in Phase 8
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
