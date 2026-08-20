#pragma once

// Network OS — IPlatformAdapter (master doc §42 ResourceManager signals,
// §89 Phase 1).
//
// The seam that keeps the C++ core free of Android APIs. The core consumes
// abstract signals (connectivity, metered, battery, storage, foreground);
// the Android adapter obtains them from Android (ConnectivityManager,
// BatteryManager, ActivityManager, WorkManager) and pushes them into the
// runtime. Desktop uses a NullPlatformAdapter.

#include <cstdint>
#include <functional>
#include <string>

#include "Runtime.h"

namespace networkos {

// Abstract platform signals consumed by the engine.
enum class PlatformSignal : uint8_t {
    kConnectivity,      // value: "wifi" | "cellular" | "ethernet" | "none"
    kMetered,           // value: "1" | "0"
    kBattery,           // value: percent 0..100
    kCharging,          // value: "1" | "0"
    kStoragePressure,   // value: "low" | "ok"
    kForeground,        // value: "1" | "0"
    kWakeupWindow,      // value: duration hint ms (maintenance opportunity)
};

// Platform capability query results (used by resource profiles, Phase 8).
struct PlatformInfo {
    std::string connectivity = "unknown";
    bool metered = false;
    int battery_percent = 100;
    bool charging = false;
    std::string storage_pressure = "ok";
    bool foreground = true;
    std::string os = "unknown";
    std::string model = "unknown";
};

class IPlatformAdapter {
public:
    virtual ~IPlatformAdapter() = default;

    // Push a signal into the engine (called from JNI/Kotlin on Android, or
    // from tests/CLI on desktop). Thread-safe; must be cheap.
    virtual Result pushSignal(PlatformSignal signal, const std::string& value) = 0;

    // Snapshot of the current platform state.
    virtual PlatformInfo info() const = 0;

    // Scheduling bridge (Phase 8 wires this to WorkManager/alarms on
    // Android). Phase 1: desktop adapter is a no-op returning kOk.
    virtual Result requestWakeup(const std::string& reason, int64_t in_ms) = 0;

    // Name of this adapter ("android" | "desktop-null" | "desktop").
    virtual std::string name() const = 0;
};

// Desktop adapter: no real platform signals, safe no-ops. (NullPlatformAdapter.cpp)
std::unique_ptr<IPlatformAdapter> createDesktopPlatformAdapter();

// Android adapter: wired through JNI in P2/P8. Stub compiles on Android.
// (platform/android/AndroidPlatformAdapter.cpp)
std::unique_ptr<IPlatformAdapter> createAndroidPlatformAdapter();

} // namespace networkos
