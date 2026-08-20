// NullPlatformAdapter.cpp — Network OS Phase 1 desktop adapter.
//
// No real platform signals on desktop; all pushSignal/requestWakeup calls are
// recorded and treated as no-ops. The runtime still processes the signals so
// the scheduler's event hooks fire identically to Android.

#include "networkos/IPlatformAdapter.h"

#include <cstdint>
#include <mutex>
#include <string>

namespace networkos {

namespace {

class NullPlatformAdapter : public IPlatformAdapter {
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

    Result requestWakeup(const std::string&, int64_t) override {
        return Result::kOk;  // desktop: no OS scheduling needed
    }

    std::string name() const override { return "desktop-null"; }

private:
    mutable std::mutex m_mu;
    PlatformInfo m_info;
};

} // namespace

std::unique_ptr<IPlatformAdapter> createDesktopPlatformAdapter() {
    return std::make_unique<NullPlatformAdapter>();
}

} // namespace networkos
