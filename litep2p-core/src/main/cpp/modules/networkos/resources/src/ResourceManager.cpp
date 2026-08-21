// ResourceManager.cpp — Network OS Phase 8 resource-aware scheduling core.

#include "networkos/resources/ResourceManager.h"

#include <nlohmann/json.hpp>

#include <chrono>
#include <sstream>

namespace networkos {
namespace resources {

namespace {

int64_t real_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

int64_t now_or_fixed(int64_t fixed) { return fixed > 0 ? fixed : real_now_ms(); }

const char* profile_name(ResourceProfile p) {
    switch (p) {
        case ResourceProfile::kEco: return "ECO";
        case ResourceProfile::kBalanced: return "BALANCED";
        case ResourceProfile::kReliable: return "RELIABLE";
        case ResourceProfile::kCritical: return "CRITICAL";
    }
    return "BALANCED";
}

} // namespace

ResourceManager::ResourceManager() { recomputeBudget_(); }

void ResourceManager::setNowMs(int64_t now_ms) { m_now_ms = now_ms; }

ResourceProfile ResourceManager::profile() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_profile;
}

void ResourceManager::setProfile(ResourceProfile profile) {
    std::lock_guard<std::mutex> lock(m_mu);
    m_profile = profile;
    recomputeBudget_();
}

NetworkClass ResourceManager::netClass_() const {
    const std::string& c = m_info.connectivity;
    if (c == "none" || c == "offline" || c.empty()) return NetworkClass::kNone;
    if (c == "wifi") return NetworkClass::kWifi;
    if (c == "cellular") return NetworkClass::kCellular;
    if (c == "ethernet") return NetworkClass::kEthernet;
    return NetworkClass::kUnknown;
}

void ResourceManager::onSignal(PlatformSignal signal, const std::string& value) {
    std::lock_guard<std::mutex> lock(m_mu);
    switch (signal) {
        case PlatformSignal::kConnectivity:
            m_info.connectivity = value.empty() ? "none" : value;
            break;
        case PlatformSignal::kMetered:
            m_info.metered = (value == "1");
            break;
        case PlatformSignal::kBattery:
            try { m_info.battery_percent = std::stoi(value); } catch (...) {}
            break;
        case PlatformSignal::kCharging:
            m_info.charging = (value == "1");
            break;
        case PlatformSignal::kStoragePressure:
            m_info.storage_pressure = value.empty() ? "ok" : value;
            break;
        case PlatformSignal::kForeground:
            m_info.foreground = (value != "0");
            break;
        case PlatformSignal::kWakeupWindow:
            try { m_budget.maintenance_allowance_ms = std::stoll(value); } catch (...) {
                m_budget.maintenance_allowance_ms = 0;
            }
            break;
    }
    recomputeBudget_();
}

// Recompute concrete budgets from current profile + platform state (§43/§85).
void ResourceManager::recomputeBudget_() {
    // Preserve the maintenance-window allowance across recomputation: it is set
    // by the kWakeupWindow signal (Step 5.6) and must survive profile/signal
    // changes within the same window.
    const int64_t preserved_allowance = m_budget.maintenance_allowance_ms;
    ResourceBudget b;
    const bool fg = m_info.foreground;
    const bool charging = m_info.charging;
    const bool metered = m_info.metered;
    const bool offline = (netClass_() == NetworkClass::kNone);
    const bool low_battery = m_info.battery_percent < 20 && !charging;
    const bool storage_pressure = (m_info.storage_pressure == "low");

    switch (m_profile) {
        case ResourceProfile::kEco:
            b.connection_budget = 0;
            b.replication_budget = 0;
            b.discovery_intensity = 0;
            b.accept_storage = false;
            b.lease_duration_hint_ms = 3600 * 1000;
            b.cpu_quota_percent = 5;
            b.bandwidth_bytes_per_sec = 0;
            break;
        case ResourceProfile::kReliable:
            b.connection_budget = 16;
            b.replication_budget = 16;
            b.discovery_intensity = 100;
            b.accept_storage = true;
            b.lease_duration_hint_ms = 24LL * 3600 * 1000;
            b.cpu_quota_percent = 100;
            b.bandwidth_bytes_per_sec = 0;
            break;
        case ResourceProfile::kCritical:
            b.connection_budget = 32;
            b.replication_budget = 32;
            b.discovery_intensity = 100;
            b.accept_storage = true;
            b.lease_duration_hint_ms = 24LL * 3600 * 1000;
            b.cpu_quota_percent = 100;
            b.bandwidth_bytes_per_sec = 0;
            break;
        case ResourceProfile::kBalanced:
        default:
            b.connection_budget = 8;
            b.replication_budget = 8;
            b.discovery_intensity = 60;
            b.accept_storage = true;
            b.lease_duration_hint_ms = 6LL * 3600 * 1000;
            b.cpu_quota_percent = 100;
            b.bandwidth_bytes_per_sec = 0;
            break;
    }

    b.foreground = fg;
    if (offline) {
        b.connection_budget = 0;
        b.replication_budget = 0;
        b.discovery_intensity = 0;
        b.bandwidth_bytes_per_sec = 0;
    }
    if (low_battery) {
        b.connection_budget = std::min<size_t>(b.connection_budget, 1);
        b.replication_budget = std::min<size_t>(b.replication_budget, 1);
        b.discovery_intensity = std::min<uint8_t>(b.discovery_intensity, 10);
        b.accept_storage = false;
    }
    if (metered) {
        b.connection_budget = std::min<size_t>(b.connection_budget, 2);
        b.replication_budget = std::min<size_t>(b.replication_budget, 1);
    }
    if (storage_pressure) {
        b.accept_storage = false;
        b.lease_duration_hint_ms = std::min<int64_t>(b.lease_duration_hint_ms, 3600 * 1000);
    }

    b.maintenance_allowance_ms = std::max<int64_t>(0, preserved_allowance);
    m_budget = b;
}

ResourceBudget ResourceManager::budget() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_budget;
}

bool ResourceManager::isBackground() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return !m_info.foreground;
}

bool ResourceManager::canDoBackgroundWork() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return !m_info.foreground && m_budget.maintenance_allowance_ms > 0;
}

bool ResourceManager::canAcceptStorage() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_budget.accept_storage;
}

void ResourceManager::noteWakeup(const std::string& source, int64_t duration_ms) {
    std::lock_guard<std::mutex> lock(m_mu);
    WakeupSample w;
    w.source = source.empty() ? "unattributed" : source;
    w.duration_ms = duration_ms;
    w.at_ms = now_or_fixed(m_now_ms);
    m_wakeups.push_back(w);
    if (source.empty()) m_unattributed++;
}

size_t ResourceManager::wakeupCount(const std::string& source) const {
    std::lock_guard<std::mutex> lock(m_mu);
    if (source.empty()) return m_wakeups.size();
    size_t n = 0;
    for (const auto& w : m_wakeups) if (w.source == source) ++n;
    return n;
}

std::vector<WakeupSample> ResourceManager::wakeups() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_wakeups;
}

size_t ResourceManager::unattributedWakeups() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_unattributed;
}

std::string ResourceManager::profileName() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return profile_name(m_profile);
}

std::string ResourceManager::budgetJson() const {
    std::lock_guard<std::mutex> lock(m_mu);
    nlohmann::json j;
    j["profile"] = profile_name(m_profile);
    j["connection_budget"] = m_budget.connection_budget;
    j["replication_budget"] = m_budget.replication_budget;
    j["bandwidth_bytes_per_sec"] = m_budget.bandwidth_bytes_per_sec;
    j["cpu_quota_percent"] = m_budget.cpu_quota_percent;
    j["discovery_intensity"] = m_budget.discovery_intensity;
    j["accept_storage"] = m_budget.accept_storage;
    j["lease_duration_hint_ms"] = m_budget.lease_duration_hint_ms;
    j["maintenance_allowance_ms"] = m_budget.maintenance_allowance_ms;
    j["foreground"] = m_budget.foreground;
    return j.dump();
}

std::string ResourceManager::snapshot() const {
    std::lock_guard<std::mutex> lock(m_mu);
    nlohmann::json j;
    j["profile"] = static_cast<int>(m_profile);
    j["connectivity"] = m_info.connectivity;
    j["metered"] = m_info.metered;
    j["battery"] = m_info.battery_percent;
    j["charging"] = m_info.charging;
    j["storage_pressure"] = m_info.storage_pressure;
    j["foreground"] = m_info.foreground;
    j["budget"] = {
        {"replication_budget", m_budget.replication_budget},
        {"connection_budget", m_budget.connection_budget},
        {"discovery_intensity", m_budget.discovery_intensity},
        {"accept_storage", m_budget.accept_storage},
        {"lease_duration_hint_ms", m_budget.lease_duration_hint_ms},
    };
    return j.dump();
}

bool ResourceManager::restore(const std::string& json) {
    std::lock_guard<std::mutex> lock(m_mu);
    try {
        nlohmann::json j = nlohmann::json::parse(json);
        m_profile = static_cast<ResourceProfile>(j.value("profile", 1));
        if (j.contains("connectivity")) m_info.connectivity = j["connectivity"].get<std::string>();
        if (j.contains("metered")) m_info.metered = j["metered"].get<bool>();
        if (j.contains("battery")) m_info.battery_percent = j["battery"].get<int>();
        if (j.contains("charging")) m_info.charging = j["charging"].get<bool>();
        if (j.contains("storage_pressure")) m_info.storage_pressure = j["storage_pressure"].get<std::string>();
        if (j.contains("foreground")) m_info.foreground = j["foreground"].get<bool>();
    } catch (...) {
        return false;
    }
    recomputeBudget_();
    return true;
}

std::unique_ptr<ResourceManager> createResourceManager() {
    return std::make_unique<ResourceManager>();
}

} // namespace resources
} // namespace networkos