#include "file_transfer_manager.h"
#include "logger.h"

#include <algorithm>
#include <chrono>

// Defined in file_transfer_manager.cpp
std::string generate_transfer_id();

// ============================================================================
// PATH MANAGEMENT + MULTIPLEXING + PATH MONITOR
// ============================================================================

std::string FileTransferManager::register_network_path(
    const std::string& peer_id,
    const std::string& next_hop_peer_id,
    const std::string& next_hop_ip,
    int next_hop_port,
    int latency_ms,
    int bandwidth_kbps) {

    std::lock_guard<std::mutex> lock(m_paths_mutex);

    auto path = std::make_shared<NetworkPath>();
    path->path_id = "path_" + peer_id + "_" + generate_transfer_id();
    path->next_hop_peer_id = next_hop_peer_id;
    path->next_hop_ip = next_hop_ip;
    path->next_hop_port = next_hop_port;
    path->hop_count = 1;
    path->latency_ms = latency_ms;
    path->bandwidth_kbps = bandwidth_kbps;
    path->path_quality_score = 100.0f;
    path->last_used = std::chrono::steady_clock::now();
    path->is_available = true;

    m_peer_paths[peer_id].push_back(path);
    m_path_map[path->path_id] = path;

    LOG_DEBUG("FT: Registered path " + path->path_id +
              " to peer " + peer_id +
              " (latency: " + std::to_string(latency_ms) + "ms" +
              ", bandwidth: " + std::to_string(bandwidth_kbps) + " Kbps)");

    return path->path_id;
}

std::shared_ptr<NetworkPath> FileTransferManager::find_optimal_path(
    const std::string& peer_id,
    PathSelectionStrategy strategy) {

    std::lock_guard<std::mutex> lock(m_paths_mutex);

    auto it = m_peer_paths.find(peer_id);
    if (it == m_peer_paths.end() || it->second.empty()) {
        return nullptr;
    }

    auto& paths = it->second;

    // Filter available paths
    std::vector<std::shared_ptr<NetworkPath>> available;
    for (auto& path : paths) {
        if (path->is_available && path->consecutive_failures < 3) {
            available.push_back(path);
        }
    }

    if (available.empty()) {
        return nullptr;
    }

    // Find best path based on strategy
    std::shared_ptr<NetworkPath> best = available[0];
    float best_score = score_path(best, strategy);

    for (size_t i = 1; i < available.size(); i++) {
        float score = score_path(available[i], strategy);
        if (score > best_score) {
            best = available[i];
            best_score = score;
        }
    }

    return best;
}

void FileTransferManager::update_path_metrics(const std::string& path_id,
                                              int latency_ms,
                                              int bandwidth_kbps) {
    std::lock_guard<std::mutex> lock(m_paths_mutex);

    auto it = m_path_map.find(path_id);
    if (it == m_path_map.end()) {
        return;
    }

    auto& path = it->second;

    // Exponential moving average for latency and bandwidth
    path->latency_ms = (path->latency_ms * 3 + latency_ms) / 4;
    path->bandwidth_kbps = (path->bandwidth_kbps * 3 + bandwidth_kbps) / 4;
    path->consecutive_failures = 0;
    path->is_available = true;
    path->last_used = std::chrono::steady_clock::now();

    LOG_DEBUG("FT: Updated path " + path_id +
              " - latency: " + std::to_string(path->latency_ms) + "ms" +
              " bandwidth: " + std::to_string(path->bandwidth_kbps) + " Kbps");
}

void FileTransferManager::mark_path_failed(const std::string& path_id) {
    std::lock_guard<std::mutex> lock(m_paths_mutex);

    auto it = m_path_map.find(path_id);
    if (it == m_path_map.end()) {
        return;
    }

    auto& path = it->second;
    path->consecutive_failures++;

    if (path->consecutive_failures >= 3) {
        path->is_available = false;
        LOG_WARN("FT: Path " + path_id + " marked unavailable after 3 failures");
    }
}

std::vector<std::string> FileTransferManager::get_transfer_paths(
    const std::string& transfer_id) {

    std::lock_guard<std::mutex> lock(m_transfers_mutex);

    auto it = m_transfers.find(transfer_id);
    if (it == m_transfers.end()) {
        return {};
    }

    return it->second->active_paths;
}

bool FileTransferManager::add_path_to_transfer(const std::string& transfer_id,
                                               const std::string& path_id) {
    std::lock_guard<std::mutex> lock(m_transfers_mutex);

    auto it = m_transfers.find(transfer_id);
    if (it == m_transfers.end()) {
        return false;
    }

    auto& paths = it->second->active_paths;
    if (std::find(paths.begin(), paths.end(), path_id) == paths.end()) {
        paths.push_back(path_id);
        LOG_INFO("FT: Added path " + path_id + " to transfer " + transfer_id);
        return true;
    }

    return false;
}

bool FileTransferManager::remove_path_from_transfer(const std::string& transfer_id,
                                                    const std::string& path_id) {
    std::lock_guard<std::mutex> lock(m_transfers_mutex);

    auto it = m_transfers.find(transfer_id);
    if (it == m_transfers.end()) {
        return false;
    }

    auto& paths = it->second->active_paths;
    auto path_it = std::find(paths.begin(), paths.end(), path_id);
    if (path_it != paths.end()) {
        paths.erase(path_it);
        LOG_INFO("FT: Removed path " + path_id + " from transfer " + transfer_id);
        return true;
    }

    return false;
}

float FileTransferManager::score_path(const std::shared_ptr<NetworkPath>& path,
                                      PathSelectionStrategy strategy) {
    if (!path || !path->is_available) {
        return 0.0f;
    }

    switch (strategy) {
        case PathSelectionStrategy::LATENCY:
            // Lower latency is better (normalize to 0-100 range)
            return std::max(0.0f, 100.0f - (path->latency_ms / 10.0f));

        case PathSelectionStrategy::THROUGHPUT:
            // Higher bandwidth is better
            return path->bandwidth_kbps / 1000.0f;  // Normalize to 0-100 scale

        case PathSelectionStrategy::BALANCED: {
            // Combination of both
            float latency_score = std::max(0.0f, 100.0f - (path->latency_ms / 10.0f));
            float bandwidth_score = path->bandwidth_kbps / 1000.0f;
            return (latency_score * 0.5f) + (bandwidth_score * 0.5f);
        }

        case PathSelectionStrategy::COST:
            // Simple cost = hops (lower is better)
            return std::max(0.0f, 100.0f - (path->hop_count * 10.0f));

        default:
            return path->path_quality_score;
    }
}

void FileTransferManager::path_monitor_loop() {
    while (m_running) {
        // Wait for the configured interval or early shutdown signal
        std::unique_lock<std::mutex> lk(m_shutdown_mutex);
        m_shutdown_cv.wait_for(lk, std::chrono::seconds(m_path_eval_interval_sec),
                               [this] { return !m_running; });
        if (!m_running) break;

        // Evaluate and update paths periodically
        {
            std::lock_guard<std::mutex> lock(m_paths_mutex);
            for (auto& [path_id, path] : m_path_map) {
                if (!path->is_available) {
                    auto now = std::chrono::steady_clock::now();
                    auto inactive_sec = std::chrono::duration_cast<std::chrono::seconds>(
                                            now - path->last_used)
                                            .count();
                    if (inactive_sec > 60) {  // Reset after 60 seconds of inactivity
                        path->consecutive_failures = 0;
                        path->is_available = true;
                        LOG_DEBUG("FT: Path " + path_id + " recovered from failure");
                    }
                }
            }
        }
    }
}
