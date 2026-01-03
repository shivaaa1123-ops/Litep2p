#include "session_manager.h"
#include "peer.h"
#include "config_manager.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;

std::string getenv_str(const char* k, const std::string& def = "") {
    const char* v = std::getenv(k);
    return v ? std::string(v) : def;
}

int getenv_int(const char* k, int def) {
    const char* v = std::getenv(k);
    if (!v) return def;
    try { return std::stoi(v); } catch (...) { return def; }
}

void write_text(const std::string& path, const std::string& content) {
    if (path.empty()) return;
    std::ofstream f(path, std::ios::out | std::ios::trunc);
    f << content;
}
}

// WAN integration runner:
// - Starts a SessionManager peer with a deterministic peer_id and port
// - Waits until target peer_id is observed (via signaling/discovery)
// - Attempts connectToPeer(target_id)
// - Exits 0 on success within deadline, else 1
//
// Environment variables:
// - CONFIG_PATH (default: ../../config.json resolved by CWD; pass absolute in CI)
// - PEER_ID (required)
// - TARGET_PEER_ID (required)
// - PORT (default: 30001)
// - COMMS_MODE (default: UDP)
// - DEADLINE_SEC (default: 60)
// - OUT_STATUS_JSON (optional path to write a small status json)
int main() {
    const std::string config_path = getenv_str("CONFIG_PATH", "config.json");
    const std::string peer_id = getenv_str("PEER_ID");
    const std::string target_peer_id = getenv_str("TARGET_PEER_ID");
    const int port = getenv_int("PORT", 30001);
    const std::string comms_mode = getenv_str("COMMS_MODE", "UDP");
    const int deadline_sec = getenv_int("DEADLINE_SEC", 60);
    const std::string out_status = getenv_str("OUT_STATUS_JSON", "");

    if (peer_id.empty() || target_peer_id.empty()) {
        std::cerr << "PEER_ID and TARGET_PEER_ID are required\n";
        return 2;
    }

    (void)ConfigManager::getInstance().loadConfig(config_path);

    std::atomic<bool> saw_target{false};
    std::atomic<bool> connected{false};
    std::atomic<int> peer_count{0};

    auto cb = [&](const std::vector<Peer>& peers) {
        peer_count.store(static_cast<int>(peers.size()), std::memory_order_release);
        for (const auto& p : peers) {
            if (p.id == target_peer_id) {
                saw_target.store(true, std::memory_order_release);
                if (p.connected) {
                    connected.store(true, std::memory_order_release);
                }
            }
        }
    };

    SessionManager sm;
    sm.start(port, cb, comms_mode, peer_id);

    const auto start = Clock::now();
    bool connect_issued = false;

    while (std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - start).count() < deadline_sec) {
        if (connected.load(std::memory_order_acquire)) {
            write_text(out_status, std::string("{\"result\":\"connected\",\"peer_id\":\"") + peer_id +
                                  "\",\"target_peer_id\":\"" + target_peer_id + "\"}\n");
            sm.stop();
            return 0;
        }

        // Wait until we see the peer in the peer list before attempting connect.
        if (!connect_issued && saw_target.load(std::memory_order_acquire)) {
            sm.connectToPeer(target_peer_id);
            connect_issued = true;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Final status dump for CI artifacts.
    write_text(out_status, std::string("{\"result\":\"timeout\",\"peer_id\":\"") + peer_id +
                          "\",\"target_peer_id\":\"" + target_peer_id +
                          "\",\"saw_target\":" + (saw_target.load() ? "true" : "false") +
                          ",\"connected\":" + (connected.load() ? "true" : "false") +
                          ",\"peer_count\":" + std::to_string(peer_count.load()) + "}\n");

    sm.stop();
    return 1;
}


