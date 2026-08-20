// message_latency_runner.cpp — Phase 0 benchmark harness (NOT production code).
//
// Measures per-message round-trip latency (p50/p95) and handshake time
// between two in-process SessionManagers over loopback.
//
// Environment:
//   CONFIG_PATH   required   config.json to load (discovery disabled config is best)
//   SELF_ID       required
//   SELF_PORT     optional   default 32001
//   TARGET_ID     required
//   TARGET_NETID  required   ip:port
//   SIZES         optional   csv, default 1024,8192
//   ITERATIONS    optional   default 20
//   OUT_JSON      optional   output path
#include "session_manager.h"
#include "config_manager.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <numeric>
#include <sstream>
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

std::vector<int> parse_sizes_csv(const std::string& s) {
    std::vector<int> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (item.empty()) continue;
        try { out.push_back(std::stoi(item)); } catch (...) {}
    }
    return out;
}

double percentile(std::vector<double> v, double p) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const size_t idx = static_cast<size_t>((p / 100.0) * static_cast<double>(v.size() - 1));
    return v[idx];
}
} // namespace

int main() {
    const std::string config_path = getenv_str("CONFIG_PATH");
    const std::string role = getenv_str("ROLE", "sender");
    const std::string self_id = getenv_str("SELF_ID");
    const int self_port = getenv_int("SELF_PORT", 32001);
    const std::string target_id = getenv_str("TARGET_ID");
    const std::string target_netid = getenv_str("TARGET_NETID");
    const std::string sizes_csv = getenv_str("SIZES", "1024,8192");
    const int iterations = getenv_int("ITERATIONS", 20);
    const int deadline_sec = getenv_int("DEADLINE_SEC", 60);
    const std::string out_json = getenv_str("OUT_JSON");

    if (config_path.empty() || self_id.empty() ||
        (role == "sender" && (target_id.empty() || target_netid.empty()))) {
        std::cerr << "CONFIG_PATH, SELF_ID (and TARGET_ID/TARGET_NETID for sender) required\n";
        return 2;
    }
    if (role != "sender" && role != "receiver") {
        std::cerr << "ROLE must be sender|receiver\n";
        return 2;
    }

    (void)ConfigManager::getInstance().loadConfig(config_path);

    std::atomic<int> last_ack{-1};
    std::atomic<int> ping_count{0};

    SessionManager sm;
    sm.setMessageReceivedCallback([&](const std::string& from, const std::string& msg) {
        if (msg.rfind("LAT_ACK:", 0) == 0) {
            try { last_ack.store(std::stoi(msg.substr(8)), std::memory_order_release); }
            catch (...) {}
        } else if (msg.rfind("LAT_PING:", 0) == 0) {
            const auto bar = msg.find('|');
            if (bar != std::string::npos) {
                try {
                    const int n = std::stoi(msg.substr(9, bar - 9));
                    sm.sendMessageToPeer(from, std::string("LAT_ACK:") + std::to_string(n));
                    ping_count.fetch_add(1, std::memory_order_relaxed);
                } catch (...) {}
            }
        }
    });

    sm.start(self_port, [](const std::vector<Peer>&) {}, "UDP", self_id);

    if (role == "receiver") {
        // Receiver: optional peer mapping for deterministic handshake, then idle
        // until the deadline while replying to LAT_PING with LAT_ACK.
        if (!target_id.empty() && !target_netid.empty()) {
            sm.addPeer(target_id, target_netid);
        }
        const auto deadline = Clock::now() + std::chrono::seconds(deadline_sec);
        while (Clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        sm.stop();
        write_text(out_json, std::string("{\"role\":\"receiver\",\"self_id\":\"") + self_id +
                                  "\",\"ping_count\":" + std::to_string(ping_count.load()) + "}\n");
        return 0;
    }

    sm.addPeer(target_id, target_netid);


    // Handshake: connect and wait until connected (FSM READY).
    const auto t_conn0 = Clock::now();
    sm.connectToPeer(target_id);
    bool connected = false;
    for (int i = 0; i < 200 && !connected; ++i) {
        if (sm.isPeerConnected(target_id)) { connected = true; break; }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    const double handshake_ms =
        std::chrono::duration<double, std::milli>(Clock::now() - t_conn0).count();

    std::stringstream report;
    report << "{\"role\":\"" << role << "\",\"result\":\""
           << (connected ? "done" : "connect_timeout")
           << "\",\"handshake_ms\":" << handshake_ms
           << ",\"sizes\":[";

    bool first_size = true;
    for (int n : parse_sizes_csv(sizes_csv)) {
        std::vector<double> rt_ms;
        const std::string body(static_cast<size_t>(n), 'B');
        // Warmup round-trips to ensure Noise READY before timing.
        for (int w = 0; w < 3; ++w) {
            last_ack.store(-1, std::memory_order_release);
            sm.sendMessageToPeer(target_id, std::string("LAT_PING:") + std::to_string(n) + "|" + body);
            for (int k = 0; k < 300; ++k) {
                if (last_ack.load(std::memory_order_acquire) == n) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        for (int it = 0; it < iterations; ++it) {
            last_ack.store(-1, std::memory_order_release);
            const auto t0 = Clock::now();
            sm.sendMessageToPeer(target_id, std::string("LAT_PING:") + std::to_string(n) + "|" + body);
            for (int k = 0; k < 1500; ++k) {
                if (last_ack.load(std::memory_order_acquire) == n) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
            const double ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
            rt_ms.push_back(ms);
        }
        if (!first_size) report << ",";
        first_size = false;
        report << "{\"size\":" << n
               << ",\"iterations\":" << rt_ms.size()
               << ",\"p50_ms\":" << percentile(rt_ms, 50)
               << ",\"p95_ms\":" << percentile(rt_ms, 95)
               << ",\"mean_ms\":" << (rt_ms.empty() ? 0.0 :
                   std::accumulate(rt_ms.begin(), rt_ms.end(), 0.0) / rt_ms.size())
               << "}";
    }
    report << "]}";

    sm.stop();
    write_text(out_json, report.str());
    std::cout << report.str() << std::endl;
    return connected ? 0 : 1;
}

