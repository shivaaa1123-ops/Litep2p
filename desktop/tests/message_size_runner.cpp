#include "session_manager.h"
#include "config_manager.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
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
        try {
            out.push_back(std::stoi(item));
        } catch (...) {
            // ignore
        }
    }
    return out;
}

bool starts_with(const std::string& s, const std::string& pfx) {
    return s.size() >= pfx.size() && s.compare(0, pfx.size(), pfx) == 0;
}
} // namespace

// message_size_runner:
// - role=receiver: starts a SessionManager, waits for "MSG_SIZE:<n>|..." messages, replies "ACK:<n>"
// - role=sender: starts a SessionManager, connects to target, sends payload sizes, waits for ACKs
//
// Env vars:
// - CONFIG_PATH (required)
// - ROLE (sender|receiver) (required)
// - SELF_ID (required)
// - SELF_PORT (default: 31001)
// - TARGET_ID (sender required; receiver optional)
// - TARGET_NETID (sender required; receiver optional, format ip:port)
// - SIZES (sender only, csv; default: 64,128,256,512,1024,2048,4096,8192,16384,32768)
// - DEADLINE_SEC (default: 120)
// - OUT_JSON (optional path)
int main() {
    const std::string config_path = getenv_str("CONFIG_PATH");
    const std::string role = getenv_str("ROLE");
    const std::string self_id = getenv_str("SELF_ID");
    const int self_port = getenv_int("SELF_PORT", 31001);
    const std::string target_id = getenv_str("TARGET_ID");
    const std::string target_netid = getenv_str("TARGET_NETID");
    const std::string sizes_csv = getenv_str("SIZES", "64,128,256,512,1024,2048,4096,8192,16384,32768");
    const int deadline_sec = getenv_int("DEADLINE_SEC", 120);
    const std::string out_json = getenv_str("OUT_JSON");

    if (config_path.empty() || role.empty() || self_id.empty()) {
        std::cerr << "CONFIG_PATH, ROLE, SELF_ID are required\n";
        return 2;
    }
    if (role != "sender" && role != "receiver") {
        std::cerr << "ROLE must be sender|receiver\n";
        return 2;
    }
    if (role == "sender" && (target_id.empty() || target_netid.empty())) {
        std::cerr << "TARGET_ID and TARGET_NETID are required for sender\n";
        return 2;
    }

    (void)ConfigManager::getInstance().loadConfig(config_path);

    std::atomic<int> last_ack{-1};
    std::atomic<int> last_msg_size{-1};
    std::atomic<int> msg_count{0};

    SessionManager sm;
    sm.setMessageReceivedCallback([&](const std::string& from, const std::string& msg) {
        (void)from;
        msg_count.fetch_add(1, std::memory_order_relaxed);

        if (starts_with(msg, "ACK:")) {
            try {
                const int n = std::stoi(msg.substr(4));
                last_ack.store(n, std::memory_order_release);
            } catch (...) {}
            return;
        }
        if (starts_with(msg, "MSG_SIZE:")) {
            // Format: MSG_SIZE:<n>|<payload>
            const auto bar = msg.find('|');
            if (bar != std::string::npos) {
                try {
                    const int n = std::stoi(msg.substr(std::string("MSG_SIZE:").size(), bar - std::string("MSG_SIZE:").size()));
                    last_msg_size.store(n, std::memory_order_release);
                    // Reply with ACK so sender can deterministically validate delivery.
                    sm.sendMessageToPeer(from, std::string("ACK:") + std::to_string(n));
                } catch (...) {}
            }
        }
    });

    sm.start(self_port, [](const std::vector<Peer>&) {}, "UDP", self_id);

    const auto t0 = Clock::now();
    const auto deadline = t0 + std::chrono::seconds(deadline_sec);

    if (role == "receiver") {
        // Optional: deterministic mapping to sender so we can respond immediately without discovery races.
        if (!target_id.empty() && !target_netid.empty()) {
            sm.addPeer(target_id, target_netid);
        }
        // Run until deadline.
        while (Clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        sm.stop();
        write_text(out_json,
                   std::string("{\"role\":\"receiver\",\"self_id\":\"") + self_id +
                       "\",\"self_port\":" + std::to_string(self_port) +
                       ",\"msg_count\":" + std::to_string(msg_count.load()) +
                       ",\"last_msg_size\":" + std::to_string(last_msg_size.load()) + "}\n");
        return 0;
    }

    // sender
    sm.addPeer(target_id, target_netid);
    sm.connectToPeer(target_id);

    // Wait for connection
    while (Clock::now() < deadline) {
        if (sm.isPeerConnected(target_id)) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (!sm.isPeerConnected(target_id)) {
        sm.stop();
        write_text(out_json,
                   std::string("{\"role\":\"sender\",\"result\":\"connect_timeout\",\"self_id\":\"") + self_id +
                       "\",\"target_id\":\"" + target_id + "\"}\n");
        return 1;
    }

    // Warmup: ensure we can complete a request/ack loop (also ensures Noise session is READY).
    {
        const int warm_sz = 64;
        const std::string warm_body(static_cast<size_t>(warm_sz), 'W');
        const std::string warm_msg = std::string("MSG_SIZE:") + std::to_string(warm_sz) + "|" + warm_body;
        bool ok = false;
        for (int attempt = 0; attempt < 20 && Clock::now() < deadline; ++attempt) {
            last_ack.store(-1, std::memory_order_release);
            sm.sendMessageToPeer(target_id, warm_msg);
            const auto ack_deadline = Clock::now() + std::chrono::seconds(3);
            while (Clock::now() < ack_deadline) {
                if (last_ack.load(std::memory_order_acquire) == warm_sz) {
                    ok = true;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            if (ok) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
        if (!ok) {
            sm.stop();
            write_text(out_json,
                       std::string("{\"role\":\"sender\",\"result\":\"warmup_failed\",\"self_id\":\"") + self_id +
                           "\",\"target_id\":\"" + target_id + "\"}\n");
            return 1;
        }
    }

    const auto sizes = parse_sizes_csv(sizes_csv);
    int max_ok = -1;
    int failures = 0;

    for (int n : sizes) {
        if (n <= 0) continue;
        // Build a payload of exact size n bytes for the "body" portion; header excluded.
        std::string body(static_cast<size_t>(n), 'A');
        const std::string msg = std::string("MSG_SIZE:") + std::to_string(n) + "|" + body;

        last_ack.store(-1, std::memory_order_release);
        sm.sendMessageToPeer(target_id, msg);

        // Wait for ACK:<n>
        const auto ack_deadline = Clock::now() + std::chrono::seconds(15);
        while (Clock::now() < ack_deadline) {
            if (last_ack.load(std::memory_order_acquire) == n) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        if (last_ack.load(std::memory_order_acquire) == n) {
            max_ok = n;
        } else {
            failures++;
        }
    }

    sm.stop();

    write_text(out_json,
               std::string("{\"role\":\"sender\",\"result\":\"done\",\"self_id\":\"") + self_id +
                   "\",\"self_port\":" + std::to_string(self_port) +
                   ",\"target_id\":\"" + target_id +
                   "\",\"target_netid\":\"" + target_netid +
                   "\",\"max_ok\":" + std::to_string(max_ok) +
                   ",\"failures\":" + std::to_string(failures) + "}\n");

    return failures == 0 ? 0 : 1;
}


