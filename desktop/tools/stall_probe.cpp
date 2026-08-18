// stall_probe — live diagnostic for the AnomalyReporter stall detector.
//
// Starts a session manager, then connects to a blackhole TEST-NET endpoint
// (203.0.113.9) with a long UDP timeout so the peer FSM stays in CONNECTING
// past anomaly_reporter.stall_threshold_ms. The maintenance loop's
// detectStalledPeers() must then write a `stall_not_recovered` incident file
// (and upload it when configured).
//
//   cmake --build desktop/build_fixcheck --target stall_probe
//   ./desktop/build_fixcheck/bin/stall_probe <config.json>
//
// Config knobs honoured: anomaly_reporter.stall_threshold_ms (default 60000),
// communication.udp.timeout_ms (default 5000 — must exceed the threshold),
// anomaly_reporter.upload_enabled/upload_url for upload verification.

#include "session_manager.h"
#include "peer.h"
#include "config_manager.h"
#include "anomaly_reporter.h"

#include <chrono>
#include <iostream>
#include <string>
#include <thread>

namespace {
void peer_cb(const std::vector<Peer>&) {}
} // namespace

int main(int argc, char* argv[]) {
    const std::string config_path = (argc > 1) ? argv[1] : "config.json";
    if (!ConfigManager::getInstance().loadConfig(config_path)) {
        std::cerr << "Failed to load " << config_path << std::endl;
        return 1;
    }

    // Ensure the FSM stays CONNECTING long enough to trip the stall detector.
    ConfigManager::getInstance().setValueAtPath({"communication", "udp", "timeout_ms"}, 120000);
    ConfigManager::getInstance().setValueAtPath({"anomaly_reporter", "stall_threshold_ms"}, 20000);
    AnomalyReporter::getInstance().setDeviceInfo(
        "{\"brand\":\"desktop\",\"model\":\"stall-probe\",\"os\":\"macOS\",\"abi\":\"x86_64\"}");

    SessionManager sm;
    sm.start(34501, peer_cb, "UDP", "stall-probe-peer");
    sm.addPeer("blackhole-peer", "203.0.113.9:30001");
    sm.connectToPeer("blackhole-peer");

    std::cout << "Connected to blackhole endpoint; waiting 40s for the stall detector..."
              << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(40));

    std::cout << "Incident directory: " << AnomalyReporter::getInstance().directory() << std::endl;
    std::cout << "Pending incident files: "
              << AnomalyReporter::getInstance().pendingFileCount() << std::endl;
    sm.stop();
    return 0;
}
