// crash_probe — live diagnostic for the native CrashHandler.
//
// Default mode: configures the AnomalyReporter (which installs the crash
// handler + refreshes the shared context buffer), then deliberately faults
// (nullptr deref) so the signal handler writes a `crash_*.json` report and the
// process dies with signal semantics. Run it and check the anomalies dir.
//
//   --collect mode: starts a session manager briefly so the maintenance tick
//   uploads any pending crash_*/anomaly_* files to the configured collector
//   (the next-run upload pattern).
//
//   ./desktop/build_fixcheck/bin/crash_probe <config.json>            # crash
//   ./desktop/build_fixcheck/bin/crash_probe <config.json> --collect  # upload

#include "session_manager.h"
#include "peer.h"
#include "config_manager.h"
#include "anomaly_reporter.h"

#include <chrono>
#include <cstring>
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
    AnomalyReporter::getInstance().setDeviceInfo(
        "{\"brand\":\"desktop\",\"model\":\"crash-probe\",\"os\":\"macOS\",\"abi\":\"x86_64\"}");

    const bool collect_mode = (argc > 2 && std::string(argv[2]) == "--collect");

    if (collect_mode) {
        // Boot a short-lived engine so the maintenance tick flushes/upload
        // any pending crash/anomaly files left by previous runs.
        SessionManager sm;
        sm.start(34511, peer_cb, "UDP", "crash-collector");
        std::cout << "Collect mode: waiting 12s for upload of pending reports..."
                  << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(12));
        std::cout << "Pending reports now: "
                  << AnomalyReporter::getInstance().pendingFileCount() << std::endl;
        sm.stop();
        return 0;
    }

    // Default: crash. Configure the reporter (installs the crash handler and
    // refreshes the shared context), then fault.
    AnomalyReporter::Config acfg;
    acfg.enabled = true;
    acfg.base_dir = "/tmp/ar_test";
    acfg.subdir = "anomalies";
    acfg.max_files = 100;
    acfg.engine_version = "0.4.0";
    acfg.peer_id = "crash-probe";
    acfg.include_telemetry = true;
    AnomalyReporter::getInstance().configure(acfg);

    if (argc > 2 && std::string(argv[2]) == "--abort") {
        std::cerr << "crash_probe: raising SIGABRT (expect abort + crash report)" << std::endl;
        ::abort();  // SIGABRT
    }

    std::cerr << "crash_probe: deliberately dereferencing nullptr (expect SIGSEGV + crash report)"
              << std::endl;
    volatile int* p = nullptr;
    return *p;  // SIGSEGV
}
