// network_runtime_kill_probe.cpp — Network OS Phase 1 SIGKILL restore probe.
//
// Starts a NetworkRuntime over a persistent files_dir, prints its resolved
// PeerID, then sleeps until killed (SIGKILL by the harness). The harness runs
// this 20x, killing at random points during start, and asserts the printed
// PeerID is identical every run — proving identity survives process death
// (atomic tmp+rename identity write, master doc §12).
//
// Usage: network_runtime_kill_probe --files-dir <dir> [--peer-id <id>]

#include "networkos/Runtime.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

namespace {

void usage() {
    std::cerr << "usage: network_runtime_kill_probe --files-dir <dir> [--peer-id <id>]\n";
    std::exit(2);
}

} // namespace

int main(int argc, char** argv) {
    std::string files_dir;
    std::string peer_id;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--files-dir") == 0 && i + 1 < argc) {
            files_dir = argv[++i];
        } else if (std::strcmp(argv[i], "--peer-id") == 0 && i + 1 < argc) {
            peer_id = argv[++i];
        } else {
            usage();
        }
    }
    if (files_dir.empty()) usage();

    auto rt = networkos::createRuntime();
    networkos::RuntimeConfig cfg;
    cfg.files_dir = files_dir;
    cfg.peer_id = peer_id;
    cfg.listen_port = 30001;
    cfg.enable_discovery = false;
    cfg.comms_mode = "UDP";

    const auto rc = rt->start(cfg);
    if (rc != networkos::Result::kOk) {
        std::cerr << "PROBE: start failed\n";
        return 1;
    }
    // Deterministic, greppable output for the harness.
    std::cout << "PEERID=" << rt->peerId() << std::endl;
    std::cout << "READY" << std::endl;

    // Sleep forever; the harness SIGKILLs us (possibly mid-start next time).
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
    return 0;
}
