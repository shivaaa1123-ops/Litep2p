#include "session_manager.h"
#include "peer.h"
#include "config_manager.h"
#include "peer_reconnect_policy.h"
#include <iostream>
#include <filesystem>
#include <thread>
#include <chrono>
#include <cassert>
#include <cstring>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAIL: " << msg << " [" << __FILE__ << ":" << __LINE__ << "]" << std::endl; \
            tests_failed++; \
            return false; \
        } \
    } while (0)

// Mock callback for peer updates
void mock_peer_callback(const std::vector<Peer>& peers) {
    // Do nothing
}

static std::string find_repo_config_json_path() {
    namespace fs = std::filesystem;
    fs::path p = fs::current_path();
    // Walk upwards a few levels to find the repo root config.json.
    for (int i = 0; i < 8; ++i) {
        fs::path cand = p / "config.json";
        if (fs::exists(cand)) {
            return cand.string();
        }
        if (!p.has_parent_path()) break;
        p = p.parent_path();
    }
    // Fallback to whatever the current working directory provides.
    return "config.json";
}

static void configure_unit_test_runtime() {
    // IMPORTANT: PeerReconnectPolicy is a process-wide singleton. Reset it between tests so per-peer
    // backoff/jitter from earlier tests cannot suppress connection attempts in later tests.
    PeerReconnectPolicy::getInstance().shutdown();

    // Use the repo config as a baseline, but disable network-dependent subsystems.
    // This keeps unit tests stable on machines without external network access.
    const std::string config_path = find_repo_config_json_path();
    (void)ConfigManager::getInstance().loadConfig(config_path);

    // Reduce log noise so test output stays readable and doesn't overwhelm CI/terminals.
    (void)ConfigManager::getInstance().setValueAtPath({"logging", "level"}, "error");
    (void)ConfigManager::getInstance().setValueAtPath({"logging", "console_output"}, false);

    (void)ConfigManager::getInstance().setValueAtPath({"signaling", "enabled"}, false);
    (void)ConfigManager::getInstance().setValueAtPath({"nat_traversal", "enabled"}, false);
    (void)ConfigManager::getInstance().setValueAtPath({"nat_traversal", "stun_enabled"}, false);
    (void)ConfigManager::getInstance().setValueAtPath({"nat_traversal", "hole_punching_enabled"}, false);
    (void)ConfigManager::getInstance().setValueAtPath({"nat_traversal", "peer_discovery", "enabled"}, false);
    // Prevent DB-first reconnect from pulling real peers off disk during unit tests.
    (void)ConfigManager::getInstance().setValueAtPath({"storage", "peer_db", "enabled"}, false);

    // Speed up liveness-related tests.
    (void)ConfigManager::getInstance().setValueAtPath({"peer_management", "heartbeat_interval_sec"}, 1);
    // Set a large expiration so that heartbeat-bounded liveness is what flips connected->false.
    (void)ConfigManager::getInstance().setValueAtPath({"peer_management", "peer_expiration_timeout_ms"}, 60000);
 }

static int get_free_local_port(int socket_type) {
    int fd = ::socket(AF_INET, socket_type, 0);
    if (fd < 0) {
        return 0;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return 0;
    }

    socklen_t len = sizeof(addr);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        ::close(fd);
        return 0;
    }

    int port = ntohs(addr.sin_port);
    ::close(fd);
    return port;
}

static int get_free_tcp_port() {
    return get_free_local_port(SOCK_STREAM);
}

static int get_free_udp_port() {
    return get_free_local_port(SOCK_DGRAM);
}

bool test_session_start_stop() {
    std::cout << "Testing SessionManager Start/Stop..." << std::endl;

    configure_unit_test_runtime();
    
    auto session_manager = std::make_unique<SessionManager>();
    
    // Start session
    // Use TCP to avoid STUN/NAT traversal background work.
    const int port = get_free_tcp_port();
    TEST_ASSERT(port != 0, "Failed to allocate free TCP port");
    session_manager->start(port, mock_peer_callback, "TCP", "test-peer-id");
    
    // Allow some time for threads to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Stop session
    session_manager->stop();
    
    std::cout << "SessionManager Start/Stop Passed!" << std::endl;
    return true;
}

bool test_peer_connection_state() {
    std::cout << "Testing Peer Connection State..." << std::endl;

    configure_unit_test_runtime();
    
    auto session_manager = std::make_unique<SessionManager>();
    const int port = get_free_tcp_port();
    TEST_ASSERT(port != 0, "Failed to allocate free TCP port");
    session_manager->start(port, mock_peer_callback, "TCP", "test-peer-id");
    
    std::string peer_id = "remote-peer-1";
    std::string network_id = "127.0.0.1:5555";
    
    // Add a peer manually
    session_manager->addPeer(peer_id, network_id);
    
    // Initially should not be connected
    TEST_ASSERT(!session_manager->isPeerConnected(peer_id), "Peer should not be connected initially");
    
    // Simulate connection (this is tricky without a full mock, but we can check if addPeer worked)
    // In a real unit test, we would mock the transport layer to simulate a handshake.
    // For now, we verify that the peer was added to the internal structures (by checking isPeerConnected doesn't crash)
    
    session_manager->stop();
    
    std::cout << "Peer Connection State Passed!" << std::endl;
    return true;
}

bool test_stop_async_then_immediate_restart() {
    std::cout << "Testing stopAsync + immediate restart (race hardening)..." << std::endl;

    configure_unit_test_runtime();

    auto session_manager = std::make_unique<SessionManager>();

    // Use TCP to avoid NAT/STUN background work affecting stop latency in this unit-style test.
    const int port = get_free_tcp_port();
    TEST_ASSERT(port != 0, "Failed to allocate free TCP port");
    session_manager->start(port, mock_peer_callback, "TCP", "test-peer-id");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Regression: PeerReconnectPolicy is process-wide and can retain stale per-peer state
    // across engine stop/start in the same process. Ensure stop() clears it.
    {
        PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
        policy.track_peer("policy-peer-1");
        policy.on_connection_success("policy-peer-1", "TCP", 5);
        TEST_ASSERT(!policy.get_tracked_peers().empty(), "Expected policy to have at least one tracked peer before stop");
    }

    auto stop_fut = session_manager->stopAsync();

    // Attempt to restart immediately; this used to be a common crash vector
    // when start raced with teardown.
    std::atomic_bool restarted{false};
    std::thread restart_thread([&]() {
        session_manager->start(port, mock_peer_callback, "TCP", "test-peer-id");
        restarted.store(true);
    });

    auto status = stop_fut.wait_for(std::chrono::seconds(5));
    TEST_ASSERT(status == std::future_status::ready, "stopAsync did not complete within 5 seconds");

    restart_thread.join();
    TEST_ASSERT(restarted.load(), "Restart thread did not complete");

    // Clean up the restarted instance.
    session_manager->stop();

    TEST_ASSERT(PeerReconnectPolicy::getInstance().get_tracked_peers().empty(),
                "PeerReconnectPolicy should be cleared on SessionManager stop");

    std::cout << "stopAsync + immediate restart Passed!" << std::endl;
    return true;
}

bool test_udp_peer_times_out_without_disconnect() {
    std::cout << "Testing UDP liveness timeout (no disconnect callback)..." << std::endl;

    configure_unit_test_runtime();

    auto a = std::make_unique<SessionManager>();
    auto b = std::make_unique<SessionManager>();

    int port_a = get_free_udp_port();
    int port_b = get_free_udp_port();
    if (port_a == port_b) {
        port_b = get_free_udp_port();
    }
    TEST_ASSERT(port_a != 0 && port_b != 0 && port_a != port_b, "Failed to allocate free UDP ports");
    const std::string peer_a = "peer-A";
    const std::string peer_b = "peer-B";

    a->start(port_a, mock_peer_callback, "UDP", peer_a);
    b->start(port_b, mock_peer_callback, "UDP", peer_b);

    a->addPeer(peer_b, "127.0.0.1:" + std::to_string(port_b));
    b->addPeer(peer_a, "127.0.0.1:" + std::to_string(port_a));

    a->connectToPeer(peer_b);
    b->connectToPeer(peer_a);

    // Wait for initial connection.
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            if (a->isPeerConnected(peer_b) && b->isPeerConnected(peer_a)) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    TEST_ASSERT(a->isPeerConnected(peer_b), "UDP peers should connect initially (A sees B connected)");

    // Simulate abrupt remote kill: stop B. UDP has no reliable disconnect callback to A.
    b->stop();

    // With heartbeat_interval_sec=1 and heartbeat-bounded liveness (>=5s),
    // A should mark B disconnected within ~6-8 seconds.
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(9);
        while (std::chrono::steady_clock::now() < deadline) {
            if (!a->isPeerConnected(peer_b)) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    TEST_ASSERT(!a->isPeerConnected(peer_b), "A should mark B disconnected after missing heartbeats (UDP)");

    a->stop();

    std::cout << "UDP liveness timeout Passed!" << std::endl;
    return true;
}

bool test_udp_endpoint_upgrade_while_connecting_prefers_local() {
    std::cout << "Testing UDP endpoint upgrade while CONNECTING (prefer local/private over public)..." << std::endl;

    configure_unit_test_runtime();

    auto a = std::make_unique<SessionManager>();
    auto b = std::make_unique<SessionManager>();

    int port_a = get_free_udp_port();
    int port_b = get_free_udp_port();
    if (port_a == port_b) {
        port_b = get_free_udp_port();
    }
    TEST_ASSERT(port_a != 0 && port_b != 0 && port_a != port_b, "Failed to allocate free UDP ports");
    const std::string peer_a = "peer-A";
    const std::string peer_b = "peer-B";

    a->start(port_a, mock_peer_callback, "UDP", peer_a);
    b->start(port_b, mock_peer_callback, "UDP", peer_b);

    // Ensure both sides know each other's IDs so UDP handshake paths can complete.
    b->addPeer(peer_a, "127.0.0.1:" + std::to_string(port_a));

    // Simulate a stale signaling/STUN endpoint for B (public IP that will not be reachable in this unit test).
    // This mirrors the real-world case where clients try a public endpoint even though both peers are on LAN.
    a->addPeer(peer_b, "203.0.113.1:" + std::to_string(port_b));

    // Initiate connect; this will enter CONNECTING and send CONTROL_CONNECT to the stale endpoint.
    a->connectToPeer(peer_b);

    // Give it a brief moment; it should NOT connect via the stale public endpoint.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    bool ok = true;
    auto fail = [&](const std::string& msg) {
        std::cerr << "FAIL: " << msg << " [" << __FILE__ << ":" << __LINE__ << "]" << std::endl;
        tests_failed++;
        ok = false;
    };

    if (a->isPeerConnected(peer_b)) {
        fail("A should not connect via stale public endpoint");
        goto cleanup;
    }

    // Now simulate LAN discovery updating the endpoint to the correct local IP/port.
    // This should trigger an immediate connect attempt to the new endpoint and succeed.
    a->addPeer(peer_b, "127.0.0.1:" + std::to_string(port_b));

    // Wait for the connection to complete.
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            if (a->isPeerConnected(peer_b)) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    if (!a->isPeerConnected(peer_b)) {
        fail("A should connect after endpoint upgrade to local address");
        goto cleanup;
    }

cleanup:
    // Always stop both sides to avoid hangs when assertions fail.
    b->stop();
    a->stop();

    if (ok) {
        std::cout << "UDP endpoint upgrade while CONNECTING Passed!" << std::endl;
    }
    return ok;
}

int main() {
    std::cout << "Running SessionManager Tests..." << std::endl;
    
    test_session_start_stop();
    test_peer_connection_state();
    test_stop_async_then_immediate_restart();
    test_udp_peer_times_out_without_disconnect();
    test_udp_endpoint_upgrade_while_connecting_prefers_local();
    
    if (tests_failed == 0) {
        std::cout << "ALL SESSION MANAGER TESTS PASSED" << std::endl;
        return 0;
    } else {
        std::cerr << tests_failed << " TESTS FAILED" << std::endl;
        return 1;
    }
}
