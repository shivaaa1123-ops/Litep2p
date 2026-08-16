#include "session_manager.h"
#include "peer.h"
#include "config_manager.h"
#include "peer_reconnect_policy.h"
#include "telemetry.h"
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

static int64_t get_telemetry_counter_value(const std::string& telemetry_json, const std::string& counter_name) {
    // Very small/robust parser for the Telemetry JSON line.
    // We only need to extract a single counter value from: "counters":{"name":123,...}
    const std::string needle = "\"" + counter_name + "\":";
    const auto pos = telemetry_json.find(needle);
    if (pos == std::string::npos) return 0;
    size_t i = pos + needle.size();
    while (i < telemetry_json.size() && telemetry_json[i] == ' ') i++;

    bool neg = false;
    if (i < telemetry_json.size() && telemetry_json[i] == '-') {
        neg = true;
        i++;
    }

    int64_t v = 0;
    bool any = false;
    while (i < telemetry_json.size()) {
        const char c = telemetry_json[i];
        if (c < '0' || c > '9') break;
        any = true;
        v = (v * 10) + (c - '0');
        i++;
    }
    if (!any) return 0;
    return neg ? -v : v;
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

bool test_udp_duplicate_network_id_does_not_steal_connection() {
    std::cout << "Testing UDP duplicate network_id collision handling (no connection steal)..." << std::endl;

    configure_unit_test_runtime();

    auto a = std::make_unique<SessionManager>();
    auto b = std::make_unique<SessionManager>();
    auto c = std::make_unique<SessionManager>();

    int port_a = get_free_udp_port();
    int port_b = get_free_udp_port();
    int port_c = get_free_udp_port();
    // Ensure distinct ports.
    while (port_b == port_a) port_b = get_free_udp_port();
    while (port_c == port_a || port_c == port_b) port_c = get_free_udp_port();
    TEST_ASSERT(port_a != 0 && port_b != 0 && port_c != 0, "Failed to allocate free UDP ports");

    const std::string peer_a = "peer-A";
    const std::string peer_b = "peer-B";
    const std::string peer_c = "peer-C";

    a->start(port_a, mock_peer_callback, "UDP", peer_a);
    b->start(port_b, mock_peer_callback, "UDP", peer_b);
    c->start(port_c, mock_peer_callback, "UDP", peer_c);

    // Wire up A<->B so the UDP handshake can complete.
    a->addPeer(peer_b, "127.0.0.1:" + std::to_string(port_b));
    b->addPeer(peer_a, "127.0.0.1:" + std::to_string(port_a));

    // Introduce a duplicate advertised endpoint: C claims B's network_id.
    // Historically this could overwrite the network_id->peer_id index and cause A to
    // misattribute inbound packets from B to C, breaking B's connection.
    a->addPeer(peer_c, "127.0.0.1:" + std::to_string(port_b));

    std::mutex mu;
    std::condition_variable cv;
    std::string last_from;
    std::string last_msg;
    int msg_count = 0;
    a->setMessageReceivedCallback([&](const std::string& from_peer, const std::string& msg) {
        std::lock_guard<std::mutex> lk(mu);
        last_from = from_peer;
        last_msg = msg;
        msg_count++;
        cv.notify_all();
    });

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

    bool ok = true;
    auto fail = [&](const std::string& msg) {
        std::cerr << "FAIL: " << msg << " [" << __FILE__ << ":" << __LINE__ << "]" << std::endl;
        tests_failed++;
        ok = false;
    };

    if (!a->isPeerConnected(peer_b)) {
        fail("A should connect to B even when another peer advertises B's network_id");
        goto cleanup;
    }
    if (!b->isPeerConnected(peer_a)) {
        fail("B should see A connected");
        goto cleanup;
    }
    if (a->isPeerConnected(peer_c)) {
        fail("A should not mark C connected just because it collides on network_id");
        goto cleanup;
    }

    // Send a message from B to A and ensure A attributes it to B (not C).
    b->sendMessageToPeer(peer_a, "hello-from-b");
    {
        std::unique_lock<std::mutex> lk(mu);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (msg_count == 0 && std::chrono::steady_clock::now() < deadline) {
            cv.wait_for(lk, std::chrono::milliseconds(100));
        }
    }

    {
        std::lock_guard<std::mutex> lk(mu);
        if (msg_count == 0) {
            fail("A did not receive message from B");
            goto cleanup;
        }
        if (last_from != peer_b) {
            fail("A should attribute inbound message to B (got from=" + last_from + ")");
            goto cleanup;
        }
        if (last_msg != "hello-from-b") {
            fail("A received unexpected message payload");
            goto cleanup;
        }
    }

cleanup:
    c->stop();
    b->stop();
    a->stop();

    if (ok) {
        std::cout << "UDP duplicate network_id collision handling Passed!" << std::endl;
    }
    return ok;
}

bool test_connect_to_colliding_peer_does_not_disrupt_existing_connection() {
    std::cout << "Testing connectToPeer to colliding endpoint does not disrupt existing connection..." << std::endl;

    configure_unit_test_runtime();

    auto a = std::make_unique<SessionManager>();
    auto b = std::make_unique<SessionManager>();
    auto c = std::make_unique<SessionManager>();

    int port_a = get_free_udp_port();
    int port_b = get_free_udp_port();
    int port_c = get_free_udp_port();
    while (port_b == port_a) port_b = get_free_udp_port();
    while (port_c == port_a || port_c == port_b) port_c = get_free_udp_port();
    TEST_ASSERT(port_a != 0 && port_b != 0 && port_c != 0, "Failed to allocate free UDP ports");

    const std::string peer_a = "peer-A";
    const std::string peer_b = "peer-B";
    const std::string peer_c = "peer-C";

    a->start(port_a, mock_peer_callback, "UDP", peer_a);
    b->start(port_b, mock_peer_callback, "UDP", peer_b);
    c->start(port_c, mock_peer_callback, "UDP", peer_c);

    // Establish a stable A<->B session.
    a->addPeer(peer_b, "127.0.0.1:" + std::to_string(port_b));
    b->addPeer(peer_a, "127.0.0.1:" + std::to_string(port_a));

    // Introduce a colliding endpoint: C advertises B's endpoint to A.
    a->addPeer(peer_c, "127.0.0.1:" + std::to_string(port_b));

    std::mutex mu;
    std::condition_variable cv;
    std::string last_from;
    std::string last_msg;
    int msg_count = 0;
    a->setMessageReceivedCallback([&](const std::string& from_peer, const std::string& msg) {
        std::lock_guard<std::mutex> lk(mu);
        last_from = from_peer;
        last_msg = msg;
        msg_count++;
        cv.notify_all();
    });

    a->connectToPeer(peer_b);
    b->connectToPeer(peer_a);

    // Wait for A<->B connection.
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            if (a->isPeerConnected(peer_b) && b->isPeerConnected(peer_a)) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    bool ok = true;
    auto fail = [&](const std::string& msg) {
        std::cerr << "FAIL: " << msg << " [" << __FILE__ << ":" << __LINE__ << "]" << std::endl;
        tests_failed++;
        ok = false;
    };

    if (!a->isPeerConnected(peer_b) || !b->isPeerConnected(peer_a)) {
        fail("Expected A and B to be connected before colliding connect attempt");
        goto cleanup;
    }

    // Attempt to connect to the colliding peer; this should not send traffic that disrupts A<->B.
    for (int i = 0; i < 5; ++i) {
        a->connectToPeer(peer_c);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (!a->isPeerConnected(peer_b)) {
        fail("A should remain connected to B after connectToPeer(C) where C collides on endpoint");
        goto cleanup;
    }

    if (a->isPeerConnected(peer_c)) {
        fail("A should not mark C connected when C only advertises a colliding endpoint");
        goto cleanup;
    }

    // Verify inbound attribution is still correct.
    b->sendMessageToPeer(peer_a, "hello-after-colliding-connect");
    {
        std::unique_lock<std::mutex> lk(mu);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (msg_count == 0 && std::chrono::steady_clock::now() < deadline) {
            cv.wait_for(lk, std::chrono::milliseconds(100));
        }
    }

    {
        std::lock_guard<std::mutex> lk(mu);
        if (msg_count == 0) {
            fail("A did not receive message from B after colliding connect attempt");
            goto cleanup;
        }
        if (last_from != peer_b) {
            fail("A should attribute inbound message to B (got from=" + last_from + ")");
            goto cleanup;
        }
        if (last_msg != "hello-after-colliding-connect") {
            fail("A received unexpected message payload");
            goto cleanup;
        }
    }

cleanup:
    c->stop();
    b->stop();
    a->stop();

    if (ok) {
        std::cout << "connectToPeer colliding endpoint regression Passed!" << std::endl;
    }
    return ok;
}

bool test_connect_to_peer_while_connected_does_not_increment_suppressed() {
    std::cout << "Testing connectToPeer idempotency (no reconnect-policy suppression while CONNECTED)..." << std::endl;

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

    bool ok = true;
    auto fail = [&](const std::string& msg) {
        std::cerr << "FAIL: " << msg << " [" << __FILE__ << ":" << __LINE__ << "]" << std::endl;
        tests_failed++;
        ok = false;
    };

    if (!a->isPeerConnected(peer_b)) {
        fail("A should be connected to B before idempotent connectToPeer calls");
    }

    int64_t before = 0;
    int64_t after = 0;

    if (ok) {
        before = get_telemetry_counter_value(Telemetry::getInstance().snapshot_json("unit-test"),
                                             "connect_suppressed_total");

        // Repeated connect requests should be handled as idempotent (skip) and must not be counted as
        // reconnect-policy suppressions.
        for (int i = 0; i < 5; ++i) {
            a->connectToPeer(peer_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }

        // Give event loop time to process.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        after = get_telemetry_counter_value(Telemetry::getInstance().snapshot_json("unit-test"),
                                            "connect_suppressed_total");

        if (after != before) {
            fail("connect_suppressed_total should not increase for idempotent connectToPeer while connected (before=" +
                 std::to_string(before) + ", after=" + std::to_string(after) + ")");
        }
    }

    b->stop();
    a->stop();

    if (ok) {
        std::cout << "connectToPeer idempotency Passed!" << std::endl;
    }
    return ok;
}

bool test_connect_request_bypasses_reconnect_policy_suppression() {
    std::cout << "Testing CONNECT_REQUEST bypasses reconnect policy suppression..." << std::endl;

    configure_unit_test_runtime();

    auto session_manager = std::make_unique<SessionManager>();
    const int port = get_free_tcp_port();
    TEST_ASSERT(port != 0, "Failed to allocate free TCP port");
    session_manager->start(port, mock_peer_callback, "TCP", "test-peer-id");

    const std::string peer_id = "remote-peer-suppressed";
    const std::string network_id = "127.0.0.1:65001"; // intentionally unused
    session_manager->addPeer(peer_id, network_id);

    PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
    policy.set_reconnect_mode_string("balanced");
    policy.set_network_type(true, true);
    policy.track_peer(peer_id);

    // Push the peer into circuit-breaker/backoff state.
    for (int i = 0; i < 7; ++i) {
        policy.on_connection_failure(peer_id, "TCP");
    }

    auto strat = policy.get_retry_strategy(peer_id);
    TEST_ASSERT(!strat.should_retry, "Expected reconnect policy to suppress retries (should_retry=false)");

    const int64_t before = get_telemetry_counter_value(
        Telemetry::getInstance().snapshot_json("unit-test"),
        "connect_suppressed_total");

    // Normal connectToPeer should be suppressed.
    session_manager->connectToPeer(peer_id);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const int64_t after_normal = get_telemetry_counter_value(
        Telemetry::getInstance().snapshot_json("unit-test"),
        "connect_suppressed_total");
    TEST_ASSERT(after_normal == before + 1,
                "Expected connect_suppressed_total to increment for normal connectToPeer under suppression");

    // Bypass connect should not be counted as a policy suppression.
    session_manager->connectToPeer(peer_id, true);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const int64_t after_bypass = get_telemetry_counter_value(
        Telemetry::getInstance().snapshot_json("unit-test"),
        "connect_suppressed_total");
    TEST_ASSERT(after_bypass == after_normal,
                "connect_suppressed_total should not increase for bypass connectToPeer");

    session_manager->stop();
    std::cout << "CONNECT_REQUEST bypass suppression Passed!" << std::endl;
    return true;
}

bool test_network_change_resets_reconnect_policy_backoff() {
    std::cout << "Testing network change resets reconnect policy backoff..." << std::endl;

    configure_unit_test_runtime();

    auto session_manager = std::make_unique<SessionManager>();
    const int port = get_free_tcp_port();
    TEST_ASSERT(port != 0, "Failed to allocate free TCP port");
    session_manager->start(port, mock_peer_callback, "TCP", "test-peer-id");

    // Establish an initial network state inside SessionManager so the subsequent call
    // is treated as a true transition.
    session_manager->set_network_info(true, true);

    const std::string peer_id = "remote-peer-backoff";
    session_manager->addPeer(peer_id, "127.0.0.1:65002");

    PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
    policy.set_reconnect_mode_string("balanced");
    policy.set_network_type(true, true);
    policy.track_peer(peer_id);

    for (int i = 0; i < 7; ++i) {
        policy.on_connection_failure(peer_id, "TCP");
    }

    auto st_before = policy.get_peer_stats(peer_id);
    TEST_ASSERT(st_before.consecutive_failures >= 7, "Expected failures >= 7 before reset");
    TEST_ASSERT(st_before.circuit_breaker_until_ms != 0, "Expected circuit breaker to be open before reset");

    // Trigger a network type change: WiFi -> Mobile (availability stays true).
    session_manager->set_network_info(false, true);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto st_after = policy.get_peer_stats(peer_id);
    TEST_ASSERT(st_after.consecutive_failures == 0, "Expected failures reset to 0 after network change");
    TEST_ASSERT(st_after.circuit_breaker_until_ms == 0, "Expected circuit breaker closed after network change");
    TEST_ASSERT(st_after.next_retry_time_ms == 0, "Expected next_retry_time_ms cleared after network change");

    session_manager->stop();
    std::cout << "Network change resets reconnect policy Passed!" << std::endl;
    return true;
}

bool test_maintenance_retries_disconnected_peer_even_when_another_connected() {
    std::cout << "Testing maintenance retry scan (retries non-connected peer while another is connected)..." << std::endl;

    configure_unit_test_runtime();

    auto a = std::make_unique<SessionManager>();
    auto b = std::make_unique<SessionManager>();

    int port_a = get_free_tcp_port();
    int port_b = get_free_tcp_port();
    while (port_b == port_a) port_b = get_free_tcp_port();
    TEST_ASSERT(port_a != 0 && port_b != 0 && port_a != port_b, "Failed to allocate free TCP ports");

    const std::string peer_a = "peer-A";
    const std::string peer_b = "peer-B";

    a->start(port_a, mock_peer_callback, "TCP", peer_a);
    b->start(port_b, mock_peer_callback, "TCP", peer_b);

    // Ensure policy sees a stable network state.
    a->set_network_info(true, true);
    b->set_network_info(true, true);

    // Make retries responsive in this unit test.
    PeerReconnectPolicy::getInstance().set_reconnect_mode_string("aggressive");

    // Establish a stable A<->B connection.
    a->addPeer(peer_b, "127.0.0.1:" + std::to_string(port_b));
    b->addPeer(peer_a, "127.0.0.1:" + std::to_string(port_a));
    a->connectToPeer(peer_b);
    b->connectToPeer(peer_a);

    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            if (a->isPeerConnected(peer_b) && b->isPeerConnected(peer_a)) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    TEST_ASSERT(a->isPeerConnected(peer_b), "Expected A to be connected to B before retry scan assertion");

    // Add an unreachable peer to A.
    int port_c = get_free_tcp_port();
    while (port_c == port_a || port_c == port_b) port_c = get_free_tcp_port();
    TEST_ASSERT(port_c != 0, "Failed to allocate free TCP port for unreachable peer");
    const std::string peer_c = "peer-C-unreachable";
    a->addPeer(peer_c, "127.0.0.1:" + std::to_string(port_c));

    const int64_t before = get_telemetry_counter_value(
        Telemetry::getInstance().snapshot_json("unit-test"),
        "connect_requested_total");

    // Seed an initial failure so policy backoff is active.
    a->connectToPeer(peer_c);
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    const int64_t after_first = get_telemetry_counter_value(
        Telemetry::getInstance().snapshot_json("unit-test"),
        "connect_requested_total");
    TEST_ASSERT(after_first >= before + 1,
                "Expected at least one connect attempt for unreachable peer (connect_requested_total to increase)");

    // MaintenanceManager should continue to schedule retries for peer C even though peer B is connected.
    bool saw_retry = false;
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(6);
        while (std::chrono::steady_clock::now() < deadline) {
            const int64_t cur = get_telemetry_counter_value(
                Telemetry::getInstance().snapshot_json("unit-test"),
                "connect_requested_total");
            if (cur >= after_first + 1) {
                saw_retry = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    b->stop();
    a->stop();

    TEST_ASSERT(saw_retry, "Expected at least one maintenance-scheduled retry for unreachable peer while another peer is connected");

    std::cout << "Maintenance retry scan Passed!" << std::endl;
    return true;
}

bool test_user_disconnect_suppresses_auto_reconnect() {
    std::cout << "Testing user disconnect suppresses auto-reconnect (network change + maintenance)..." << std::endl;

    configure_unit_test_runtime();

    auto session_manager = std::make_unique<SessionManager>();
    const int port = get_free_tcp_port();
    TEST_ASSERT(port != 0, "Failed to allocate free TCP port");
    session_manager->start(port, mock_peer_callback, "TCP", "test-peer-id");

    // Establish a stable network state so the subsequent call is a true transition.
    session_manager->set_network_info(true, true);

    // Use an unreachable endpoint (closed port) so the connect attempt fails deterministically.
    int unreachable_port = get_free_tcp_port();
    while (unreachable_port == port) unreachable_port = get_free_tcp_port();
    TEST_ASSERT(unreachable_port != 0, "Failed to allocate unreachable port");

    const std::string peer_id = "peer-suppress-reconnect";
    session_manager->addPeer(peer_id, "127.0.0.1:" + std::to_string(unreachable_port));

    // Make retries responsive so the maintenance scan would normally reconnect quickly.
    PeerReconnectPolicy::getInstance().set_reconnect_mode_string("aggressive");

    // Initiate a connect (will fail since endpoint is unreachable).
    session_manager->connectToPeer(peer_id);

    // Wait for the connect attempt to be processed and the peer to leave CONNECTING state.
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            const std::string state = session_manager->getPeerFsmState(peer_id);
            if (state == "DEGRADED" || state == "FAILED" || state == "DISCONNECTED") break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    // User explicitly disconnects the peer. This should suppress auto-reconnects.
    const bool disconnect_ok = session_manager->disconnectFromPeer(peer_id);
    TEST_ASSERT(disconnect_ok, "disconnectFromPeer should return true for a known peer");

    // Wait for the disconnect to be fully processed (FSM -> DISCONNECTED).
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline) {
            if (session_manager->getPeerFsmState(peer_id) == "DISCONNECTED") break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    TEST_ASSERT(session_manager->getPeerFsmState(peer_id) == "DISCONNECTED",
                "Peer FSM should be DISCONNECTED after disconnectFromPeer");

    // Trigger a network type change (WiFi -> Mobile). This normally triggers
    // immediate reconnects for all disconnected peers via "network_change_immediate",
    // and the maintenance scan retries DISCONNECTED peers. With user-disconnect
    // suppression active, THIS peer must not be re-attempted.
    session_manager->set_network_info(false, true);

    // Wait long enough for the network-change reconnect + maintenance scan to fire.
    // The maintenance scan interval in aggressive mode is 250ms; timer tick is 500ms.
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    // Assert on the PER-PEER FSM state rather than the process-global
    // connect_requested_total counter: LAN broadcast discovery may observe real
    // peers on the host network and increment the global counter for OTHER peers.
    // If suppression were broken, a reconnect attempt would move this peer out of
    // DISCONNECTED (to CONNECTING, then DEGRADED after the unreachable endpoint fails).
    // Staying DISCONNECTED proves no reconnect was attempted for this peer.
    const std::string state_after_network_change = session_manager->getPeerFsmState(peer_id);
    TEST_ASSERT(state_after_network_change == "DISCONNECTED",
                "Peer should remain DISCONNECTED after network change (suppression active), got state=" +
                state_after_network_change);

    // Verify the peer is still not connected.
    TEST_ASSERT(!session_manager->isPeerConnected(peer_id),
                "Peer should remain disconnected after suppressed network-change reconnect");

    // Now explicitly reconnect (user_api source). This should clear the suppression
    // and drive the peer out of DISCONNECTED (to CONNECTING, then DEGRADED since the
    // endpoint is unreachable).
    session_manager->connectToPeer(peer_id);

    // Wait for the explicit connect to be processed and move the peer out of DISCONNECTED.
    bool left_disconnected = false;
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline) {
            const std::string st = session_manager->getPeerFsmState(peer_id);
            if (st != "DISCONNECTED") { left_disconnected = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    TEST_ASSERT(left_disconnected,
                "Explicit user connectToPeer should clear suppression and move the peer out of DISCONNECTED");

    session_manager->stop();
    std::cout << "User disconnect suppression Passed!" << std::endl;
    return true;
}

int main() {
    std::cout << "Running SessionManager Tests..." << std::endl;
    
    test_session_start_stop();
    test_peer_connection_state();
    test_stop_async_then_immediate_restart();
    test_udp_peer_times_out_without_disconnect();
    test_udp_endpoint_upgrade_while_connecting_prefers_local();
    test_udp_duplicate_network_id_does_not_steal_connection();
    test_connect_to_colliding_peer_does_not_disrupt_existing_connection();
    test_connect_to_peer_while_connected_does_not_increment_suppressed();
    test_connect_request_bypasses_reconnect_policy_suppression();
    test_network_change_resets_reconnect_policy_backoff();
    test_maintenance_retries_disconnected_peer_even_when_another_connected();
    test_user_disconnect_suppresses_auto_reconnect();
    
    if (tests_failed == 0) {
        std::cout << "ALL SESSION MANAGER TESTS PASSED" << std::endl;
        return 0;
    } else {
        std::cerr << tests_failed << " TESTS FAILED" << std::endl;
        return 1;
    }
}
