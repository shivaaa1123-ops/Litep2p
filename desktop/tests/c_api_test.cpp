/*
 * c_api_test.cpp — End-to-end tests for the public C ABI (litep2p.h).
 *
 * Exercises the exact contract integrators use:
 *   - Version / result-string helpers
 *   - Config init + invalid-arg handling
 *   - Lifecycle: init → start → get_state → get_peer_id → stop → shutdown
 *   - Disconnect suppression: litep2p_disconnect keeps a peer disconnected
 *     across a network change (behavioral guarantee via peer_is_connected)
 *   - File-transfer error paths (send to unconnected peer, unknown transfer id)
 *
 * The test writes a hermetic config.json to a temp directory so no external
 * network (signaling, STUN) is required. Assertions use per-peer queries
 * (litep2p_peer_is_connected) rather than process-global telemetry counters,
 * because LAN broadcast discovery may observe real peers on the host network
 * and increment global counters.
 */
#include "litep2p.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

#include <netinet/in.h>
#include <sys/socket.h>
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Allocate a free TCP port by binding to port 0 and reading the assigned port.
static int get_free_tcp_port() {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
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
    const int port = ntohs(addr.sin_port);
    ::close(fd);
    return port;
}

// Write a hermetic config.json that disables all network-dependent subsystems.
static bool write_hermetic_config(const std::filesystem::path& dir) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) return false;

    const std::string config = R"({
    "communication": { "default_protocol": "TCP" },
    "signaling": { "enabled": false },
    "nat_traversal": {
        "enabled": false,
        "stun_enabled": false,
        "upnp_enabled": false,
        "hole_punching_enabled": false,
        "peer_discovery": { "enabled": false }
    },
    "storage": { "peer_db": { "enabled": false } },
    "logging": { "level": "error", "console_output": false },
    "monitoring": { "telemetry": { "enabled": true } },
    "security": {
        "noise_nk_protocol": {
            "enabled": false,
            "key_store_path": ")" + (dir / "keystore").string() + R"("
        }
    }
})";

    std::ofstream out(dir / "config.json", std::ios::trunc);
    if (!out.is_open()) return false;
    out << config;
    out.flush();
    return static_cast<bool>(out);
}

// Wait until the engine reaches the desired state, or timeout.
static bool wait_for_state(litep2p_state_t desired, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (litep2p_get_state() == desired) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return litep2p_get_state() == desired;
}

// Fill a config for a hermetic single-engine test. Returns false if no free port.
static bool make_hermetic_config(const std::filesystem::path& workdir,
                                 const char* peer_id,
                                 litep2p_config_t& cfg,
                                 std::string& config_path_out,
                                 std::string& files_dir_out,
                                 int& port_out) {
    if (!write_hermetic_config(workdir)) return false;
    const int port = get_free_tcp_port();
    if (port == 0) return false;

    config_path_out = (workdir / "config.json").string();
    files_dir_out = workdir.string();

    litep2p_config_init(&cfg);
    cfg.peer_id = peer_id;
    cfg.comms_mode = "TCP";
    cfg.listen_port = port;
    cfg.files_dir = files_dir_out.c_str();
    cfg.config_path = config_path_out.c_str();
    cfg.enable_encryption = 0;   // disable Noise for simplicity
    cfg.enable_discovery = 0;    // no peer discovery
    cfg.enable_file_transfer = 1;
    cfg.telemetry_enabled = 1;
    port_out = port;
    return true;
}

// RAII guard: always shut down the engine when the scope exits, even on a
// failed TEST_ASSERT early-return. Prevents a leaked running engine from
// breaking subsequent tests in the same process.
struct EngineGuard {
    ~EngineGuard() {
        // Best-effort: stop + shutdown regardless of current state.
        litep2p_shutdown();
    }
};

// ---------------------------------------------------------------------------
// Test: version and result-string helpers
// ---------------------------------------------------------------------------
static bool test_version_and_result_strings() {
    std::cout << "Testing version and result-string helpers..." << std::endl;

    const uint32_t ver = litep2p_version();
    TEST_ASSERT(ver != 0, "litep2p_version should return non-zero");

    const char* ver_str = litep2p_version_string();
    TEST_ASSERT(ver_str != nullptr && ver_str[0] != '\0',
                "litep2p_version_string should return non-empty string");

    // Verify packed version matches header constants.
    const uint32_t expected = (LITEP2P_VERSION_MAJOR << 16) |
                              (LITEP2P_VERSION_MINOR << 8) |
                              LITEP2P_VERSION_PATCH;
    TEST_ASSERT(ver == expected, "litep2p_version should match header version constants");

    // Result strings should be non-null for all defined codes.
    TEST_ASSERT(litep2p_result_string(LITEP2P_OK) != nullptr, "result_string(OK) non-null");
    TEST_ASSERT(litep2p_result_string(LITEP2P_ERR_INVALID_ARG) != nullptr, "result_string(INVALID_ARG) non-null");
    TEST_ASSERT(litep2p_result_string(LITEP2P_ERR_NOT_FOUND) != nullptr, "result_string(NOT_FOUND) non-null");
    TEST_ASSERT(litep2p_result_string(LITEP2P_ERR_UNSUPPORTED) != nullptr, "result_string(UNSUPPORTED) non-null");

    std::cout << "Version/result-string helpers Passed!" << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// Test: config init and invalid-arg handling
// ---------------------------------------------------------------------------
static bool test_config_init_and_invalid_args() {
    std::cout << "Testing config init and invalid-arg handling..." << std::endl;

    litep2p_config_t cfg;
    litep2p_config_init(&cfg);
    TEST_ASSERT(cfg.struct_size == sizeof(litep2p_config_t), "config_init sets struct_size");
    TEST_ASSERT(cfg.enable_encryption == 1, "config_init default enable_encryption=1");
    TEST_ASSERT(cfg.enable_discovery == 1, "config_init default enable_discovery=1");
    TEST_ASSERT(cfg.enable_file_transfer == 1, "config_init default enable_file_transfer=1");
    TEST_ASSERT(cfg.telemetry_enabled == 1, "config_init default telemetry_enabled=1");

    // NULL config → INVALID_ARG
    TEST_ASSERT(litep2p_init(nullptr) == LITEP2P_ERR_INVALID_ARG,
                "litep2p_init(NULL) should return INVALID_ARG");

    // NULL/empty peer_id on peer ops → INVALID_ARG
    TEST_ASSERT(litep2p_connect(nullptr) == LITEP2P_ERR_INVALID_ARG,
                "litep2p_connect(NULL) should return INVALID_ARG");
    TEST_ASSERT(litep2p_connect("") == LITEP2P_ERR_INVALID_ARG,
                "litep2p_connect(\"\") should return INVALID_ARG");
    TEST_ASSERT(litep2p_disconnect(nullptr) == LITEP2P_ERR_INVALID_ARG,
                "litep2p_disconnect(NULL) should return INVALID_ARG");
    TEST_ASSERT(litep2p_add_peer(nullptr, "127.0.0.1:1234") == LITEP2P_ERR_INVALID_ARG,
                "litep2p_add_peer(NULL) should return INVALID_ARG");

    // NULL/empty args on file-transfer ops → INVALID_ARG
    char tid[64];
    TEST_ASSERT(litep2p_send_file(nullptr, "/tmp/x", 0, tid, sizeof(tid)) == LITEP2P_ERR_INVALID_ARG,
                "litep2p_send_file(NULL peer) should return INVALID_ARG");
    TEST_ASSERT(litep2p_send_file("peer", nullptr, 0, tid, sizeof(tid)) == LITEP2P_ERR_INVALID_ARG,
                "litep2p_send_file(NULL path) should return INVALID_ARG");
    TEST_ASSERT(litep2p_accept_file_transfer(nullptr, "/tmp/x") == LITEP2P_ERR_INVALID_ARG,
                "litep2p_accept_file_transfer(NULL id) should return INVALID_ARG");
    TEST_ASSERT(litep2p_decline_file_transfer(nullptr) == LITEP2P_ERR_INVALID_ARG,
                "litep2p_decline_file_transfer(NULL) should return INVALID_ARG");
    TEST_ASSERT(litep2p_pause_transfer(nullptr) == LITEP2P_ERR_INVALID_ARG,
                "litep2p_pause_transfer(NULL) should return INVALID_ARG");
    TEST_ASSERT(litep2p_resume_transfer(nullptr) == LITEP2P_ERR_INVALID_ARG,
                "litep2p_resume_transfer(NULL) should return INVALID_ARG");
    TEST_ASSERT(litep2p_cancel_transfer(nullptr) == LITEP2P_ERR_INVALID_ARG,
                "litep2p_cancel_transfer(NULL) should return INVALID_ARG");

    // Invalid reconnect mode → INVALID_ARG
    TEST_ASSERT(litep2p_set_reconnect_mode("bogus_mode") == LITEP2P_ERR_INVALID_ARG,
                "litep2p_set_reconnect_mode(bogus) should return INVALID_ARG");

    // Invalid log level → INVALID_ARG
    TEST_ASSERT(litep2p_set_log_level(99) == LITEP2P_ERR_INVALID_ARG,
                "litep2p_set_log_level(99) should return INVALID_ARG");

    std::cout << "Config init / invalid-arg handling Passed!" << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// Test: lifecycle (init → start → get_state → get_peer_id → stop → shutdown)
// ---------------------------------------------------------------------------
static bool test_lifecycle(const std::filesystem::path& workdir) {
    std::cout << "Testing C API lifecycle..." << std::endl;
    EngineGuard guard;  // ensures shutdown even on early return

    litep2p_config_t cfg;
    std::string config_path, files_dir;
    int port = 0;
    TEST_ASSERT(make_hermetic_config(workdir, "c-api-test-peer", cfg, config_path, files_dir, port),
                "Failed to prepare hermetic config");

    // Before init, start should fail.
    TEST_ASSERT(litep2p_start() == LITEP2P_ERR_INVALID_STATE,
                "litep2p_start before init should return INVALID_STATE");

    TEST_ASSERT(litep2p_init(&cfg) == LITEP2P_OK, "litep2p_init should succeed");
    TEST_ASSERT(litep2p_get_state() == LITEP2P_STATE_STOPPED,
                "State should be STOPPED after init (before start)");

    TEST_ASSERT(litep2p_start() == LITEP2P_OK, "litep2p_start should succeed");
    TEST_ASSERT(wait_for_state(LITEP2P_STATE_RUNNING, std::chrono::seconds(5)),
                "State should be RUNNING after start");

    // get_peer_id should return the configured peer id.
    char peer_id_buf[128] = {0};
    const litep2p_result_t pid_res = litep2p_get_peer_id(peer_id_buf, sizeof(peer_id_buf));
    TEST_ASSERT(pid_res >= 0, "litep2p_get_peer_id should succeed");
    TEST_ASSERT(std::string(peer_id_buf) == "c-api-test-peer",
                "get_peer_id should return configured peer id");

    // Stop the engine.
    TEST_ASSERT(litep2p_stop() == LITEP2P_OK, "litep2p_stop should succeed");
    TEST_ASSERT(wait_for_state(LITEP2P_STATE_STOPPED, std::chrono::seconds(5)),
                "State should be STOPPED after stop");

    // Shutdown releases all state (guard also calls it; idempotent).
    TEST_ASSERT(litep2p_shutdown() == LITEP2P_OK, "litep2p_shutdown should succeed");
    TEST_ASSERT(litep2p_get_state() == LITEP2P_STATE_STOPPED,
                "State should be STOPPED after shutdown");

    std::cout << "C API lifecycle Passed!" << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// Test: disconnect suppression via C API
//
// Verifies the litep2p_disconnect contract:
//   - Returns OK for a known peer, NOT_FOUND for an unknown peer.
//   - After disconnect + a network-type change, the peer remains disconnected
//     (auto-reconnect is suppressed). We assert the behavioral outcome via
//     litep2p_peer_is_connected rather than the process-global telemetry
//     counter, because LAN broadcast discovery may observe real peers on the
//     host network and increment global counters.
//   - An explicit litep2p_connect after disconnect is accepted (clears the
//     suppression) and returns OK.
// ---------------------------------------------------------------------------
static bool test_disconnect_suppression_via_c_api(const std::filesystem::path& workdir) {
    std::cout << "Testing disconnect suppression via C API..." << std::endl;
    EngineGuard guard;  // ensures shutdown even on early return

    litep2p_config_t cfg;
    std::string config_path, files_dir;
    int port = 0;
    TEST_ASSERT(make_hermetic_config(workdir, "c-api-suppress-peer", cfg, config_path, files_dir, port),
                "Failed to prepare hermetic config");

    TEST_ASSERT(litep2p_init(&cfg) == LITEP2P_OK, "litep2p_init should succeed");
    TEST_ASSERT(litep2p_start() == LITEP2P_OK, "litep2p_start should succeed");
    TEST_ASSERT(wait_for_state(LITEP2P_STATE_RUNNING, std::chrono::seconds(5)),
                "Engine should be RUNNING");

    // Aggressive reconnect so maintenance would normally retry quickly.
    TEST_ASSERT(litep2p_set_reconnect_mode("aggressive") == LITEP2P_OK,
                "set_reconnect_mode(aggressive) should succeed");
    // Initial network state (WiFi, available).
    TEST_ASSERT(litep2p_set_network_info(1, 1) == LITEP2P_OK,
                "set_network_info should succeed");

    // Add a peer with an unreachable endpoint (free port, nothing listening).
    const char* remote_peer = "remote-unreachable-peer";
    const int unreachable_port = get_free_tcp_port();
    TEST_ASSERT(unreachable_port != 0, "Failed to allocate unreachable port");
    const std::string network_id = "127.0.0.1:" + std::to_string(unreachable_port);
    TEST_ASSERT(litep2p_add_peer(remote_peer, network_id.c_str()) == LITEP2P_OK,
                "litep2p_add_peer should succeed");

    // Initiate a connect (will fail since endpoint is unreachable).
    TEST_ASSERT(litep2p_connect(remote_peer) == LITEP2P_OK,
                "litep2p_connect should be accepted");
    std::this_thread::sleep_for(std::chrono::milliseconds(800));

    // disconnect on an UNKNOWN peer → NOT_FOUND.
    TEST_ASSERT(litep2p_disconnect("no-such-peer") == LITEP2P_ERR_NOT_FOUND,
                "litep2p_disconnect(unknown) should return NOT_FOUND");

    // disconnect on the KNOWN peer → OK.
    TEST_ASSERT(litep2p_disconnect(remote_peer) == LITEP2P_OK,
                "litep2p_disconnect should succeed for known peer");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Peer must not be connected right after disconnect.
    int connected = -1;
    TEST_ASSERT(litep2p_peer_is_connected(remote_peer, &connected) == LITEP2P_OK,
                "peer_is_connected should succeed");
    TEST_ASSERT(connected == 0, "Peer should not be connected immediately after disconnect");

    // Trigger a network type change (WiFi → Mobile). This normally triggers
    // immediate reconnects for disconnected peers. With user-disconnect
    // suppression active, this peer must remain disconnected.
    TEST_ASSERT(litep2p_set_network_info(0, 1) == LITEP2P_OK,
                "set_network_info (WiFi→Mobile) should succeed");

    // Wait long enough for the network-change reconnect + maintenance scan.
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    TEST_ASSERT(litep2p_peer_is_connected(remote_peer, &connected) == LITEP2P_OK,
                "peer_is_connected after network change should succeed");
    TEST_ASSERT(connected == 0,
                "Peer should remain disconnected after network change (suppression active)");

    // Explicit reconnect clears suppression and is accepted by the ABI.
    TEST_ASSERT(litep2p_connect(remote_peer) == LITEP2P_OK,
                "litep2p_connect (explicit) should be accepted after disconnect");

    std::cout << "Disconnect suppression via C API Passed!" << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// Test: file-transfer error paths
// ---------------------------------------------------------------------------
static bool test_file_transfer_error_paths(const std::filesystem::path& workdir) {
    std::cout << "Testing file-transfer error paths via C API..." << std::endl;
    EngineGuard guard;  // ensures shutdown even on early return

    litep2p_config_t cfg;
    std::string config_path, files_dir;
    int port = 0;
    TEST_ASSERT(make_hermetic_config(workdir, "c-api-ft-peer", cfg, config_path, files_dir, port),
                "Failed to prepare hermetic config");

    TEST_ASSERT(litep2p_init(&cfg) == LITEP2P_OK, "litep2p_init should succeed");
    TEST_ASSERT(litep2p_start() == LITEP2P_OK, "litep2p_start should succeed");
    TEST_ASSERT(wait_for_state(LITEP2P_STATE_RUNNING, std::chrono::seconds(5)),
                "Engine should be RUNNING");

    // Create a small test file.
    const auto test_file = workdir / "ft_test.bin";
    {
        std::ofstream out(test_file, std::ios::binary);
        TEST_ASSERT(out.is_open(), "Failed to create test file");
        const char data[] = "hello file transfer";
        out.write(data, sizeof(data));
    }

    // send_file to an unconnected/unknown peer → NOT_FOUND.
    char tid[64] = {0};
    const litep2p_result_t res = litep2p_send_file(
        "nonexistent-peer", test_file.string().c_str(), 0, tid, sizeof(tid));
    TEST_ASSERT(res == LITEP2P_ERR_NOT_FOUND,
                "send_file to unconnected peer should return NOT_FOUND");

    // accept/decline/pause/resume/cancel with unknown transfer id → NOT_FOUND.
    TEST_ASSERT(litep2p_accept_file_transfer("unknown-tid", "/tmp/out") == LITEP2P_ERR_NOT_FOUND,
                "accept unknown transfer should return NOT_FOUND");
    TEST_ASSERT(litep2p_decline_file_transfer("unknown-tid") == LITEP2P_ERR_NOT_FOUND,
                "decline unknown transfer should return NOT_FOUND");
    TEST_ASSERT(litep2p_pause_transfer("unknown-tid") == LITEP2P_ERR_NOT_FOUND,
                "pause unknown transfer should return NOT_FOUND");
    TEST_ASSERT(litep2p_resume_transfer("unknown-tid") == LITEP2P_ERR_NOT_FOUND,
                "resume unknown transfer should return NOT_FOUND");
    TEST_ASSERT(litep2p_cancel_transfer("unknown-tid") == LITEP2P_ERR_NOT_FOUND,
                "cancel unknown transfer should return NOT_FOUND");

    std::cout << "File-transfer error paths Passed!" << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// Test: overlay / multi-hop routing API (Phase C1)
// ---------------------------------------------------------------------------
static std::string make_hex_key(size_t bytes) {
    static const char* hexd = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < bytes; ++i) {
        out.push_back(hexd[(i * 7 + 3) % 16]);
        out.push_back(hexd[(i * 13 + 11) % 16]);
    }
    return out;
}

static bool test_overlay_api(const std::filesystem::path& workdir) {
    std::cout << "Testing overlay / multi-hop routing via C API..." << std::endl;
    EngineGuard guard;  // ensures shutdown even on early return

    litep2p_config_t cfg;
    std::string config_path, files_dir;
    int port = 0;
    TEST_ASSERT(make_hermetic_config(workdir, "c-api-overlay-peer", cfg, config_path, files_dir, port),
                "Failed to prepare hermetic config");

    TEST_ASSERT(litep2p_init(&cfg) == LITEP2P_OK, "litep2p_init should succeed");
    TEST_ASSERT(litep2p_start() == LITEP2P_OK, "litep2p_start should succeed");
    TEST_ASSERT(wait_for_state(LITEP2P_STATE_RUNNING, std::chrono::seconds(5)),
                "Engine should be RUNNING");

    // --- Invalid-argument handling --------------------------------------
    char frame_id[64] = {0};
    const uint8_t msg[] = "through the onion";
    TEST_ASSERT(litep2p_send_overlay(nullptr, msg, sizeof(msg), 0, 0, frame_id, sizeof(frame_id)) ==
                    LITEP2P_ERR_INVALID_ARG,
                "send_overlay(NULL peer) -> INVALID_ARG");
    TEST_ASSERT(litep2p_send_overlay("peer-x", nullptr, 5, 0, 0, frame_id, sizeof(frame_id)) ==
                    LITEP2P_ERR_INVALID_ARG,
                "send_overlay(NULL data) -> INVALID_ARG");
    TEST_ASSERT(litep2p_send_overlay("peer-x", msg, sizeof(msg), 0, 0, nullptr, 0) ==
                    LITEP2P_ERR_INVALID_ARG,
                "send_overlay(NULL frame buffer) -> INVALID_ARG");
    TEST_ASSERT(litep2p_overlay_register_relay(nullptr, 32, 4, 1) == LITEP2P_ERR_INVALID_ARG,
                "register_relay(NULL) -> INVALID_ARG");
    TEST_ASSERT(litep2p_overlay_register_peer_signing_key("peer-x", "zz-not-hex") ==
                    LITEP2P_ERR_INVALID_ARG,
                "register signing key with bad hex -> INVALID_ARG");
    TEST_ASSERT(litep2p_overlay_register_peer_signing_key("peer-x", "deadbeef") ==
                    LITEP2P_ERR_INVALID_ARG,
                "register signing key with wrong length -> INVALID_ARG");
    TEST_ASSERT(litep2p_overlay_pickup_mailbox(nullptr) == LITEP2P_ERR_INVALID_ARG,
                "pickup_mailbox(NULL) -> INVALID_ARG");
    TEST_ASSERT(litep2p_overlay_stats(nullptr) == LITEP2P_ERR_INVALID_ARG,
                "overlay_stats(NULL) -> INVALID_ARG");

    // --- Before any keys/relays: NOT_FOUND / NO_ROUTE ---------------------
    TEST_ASSERT(litep2p_send_overlay("peer-x", msg, sizeof(msg), 0, 0, frame_id, sizeof(frame_id)) ==
                    LITEP2P_ERR_NOT_FOUND,
                "send_overlay without peer key -> NOT_FOUND");

    // Register the peer's Noise static key -> now NoKey is resolved.
    const std::string peer_key = make_hex_key(32);
    TEST_ASSERT(litep2p_register_peer_key("peer-x", peer_key.c_str()) == LITEP2P_OK,
                "register_peer_key should succeed");

    // No relays registered yet -> NO_ROUTE.
    TEST_ASSERT(litep2p_send_overlay("peer-x", msg, sizeof(msg), 0, 0, frame_id, sizeof(frame_id)) ==
                    LITEP2P_ERR_NO_ROUTE,
                "send_overlay without relays -> NO_ROUTE");

    // Register a relay candidate -> now the path exists. The relay is also a
    // real peer: its static key must be registered for hop sealing.
    TEST_ASSERT(litep2p_overlay_register_relay("relay-peer", 32, 4, 1) == LITEP2P_OK,
                "register_relay should succeed");
    const std::string relay_key = make_hex_key(32);
    TEST_ASSERT(litep2p_register_peer_key("relay-peer", relay_key.c_str()) == LITEP2P_OK,
                "register relay peer key should succeed");

    // --- Successful overlay send -------------------------------------------
    TEST_ASSERT(litep2p_send_overlay("peer-x", msg, sizeof(msg), 0, 0, frame_id, sizeof(frame_id)) ==
                    LITEP2P_OK,
                "send_overlay should succeed once key + relay are known");
    TEST_ASSERT(std::strlen(frame_id) == 32, "send_overlay should return a 32-char frame id");

    // Reliable send (want_ack) also accepted.
    TEST_ASSERT(litep2p_send_overlay("peer-x", msg, sizeof(msg), 1, 0, frame_id, sizeof(frame_id)) ==
                    LITEP2P_OK,
                "send_overlay(want_ack=1) should succeed");
    TEST_ASSERT(litep2p_send_overlay("peer-x", msg, sizeof(msg), 0, 1, frame_id, sizeof(frame_id)) ==
                    LITEP2P_OK,
                "send_overlay(via_mailbox=1) should succeed");

    // --- Mailbox + relay toggles ------------------------------------------
    TEST_ASSERT(litep2p_overlay_pickup_mailbox("relay-peer") == LITEP2P_OK,
                "pickup_mailbox should succeed");
    TEST_ASSERT(litep2p_set_overlay_relay_enabled(1) == LITEP2P_OK,
                "set_overlay_relay_enabled(1) should succeed");
    TEST_ASSERT(litep2p_set_overlay_relay_enabled(0) == LITEP2P_OK,
                "set_overlay_relay_enabled(0) should succeed");

    // Signing key registration (valid 32-byte ed25519 hex).
    const std::string sign_key = make_hex_key(32);
    TEST_ASSERT(litep2p_overlay_register_peer_signing_key("peer-x", sign_key.c_str()) == LITEP2P_OK,
                "register peer signing key should succeed");

    // --- Stats -------------------------------------------------------------
    char* stats = nullptr;
    TEST_ASSERT(litep2p_overlay_stats(&stats) == LITEP2P_OK && stats != nullptr,
                "overlay_stats should succeed");
    if (stats) {
        const std::string s(stats);
        TEST_ASSERT(s.find("\"sent_total\"") != std::string::npos,
                    "overlay_stats should report sent_total");
        litep2p_free(stats);
    }

    TEST_ASSERT(litep2p_stop() == LITEP2P_OK, "litep2p_stop should succeed");
    TEST_ASSERT(wait_for_state(LITEP2P_STATE_STOPPED, std::chrono::seconds(5)),
                "State should be STOPPED after stop");

    std::cout << "Overlay / multi-hop routing Passed!" << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// Test: feature flags (compile-time module availability)
// ---------------------------------------------------------------------------
static bool test_feature_flags() {
    std::cout << "Testing feature flags..." << std::endl;

    const uint32_t flags = litep2p_get_feature_flags();
    // Telemetry is always compiled in.
    TEST_ASSERT((flags & LITEP2P_FEATURE_TELEMETRY) != 0,
                "telemetry feature flag should be set");

    // The desktop build compiles file transfer, voice calls, overlay, proxy
    // and noise.
    TEST_ASSERT((flags & LITEP2P_FEATURE_FILE_TRANSFER) != 0,
                "file-transfer feature flag should be set");
    TEST_ASSERT((flags & LITEP2P_FEATURE_VOICE_CALL) != 0,
                "voice-call feature flag should be set");
    TEST_ASSERT((flags & LITEP2P_FEATURE_OVERLAY) != 0,
                "overlay feature flag should be set");
    TEST_ASSERT((flags & LITEP2P_FEATURE_PROXY) != 0,
                "proxy feature flag should be set");
    TEST_ASSERT((flags & LITEP2P_FEATURE_ENCRYPTION) != 0,
                "encryption feature flag should be set");

    // No reserved/unknown bits set. (Phase 12 adds LITEP2P_FEATURE_NETWORK_OS.)
    TEST_ASSERT((flags & ~(LITEP2P_FEATURE_FILE_TRANSFER | LITEP2P_FEATURE_VOICE_CALL |
                           LITEP2P_FEATURE_OVERLAY | LITEP2P_FEATURE_PROXY |
                           LITEP2P_FEATURE_ENCRYPTION |
                           LITEP2P_FEATURE_DISCOVERY | LITEP2P_FEATURE_TELEMETRY |
                           LITEP2P_FEATURE_NETWORK_OS)) == 0,
                "no unknown feature bits should be set");

    std::cout << "Feature flags Passed!" << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "Running C API Tests..." << std::endl;

    // Use a temp working directory for hermetic configs and test files.
    const auto workdir = std::filesystem::temp_directory_path() / "litep2p_c_api_test";
    std::error_code ec;
    std::filesystem::remove_all(workdir, ec);
    std::filesystem::create_directories(workdir, ec);

    test_version_and_result_strings();
    test_feature_flags();
    test_config_init_and_invalid_args();
    test_lifecycle(workdir / "lifecycle");
    test_disconnect_suppression_via_c_api(workdir / "suppress");
    test_file_transfer_error_paths(workdir / "filetransfer");
    test_overlay_api(workdir / "overlay");

    // Cleanup temp dir.
    std::filesystem::remove_all(workdir, ec);

    if (tests_failed == 0) {
        std::cout << "ALL C API TESTS PASSED" << std::endl;
        return 0;
    } else {
        std::cerr << tests_failed << " C API TESTS FAILED" << std::endl;
        return 1;
    }
}
