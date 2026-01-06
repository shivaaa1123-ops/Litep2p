#include "nat_traversal.h"
#include "nat_stun.h"
#include "peer_reconnect_policy.h"

#include <arpa/inet.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

// Test result tracking
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(condition, msg) \
    do { \
        if (!(condition)) { \
            std::cerr << "FAIL: " << msg << " [" << __FILE__ << ":" << __LINE__ << "]" << std::endl; \
            tests_failed++; \
            return false; \
        } \
    } while(0)

#define TEST_PASS(msg) \
    do { \
        std::cout << "PASS: " << msg << std::endl; \
        tests_passed++; \
    } while(0)

class MockUdpConnectionManager : public IUdpConnectionManager {
public:
    void setStunResponseDelayMs(int delay_ms) {
        stun_response_delay_ms_.store(delay_ms < 0 ? 0 : delay_ms);
    }

    bool startServer(int port,
                     std::function<void(const std::string&, const std::string&)> dataCallback,
                     std::function<void(const std::string&)> disconnectCallback) override {
        (void)port;
        data_callback_ = std::move(dataCallback);
        disconnect_callback_ = std::move(disconnectCallback);
        return true;
    }

    void stop() override {}

    bool connectToPeer(const std::string& ip, int port) override {
        (void)ip;
        (void)port;
        return true;
    }

    void sendMessageToPeer(const std::string& networkId, const std::string& message) override {
        (void)networkId;
        (void)message;
    }

    void sendRawPacket(const std::string& ip, int port, const std::vector<uint8_t>& data) override {
        STUNMessage request;
        if (request.decode(data) && request.getType() == STUNMessageType::BindingRequest) {
            const int delay_ms = stun_response_delay_ms_.load();
            if (delay_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
            }

            STUNMessage response;
            response.setType(STUNMessageType::BindingResponse);
            response.setTransactionId(request.getTransactionId());

            std::vector<uint8_t> attr;
            attr.reserve(8);
            attr.push_back(0x00);
            attr.push_back(0x01);

            uint16_t xor_port = static_cast<uint16_t>(port) ^ static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);
            attr.push_back(static_cast<uint8_t>((xor_port >> 8) & 0xFF));
            attr.push_back(static_cast<uint8_t>(xor_port & 0xFF));

            uint32_t addr = inet_addr(ip.c_str());
            uint32_t xor_addr = ntohl(addr) ^ STUN_MAGIC_COOKIE;
            attr.push_back(static_cast<uint8_t>((xor_addr >> 24) & 0xFF));
            attr.push_back(static_cast<uint8_t>((xor_addr >> 16) & 0xFF));
            attr.push_back(static_cast<uint8_t>((xor_addr >> 8) & 0xFF));
            attr.push_back(static_cast<uint8_t>(xor_addr & 0xFF));

            response.addAttribute(STUNAttributeType::XorMappedAddress, attr);

            auto payload = response.encode();
            if (stun_callback_) {
                stun_callback_(ip, port, payload);
            }
        }
    }

    void setStunPacketCallback(OnStunPacketCallback callback) override {
        stun_callback_ = std::move(callback);
    }

private:
    std::atomic<int> stun_response_delay_ms_{0};
    OnStunPacketCallback stun_callback_;
    std::function<void(const std::string&, const std::string&)> data_callback_;
    std::function<void(const std::string&)> disconnect_callback_;
};

int main() {
    // Ensure clean singleton state for repeatable tests
    NATTraversal& nat = NATTraversal::getInstance();
    nat.shutdown();

    MockUdpConnectionManager manager;
    nat.setConnectionManager(&manager);

    constexpr uint16_t kLocalPort = 39000;
    nat.initialize(kLocalPort);

    PeerAddress peer;
    peer.peer_id = "peer-alpha";
    peer.network_id = "net-A";
    peer.internal_ip = "10.0.0.2";
    peer.internal_port = 5000;
    peer.external_ip = "203.0.113.1";
    peer.external_port = 62000;
    peer.nat_type = "Restricted";
    peer.discovered_at_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    nat.registerPeer(peer);

    if (!nat.performHolePunching(peer.peer_id)) {
        nat.shutdown();
        return 1;
    }

    // Allow time for background punch worker
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto peers = nat.getRegisteredPeers();
    bool punch_success = false;
    for (const auto& p : peers) {
        if (p.peer_id == peer.peer_id && p.last_successful_punch_ms > 0) {
            punch_success = true;
            break;
        }
    }

    nat.shutdown();
    
    if (!punch_success) {
        std::cerr << "FAIL: Basic hole punching test failed" << std::endl;
        return 1;
    }
    
    std::cout << "PASS: Basic hole punching test" << std::endl;
    
    // -------------------------------------------------------------------------
    // Test: STUN Error Codes
    // -------------------------------------------------------------------------
    {
        std::cout << "\n--- Testing STUN Error Codes ---" << std::endl;
        
        // Test error code to string conversion
        std::string err_str = stunErrorToString(STUNErrorCode::SocketCreationFailed);
        if (err_str.find("Socket") == std::string::npos) {
            std::cerr << "FAIL: stunErrorToString for SocketCreationFailed" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("stunErrorToString for SocketCreationFailed");
        }
        
        err_str = stunErrorToString(STUNErrorCode::DnsResolutionFailed);
        if (err_str.find("DNS") == std::string::npos && err_str.find("resolution") == std::string::npos) {
            std::cerr << "FAIL: stunErrorToString for DnsResolutionFailed" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("stunErrorToString for DnsResolutionFailed");
        }
        
        err_str = stunErrorToString(STUNErrorCode::ReceiveTimeout);
        if (err_str.find("timeout") == std::string::npos && err_str.find("Timeout") == std::string::npos) {
            std::cerr << "FAIL: stunErrorToString for ReceiveTimeout" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("stunErrorToString for ReceiveTimeout");
        }
    }
    
    // -------------------------------------------------------------------------
    // Test: ProbeResult factory methods
    // -------------------------------------------------------------------------
    {
        std::cout << "\n--- Testing ProbeResult Factory ---" << std::endl;
        
        auto failure_result = STUNClient::ProbeResult::failure(STUNErrorCode::AllServersFailed, "Custom message");
        if (failure_result.success) {
            std::cerr << "FAIL: ProbeResult::failure should set success=false" << std::endl;
            tests_failed++;
        } else if (failure_result.error_code != STUNErrorCode::AllServersFailed) {
            std::cerr << "FAIL: ProbeResult::failure should set error_code correctly" << std::endl;
            tests_failed++;
        } else if (failure_result.error_message != "Custom message") {
            std::cerr << "FAIL: ProbeResult::failure should set custom message" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("ProbeResult::failure with custom message");
        }
        
        auto default_msg_result = STUNClient::ProbeResult::failure(STUNErrorCode::ReceiveTimeout);
        if (default_msg_result.error_message.empty()) {
            std::cerr << "FAIL: ProbeResult::failure should use default message" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("ProbeResult::failure with default message");
        }
    }
    
    // -------------------------------------------------------------------------
    // Test: NATMetrics structure
    // -------------------------------------------------------------------------
    {
        std::cout << "\n--- Testing NATMetrics ---" << std::endl;
        
        NATMetrics metrics;
        
        // Check default initialization
        if (metrics.stun_requests_sent != 0) {
            std::cerr << "FAIL: NATMetrics default stun_requests_sent should be 0" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("NATMetrics default stun_requests_sent");
        }
        
        if (metrics.hole_punch_attempts != 0) {
            std::cerr << "FAIL: NATMetrics default hole_punch_attempts should be 0" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("NATMetrics default hole_punch_attempts");
        }
        
        if (metrics.active_peers != 0) {
            std::cerr << "FAIL: NATMetrics default active_peers should be 0" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("NATMetrics default active_peers");
        }
        
        if (metrics.heartbeats_sent != 0) {
            std::cerr << "FAIL: NATMetrics default heartbeats_sent should be 0" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("NATMetrics default heartbeats_sent");
        }
        
        if (metrics.discovery_broadcasts_sent != 0) {
            std::cerr << "FAIL: NATMetrics default discovery_broadcasts_sent should be 0" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("NATMetrics default discovery_broadcasts_sent");
        }
    }
    
    // -------------------------------------------------------------------------
    // Test: Metrics tracking in NATTraversal
    // -------------------------------------------------------------------------
    {
        std::cout << "\n--- Testing NATTraversal Metrics Tracking ---" << std::endl;
        
        NATTraversal& nat2 = NATTraversal::getInstance();
        nat2.shutdown();  // Reset state
        
        MockUdpConnectionManager manager2;
        nat2.setConnectionManager(&manager2);
        nat2.initialize(39001);
        
        // Reset metrics
        nat2.resetMetrics();
        
        // Register a peer and check peer count metric
        PeerAddress peer2;
        peer2.peer_id = "test-metrics-peer";
        peer2.network_id = "test-net";
        peer2.external_ip = "192.168.1.100";
        peer2.external_port = 5000;
        
        nat2.registerPeer(peer2);
        
        NATMetrics metrics = nat2.getMetrics();
        if (metrics.active_peers != 1) {
            std::cerr << "FAIL: active_peers should be 1 after registerPeer, got " << metrics.active_peers << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("Metrics active_peers tracking");
        }
        
        // Trigger hole punching and check metrics
        nat2.performHolePunching(peer2.peer_id);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        
        metrics = nat2.getMetrics();
        if (metrics.hole_punch_attempts == 0) {
            std::cerr << "FAIL: hole_punch_attempts should be > 0 after performHolePunching" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("Metrics hole_punch_attempts tracking");
        }
        
        nat2.shutdown();
    }

    // -------------------------------------------------------------------------
    // Test: Punch task de-duplication / coalescing
    // -------------------------------------------------------------------------
    {
        std::cout << "\n--- Testing Punch Task De-duplication ---" << std::endl;

        NATTraversal& nat3 = NATTraversal::getInstance();
        nat3.shutdown();  // Reset state

        MockUdpConnectionManager manager3;
        // Delay responses so the first punch job remains queued/in-flight while we spam scheduling.
        manager3.setStunResponseDelayMs(80);
        nat3.setConnectionManager(&manager3);
        nat3.initialize(39003);
        nat3.resetMetrics();

        PeerAddress peer3;
        peer3.peer_id = "peer-dedup";
        peer3.network_id = "net-dedup";
        peer3.external_ip = "192.168.1.101";
        peer3.external_port = 5001;
        nat3.registerPeer(peer3);

        // Schedule once, then spam repeated scheduling. The NATTraversal scheduler should
        // coalesce these requests, allowing at most one additional reschedule.
        nat3.performHolePunching(peer3.peer_id);
        for (int i = 0; i < 25; ++i) {
            nat3.performHolePunching(peer3.peer_id);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(700));

        NATMetrics metrics3 = nat3.getMetrics();
        nat3.shutdown();

        if (metrics3.hole_punch_attempts > 2) {
            std::cerr << "FAIL: Punch task de-duplication expected <=2 jobs, got "
                      << metrics3.hole_punch_attempts << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("Punch task de-duplication coalesces schedules");
        }
    }

    // -------------------------------------------------------------------------
    // Test: Punch cancellation (prevents repeated storm scheduling)
    // -------------------------------------------------------------------------
    {
        std::cout << "\n--- Testing Punch Cancellation ---" << std::endl;

        NATTraversal& nat4 = NATTraversal::getInstance();
        nat4.shutdown();  // Reset state

        MockUdpConnectionManager manager4;
        // Keep the first punch job alive briefly so cancellation has a chance to interrupt it.
        manager4.setStunResponseDelayMs(120);
        nat4.setConnectionManager(&manager4);
        nat4.initialize(39004);
        nat4.resetMetrics();

        PeerAddress peer4;
        peer4.peer_id = "peer-cancel";
        peer4.network_id = "net-cancel";
        peer4.external_ip = "203.0.113.9";
        peer4.external_port = 62009;
        nat4.registerPeer(peer4);

        nat4.performHolePunching(peer4.peer_id);
        nat4.cancelHolePunching(peer4.peer_id);

        // Spam scheduling after cancellation; these should be dropped.
        for (int i = 0; i < 50; ++i) {
            nat4.performHolePunching(peer4.peer_id);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(700));

        NATMetrics metrics4 = nat4.getMetrics();
        nat4.shutdown();

        if (metrics4.hole_punch_attempts > 1) {
            std::cerr << "FAIL: Punch cancellation expected <=1 job, got "
                      << metrics4.hole_punch_attempts << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("Punch cancellation drops reschedules");
        }
    }
    
    // -------------------------------------------------------------------------
    // Test: STUN Message encoding/decoding
    // -------------------------------------------------------------------------
    {
        std::cout << "\n--- Testing STUN Message Encoding/Decoding ---" << std::endl;
        
        STUNMessage request;
        request.setType(STUNMessageType::BindingRequest);
        
        std::vector<uint8_t> encoded = request.encode();
        
        // Check minimum STUN header length (20 bytes)
        if (encoded.size() < 20) {
            std::cerr << "FAIL: Encoded STUN message too short: " << encoded.size() << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("STUN message minimum header length");
        }
        
        // Check magic cookie
        uint32_t cookie = (static_cast<uint32_t>(encoded[4]) << 24) |
                          (static_cast<uint32_t>(encoded[5]) << 16) |
                          (static_cast<uint32_t>(encoded[6]) << 8) |
                          static_cast<uint32_t>(encoded[7]);
        if (cookie != STUN_MAGIC_COOKIE) {
            std::cerr << "FAIL: Magic cookie mismatch: " << std::hex << cookie << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("STUN magic cookie encoding");
        }
        
        // Decode and verify
        STUNMessage decoded;
        if (!decoded.decode(encoded)) {
            std::cerr << "FAIL: Could not decode encoded STUN message" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("STUN message decode roundtrip");
        }
        
        if (decoded.getType() != STUNMessageType::BindingRequest) {
            std::cerr << "FAIL: Decoded message type mismatch" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("STUN message type preservation");
        }
        
        if (decoded.getTransactionId() != request.getTransactionId()) {
            std::cerr << "FAIL: Transaction ID mismatch after decode" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("STUN transaction ID preservation");
        }
    }
    
    // -------------------------------------------------------------------------
    // Test: CHANGE-REQUEST attribute encoding
    // -------------------------------------------------------------------------
    {
        std::cout << "\n--- Testing CHANGE-REQUEST Attribute ---" << std::endl;
        
        STUNMessage msg;
        msg.setType(STUNMessageType::BindingRequest);
        msg.addChangeRequest(true, true);  // Change IP + Port
        
        std::vector<uint8_t> encoded = msg.encode();
        
        // Should have header (20) + CHANGE-REQUEST attribute (4+4 = 8)
        if (encoded.size() < 28) {
            std::cerr << "FAIL: CHANGE-REQUEST message too short: " << encoded.size() << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("CHANGE-REQUEST attribute size");
        }
        
        // Decode and verify
        STUNMessage decoded;
        if (!decoded.decode(encoded)) {
            std::cerr << "FAIL: Could not decode CHANGE-REQUEST message" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("CHANGE-REQUEST decode");
        }

        // Regression: decode() must be safe to call repeatedly on the same instance
        // without accumulating attributes from previous parses.
        STUNMessage reusable;
        if (!reusable.decode(encoded)) {
            std::cerr << "FAIL: Could not decode CHANGE-REQUEST message into reusable instance" << std::endl;
            tests_failed++;
        } else {
            const auto first_count = reusable.getAttributes().size();
            if (!reusable.decode(encoded)) {
                std::cerr << "FAIL: Second decode() failed on reusable instance" << std::endl;
                tests_failed++;
            } else {
                const auto second_count = reusable.getAttributes().size();
                if (first_count != second_count) {
                    std::cerr << "FAIL: STUNMessage::decode accumulated attributes across calls (" 
                              << first_count << " -> " << second_count << ")" << std::endl;
                    tests_failed++;
                } else {
                    TEST_PASS("STUNMessage::decode reuse does not accumulate attributes");
                }
            }
        }
    }
    
    // -------------------------------------------------------------------------
    // Test: Connection validation helpers
    // -------------------------------------------------------------------------
    {
        std::cout << "\n--- Testing Connection Validation ---" << std::endl;
        
        NATTraversal& nat3 = NATTraversal::getInstance();
        nat3.shutdown();
        
        MockUdpConnectionManager manager3;
        nat3.setConnectionManager(&manager3);
        nat3.initialize(39002);
        
        PeerAddress peer3;
        peer3.peer_id = "validation-test-peer";
        peer3.network_id = "validation-net";
        peer3.external_ip = "10.0.0.50";
        peer3.external_port = 6000;
        peer3.verified = true;
        peer3.last_heartbeat_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        
        nat3.registerPeer(peer3);
        
        // Test isPeerReachable
        bool reachable = nat3.isPeerReachable(peer3.peer_id);
        // Since we just registered, should be reachable (within timeout)
        if (!reachable) {
            std::cerr << "FAIL: Newly registered peer should be reachable" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("isPeerReachable for new peer");
        }
        
        // Test getPeerLatencyMs (should return -1 for unknown, or >= 0 for measured)
        int64_t latency = nat3.getPeerLatencyMs(peer3.peer_id);
        // Initial latency is 0 (not yet measured)
        if (latency < -1) {
            std::cerr << "FAIL: getPeerLatencyMs returned invalid value: " << latency << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("getPeerLatencyMs initial value");
        }
        
        nat3.shutdown();
    }

    // -------------------------------------------------------------------------
    // Test: PeerReconnectPolicy scheduling semantics
    // -------------------------------------------------------------------------
    {
        std::cout << "\n--- Testing PeerReconnectPolicy Scheduling ---" << std::endl;

        PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
        policy.shutdown();
        policy.initialize(90, true);  // Good battery + WiFi

        const std::string peer_id = "reconnect-peer";
        policy.track_peer(peer_id);

        auto now_tp = std::chrono::steady_clock::now().time_since_epoch();
        const uint64_t before_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now_tp).count());

        policy.on_connection_failure(peer_id, "TCP");

        now_tp = std::chrono::steady_clock::now().time_since_epoch();
        const uint64_t after_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now_tp).count());

        const PeerConnectionStats stats = policy.get_peer_stats(peer_id);
        if (stats.last_connection_attempt_ms < before_ms || stats.last_connection_attempt_ms > after_ms) {
            std::cerr << "FAIL: PeerReconnectPolicy last_connection_attempt_ms not set correctly" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("PeerReconnectPolicy sets last_connection_attempt_ms");
        }

        if (stats.next_retry_time_ms <= stats.last_connection_attempt_ms) {
            std::cerr << "FAIL: PeerReconnectPolicy next_retry_time_ms not in the future" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("PeerReconnectPolicy schedules next_retry_time_ms in the future");
        }

        const auto strategy = policy.get_retry_strategy(peer_id);
        const uint64_t scheduled_delay_ms = stats.next_retry_time_ms - stats.last_connection_attempt_ms;
        if (!strategy.should_retry || strategy.backoff_ms == 0 || static_cast<uint64_t>(strategy.backoff_ms) > scheduled_delay_ms) {
            std::cerr << "FAIL: PeerReconnectPolicy reported invalid remaining backoff" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("PeerReconnectPolicy reports remaining backoff delay");
        }

        if (policy.should_reconnect_now(peer_id)) {
            std::cerr << "FAIL: PeerReconnectPolicy should not reconnect immediately after failure" << std::endl;
            tests_failed++;
        } else {
            TEST_PASS("PeerReconnectPolicy does not reconnect immediately after failure");
        }

        policy.shutdown();
    }
    
    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Summary:" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
