#include "nat_traversal.h"
#include "nat_stun.h"
#include "peer_reconnect_policy.h"

#include "test_harness.h"

#include <arpa/inet.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <vector>

// Build a raw XOR-MAPPED-ADDRESS attribute value (RFC 5389): reserved(1)
// family(1) xor-port(2) xor-ip(4). Port XORed with high 16 bits of the magic
// cookie, address XORed with the full cookie.
static std::vector<uint8_t> make_xor_mapped_attr(const std::string& ip, uint16_t port) {
    std::vector<uint8_t> attr;
    attr.reserve(8);
    attr.push_back(0x00);
    attr.push_back(0x01);
    const uint16_t xor_port = port ^ static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);
    attr.push_back(static_cast<uint8_t>((xor_port >> 8) & 0xFF));
    attr.push_back(static_cast<uint8_t>(xor_port & 0xFF));
    const uint32_t addr = ntohl(inet_addr(ip.c_str()));
    const uint32_t xor_addr = addr ^ STUN_MAGIC_COOKIE;
    attr.push_back(static_cast<uint8_t>((xor_addr >> 24) & 0xFF));
    attr.push_back(static_cast<uint8_t>((xor_addr >> 16) & 0xFF));
    attr.push_back(static_cast<uint8_t>((xor_addr >> 8) & 0xFF));
    attr.push_back(static_cast<uint8_t>(xor_addr & 0xFF));
    return attr;
}

// Build a raw MAPPED-ADDRESS attribute value: reserved(1) family(1) port(2) ip(4).
static std::vector<uint8_t> make_mapped_attr(const std::string& ip, uint16_t port) {
    std::vector<uint8_t> attr;
    attr.reserve(8);
    attr.push_back(0x00);
    attr.push_back(0x01);
    attr.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
    attr.push_back(static_cast<uint8_t>(port & 0xFF));
    const uint32_t addr = ntohl(inet_addr(ip.c_str()));
    attr.push_back(static_cast<uint8_t>((addr >> 24) & 0xFF));
    attr.push_back(static_cast<uint8_t>((addr >> 16) & 0xFF));
    attr.push_back(static_cast<uint8_t>((addr >> 8) & 0xFF));
    attr.push_back(static_cast<uint8_t>(addr & 0xFF));
    return attr;
}

class MockUdpConnectionManager : public IUdpConnectionManager {
public:
    void setRespondToStun(bool enabled) { respond_to_stun_.store(enabled); }
    void setStunResponseDelayMs(int delay_ms) { stun_response_delay_ms_.store(delay_ms < 0 ? 0 : delay_ms); }

    bool startServer(int port,
                     std::function<void(const std::string&, const std::string&)> dataCallback,
                     std::function<void(const std::string&)> disconnectCallback) override {
        (void)port;
        data_callback_ = std::move(dataCallback);
        disconnect_callback_ = std::move(disconnectCallback);
        return true;
    }
    void stop() override {}
    bool connectToPeer(const std::string& ip, int port) override { (void)ip; (void)port; return true; }
    void sendMessageToPeer(const std::string& networkId, const std::string& message) override {
        (void)networkId; (void)message;
    }

    void sendRawPacket(const std::string& ip, int port, const std::vector<uint8_t>& data) override {
        if (!respond_to_stun_.load()) { (void)ip; (void)port; (void)data; return; }
        STUNMessage request;
        if (request.decode(data) && request.getType() == STUNMessageType::BindingRequest) {
            const int delay_ms = stun_response_delay_ms_.load();
            if (delay_ms > 0) std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
            STUNMessage response;
            response.setType(STUNMessageType::BindingResponse);
            response.setTransactionId(request.getTransactionId());
            response.addAttribute(STUNAttributeType::XorMappedAddress,
                                  make_xor_mapped_attr(ip, static_cast<uint16_t>(port)));
            auto payload = response.encode();
            if (stun_callback_) stun_callback_(ip, port, payload);
        }
    }

    void setStunPacketCallback(OnStunPacketCallback callback) override { stun_callback_ = std::move(callback); }
    bool restartSocket() override { return true; }

private:
    std::atomic<bool> respond_to_stun_{true};
    std::atomic<int> stun_response_delay_ms_{0};
    OnStunPacketCallback stun_callback_;
    std::function<void(const std::string&, const std::string&)> data_callback_;
    std::function<void(const std::string&)> disconnect_callback_;
};

static PeerAddress make_peer(const std::string& id, const std::string& net,
                             const std::string& ext_ip, uint16_t ext_port) {
    PeerAddress p;
    p.peer_id = id;
    p.network_id = net;
    p.internal_ip = "10.0.0.2";
    p.internal_port = 5000;
    p.external_ip = ext_ip;
    p.external_port = ext_port;
    p.nat_type = "Restricted";
    p.discovered_at_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return p;
}

// ---------------------------------------------------------------------------
// Section 1: STUN wire-format unit tests (pure logic, no network).
// ---------------------------------------------------------------------------
static void test_stun_wire_format() {
    std::cout << "\n--- STUN wire-format unit tests ---" << std::endl;

    // 1.1 Binding request encode -> decode roundtrip.
    {
        STUNMessage req;
        req.setType(STUNMessageType::BindingRequest);
        const std::vector<uint8_t> encoded = req.encode();
        CHECK(encoded.size() >= 20, "STUN header is at least 20 bytes");

        const uint32_t cookie = (static_cast<uint32_t>(encoded[4]) << 24) |
                                (static_cast<uint32_t>(encoded[5]) << 16) |
                                (static_cast<uint32_t>(encoded[6]) << 8) |
                                static_cast<uint32_t>(encoded[7]);
        CHECK_EQ(cookie, STUN_MAGIC_COOKIE, "STUN magic cookie encoded correctly");

        STUNMessage decoded;
        CHECK(decoded.decode(encoded), "STUN binding request decodes");
        CHECK(decoded.getType() == STUNMessageType::BindingRequest, "STUN type preserved");
        CHECK(decoded.getTransactionId() == req.getTransactionId(), "STUN transaction id preserved");
    }

    // 1.2 Transaction id is 12 bytes (96 bits) per RFC 5389.
    {
        STUNMessage req;
        req.setType(STUNMessageType::BindingRequest);
        CHECK_EQ(req.getTransactionId().size(), static_cast<size_t>(12), "STUN transaction id is 12 bytes");
    }

    // 1.3 XOR-MAPPED-ADDRESS roundtrip.
    {
        const std::string ip = "203.0.113.7";
        const uint16_t port = 62000;
        STUNMessage resp;
        resp.setType(STUNMessageType::BindingResponse);
        resp.addAttribute(STUNAttributeType::XorMappedAddress, make_xor_mapped_attr(ip, port));
        STUNMessage decoded;
        CHECK(decoded.decode(resp.encode()), "XOR-MAPPED-ADDRESS message decodes");
        STUNAddress addr;
        CHECK(decoded.getXorMappedAddress(addr), "getXorMappedAddress finds attribute");
        CHECK_EQ(addr.ip, ip, "XOR-MAPPED-ADDRESS IP roundtrip");
        CHECK_EQ(addr.port, port, "XOR-MAPPED-ADDRESS port roundtrip");
        CHECK_EQ(addr.family, static_cast<uint8_t>(0x01), "XOR-MAPPED-ADDRESS family is IPv4");
    }

    // 1.4 MAPPED-ADDRESS roundtrip (non-XOR form).
    {
        const std::string ip = "198.51.100.42";
        const uint16_t port = 3478;
        STUNMessage resp;
        resp.setType(STUNMessageType::BindingResponse);
        resp.addAttribute(STUNAttributeType::MappedAddress, make_mapped_attr(ip, port));
        STUNMessage decoded;
        CHECK(decoded.decode(resp.encode()), "MAPPED-ADDRESS message decodes");
        STUNAddress addr;
        CHECK(decoded.getMappedAddress(addr), "getMappedAddress finds attribute");
        CHECK_EQ(addr.ip, ip, "MAPPED-ADDRESS IP roundtrip");
        CHECK_EQ(addr.port, port, "MAPPED-ADDRESS port roundtrip");
    }

    // 1.5 CHANGE-REQUEST attribute roundtrip.
    {
        STUNMessage req;
        req.setType(STUNMessageType::BindingRequest);
        req.addChangeRequest(true, true);
        STUNMessage decoded;
        CHECK(decoded.decode(req.encode()), "CHANGE-REQUEST message decodes");
        std::vector<uint8_t> value;
        CHECK(decoded.getAttribute(STUNAttributeType::ChangeRequest, value), "CHANGE-REQUEST attribute present");
        CHECK_EQ(value.size(), static_cast<size_t>(4), "CHANGE-REQUEST value is 4 bytes");
        const uint32_t flags = (static_cast<uint32_t>(value[0]) << 24) |
                               (static_cast<uint32_t>(value[1]) << 16) |
                               (static_cast<uint32_t>(value[2]) << 8) |
                               static_cast<uint32_t>(value[3]);
        CHECK((flags & STUN_CHANGE_IP) != 0, "CHANGE-REQUEST change-IP flag set");
        CHECK((flags & STUN_CHANGE_PORT) != 0, "CHANGE-REQUEST change-PORT flag set");
    }

    // 1.6 Corrupted magic cookie must be rejected.
    {
        STUNMessage req;
        req.setType(STUNMessageType::BindingRequest);
        std::vector<uint8_t> bad = req.encode();
        bad[4] ^= 0xFF;
        STUNMessage decoded;
        CHECK(!decoded.decode(bad), "STUN rejects invalid magic cookie");
    }

    // 1.7 Truncated message must be rejected.
    {
        STUNMessage req;
        req.setType(STUNMessageType::BindingRequest);
        const auto encoded = req.encode();
        std::vector<uint8_t> truncated(encoded.begin(), encoded.begin() + 10);
        STUNMessage decoded;
        CHECK(!decoded.decode(truncated), "STUN rejects truncated message");
    }

    // 1.8 Empty input must be rejected.
    {
        STUNMessage decoded;
        CHECK(!decoded.decode({}), "STUN rejects empty input");
    }

    // 1.9 decode() reuse must not accumulate attributes.
    {
        STUNMessage msg;
        msg.setType(STUNMessageType::BindingRequest);
        msg.addChangeRequest(true, true);
        const auto encoded = msg.encode();
        STUNMessage reusable;
        CHECK(reusable.decode(encoded), "first decode into reusable instance");
        const size_t first = reusable.getAttributes().size();
        CHECK(reusable.decode(encoded), "second decode into reusable instance");
        CHECK_EQ(reusable.getAttributes().size(), first, "decode() reuse does not accumulate attributes");
    }
}

// ---------------------------------------------------------------------------
// Section 2: NATTraversal mock integration tests.
// ---------------------------------------------------------------------------
static void test_nat_traversal_integration() {
    NATTraversal& nat = NATTraversal::getInstance();
    nat.shutdown();

    MockUdpConnectionManager manager;
    nat.setConnectionManager(&manager);

    constexpr uint16_t kLocalPort = 39000;
    nat.initialize(kLocalPort);

    const PeerAddress peer = make_peer("peer-alpha", "net-A", "203.0.113.1", 62000);
    nat.registerPeer(peer);

    // 2.1 Basic hole punching: observer reports success and the peer records a
    //     successful punch timestamp.
    {
        std::mutex mu;
        std::condition_variable cv;
        bool observed = false;
        bool observed_success = false;

        const int obs_id = nat.addPunchResultObserver([&](const std::string& pid, bool success) {
            if (pid != peer.peer_id) return;
            {
                std::lock_guard<std::mutex> lk(mu);
                observed = true;
                observed_success = success;
            }
            cv.notify_one();
        });

        CHECK(nat.performHolePunching(peer.peer_id), "hole punching scheduled");
        {
            std::unique_lock<std::mutex> lk(mu);
            cv.wait_for(lk, std::chrono::seconds(3), [&]() { return observed; });
        }
        nat.removePunchResultObserver(obs_id);

        CHECK(observed, "punch observer was notified");
        CHECK(observed_success, "punch observer reported success");
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    {
        const auto peers = nat.getRegisteredPeers();
        bool punch_success = false;
        for (const auto& p : peers) {
            if (p.peer_id == peer.peer_id && p.last_successful_punch_ms > 0) {
                punch_success = true;
                break;
            }
        }
        CHECK(punch_success, "peer records last_successful_punch_ms");
    }

    // 2.2 Punch observer on exhausted retries reports failure.
    {
        nat.shutdown();
        manager.setRespondToStun(false);
        nat.setConnectionManager(&manager);
        nat.initialize(kLocalPort);

        PeerAddress peer2 = peer;
        peer2.peer_id = "peer-beta";
        peer2.external_port = static_cast<uint16_t>(peer.external_port + 1);
        nat.registerPeer(peer2);

        std::mutex mu;
        std::condition_variable cv;
        bool observed = false;
        bool observed_success = true;

        const int obs_id = nat.addPunchResultObserver([&](const std::string& pid, bool success) {
            if (pid != peer2.peer_id) return;
            {
                std::lock_guard<std::mutex> lk(mu);
                observed = true;
                observed_success = success;
            }
            cv.notify_one();
        });

        CHECK(nat.performHolePunching(peer2.peer_id), "failure-case punch scheduled");
        {
            std::unique_lock<std::mutex> lk(mu);
            cv.wait_for(lk, std::chrono::seconds(6), [&]() { return observed; });
        }
        nat.removePunchResultObserver(obs_id);
        nat.shutdown();
        manager.setRespondToStun(true);

        CHECK(observed, "failure-case observer was notified");
        CHECK(!observed_success, "punch observer reported failure on exhausted retries");
    }

    // 2.3 On-demand punch scheduling queues (does not drop) when more peers are
    //     scheduled than the concurrency cap.
    {
        nat.shutdown();
        manager.setRespondToStun(true);
        manager.setStunResponseDelayMs(80);
        nat.setConnectionManager(&manager);
        nat.initialize(kLocalPort);

        constexpr int kPeers = 5;
        std::vector<PeerAddress> peers_to_register;
        peers_to_register.reserve(kPeers);
        for (int i = 0; i < kPeers; ++i) {
            PeerAddress p = peer;
            p.peer_id = std::string("peer-od-") + std::to_string(i);
            p.network_id = std::string("net-od-") + std::to_string(i);
            p.external_port = static_cast<uint16_t>(62000 + i);
            peers_to_register.push_back(p);
            nat.registerPeer(p);
        }

        std::mutex mu;
        std::condition_variable cv;
        std::unordered_set<std::string> ok_peers;

        const int obs_id = nat.addPunchResultObserver([&](const std::string& pid, bool success) {
            if (!success) return;
            {
                std::lock_guard<std::mutex> lk(mu);
                ok_peers.insert(pid);
            }
            cv.notify_one();
        });

        for (const auto& p : peers_to_register) {
            CHECK(nat.performHolePunching(p.peer_id), "on-demand punch scheduled");
        }
        {
            std::unique_lock<std::mutex> lk(mu);
            cv.wait_for(lk, std::chrono::seconds(4), [&]() {
                return static_cast<int>(ok_peers.size()) >= kPeers;
            });
        }
        nat.removePunchResultObserver(obs_id);
        nat.shutdown();
        manager.setStunResponseDelayMs(0);

        CHECK_EQ(static_cast<int>(ok_peers.size()), kPeers, "on-demand punch queueing does not drop tasks");
    }

    // 2.4 STUN error code -> string mapping.
    {
        CHECK(stunErrorToString(STUNErrorCode::SocketCreationFailed).find("Socket") != std::string::npos,
              "stunErrorToString(SocketCreationFailed)");
        CHECK(stunErrorToString(STUNErrorCode::DnsResolutionFailed).find("DNS") != std::string::npos,
              "stunErrorToString(DnsResolutionFailed)");
        CHECK(stunErrorToString(STUNErrorCode::ReceiveTimeout).find("timeout") != std::string::npos,
              "stunErrorToString(ReceiveTimeout)");
    }

    // 2.5 ProbeResult factory methods.
    {
        const auto failure = STUNClient::ProbeResult::failure(STUNErrorCode::AllServersFailed, "Custom message");
        CHECK(!failure.success, "ProbeResult::failure sets success=false");
        CHECK(failure.error_code == STUNErrorCode::AllServersFailed, "ProbeResult::failure sets error_code");
        CHECK_EQ(failure.error_message, std::string("Custom message"), "ProbeResult::failure keeps custom message");

        const auto default_msg = STUNClient::ProbeResult::failure(STUNErrorCode::ReceiveTimeout);
        CHECK(!default_msg.error_message.empty(), "ProbeResult::failure fills default message");
    }

    // 2.6 NATMetrics default initialization.
    {
        NATMetrics metrics;
        CHECK_EQ(metrics.stun_requests_sent, static_cast<uint64_t>(0), "NATMetrics stun_requests_sent default");
        CHECK_EQ(metrics.hole_punch_attempts, static_cast<uint64_t>(0), "NATMetrics hole_punch_attempts default");
        CHECK_EQ(metrics.active_peers, static_cast<uint64_t>(0), "NATMetrics active_peers default");
        CHECK_EQ(metrics.heartbeats_sent, static_cast<uint64_t>(0), "NATMetrics heartbeats_sent default");
        CHECK_EQ(metrics.discovery_broadcasts_sent, static_cast<uint64_t>(0), "NATMetrics discovery_broadcasts_sent default");
    }

    // 2.7 Metrics tracking inside NATTraversal.
    {
        NATTraversal& nat2 = NATTraversal::getInstance();
        nat2.shutdown();
        MockUdpConnectionManager manager2;
        nat2.setConnectionManager(&manager2);
        nat2.initialize(39001);
        nat2.resetMetrics();

        PeerAddress peer2 = make_peer("test-metrics-peer", "test-net", "192.168.1.100", 5000);
        nat2.registerPeer(peer2);

        NATMetrics metrics = nat2.getMetrics();
        CHECK_EQ(metrics.active_peers, static_cast<uint64_t>(1), "metrics active_peers after registerPeer");

        nat2.performHolePunching(peer2.peer_id);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        metrics = nat2.getMetrics();
        CHECK(metrics.hole_punch_attempts > 0, "metrics hole_punch_attempts after performHolePunching");

        nat2.shutdown();
    }

    // 2.8 Punch task de-duplication / coalescing.
    {
        NATTraversal& nat3 = NATTraversal::getInstance();
        nat3.shutdown();
        MockUdpConnectionManager manager3;
        manager3.setStunResponseDelayMs(80);
        nat3.setConnectionManager(&manager3);
        nat3.initialize(39003);
        nat3.resetMetrics();

        PeerAddress peer3 = make_peer("peer-dedup", "net-dedup", "192.168.1.101", 5001);
        nat3.registerPeer(peer3);

        nat3.performHolePunching(peer3.peer_id);
        for (int i = 0; i < 25; ++i) {
            nat3.performHolePunching(peer3.peer_id);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(700));

        NATMetrics metrics3 = nat3.getMetrics();
        nat3.shutdown();

        CHECK(metrics3.hole_punch_attempts <= 2, "punch de-duplication coalesces schedules");
    }

    // 2.9 Punch cancellation drops reschedules.
    {
        NATTraversal& nat4 = NATTraversal::getInstance();
        nat4.shutdown();
        MockUdpConnectionManager manager4;
        manager4.setStunResponseDelayMs(120);
        nat4.setConnectionManager(&manager4);
        nat4.initialize(39004);
        nat4.resetMetrics();

        PeerAddress peer4 = make_peer("peer-cancel", "net-cancel", "203.0.113.9", 62009);
        nat4.registerPeer(peer4);

        nat4.performHolePunching(peer4.peer_id);
        nat4.cancelHolePunching(peer4.peer_id);
        for (int i = 0; i < 50; ++i) {
            nat4.performHolePunching(peer4.peer_id);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(700));

        NATMetrics metrics4 = nat4.getMetrics();
        nat4.shutdown();

        CHECK(metrics4.hole_punch_attempts <= 1, "punch cancellation drops reschedules");
    }

    // 2.10 Connection validation helpers.
    {
        NATTraversal& nat5 = NATTraversal::getInstance();
        nat5.shutdown();
        MockUdpConnectionManager manager5;
        nat5.setConnectionManager(&manager5);
        nat5.initialize(39002);

        PeerAddress peer5 = make_peer("validation-test-peer", "validation-net", "10.0.0.50", 6000);
        peer5.verified = true;
        peer5.last_heartbeat_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        nat5.registerPeer(peer5);

        CHECK(nat5.isPeerReachable(peer5.peer_id), "isPeerReachable for newly registered peer");
        CHECK(nat5.getPeerLatencyMs(peer5.peer_id) >= -1, "getPeerLatencyMs returns valid value");

        nat5.shutdown();
    }
}

// ---------------------------------------------------------------------------
// Section 3: PeerReconnectPolicy scheduling semantics.
// ---------------------------------------------------------------------------
static void test_reconnect_policy() {
    std::cout << "\n--- PeerReconnectPolicy scheduling ---" << std::endl;

    PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
    policy.shutdown();
    policy.initialize(90, true);  // good battery + WiFi

    const std::string peer_id = "reconnect-peer";
    policy.track_peer(peer_id);

    const auto before_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());

    policy.on_connection_failure(peer_id, "TCP");

    const auto after_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());

    const PeerConnectionStats stats = policy.get_peer_stats(peer_id);
    CHECK(stats.last_connection_attempt_ms >= before_ms &&
              stats.last_connection_attempt_ms <= after_ms,
          "last_connection_attempt_ms recorded");
    CHECK(stats.next_retry_time_ms > stats.last_connection_attempt_ms,
          "next_retry_time_ms scheduled in the future");

    const auto strategy = policy.get_retry_strategy(peer_id);
    const uint64_t scheduled_delay_ms = stats.next_retry_time_ms - stats.last_connection_attempt_ms;
    CHECK(strategy.should_retry, "retry strategy says should_retry");
    CHECK(strategy.backoff_ms > 0, "retry strategy has positive backoff");
    CHECK(static_cast<uint64_t>(strategy.backoff_ms) <= scheduled_delay_ms,
          "retry strategy backoff within scheduled window");

    CHECK(!policy.should_reconnect_now(peer_id),
          "policy does not reconnect immediately after failure");

    policy.shutdown();
}

int main() {
    test_stun_wire_format();
    test_nat_traversal_integration();
    test_reconnect_policy();
    return suite_exit("NAT traversal");
}
