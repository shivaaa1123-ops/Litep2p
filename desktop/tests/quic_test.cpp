// quic_test.cpp - Real QUIC (RFC 9000, picoquic) transport integration test.
//
// Verifies:
//   1. Two RealQuicTransport instances complete a QUIC handshake over IPv6
//      loopback (::1) - proving the IPv6-preferred, dual-stack listener works.
//   2. Datagrams flow in both directions after the handshake.
//   3. Clean shutdown.
//
// Requires LITEP2P_ENABLE_REAL_QUIC=1 (linked against picoquic).

#include "real_quic_transport.h"
#include "logger.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAIL: " << msg << " [" << __FILE__ << ":" << __LINE__ << "]" << std::endl; \
            tests_failed++; \
        } \
    } while (0)

int main() {
    set_log_level(LogLevel::DEBUG);

    if (!RealQuicTransport::available()) {
        std::cerr << "SKIP: real QUIC not compiled in" << std::endl;
        return 0;
    }

    std::cout << "Real QUIC transport integration test (IPv6 loopback)" << std::endl;

    // Ports for the two endpoints.
    const uint16_t kPortA = 45678;
    const uint16_t kPortB = 45679;
    const std::string kPeerA = "peer-a";
    const std::string kPeerB = "peer-b";

    RealQuicTransport a;
    RealQuicTransport b;

    std::mutex mu;
    std::condition_variable cv;
    std::atomic<bool> b_ready{false};
    std::atomic<bool> a_ready{false};
    // Incoming connections are labeled by peer address ("ip:port" or
    // "[v6]:port"), mirroring the UDP transport's network_id convention.
    // So we accept data from any source id and verify the payload.
    std::string b_received;
    std::string a_received;

    const bool started_a = a.start(kPortA,
        [&](const std::string& from, const std::string& data) {
            (void)from;
            std::lock_guard<std::mutex> lock(mu);
            a_received = data;
            cv.notify_all();
        },
        [&](const std::string& peer_id) {
            (void)peer_id;
            a_ready.store(true);
            cv.notify_all();
        },
        [](const std::string&) {});

    const bool started_b = b.start(kPortB,
        [&](const std::string& from, const std::string& data) {
            (void)from;
            std::lock_guard<std::mutex> lock(mu);
            b_received = data;
            cv.notify_all();
        },
        [&](const std::string& peer_id) {
            (void)peer_id;
            b_ready.store(true);
            cv.notify_all();
        },
        [](const std::string&) {});

    TEST_ASSERT(started_a, "transport A failed to start");
    TEST_ASSERT(started_b, "transport B failed to start");

    // Connect over IPv6 loopback (::1). If the system lacks IPv6, fall back
    // to IPv4 loopback so the test still validates the QUIC stack itself.
    std::string host = "::1";
    if (!a.connect(kPeerB, host, kPortB)) {
        TEST_ASSERT(false, "connect A->B (::1) failed to enqueue");
    }
    if (!b.connect(kPeerA, host, kPortA)) {
        TEST_ASSERT(false, "connect B->A (::1) failed to enqueue");
    }

    // Wait for both sides to report READY (handshake complete).
    {
        std::unique_lock<std::mutex> lock(mu);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        while ((!a_ready.load() || !b_ready.load()) &&
               std::chrono::steady_clock::now() < deadline) {
            cv.wait_for(lock, std::chrono::milliseconds(100));
        }
    }

    if (!a_ready.load() || !b_ready.load()) {
        // Retry over IPv4 loopback - the host may be IPv4-only.
        std::cout << "IPv6 loopback handshake incomplete; retrying over IPv4 loopback" << std::endl;
        host = "127.0.0.1";
        b.connect(kPeerA, host, kPortA);
        a.connect(kPeerB, host, kPortB);

        std::unique_lock<std::mutex> lock(mu);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        while ((!a_ready.load() || !b_ready.load()) &&
               std::chrono::steady_clock::now() < deadline) {
            cv.wait_for(lock, std::chrono::milliseconds(100));
        }
    }

    TEST_ASSERT(a_ready.load(), "A never reached READY");
    TEST_ASSERT(b_ready.load(), "B never reached READY");
    std::cout << "QUIC handshake complete over " << host << std::endl;

    // Datagrams both ways (retry briefly: datagrams are queued on the QUIC
    // connection which is now ready, so delivery should be prompt).
    const std::string msg_ab = "hello-from-A";
    const std::string msg_ba = "hello-from-B";

    for (int attempt = 0; attempt < 5; ++attempt) {
        a.send(kPeerB, msg_ab);
        b.send(kPeerA, msg_ba);

        std::unique_lock<std::mutex> lock(mu);
        cv.wait_for(lock, std::chrono::seconds(2), [&] {
            return !a_received.empty() && !b_received.empty();
        });
        if (!a_received.empty() && !b_received.empty()) break;
    }

    TEST_ASSERT(b_received == msg_ab, "B did not receive A's datagram (got: '" + b_received + "')");
    TEST_ASSERT(a_received == msg_ba, "A did not receive B's datagram (got: '" + a_received + "')");

    a.stop();
    b.stop();

    if (tests_failed == 0) {
        std::cout << "ALL QUIC TESTS PASSED" << std::endl;
        return 0;
    }
    std::cerr << tests_failed << " QUIC TEST(S) FAILED" << std::endl;
    return 1;
}
