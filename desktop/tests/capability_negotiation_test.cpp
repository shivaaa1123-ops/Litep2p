// capability_negotiation_test.cpp — Network OS Phase 2 verification.
//
// Covers (phase file §9):
//   1. Capability codec: encode/decode round-trip, unknown-field tolerance,
//      malformed rejection, oversized rejection.
//   2. Version intersect: compatible + incompatible ranges.
//   3. Privacy: no battery/device identifiers in the document.
//   4. Session bounds: pending-handshake cap enforced by SessionFacade.
//   5. Stable PeerID across endpoint (address) changes.
//   6. Session telemetry counters.

#include "networkos/Runtime.h"
#include "networkos/capability.h"
#include "networkos/session/SessionFacade.h"

#include <cstdint>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

int g_failures = 0;
int g_checks = 0;

#define TEST_ASSERT(cond, msg)                                        \
    do {                                                              \
        ++g_checks;                                                   \
        if (!(cond)) {                                                \
            std::cerr << "FAIL: " << msg << " (line " << __LINE__ << ")\n"; \
            ++g_failures;                                             \
        }                                                             \
    } while (0)

std::string tmp_dir(const std::string& tag) {
    const std::string base = std::string("/tmp/networkos_p2_") + tag;
    std::error_code ec;
    std::filesystem::remove_all(base, ec);
    std::filesystem::create_directories(base, ec);
    return base;
}

// Writes a hermetic config.json (signaling/discovery/NAT off) so test
// runtimes never register with a LAN signaling server or see foreign peers.
void write_hermetic_config(const std::string& dir) {
    std::ofstream f(dir + "/config.json", std::ios::trunc);
    f << "{\n"
      << "  \"communication\": {\"default_protocol\": \"UDP\",\n"
      << "    \"udp\": {\"enabled\": true, \"port\": 30001, \"buffer_size\": 65535}},\n"
      << "  \"peer_management\": {\"max_message_size\": 10485760},\n"
      << "  \"discovery\": {\"enabled\": false},\n"
      << "  \"security\": {\"noise_nk_protocol\": {\"enabled\": true, \"mandatory\": true}},\n"
      << "  \"nat_traversal\": {\"enabled\": false, \"mode\": \"off\", \"stun_enabled\": false},\n"
      << "  \"signaling\": {\"enabled\": false}\n"
      << "}\n";
    f.flush();
}

} // namespace

// ---------------------------------------------------------------------------
// 1. Codec round-trip (10 iterations with varied documents)
// ---------------------------------------------------------------------------
static void test_codec_roundtrip() {
    for (int i = 0; i < 10; ++i) {
        networkos::CapabilityDocument doc;
        doc.protocol_min = 1;
        doc.protocol_max = static_cast<uint8_t>(1 + (i % 3));
        doc.transports = static_cast<uint16_t>(networkos::kWireUdp | (i % 2 ? networkos::kWireTcp : 0));
        doc.max_frame_size = static_cast<uint32_t>(1024u * 1024u * (1 + (i % 10)));
        doc.max_object_size = static_cast<uint64_t>(64u * 1024u * 1024u * (1 + (i % 2)));
        doc.features = static_cast<uint8_t>(networkos::kFeatCarrier | (i % 2 ? networkos::kFeatChunking : 0));
        doc.carrier_class = static_cast<networkos::CarrierCapacityClass>(i % 4);
        doc.security_suites = networkos::kSecNoiseNK;
        if (i % 2) doc.namespaces.push_back("chat");

        const std::string b64 = networkos::cap::encodeB64(doc);
        TEST_ASSERT(!b64.empty(), "encodeB64 non-empty");
        networkos::CapabilityDocument out;
        TEST_ASSERT(networkos::cap::decodeB64(b64, out), "decodeB64 ok");
        TEST_ASSERT(out.protocol_min == doc.protocol_min, "pmin round-trip");
        TEST_ASSERT(out.protocol_max == doc.protocol_max, "pmax round-trip");
        TEST_ASSERT(out.transports == doc.transports, "transports round-trip");
        TEST_ASSERT(out.max_frame_size == doc.max_frame_size, "max_frame round-trip");
        TEST_ASSERT(out.max_object_size == doc.max_object_size, "max_object round-trip");
        TEST_ASSERT(out.features == doc.features, "features round-trip");
        TEST_ASSERT(out.carrier_class == doc.carrier_class, "carrier class round-trip");
        TEST_ASSERT(out.security_suites == doc.security_suites, "security round-trip");
        TEST_ASSERT(out.namespaces == doc.namespaces, "namespaces round-trip");
    }
    std::cout << "codec round-trip: 10 iterations ok\n";
}

// ---------------------------------------------------------------------------
// 2. Unknown-field tolerance + malformed rejection
// ---------------------------------------------------------------------------
static void test_unknown_fields_tolerated() {
    networkos::CapabilityDocument doc;
    doc.protocol_min = 1;
    doc.protocol_max = 2;
    const std::string raw = networkos::cap::encode(doc);
    TEST_ASSERT(!raw.empty(), "base encode ok");

    const std::string fixed = raw.substr(0, raw.size() - 2);  // strip opt_count u16
    std::string extended = fixed;
    extended.push_back(1); extended.push_back(0);  // opt_count=1 (u16 LE)
    extended.push_back(7);                                                // key=7 (unknown)
    extended.push_back(3); extended.push_back(0);                         // len=3 LE
    extended.push_back('a'); extended.push_back('b'); extended.push_back('c');

    networkos::CapabilityDocument out;
    TEST_ASSERT(networkos::cap::decode(extended, out), "unknown optional field skipped");
    TEST_ASSERT(out.protocol_min == 1 && out.protocol_max == 2, "fields intact");

    TEST_ASSERT(!networkos::cap::decode("", out), "empty rejected");
    TEST_ASSERT(!networkos::cap::decode(std::string(5000, 'x'), out), "oversized rejected");
    std::string bad_docver = raw;
    bad_docver[0] = 9;
    TEST_ASSERT(!networkos::cap::decode(bad_docver, out), "bad docver rejected");
    std::string truncated = raw.substr(0, raw.size() - 3);
    TEST_ASSERT(!networkos::cap::decode(truncated, out), "truncated rejected");

    std::cout << "unknown-field tolerance + malformed rejection ok\n";
}

// ---------------------------------------------------------------------------
// 3. Version intersect
// ---------------------------------------------------------------------------
static void test_version_intersect() {
    networkos::CapabilityDocument a;
    a.protocol_min = 1; a.protocol_max = 1;
    networkos::CapabilityDocument b;
    b.protocol_min = 1; b.protocol_max = 1;
    auto n = a.negotiated_with(b);
    TEST_ASSERT(n.compatible, "identical versions compatible");
    TEST_ASSERT(n.protocol_version == 1, "highest common = 1");

    networkos::CapabilityDocument old_peer;
    old_peer.protocol_min = 1; old_peer.protocol_max = 1;
    networkos::CapabilityDocument new_peer;
    new_peer.protocol_min = 1; new_peer.protocol_max = 3;
    auto n2 = old_peer.negotiated_with(new_peer);
    TEST_ASSERT(n2.compatible && n2.protocol_version == 1, "intersect to 1");

    networkos::CapabilityDocument future;
    future.protocol_min = 5; future.protocol_max = 6;
    auto n3 = a.negotiated_with(future);
    TEST_ASSERT(!n3.compatible, "non-overlapping ranges incompatible");

    networkos::CapabilityDocument a2;
    a2.protocol_min = 1; a2.protocol_max = 4;
    networkos::CapabilityDocument b2;
    b2.protocol_min = 2; b2.protocol_max = 3;
    auto n4 = a2.negotiated_with(b2);
    TEST_ASSERT(n4.compatible && n4.protocol_version == 3, "highest common = 3");

    std::cout << "version intersect ok\n";
}

// ---------------------------------------------------------------------------
// 4. Privacy: no battery/device identifiers in the document
// ---------------------------------------------------------------------------
static void test_privacy_no_identifiers() {
    networkos::CapabilityDocument doc;
    const std::string raw = networkos::cap::encode(doc);
    for (const char* banned : {"battery", "model", "manufacturer", "bssid", "android_id", "serial"}) {
        TEST_ASSERT(raw.find(banned) == std::string::npos,
                    (std::string("no '") + banned + "' in capability document").c_str());
    }
    std::cout << "privacy: no device identifiers in capability document\n";
}

// ---------------------------------------------------------------------------
// 5. Session bounds + telemetry (SessionFacade)
// ---------------------------------------------------------------------------
static void test_session_bounds() {
    // Pending-handshake cap.
    networkos::SessionFacade::Bounds tight;
    tight.max_pending_handshakes = 1;
    networkos::SessionFacade facade_tight(nullptr, tight);
    facade_tight.onPeerState("peer-a", "CONNECTING");
    TEST_ASSERT(facade_tight.connect("peer-b", "127.0.0.1:1") == networkos::Result::kBusy,
                "pending-handshake cap returns BUSY");

    // Active-session cap.
    networkos::SessionFacade::Bounds active_tight;
    active_tight.max_active_sessions = 1;
    active_tight.max_pending_handshakes = 8;
    networkos::SessionFacade facade_active(nullptr, active_tight);
    facade_active.onPeerState("peer-a", "READY");
    TEST_ASSERT(facade_active.connect("peer-b", "127.0.0.1:1") == networkos::Result::kBusy,
                "active-session cap returns BUSY");

    // Handshake timeout: a peer stuck in CONNECTING beyond the timeout is
    // failed by the next event-driven check (no timer).
    networkos::SessionFacade::Bounds timeouts;
    timeouts.handshake_timeout_ms = 1;   // 1 ms
    networkos::SessionFacade facade_to(nullptr, timeouts);
    (void)facade_to.connect("peer-a", "127.0.0.1:1");  // marks CONNECTING, started=now
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    facade_to.onPeerState("peer-a", "HANDSHAKING");    // triggers checkTimeoutsLocked_
    auto tel_to = facade_to.telemetry();
    TEST_ASSERT(tel_to.handshake_failed_total == 1, "slow handshake timed out");
    TEST_ASSERT(tel_to.connect_failed_total == 1, "timeout counted as connect failure");
    TEST_ASSERT(tel_to.pending_handshakes == 0, "timed-out peer no longer pending");

    // Handshake latency + session duration telemetry.
    networkos::SessionFacade facade_metrics(nullptr, networkos::SessionFacade::Bounds{});
    facade_metrics.onHandshakeStarted("peer-a");
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    facade_metrics.onHandshakeSucceeded("peer-a");
    auto tm = facade_metrics.telemetry();
    TEST_ASSERT(tm.handshake_latency_count == 1 && tm.avgHandshakeLatencyMs() >= 1,
                "handshake latency measured");
    facade_metrics.onPeerState("peer-a", "READY");
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    facade_metrics.onPeerState("peer-a", "DISCONNECTED");
    auto td = facade_metrics.telemetry();
    TEST_ASSERT(td.session_duration_count == 1 && td.avgSessionDurationMs() >= 1,
                "session duration measured");
    TEST_ASSERT(td.avgHandshakeLatencyMs() >= 1, "latency avg present in JSON");
    TEST_ASSERT(facade_metrics.telemetryJson().find("handshake_latency_avg_ms") != std::string::npos,
                "latency avg in telemetry JSON");

    std::cout << "session bounds + timeouts + telemetry ok\n";
}

// ---------------------------------------------------------------------------
// 6. Stable PeerID across endpoint (address) changes
// ---------------------------------------------------------------------------
static void test_stable_peerid_across_address_change() {
    const std::string dir = tmp_dir("addr");
    write_hermetic_config(dir);
    std::string first_id;
    // Three "network change" cycles: each is a fresh runtime on a different
    // listen port (port change == endpoint change). The LOCAL identity must
    // never change (endpoints are temporary, identity stable — §74).
    for (int i = 0; i < 3; ++i) {
        auto rt = networkos::createRuntime();
        networkos::RuntimeConfig cfg;
        cfg.files_dir = dir;
        cfg.listen_port = 34002 + i;
        cfg.enable_discovery = false;
        cfg.comms_mode = "UDP";
        TEST_ASSERT(rt->start(cfg) == networkos::Result::kOk, "runtime start");
        const std::string id = rt->peerId();
        TEST_ASSERT(!id.empty(), "peer id resolved");
        if (first_id.empty()) {
            first_id = id;
        } else {
            TEST_ASSERT(id == first_id, "PeerID unchanged across network changes");
        }
        TEST_ASSERT(rt->stop() == networkos::Result::kOk, "runtime stop");
    }
    std::cout << "stable PeerID across network (endpoint) changes ok\n";
}

int main() {
    test_codec_roundtrip();
    test_unknown_fields_tolerated();
    test_version_intersect();
    test_privacy_no_identifiers();
    test_session_bounds();
    test_stable_peerid_across_address_change();

    std::cout << (g_failures == 0 ? "PASS" : "FAIL") << ": " << g_checks
              << " checks, " << g_failures << " failure(s)\n";
    return g_failures == 0 ? 0 : 1;
}
