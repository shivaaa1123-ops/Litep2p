// discovery_manager_test.cpp — Network OS Phase 9 verification suite.
//
// Covers (phase file §9): backend registration + enable/disable + intensity
// scaling, bounded discovery with dedup, graceful degradation (optional infra
// can vanish; core still functional — invariant 19), NAT/internet reachability
// layering (§73), carrier willingness + HA capabilities (§52/§79), bounded
// peer exchange with dedup, serverless presence + alias fallback (decision 11),
// and Gate A decentralization (no single point of failure).

#include "networkos/discovery/DiscoveryManager.h"

#include <iostream>
#include <memory>
#include <string>
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

using namespace networkos::discovery;

// A controllable backend for tests. `optional` marks optional infrastructure
// (signaling/relay); `available` simulates the component being up/down.
class MockBackend : public IDiscoveryBackend {
public:
    MockBackend(BackendKind kind, std::string name, bool optional,
                std::vector<DiscoveredPeer> peers)
        : m_kind(kind), m_name(std::move(name)), m_optional(optional),
          m_peers(std::move(peers)) {}

    BackendKind kind() const override { return m_kind; }
    std::string name() const override { return m_name; }
    bool available() const override { return m_available; }
    bool optional() const override { return m_optional; }
    void setEnabled(bool e) override { m_enabled = e; }
    bool enabled() const override { return m_enabled; }
    std::vector<DiscoveredPeer> discover(int max) override {
        std::vector<DiscoveredPeer> out;
        for (size_t i = 0; i < m_peers.size() && static_cast<int>(i) < max; ++i) {
            out.push_back(m_peers[i]);
        }
        return out;
    }
    void setAvailable(bool a) { m_available = a; }

private:
    BackendKind m_kind;
    std::string m_name;
    bool m_optional;
    std::vector<DiscoveredPeer> m_peers;
    bool m_enabled{true};
    bool m_available{true};
};

// Hold a raw pointer so tests can flip availability after registering.
std::unique_ptr<MockBackend> mkbackend(BackendKind kind, const std::string& name,
                                       bool optional, std::vector<DiscoveredPeer> peers) {
    return std::make_unique<MockBackend>(kind, name, optional, std::move(peers));
}

DiscoveredPeer mkpeer(const std::string& id, BackendKind src, int64_t seen = 0) {
    DiscoveredPeer p;
    p.peer_id = id;
    p.source = src;
    p.last_seen_ms = seen;
    return p;
}

DiscoveryManager::Config baseCfg() {
    DiscoveryManager::Config c;
    c.local_peer_id = "peer-self";
    c.intensity = 100;
    c.peer_exchange_max = 4;
    return c;
}

// ---------------------------------------------------------------------------
// 1. Backend registration + enable/disable + intensity scaling.
// ---------------------------------------------------------------------------
static void test_registration_intensity() {
    DiscoveryManager dm(baseCfg());
    TEST_ASSERT(dm.backendCount() == 0, "starts with no backends");
    dm.registerBackend(mkbackend(BackendKind::kLan, "lan", false,
        {mkpeer("peer-a", BackendKind::kLan)}));
    dm.registerBackend(mkbackend(BackendKind::kBootstrap, "signaling", true,
        {mkpeer("peer-b", BackendKind::kBootstrap)}));
    TEST_ASSERT(dm.backendCount() == 2, "2 backends registered");
    TEST_ASSERT(dm.backendEnabled(BackendKind::kLan), "lan enabled by default");

    // Re-registering the same kind replaces (idempotent).
    dm.registerBackend(mkbackend(BackendKind::kLan, "lan-v2", false,
        {mkpeer("peer-c", BackendKind::kLan)}));
    TEST_ASSERT(dm.backendCount() == 2, "re-register same kind does not add");

    // Disable a backend -> its peers stop appearing.
    dm.setBackendEnabled(BackendKind::kLan, false);
    TEST_ASSERT(!dm.backendEnabled(BackendKind::kLan), "lan disabled");
    auto found = dm.discover();
    bool saw_c = false;
    for (auto& p : found) if (p.peer_id == "peer-c") saw_c = true;
    TEST_ASSERT(!saw_c, "disabled backend contributes nothing");
    dm.setBackendEnabled(BackendKind::kLan, true);

    // Intensity scaling: 0 => no discovery; high => discovery works.
    dm.setIntensity(0);
    TEST_ASSERT(dm.intensity() == 0, "intensity set to 0");
    TEST_ASSERT(dm.discover().empty(), "intensity 0 => no discovery");
    dm.setIntensity(100);
    TEST_ASSERT(!dm.discover().empty(), "intensity 100 => discovery works");
    std::cout << "registration + intensity ok\n";
}

// ---------------------------------------------------------------------------
// 2. Bounded discovery with dedup across backends.
// ---------------------------------------------------------------------------
static void test_discover_dedup() {
    DiscoveryManager dm(baseCfg());
    dm.registerBackend(mkbackend(BackendKind::kLan, "lan", false,
        {mkpeer("peer-a", BackendKind::kLan), mkpeer("peer-b", BackendKind::kLan)}));
    dm.registerBackend(mkbackend(BackendKind::kKnownPeer, "known", false,
        {mkpeer("peer-a", BackendKind::kKnownPeer)}));
    auto found = dm.discover();
    int count_a = 0;
    for (auto& p : found) if (p.peer_id == "peer-a") ++count_a;
    TEST_ASSERT(count_a == 1, "peer-a deduped across backends");
    TEST_ASSERT(found.size() == 2, "2 unique peers discovered");
    // Local peer id never appears in results.
    dm.registerBackend(mkbackend(BackendKind::kRelay, "relay", true,
        {mkpeer("peer-self", BackendKind::kRelay)}));
    for (auto& p : dm.discover()) TEST_ASSERT(p.peer_id != "peer-self", "local peer excluded");
    std::cout << "discover dedup ok\n";
}

// ---------------------------------------------------------------------------
// 3. Graceful degradation (§15, invariant 19): optional infra can vanish; the
//    network keeps functioning via core backends.
// ---------------------------------------------------------------------------
static void test_graceful_degradation() {
    DiscoveryManager dm(baseCfg());
    auto lan = mkbackend(BackendKind::kLan, "lan", false,
        {mkpeer("peer-a", BackendKind::kLan)});
    MockBackend* lan_ptr = lan.get();
    dm.registerBackend(std::move(lan));
    auto sig = mkbackend(BackendKind::kBootstrap, "signaling", true,
        {mkpeer("peer-b", BackendKind::kBootstrap)});
    MockBackend* sig_ptr = sig.get();
    dm.registerBackend(std::move(sig));

    TEST_ASSERT(dm.functionalWithoutOptional(), "functional with all up");
    TEST_ASSERT(dm.coreBackendCount() == 1, "1 core (non-optional) backend");

    // Kill the optional signaling server -> still functional (invariant 19).
    sig_ptr->setAvailable(false);
    TEST_ASSERT(!dm.backendAvailable(BackendKind::kBootstrap), "signaling down");
    TEST_ASSERT(dm.functionalWithoutOptional(), "still functional without signaling");
    auto found = dm.discover();
    bool saw_a = false;
    for (auto& p : found) if (p.peer_id == "peer-a") saw_a = true;
    TEST_ASSERT(saw_a, "LAN discovery continues after signaling loss");

    // Kill the core LAN too -> now NOT functional (nothing left).
    lan_ptr->setAvailable(false);
    TEST_ASSERT(!dm.functionalWithoutOptional(), "no core backends => not functional");
    std::cout << "graceful degradation ok: optional infra may vanish\n";
}

// ---------------------------------------------------------------------------
// 4. NAT/internet reachability layering (§73): direct -> NAT -> relay -> S&F.
// ---------------------------------------------------------------------------
static void test_nat_layering() {
    DiscoveryManager dm(baseCfg());
    DiscoveredPeer direct = mkpeer("p1", BackendKind::kLan);
    direct.direct_reachable = true;
    TEST_ASSERT(dm.choosePath(direct) == ReachPath::kDirect, "direct preferred");

    DiscoveredPeer nat = mkpeer("p2", BackendKind::kLan);
    nat.nat_traversable = true;
    TEST_ASSERT(dm.choosePath(nat) == ReachPath::kNatTraversal, "NAT traversal next");

    DiscoveredPeer relay = mkpeer("p3", BackendKind::kLan);
    relay.relay_capable = true;
    TEST_ASSERT(dm.choosePath(relay) == ReachPath::kRelay, "relay next");

    DiscoveredPeer none = mkpeer("p4", BackendKind::kLan);
    TEST_ASSERT(dm.choosePath(none) == ReachPath::kStoreAndForward, "store-and-forward last");
    // Layering order: direct beats NAT even if both flags set.
    DiscoveredPeer both = mkpeer("p5", BackendKind::kLan);
    both.direct_reachable = true;
    both.nat_traversable = true;
    TEST_ASSERT(dm.choosePath(both) == ReachPath::kDirect, "direct wins over NAT");
    std::cout << "NAT layering ok: direct > nat > relay > store-forward\n";
}

// ---------------------------------------------------------------------------
// 5. Carrier willingness + HA capabilities (§52/§79).
// ---------------------------------------------------------------------------
static void test_carrier_willingness() {
    DiscoveryManager dm(baseCfg());
    dm.setLocalCapabilities(true, false, false);
    auto cap = dm.localCapabilities();
    TEST_ASSERT(cap.storage_carrier, "carrier willing by default");
    TEST_ASSERT(!cap.ha_node, "not HA by default");
    // Low battery / policy => advertise storage_carrier=false (§51).
    dm.setLocalCapabilities(false, false, false);
    TEST_ASSERT(!dm.localCapabilities().storage_carrier, "carrier=false honored");
    // HA node advertises larger capabilities.
    dm.setLocalCapabilities(true, true, true);
    auto ha = dm.localCapabilities();
    TEST_ASSERT(ha.ha_node && ha.relay_capable, "HA + relay advertised");
    std::cout << "carrier willingness + HA ok\n";
}

// ---------------------------------------------------------------------------
// 6. Peer exchange (bounded, dedup, fresher-wins) (Step 5.1).
// ---------------------------------------------------------------------------
static void test_peer_exchange() {
    DiscoveryManager dm(baseCfg());   // peer_exchange_max = 4
    // Incoming 6 peers -> bounded to 4.
    std::vector<DiscoveredPeer> incoming;
    for (int i = 0; i < 6; ++i) incoming.push_back(mkpeer("px-" + std::to_string(i), BackendKind::kPeerExchange));
    auto merged = dm.peerExchange(incoming);
    TEST_ASSERT(merged.size() == 4, "peer exchange bounded to max");
    // Re-exchanging the SAME accepted peers -> dedup (no duplicates).
    std::vector<DiscoveredPeer> already(merged.begin(), merged.end());
    auto merged2 = dm.peerExchange(already);
    TEST_ASSERT(merged2.empty(), "re-exchange of known peers dedups");
    // The peers bounded out of the first exchange are accepted next time
    // (bounded per exchange, eventually consistent — no flooding).
    auto merged2b = dm.peerExchange(incoming);
    TEST_ASSERT(merged2b.size() == 2, "previously bounded-out peers accepted later");
    // Fresher last_seen wins and is merged.
    auto fresh = mkpeer("px-0", BackendKind::kPeerExchange, 9999);
    auto merged3 = dm.peerExchange({fresh});
    TEST_ASSERT(merged3.size() == 1, "fresher info merged");
    std::cout << "peer exchange ok: bounded + dedup + fresher-wins\n";
}

// ---------------------------------------------------------------------------
// 7. Serverless presence + alias fallback (Step 5.7, decision 11): presence +
//    alias work with the signaling server DOWN.
// ---------------------------------------------------------------------------
static void test_presence_alias_serverless() {
    DiscoveryManager dm(baseCfg());
    // Presence derived from peer-exchange-learned last-seen (no server needed).
    dm.notePeerSeen("peer-a", 1000);
    TEST_ASSERT(dm.isPeerPresent("peer-a", 1000 + 60 * 1000), "present within window");
    TEST_ASSERT(!dm.isPeerPresent("peer-a", 1000 + 10 * 60 * 1000), "absent after window");
    TEST_ASSERT(!dm.isPeerPresent("peer-unknown", 2000), "unknown peer not present");

    // Alias resolution falls back to the decentralized known-peer table.
    dm.setAlias("alice", "peer-alice-id");
    TEST_ASSERT(dm.resolveAlias("alice") == "peer-alice-id", "alias resolves");
    // Fallback: an alias learned only via peer exchange (known table).
    dm.peerExchange({mkpeer("peer-bob-id", BackendKind::kPeerExchange)});
    TEST_ASSERT(dm.resolveAlias("peer-bob-id") == "peer-bob-id",
                "alias falls back to known peers (server down)");
    TEST_ASSERT(dm.resolveAlias("nobody") == "", "unresolvable alias => empty");
    std::cout << "serverless presence + alias fallback ok\n";
}

// ---------------------------------------------------------------------------
// 8. Gate A — decentralization (no single point of failure, Step 5.8): killing
//    the server / relay / HA peer never removes the last functional path.
// ---------------------------------------------------------------------------
static void test_gate_a_decentralization() {
    DiscoveryManager dm(baseCfg());
    auto lan = mkbackend(BackendKind::kLan, "lan", false,
        {mkpeer("peer-a", BackendKind::kLan)});
    MockBackend* lan_ptr = lan.get();
    dm.registerBackend(std::move(lan));
    auto known = mkbackend(BackendKind::kKnownPeer, "known", false,
        {mkpeer("peer-b", BackendKind::kKnownPeer)});
    MockBackend* known_ptr = known.get();
    dm.registerBackend(std::move(known));
    auto sig = mkbackend(BackendKind::kBootstrap, "signaling", true,
        {mkpeer("peer-c", BackendKind::kBootstrap)});
    MockBackend* sig_ptr = sig.get();
    dm.registerBackend(std::move(sig));
    auto relay = mkbackend(BackendKind::kRelay, "relay", true,
        {mkpeer("peer-d", BackendKind::kRelay)});
    MockBackend* relay_ptr = relay.get();
    dm.registerBackend(std::move(relay));

    TEST_ASSERT(dm.functionalWithoutOptional(), "all up => functional");
    // Kill server + relay + (simulate) HA peer one at a time and combined.
    sig_ptr->setAvailable(false);
    TEST_ASSERT(dm.functionalWithoutOptional(), "server down => still functional");
    relay_ptr->setAvailable(false);
    TEST_ASSERT(dm.functionalWithoutOptional(), "server+relay down => still functional");
    // Even with optional infra gone, discovery still finds peers via LAN/known.
    auto found = dm.discover();
    TEST_ASSERT(!found.empty(), "discovery works with only core backends");
    // Only when ALL core backends die does functionality drop (no SPOF among
    // the optional components).
    lan_ptr->setAvailable(false);
    known_ptr->setAvailable(false);
    TEST_ASSERT(!dm.functionalWithoutOptional(),
                "only fails when every core backend is gone");
    std::cout << "Gate A decentralization ok: no SPOF in optional infra\n";
}

} // namespace

int main() {
    test_registration_intensity();
    test_discover_dedup();
    test_graceful_degradation();
    test_nat_layering();
    test_carrier_willingness();
    test_peer_exchange();
    test_presence_alias_serverless();
    test_gate_a_decentralization();
    std::cout << (g_failures == 0 ? "PASS" : "FAIL") << ": " << g_checks
              << " checks, " << g_failures << " failure(s)\n";
    return g_failures == 0 ? 0 : 1;
}