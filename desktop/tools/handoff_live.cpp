// handoff_live.cpp — Network OS Phase 4 live two-peer handoff tool.
//
// Proves S -> C durable handoff over a real encrypted session (D offline):
//   - carrier role: starts the engine, advertises its signing key, accepts
//     offers, durably commits, sends STORED_ACK.
//   - sender role: connects, registers the carrier key, stores + offers an
//     object, waits for a validated STORED_ACK (DURABILITY_REACHED).
//   - sender --verify: after a simulated restart, reopens the store and
//     asserts the lease + DURABILITY_REACHED state survived (kill-proof).
//
// Usage:
//   handoff_live --role carrier --id C --port 33001 --files-dir /tmp/c \
//       --config config.json --carrier-pk-file /tmp/c_pk.hex
//   handoff_live --role sender --id S --port 33002 --files-dir /tmp/s \
//       --config config.json --target-id C --target-netid 127.0.0.1:33001 \
//       --carrier-pk-file /tmp/c_pk.hex --sender-pk-file /tmp/s_pk.hex
//   handoff_live --role sender --id S --files-dir /tmp/s --verify 1 --marker <id>
#include "networkos/handoff/HandoffManager.h"
#include "networkos/object/envelope.h"
#include "networkos/objectstore/ObjectStore.h"
#include "session_manager.h"
#include "config_manager.h"

#include "message_types.h"

#include <sodium.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

namespace {

std::string get_arg(int argc, char** argv, const char* key) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == key) return argv[i + 1];
    }
    return {};
}

void mark(const std::string& s) {
    std::cout << s << std::endl;
    std::cout.flush();
}

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string to_hex(const std::string& raw) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    for (unsigned char c : raw) {
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0x0F]);
    }
    return out;
}

bool write_file(const std::string& path, const std::string& content) {
    if (path.empty()) return true;
    std::ofstream f(path, std::ios::trunc);
    f << content;
    return f.good();
}

bool read_file(const std::string& path, std::string& out) {
    if (path.empty()) return false;
    std::ifstream f(path);
    if (!f.good()) return false;
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return true;
}

bool from_hex(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2) return false;
    out.resize(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int hi = nib(hex[i * 2]);
        const int lo = nib(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

} // namespace
int main(int argc, char** argv) {
    (void)sodium_init();
    const std::string role = get_arg(argc, argv, "--role");
    const std::string self_id = get_arg(argc, argv, "--id");
    const std::string self_port_s = get_arg(argc, argv, "--port");
    const std::string files_dir = get_arg(argc, argv, "--files-dir");
    const std::string config_path = get_arg(argc, argv, "--config");
    const std::string target_id = get_arg(argc, argv, "--target-id");
    const std::string target_netid = get_arg(argc, argv, "--target-netid");
    const std::string carrier_pk_file = get_arg(argc, argv, "--carrier-pk-file");
    const std::string sender_pk_file = get_arg(argc, argv, "--sender-pk-file");
    const bool verify_mode = get_arg(argc, argv, "--verify") == "1";
    const int self_port = self_port_s.empty() ? 33001 : std::atoi(self_port_s.c_str());

    if (role.empty() || self_id.empty() || files_dir.empty()) {
        std::cerr << "handoff_live: --role --id --files-dir required\n";
        return 2;
    }
    (void)ConfigManager::getInstance().loadConfig(config_path);
    if (verify_mode && role != "sender") {
        std::cerr << "handoff_live: --verify requires --role sender\n";
        return 2;
    }

    // ---- engine + store + handoff wiring (same shape as NetworkRuntime) ----
    SessionManager sm;
    networkos::ObjectStore store;
    {
        networkos::ObjectStore::Options opt;
        opt.path = files_dir + "/networkos.sqlite";
        if (!store.open(opt)) {
            std::cerr << "handoff_live: cannot open store at " << opt.path << "\n";
            return 2;
        }
    }

    // ---- sender --verify: restart-proof (no live handoff) ------------------
    if (verify_mode) {
        const std::string marker = get_arg(argc, argv, "--marker");
        networkos::ObjectMeta mo;
        networkos::ObjectId id;
        if (!networkos::ObjectId::fromHex(marker, id)) {
            std::cerr << "handoff_live: bad --marker " << marker << "\n";
            return 2;
        }
        if (store.getMeta(id, mo) != networkos::Result::kOk) {
            std::cerr << "handoff_live: object missing after restart\n";
            return 1;
        }
        std::vector<networkos::ObjectStore::LeaseInfo> leases;
        store.getLeases(id, leases);
        if (leases.empty()) {
            std::cerr << "handoff_live: no lease after restart\n";
            return 1;
        }
        std::cout << "RESTART_PROOF_OK state=" << static_cast<int>(mo.status)
                  << " leases=" << leases.size() << "\n";
        return mo.status == networkos::ObjectStatus::kDurabilityReached ? 0 : 1;
    }

    sm.start(self_port, [](const std::vector<Peer>&) {}, "UDP", self_id);

    // Local signing keys (the engine's origin-signing keypair).
    const auto keys = sm.get_local_signing_keys();
    if (keys.first.size() != 32 || keys.second.size() != 64) {
        std::cerr << "handoff_live: no local signing keys\n";
        sm.stop();
        return 2;
    }
    if (role == "carrier") {
        write_file(carrier_pk_file,
                   to_hex(std::string(keys.first.begin(), keys.first.end())));
        mark("CARRIER_READY");
    } else {
        write_file(sender_pk_file,
                   to_hex(std::string(keys.first.begin(), keys.first.end())));
    }

    networkos::handoff::HandoffManager::Config hcfg;
    hcfg.local_peer_id = self_id;
    networkos::handoff::HandoffManager handoff(&store, hcfg);
    handoff.setSendFn([&sm](const std::string& pid, MessageType type,
                            const std::string& payload) -> bool {
        return sm.send_handoff_frame(pid, type, payload);
    });
    handoff.setConnectedPeersFn([&sm]() -> std::vector<std::string> {
        return sm.getConnectedPeerIds();
    });
    handoff.setSigningKeysFns(
        [&]() { return std::make_pair(keys.first, keys.second); },
        [&sm](const std::string& pid) { return sm.get_peer_signing_key(pid); });
    std::atomic<bool> handoff_complete{false};
    handoff.setEventFn([&](const std::string& kind, const std::string&) {
        if (kind == "STORED_ACK_RECEIVED") handoff_complete.store(true);
        if (kind == "STORED_ACK_SENT") mark("CARRIER_STORED");
    });
    sm.set_handoff_frame_handler(
        [&](const std::string& pid, MessageType type, const std::string& payload) {
            handoff.onFrame(pid, type, payload);
        });

    // ---- sender flow -------------------------------------------------------
    if (role == "sender") {
        // Register the carrier's signing key (trust anchor for STORED_ACK).
        std::string carrier_pk_hex;
        if (!read_file(carrier_pk_file, carrier_pk_hex)) {
            std::cerr << "handoff_live: cannot read carrier pk file\n";
            sm.stop();
            return 2;
        }
        std::vector<uint8_t> carrier_pk;
        if (!from_hex(carrier_pk_hex, carrier_pk) || carrier_pk.size() != 32) {
            std::cerr << "handoff_live: bad carrier pk\n";
            sm.stop();
            return 2;
        }
        sm.overlay_register_peer_signing_key(target_id, carrier_pk);

        if (target_netid.empty()) {
            std::cerr << "handoff_live: sender needs --target-netid\n";
            sm.stop();
            return 2;
        }
        sm.addPeer(target_id, target_netid);
        sm.connectToPeer(target_id);
        // Wait until the peer is READY (getConnectedPeerIds reflects the FSM).
        bool ready = false;
        for (int i = 0; i < 200 && !ready; ++i) {
            for (const auto& pid : sm.getConnectedPeerIds()) {
                if (pid == target_id) { ready = true; break; }
            }
            if (!ready) std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (!ready) {
            std::cerr << "handoff_live: sender never reached READY with " << target_id << "\n";
            sm.stop();
            return 1;
        }

        // Build + sign the object envelope, then store + offer.
        networkos::obj::NetworkObject obj;
        obj.origin.network_id = "chatp2p-mesh";
        obj.origin.namespace_id = "chat";
        obj.origin.object_type = "message";
        obj.origin.origin = self_id;
        obj.origin.destination = "peer-d-offline";
        obj.origin.created_at_ms = now_ms();
        obj.origin.ttl_ms = 7LL * 24 * 3600 * 1000;
        const std::string payload = "live-handoff-payload";
        obj.origin.payload_size = payload.size();
        obj.origin.payload_hash = networkos::obj::compute_payload_hash(payload);
        obj.payload = payload;
        networkos::ObjectId id = networkos::ObjectId::generate("chatp2p-mesh", self_id);
        obj.origin.object_id_hex = id.toHex();
        if (!networkos::obj::sign_object(obj, keys.second.data(), keys.first.data())) {
            std::cerr << "handoff_live: sign failed\n";
            sm.stop();
            return 1;
        }
        networkos::ObjectMeta meta;
        meta.id = id;
        meta.namespace_id = "chat";
        meta.origin = self_id;
        meta.destination = "peer-d-offline";
        meta.object_type = "message";
        meta.created_at_ms = obj.origin.created_at_ms;
        meta.ttl_ms = obj.origin.ttl_ms;
        meta.priority = 1;

        const networkos::Result rc =
            handoff.storeAndOffer(meta, networkos::obj::serialize(obj));
        if (rc != networkos::Result::kOk) {
            std::cerr << "handoff_live: storeAndOffer rc="
                      << static_cast<int>(rc) << "\n";
            sm.stop();
            return 1;
        }
        mark("OFFERED " + id.toHex());

        bool done = false;
        for (int i = 0; i < 200 && !done; ++i) {
            if (handoff_complete.load()) done = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (!done) {
            std::cerr << "handoff_live: no STORED_ACK within deadline\n";
            sm.stop();
            return 1;
        }
        mark("HANDOFF_COMPLETE " + id.toHex());
        sm.stop();
        return 0;
    }

    // ---- carrier: idle and serve ------------------------------------------
    // Register the sender's signing key once its pk file appears (out-of-band
    // trust anchor exchange — Phase 5 automates this).
    for (int i = 0; i < 400; ++i) {
        std::string spk_hex;
        std::vector<uint8_t> spk;
        if (read_file(sender_pk_file, spk_hex) && from_hex(spk_hex, spk) &&
            spk.size() == 32) {
            sm.overlay_register_peer_signing_key(target_id, spk);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    sm.stop();
    return 0;
}

