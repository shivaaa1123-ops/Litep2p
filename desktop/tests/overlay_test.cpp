/*
 * overlay_test.cpp — end-to-end tests for the multi-hop overlay (LPX2, B2).
 *
 * The full onion stack is exercised in-memory: OverlayRouter instances
 * (origin Alice, relays R1/R2, destination Bob) wired together with direct
 * function calls, mirroring exactly what the session send path does in the
 * real engine. No sockets, no flakiness — deterministic hop-by-hop coverage:
 *
 *   1. Frame codec round-trip + strict-parse rejection
 *   2. Sealed-box confidentiality (wrong key cannot open)
 *   3. 2-relay onion delivery (relays see only forwarding)
 *   4. End-to-end ACK with bounded reliability
 *   5. Mailbox store-and-forward for offline destinations
 *   6. Loop/duplicate frame drops (frame-id dedup)
 *   7. Replay protection (stale sealed payloads rejected)
 *   8. Relay advertisement learning
 *   9. TTL enforcement
 */

#include "overlay_frame.h"
#include "overlay_mailbox.h"
#include "overlay_router.h"
#include "test_harness.h"

#include <sodium.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

using overlay::OverlayRouter;

namespace {

struct KeyPair {
    std::vector<uint8_t> pk, sk;
};

KeyPair gen_key() {
    KeyPair kp;
    kp.pk.resize(crypto_box_PUBLICKEYBYTES);
    kp.sk.resize(crypto_box_SECRETKEYBYTES);
    CHECK(crypto_box_keypair(kp.pk.data(), kp.sk.data()) == 0, "crypto_box_keypair");
    return kp;
}

// Phase B: Ed25519 signing keypair (32B pk, 64B sk).
struct SignKeyPair {
    std::vector<uint8_t> pk, sk;
};
SignKeyPair gen_sign_key() {
    SignKeyPair kp;
    kp.pk.resize(crypto_sign_PUBLICKEYBYTES);
    kp.sk.resize(crypto_sign_SECRETKEYBYTES);
    CHECK(crypto_sign_keypair(kp.pk.data(), kp.sk.data()) == 0, "crypto_sign_keypair");
    return kp;
}

// In-memory node: one router + delivery/status recording. send_fn pipes wire
// frames straight into the target router's on_frame (the same entry point the
// session uses), so the onion is traversed synchronously per hop.
struct Node {
    std::string id;
    KeyPair keys;
    std::unique_ptr<OverlayRouter> router;

    std::mutex mu;
    std::condition_variable cv;
    std::vector<std::pair<std::string, std::string>> delivered;  // (origin, payload)
    std::vector<std::pair<std::string, OverlayRouter::DeliveryStatus>> statuses;
    std::atomic<bool> connected{true};

    bool has_payload(const std::string& s) {
        std::lock_guard<std::mutex> lk(mu);
        for (auto& d : delivered) if (d.second == s) return true;
        return false;
    }
    size_t delivered_count() {
        std::lock_guard<std::mutex> lk(mu);
        return delivered.size();
    }
};

class Mesh {
public:
    // Shared key directory: mirrors the engine's NoiseKeyStore visibility.
    std::unordered_map<std::string, std::vector<uint8_t>> key_dir;

    Node* make(const std::string& id, bool relay_on,
               int ack_timeout_ms = 600, uint8_t hops = 2);
    Node* find(const std::string& id) {
        for (auto& n : nodes_) if (n->id == id) return n.get();
        return nullptr;
    }
    void seed_relays(Node* n, const std::vector<std::string>& relay_ids) {
        for (const auto& r : relay_ids) n->router->register_relay_candidate(r, 32, 4, true);
    }
    // Phase B: shared Ed25519 signing-key directory (identity trust anchors).
    std::unordered_map<std::string, std::vector<uint8_t>> sign_dir;
    ~Mesh() {
        for (auto& n : nodes_) n->router->stop();
    }
    Mesh() = default;
    Mesh(const Mesh&) = delete;
    Mesh& operator=(const Mesh&) = delete;

private:
    std::vector<std::unique_ptr<Node>> nodes_;
};

bool wait_for(Node* n, const std::string& payload, int timeout_ms) {
    std::unique_lock<std::mutex> lk(n->mu);
    return n->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] {
        for (auto& d : n->delivered) if (d.second == payload) return true;
        return false;
    });
}

bool wait_status(Node* n, OverlayRouter::DeliveryStatus st, int timeout_ms) {
    std::unique_lock<std::mutex> lk(n->mu);
    return n->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] {
        for (auto& s : n->statuses) if (s.second == st) return true;
        return false;
    });
}

Node* Mesh::make(const std::string& id, bool relay_on,
                 int ack_timeout_ms, uint8_t hops) {
    auto n = std::make_unique<Node>();
    n->id = id;
    n->keys = gen_key();
    key_dir[id] = n->keys.pk;
    const SignKeyPair s = gen_sign_key();
    sign_dir[id] = s.pk;

    OverlayRouter::Config cfg{};
    cfg.relay_enabled = relay_on;
    cfg.advertise_relay = false;  // tests register candidates explicitly
    cfg.default_hops = hops;
    cfg.ack_timeout_ms = ack_timeout_ms;
    cfg.max_send_attempts = 3;
    cfg.tick_interval_ms = 200;
    n->router = std::make_unique<OverlayRouter>(cfg);

    Node* raw = n.get();
    nodes_.push_back(std::move(n));

    raw->router->set_send_fn([this, raw](const std::string& to, const std::string& wire) {
        Node* dst = find(to);
        if (!dst) return false;
        dst->router->on_frame(raw->id, wire);
        return true;
    });
    raw->router->set_connect_fn([](const std::string&) {});
    raw->router->set_is_connected_fn([this](const std::string& peer) {
        Node* dst = find(peer);
        return dst && dst->connected.load();
    });
    raw->router->set_peer_key_fn([this](const std::string& pid) {
        auto it = key_dir.find(pid);
        return it == key_dir.end() ? std::vector<uint8_t>{} : it->second;
    });
    // Phase B: every node knows every peer's signing key (trust anchors).
    raw->router->set_peer_signing_key_fn([this](const std::string& pid) {
        auto it = sign_dir.find(pid);
        return it == sign_dir.end() ? std::vector<uint8_t>{} : it->second;
    });
    raw->router->set_deliver_fn([raw](const std::string& origin, const std::string& payload) {
        std::lock_guard<std::mutex> lk(raw->mu);
        raw->delivered.emplace_back(origin, payload);
        raw->cv.notify_all();
    });
    raw->router->set_delivery_cb([raw](const std::string& fid, OverlayRouter::DeliveryStatus st) {
        std::lock_guard<std::mutex> lk(raw->mu);
        raw->statuses.emplace_back(fid, st);
        raw->cv.notify_all();
    });
    raw->router->set_local_identity(raw->id, raw->keys.pk, raw->keys.sk);
    raw->router->set_local_signing_keys(s.pk, s.sk);
    raw->router->start();
    return raw;
}

} // namespace

int main() {
    CHECK(sodium_init() >= 0, "sodium_init");

    // ------------------------------------------------------------------
    // 1. Frame codec round-trip + strict-parse rejection
    // ------------------------------------------------------------------
    {
        uint8_t fid[overlay::kFrameIdSize];
        overlay::random_frame_id(fid);
        const std::string body = "\x01\x02\x03payload-bytes";
        const std::string wire = overlay::encode_frame(overlay::kFlagWantAck, 4, fid, body);

        overlay::OverlayFrameHeader hdr;
        std::string_view got_body;
        CHECK(overlay::decode_frame(wire, hdr, got_body), "frame decode ok");
        CHECK(hdr.flags == overlay::kFlagWantAck, "frame flags preserved");
        CHECK(hdr.ttl == 4, "frame ttl preserved");
        CHECK(std::string(got_body) == body, "frame body preserved");
        CHECK(overlay::frame_id_to_hex(fid).size() == 32, "frame id hex length");

        // Malformed inputs must be rejected, never crash.
        CHECK(!overlay::decode_frame("short", hdr, got_body), "short frame rejected");
        CHECK(!overlay::decode_frame("LPX1" + wire.substr(4), hdr, got_body), "wrong magic rejected");
    }

    // ------------------------------------------------------------------
    // 2. Sealed-box confidentiality: wrong key cannot open hop instructions
    // ------------------------------------------------------------------
    {
        const KeyPair alice = gen_key();
        const KeyPair mallory = gen_key();

        overlay::HopInstruction in;
        in.kind = overlay::HopKind::Forward;
        in.next_peer = "bob";
        in.inner = "nested-secret";
        const std::string sealed = overlay::seal_hop(alice.pk, in);
        CHECK(!sealed.empty(), "seal_hop produced body");

        overlay::HopInstruction out;
        CHECK(!overlay::open_hop(mallory.pk, mallory.sk, sealed, out),
              "mallory cannot open alice's sealed hop");
        CHECK(overlay::open_hop(alice.pk, alice.sk, sealed, out) && out.kind == in.kind &&
              out.next_peer == "bob" && out.inner == "nested-secret",
              "alice opens her sealed hop");
        CHECK(!overlay::open_hop(alice.pk, alice.sk, sealed + "XX", out),
              "trailing garbage rejected");
    }

    // ------------------------------------------------------------------
    // 3. 2-relay onion delivery: relays forward, never see the payload
    // ------------------------------------------------------------------
    {
        Mesh mesh;
        Node* alice = mesh.make("alice", false);
        Node* r1 = mesh.make("relay1", true);
        Node* r2 = mesh.make("relay2", true);
        Node* bob = mesh.make("bob", false);
        mesh.seed_relays(alice, {"relay1", "relay2"});
        mesh.seed_relays(bob, {"relay1", "relay2"});  // for the ACK reverse path

        std::string fid;
        const auto rc = alice->router->send("bob", "down with censorship", false, false, fid);
        CHECK(rc == OverlayRouter::SendResult::Ok, "onion send accepted");
        CHECK(!fid.empty(), "frame id returned");

        // The send chain is synchronous: delivery already happened.
        CHECK(bob->has_payload("down with censorship"), "bob received payload");
        {
            std::lock_guard<std::mutex> lk(bob->mu);
            CHECK(!bob->delivered.empty() && bob->delivered.back().first == "alice",
                  "origin id preserved end-to-end");
        }

        // Relay accounting: both relays forwarded exactly once and delivered
        // nothing to their app layers (payload confidentiality at relays).
        CHECK(r1->router->stats().relayed_total == 1, "relay1 forwarded once");
        CHECK(r2->router->stats().relayed_total == 1, "relay2 forwarded once");
        CHECK(r1->delivered_count() == 0 && r2->delivered_count() == 0,
              "relays never deliver app payloads");
        CHECK(bob->router->stats().delivered_total == 1, "bob delivered_total == 1");
    }

    // ------------------------------------------------------------------
    // 4. End-to-end ACK with bounded reliability
    // ------------------------------------------------------------------
    {
        Mesh mesh;
        Node* alice = mesh.make("alice", false, 400);
        Node* r1 = mesh.make("relay1", true);
        Node* r2 = mesh.make("relay2", true);
        Node* bob = mesh.make("bob", false, 400);
        mesh.seed_relays(alice, {"relay1", "relay2"});
        mesh.seed_relays(bob, {"relay1", "relay2"});

        std::string fid;
        const auto rc = alice->router->send("bob", "reliable message", true, false, fid);
        CHECK(rc == OverlayRouter::SendResult::Ok, "reliable send accepted");
        CHECK(bob->has_payload("reliable message"), "bob received reliable message");

        // The ACK travels back through the relay path; wait for the origin's
        // delivery callback.
        CHECK(wait_status(alice, OverlayRouter::DeliveryStatus::Delivered, 3000),
              "origin got Delivered status via overlay ACK");
        CHECK(alice->router->stats().acked_total == 1, "ack accounted");
    }

    // ------------------------------------------------------------------
    // 5. Mailbox: store-and-forward for an offline destination
    // ------------------------------------------------------------------
    {
        Mesh mesh;
        Node* alice = mesh.make("alice", false);
        Node* r1 = mesh.make("relay1", true);
        Node* r2 = mesh.make("relay2", true);
        Node* bob = mesh.make("bob", false);
        mesh.seed_relays(alice, {"relay1", "relay2"});

        // Bob is offline; Alice drops the sealed blob in the terminal relay's
        // mailbox (path shuffling decides WHICH relay terminates the path).
        std::string fid;
        const auto rc = alice->router->send("bob", "while you were away", false, true, fid);
        CHECK(rc == OverlayRouter::SendResult::Ok, "mailbox send accepted");
        CHECK(!bob->has_payload("while you were away"), "offline bob got nothing yet");

        const uint64_t stored1 = r1->router->stats().mailbox_stored_total;
        const uint64_t stored2 = r2->router->stats().mailbox_stored_total;
        CHECK(stored1 + stored2 == 1, "exactly one mailbox store happened");
        Node* const holder = (stored1 == 1) ? r1 : r2;

        // Bob comes online and collects from the holding relay.
        bob->router->pickup_mailbox(holder->id);
        CHECK(bob->has_payload("while you were away"), "bob collected mailbox blob");
        CHECK(holder->router->stats().mailbox_picked_total == 1, "mailbox picked once");
        {
            std::lock_guard<std::mutex> lk(bob->mu);
            CHECK(!bob->delivered.empty() && bob->delivered.back().first == "alice",
                  "mailbox delivery carries true origin");
        }
    }

    // ------------------------------------------------------------------
    // 6. Loop/duplicate protection: same frame id forwarded twice is dropped
    // ------------------------------------------------------------------
    {
        Mesh mesh;
        Node* r1 = mesh.make("relay1", true);
        Node* bob = mesh.make("bob", false);

        // Build a Forward(R1 -> bob) frame by hand.
        overlay::HopInstruction fwd;
        fwd.kind = overlay::HopKind::Forward;
        fwd.next_peer = "bob";
        fwd.inner = overlay::seal_hop(mesh.key_dir["bob"], {});
        const std::string body = overlay::seal_hop(mesh.key_dir["relay1"], fwd);
        uint8_t fid[overlay::kFrameIdSize];
        overlay::random_frame_id(fid);
        const std::string wire = overlay::encode_frame(0, 4, fid, body);

        r1->router->on_frame("alice", wire);
        r1->router->on_frame("alice", wire);  // duplicate
        CHECK(r1->router->stats().relayed_total == 1, "duplicate forwarded only once");
        CHECK(r1->router->stats().dedup_drops_total == 1, "duplicate dropped by dedup");
    }

    // ------------------------------------------------------------------
    // 7. Replay protection: stale sealed payloads are rejected
    // ------------------------------------------------------------------
    {
        Mesh mesh;
        Node* bob = mesh.make("bob", false);

        // A sealed final payload created 20 minutes ago (window is 15 min).
        overlay::FinalPayload fp;
        fp.origin_peer_id = "alice";
        fp.created_ts_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()) - (20ull * 60 * 1000);
        fp.app_payload = "stale replay";
        const std::string inner = overlay::seal_final(mesh.key_dir["bob"], fp);

        overlay::HopInstruction term;
        term.kind = overlay::HopKind::Deliver;
        term.inner = inner;
        const std::string body = overlay::seal_hop(mesh.key_dir["bob"], term);
        uint8_t fid[overlay::kFrameIdSize];
        overlay::random_frame_id(fid);
        bob->router->on_frame("relay1", overlay::encode_frame(0, 4, fid, body));

        CHECK(!bob->has_payload("stale replay"), "replayed payload rejected");
    }

    // ------------------------------------------------------------------
    // 8. Relay advertisement learning
    // ------------------------------------------------------------------
    {
        Mesh mesh;
        Node* alice = mesh.make("alice", false);
        Node* r1 = mesh.make("relay1", true);

        const std::string ad = overlay::encode_relay_advert("relay1", 32, 4);
        uint8_t fid[overlay::kFrameIdSize];
        overlay::random_frame_id(fid);
        alice->router->on_frame("relay1", overlay::encode_frame(overlay::kFlagRelayAdvert, 255, fid, ad));

        const auto cands = alice->router->relay_candidates();
        bool found = false;
        for (const auto& c : cands) if (c == "relay1") found = true;
        CHECK(found, "relay advert learned relay1");

        // Spoofed advert (claims to be someone else) must be ignored.
        const std::string spoof = overlay::encode_relay_advert("bob", 32, 4);
        overlay::random_frame_id(fid);
        alice->router->on_frame("relay1", overlay::encode_frame(overlay::kFlagRelayAdvert, 255, fid, spoof));
        CHECK(alice->router->relay_candidates().size() == 1, "spoofed advert ignored");
    }

    // ------------------------------------------------------------------
    // 9. TTL enforcement: ttl=0 frames die at the first hop
    // ------------------------------------------------------------------
    {
        Mesh mesh;
        Node* r1 = mesh.make("relay1", true);

        overlay::HopInstruction fwd;
        fwd.kind = overlay::HopKind::Forward;
        fwd.next_peer = "nobody";
        const std::string body = overlay::seal_hop(mesh.key_dir["relay1"], fwd);
        uint8_t fid[overlay::kFrameIdSize];
        overlay::random_frame_id(fid);
        r1->router->on_frame("alice", overlay::encode_frame(0, 0, fid, body));
        CHECK(r1->router->stats().ttl_drops_total == 1, "ttl=0 frame dropped");
        CHECK(r1->router->stats().relayed_total == 0, "ttl=0 frame never forwarded");
    }

    // ------------------------------------------------------------------
    // 10. Mailbox accounting regression (review fix): pickups must return
    //     byte/entry counters to zero, or the mailbox leaks accounting and
    //     eventually refuses every store.
    // ------------------------------------------------------------------
    {
        overlay::OverlayMailbox::Config mb_cfg;
        overlay::OverlayMailbox mb(mb_cfg);
        const uint64_t now = 1000000;
        CHECK(mb.store("keyA", "alice", std::string(300, 'x'), now), "mailbox store #1");
        CHECK(mb.store("keyA", "alice", std::string(300, 'y'), now + 1), "mailbox store #2");
        CHECK(mb.size() == 2 && mb.total_bytes() == 600, "mailbox accounting after stores");

        auto blobs = mb.pickup("keyA", 16, now + 2);
        CHECK(blobs.size() == 2, "mailbox pickup returns both");
        CHECK(mb.size() == 0 && mb.total_bytes() == 0,
              "mailbox accounting returns to zero after pickup");
    }

    // ------------------------------------------------------------------
    // 11. Want-ACK preserved through mailbox pickup (review fix): a message
    //     sent with want_ack=true + via_mailbox=true must ACK the origin once
    //     the destination collects it, even though pickup re-wraps with
    //     outer flags=0 (the sealed payload retains the request).
    // ------------------------------------------------------------------
    {
        Mesh mesh;
        Node* alice = mesh.make("alice", false, 5000);  // long ACK budget
        Node* r1 = mesh.make("relay1", true);
        Node* r2 = mesh.make("relay2", true);
        Node* bob = mesh.make("bob", false, 5000);
        mesh.seed_relays(alice, {"relay1", "relay2"});
        mesh.seed_relays(bob, {"relay1", "relay2"});  // reverse path for the ACK

        std::string fid;
        const auto rc = alice->router->send("bob", "read me later", true, true, fid);
        CHECK(rc == OverlayRouter::SendResult::Ok, "mailbox+ack send accepted");
        CHECK(!bob->has_payload("read me later"), "offline bob holds nothing yet");

        // Find the mailbox holder relay (path is shuffled) and pick up.
        Node* holder = r1->router->stats().mailbox_stored_total == 1 ? r1 : r2;
        CHECK(holder->router->stats().mailbox_stored_total == 1, "mailbox stored once");
        bob->router->pickup_mailbox(holder->id);
        CHECK(bob->has_payload("read me later"), "bob collected mailbox blob");

        // The ACK now travels back; the origin's pending send resolves.
        CHECK(wait_status(alice, OverlayRouter::DeliveryStatus::Delivered, 3000),
              "origin got Delivered for want-ack mailbox message");
        CHECK(alice->router->stats().acked_total == 1, "mailbox-delivered message acked");
    }

    // ------------------------------------------------------------------
    // 12. Cover traffic: padding buckets wire sizes; decode strips pad
    // ------------------------------------------------------------------
    {
        uint8_t fid[overlay::kFrameIdSize];
        overlay::random_frame_id(fid);
        std::string wire = overlay::encode_frame(overlay::kFlagWantAck, 4, fid, "body-123");

        const size_t unpadded = wire.size();
        overlay::pad_wire_frame(wire, 128);
        CHECK(wire.size() % 128 == 0, "padded frame lands on bucket");
        CHECK(wire.size() > unpadded, "padding actually grew the frame");

        // decode must strip the pad and return the exact body.
        overlay::OverlayFrameHeader hdr;
        std::string_view body;
        CHECK(overlay::decode_frame(wire, hdr, body), "padded frame decodes");
        CHECK(hdr.pad_len > 0, "header records pad length");
        CHECK(std::string(body) == "body-123", "body intact after padding");

        // Unpadding to bucket 0 collapses the frame back.
        overlay::pad_wire_frame(wire, 0);
        CHECK(wire.size() == unpadded, "pad stripped back to original size");

        // Same-bucket frames from same content are same size (uniformity).
        std::string a = overlay::encode_frame(0, 4, fid, "x");
        std::string b = overlay::encode_frame(0, 4, fid, "xy");
        overlay::pad_wire_frame(a, 64);
        overlay::pad_wire_frame(b, 64);
        CHECK(a.size() == b.size(), "bucketed frames hide small length differences");
    }

    // ------------------------------------------------------------------
    // 13. Obfuscated transport (B1): envelope round-trip, key/tamper/fingerprint
    // ------------------------------------------------------------------
    {
        const KeyPair alice = gen_key();  // sender
        const KeyPair bob = gen_key();    // receiver

        // Envelope must not reveal the LPX2 magic.
        uint8_t fid0[overlay::kFrameIdSize] = {};
        const std::string secret = overlay::encode_frame(overlay::kFlagWantAck, 4, fid0, "LPX2-should-not-leak");
        const std::string env = overlay::obfuscate_wrap(bob.pk, alice.sk, secret, 128);
        CHECK(!env.empty(), "obfuscate_wrap produced envelope");
        CHECK(env.size() % 128 == 0, "obfuscated envelope is bucketed");
        CHECK(env.find("LPX2") == std::string::npos, "LPX2 magic hidden on the wire");

        std::string back;
        CHECK(overlay::obfuscate_unwrap(bob.pk, bob.sk, env, back), "unwrap round-trip");
        CHECK(back == secret, "plaintext preserved");

        // Wrong receiver key fails.
        const KeyPair mallory = gen_key();
        CHECK(!overlay::obfuscate_unwrap(mallory.pk, mallory.sk, env, back),
              "wrong key cannot unwrap");

        // Tampering fails (AEAD). Flip a byte INSIDE the ciphertext — the
        // trailing bytes may be cover-traffic padding (outside the AEAD).
        std::string tampered = env;
        tampered[62] ^= 0x01;  // first ciphertext byte
        CHECK(!overlay::obfuscate_unwrap(bob.pk, bob.sk, tampered, back),
              "tampered envelope rejected");

        // Garbage / wrong magic rejected.
        CHECK(!overlay::obfuscate_unwrap(bob.pk, bob.sk, "JUNK" + env.substr(4), back),
              "wrong magic rejected");
    }

    // ------------------------------------------------------------------
    // 14. Origin authentication (B4): signing, tamper, key-mismatch, enforce
    // ------------------------------------------------------------------
    {
        // Codec level: sign + verify round trip and tamper detection.
        const SignKeyPair alice = gen_sign_key();
        overlay::FinalPayload fp;
        fp.origin_peer_id = "alice";
        fp.created_ts_ms = 12345;
        fp.app_payload = "authenticated message";
        fp.message_frame_id_hex = "deadbeef";

        const KeyPair dest = gen_key();
        const std::string sealed =
            overlay::seal_final(dest.pk, fp, alice.sk.data(), alice.pk.data());
        overlay::FinalPayload opened;
        CHECK(overlay::open_final(dest.pk, dest.sk, sealed, opened), "signed payload opens");
        CHECK(opened.signature.size() == 64 && opened.signer_pk == std::string(alice.pk.begin(), alice.pk.end()),
              "signature + signer key embedded");
        CHECK(overlay::verify_final_signature(opened, {}), "embedded-key signature verifies");
        CHECK(overlay::verify_final_signature(opened, alice.pk), "registered-key signature verifies");

        // Wrong registered key must fail (identity binding).
        const SignKeyPair mallory = gen_sign_key();
        CHECK(!overlay::verify_final_signature(opened, mallory.pk),
              "mismatched registered key rejected");

        // Tamper: change payload -> signature check must fail.
        overlay::FinalPayload tampered = opened;
        tampered.app_payload += "x";
        CHECK(!overlay::verify_final_signature(tampered, alice.pk),
              "tampered payload rejected by signature");
    }
    {
        // Router level: end-to-end signed delivery + auth accounting.
        Mesh mesh;
        Node* alice = mesh.make("alice", false);
        Node* r1 = mesh.make("relay1", true);
        Node* bob = mesh.make("bob", false);
        mesh.seed_relays(alice, {"relay1"});

        std::string fid;
        const auto rc = alice->router->send("bob", "signed end to end", false, false, fid);
        CHECK(rc == OverlayRouter::SendResult::Ok, "signed send accepted");
        CHECK(bob->has_payload("signed end to end"), "bob received signed message");
        CHECK(bob->router->stats().auth_ok_total == 1, "destination verified origin signature");
        CHECK(bob->router->stats().auth_fail_total == 0, "no auth failures on valid path");
    }
    {
        // require_origin_auth=true drops unsigned payloads.
        Mesh mesh;
        Node* bob = mesh.make("bob", false);

        // Build an UNSIGNED deliver frame by hand (seal_final without keys).
        overlay::FinalPayload fp;
        fp.origin_peer_id = "intruder";
        fp.created_ts_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        fp.app_payload = "unsigned intruder";
        const std::string inner = overlay::seal_final(mesh.key_dir["bob"], fp);
        overlay::HopInstruction term;
        term.kind = overlay::HopKind::Deliver;
        term.inner = inner;
        const std::string body = overlay::seal_hop(mesh.key_dir["bob"], term);
        uint8_t fid[overlay::kFrameIdSize];
        overlay::random_frame_id(fid);
        bob->router->on_frame("relay1", overlay::encode_frame(0, 4, fid, body));
        CHECK(bob->has_payload("unsigned intruder"), "unsigned delivered when not enforced");

        // Now enforce: unsigned must be dropped.
        OverlayRouter::Config cfg{};
        cfg.require_origin_auth = true;
        cfg.tick_interval_ms = 200;
        OverlayRouter strict(cfg);
        strict.set_local_identity("bob", bob->keys.pk, bob->keys.sk);
        strict.set_peer_key_fn([&mesh](const std::string& p) {
            auto it = mesh.key_dir.find(p);
            return it == mesh.key_dir.end() ? std::vector<uint8_t>{} : it->second;
        });
        strict.set_peer_signing_key_fn([&mesh](const std::string& p) {
            auto it = mesh.sign_dir.find(p);
            return it == mesh.sign_dir.end() ? std::vector<uint8_t>{} : it->second;
        });
        strict.set_deliver_fn([](const std::string&, const std::string&) {});
        strict.start();

        uint8_t fid2[overlay::kFrameIdSize];
        overlay::random_frame_id(fid2);
        strict.on_frame("relay1", overlay::encode_frame(0, 4, fid2, body));
        CHECK(strict.stats().auth_fail_total == 1, "require_origin_auth dropped unsigned frame");
        strict.stop();
    }

    // ------------------------------------------------------------------
    // 15. Cover traffic (B3): idle nodes emit sealed cover frames; receivers
    //     consume them silently (no delivery, no errors)
    // ------------------------------------------------------------------
    {
        Mesh mesh;
        Node* r1 = mesh.make("relay1", true);

        OverlayRouter::Config cfg{};
        cfg.relay_enabled = true;       // needed to generate cover frames
        cfg.cover_interval_ms = 100;    // emit when idle 100 ms
        cfg.tick_interval_ms = 50;
        cfg.advertise_relay = false;
        cfg.default_hops = 1;
        OverlayRouter cover_router(cfg);
        cover_router.set_local_identity("cover_node", r1->keys.pk, r1->keys.sk);
        cover_router.set_peer_key_fn([&mesh](const std::string& p) {
            auto it = mesh.key_dir.find(p);
            return it == mesh.key_dir.end() ? std::vector<uint8_t>{} : it->second;
        });
        cover_router.set_send_fn([&mesh, r1](const std::string& /*to*/, const std::string& wire) {
            r1->router->on_frame("cover_node", wire);
            return true;
        });
        cover_router.set_is_connected_fn([](const std::string&) { return true; });
        cover_router.register_relay_candidate("relay1", 32, 4, true);
        cover_router.start();

        std::this_thread::sleep_for(std::chrono::milliseconds(450));

        CHECK(cover_router.stats().cover_tx_total >= 1, "cover frames emitted while idle");
        CHECK(r1->router->stats().cover_rx_total >= 1, "relay consumed cover frames silently");
        CHECK(r1->delivered_count() == 0, "cover frames never deliver app payloads");
        cover_router.stop();
    }

    // ------------------------------------------------------------------
    // 16. Relay PEX (B5): an advertisement triggers a relay-list exchange so
    //     relay knowledge spreads peer to peer
    // ------------------------------------------------------------------
    {
        Mesh mesh;
        Node* alice = mesh.make("alice", false);
        Node* r1 = mesh.make("relay1", true);
        Node* r2 = mesh.make("relay2", true);
        mesh.seed_relays(r2, {"relay1"});  // r2 knows relay1

        // Alice "connects" to r2 by advertising; r2 answers with its relay list.
        const std::string ad = overlay::encode_relay_advert("alice", 0, 4);
        uint8_t fid[overlay::kFrameIdSize];
        overlay::random_frame_id(fid);
        r2->router->on_frame("alice", overlay::encode_frame(overlay::kFlagRelayAdvert, 255, fid, ad));

        CHECK(r2->router->stats().pex_tx_total >= 1, "relay answered advertisement with PEX");
        CHECK(alice->router->stats().pex_rx_total >= 1, "origin received PEX response");

        bool has_r1 = false;
        for (const auto& c : alice->router->relay_candidates()) {
            if (c == "relay1") has_r1 = true;
        }
        CHECK(has_r1, "origin learned relay1 through PEX");
    }

    // ------------------------------------------------------------------
    // 17. Router-level obfuscation + padding (B1+B3): full 3-hop send path
    //     (alice -> relay -> bob) through wrapped, bucketed frames. Every hop
    //     re-wraps for its neighbor, so the transport never sees LPX2 magic.
    // ------------------------------------------------------------------
    {
        std::mutex wire_mu;
        std::vector<std::string> observed_wire;  // what the "transport" saw

        const KeyPair alice = gen_key();
        const KeyPair relay = gen_key();
        const KeyPair bob = gen_key();

        auto make_cfg = [] {
            OverlayRouter::Config c{};
            c.obfuscate_transport = true;
            c.padding_bucket = 128;
            c.tick_interval_ms = 200;
            return c;
        };

        OverlayRouter sender(make_cfg());
        sender.set_local_identity("alice", alice.pk, alice.sk);
        sender.set_peer_key_fn([&](const std::string& p) {
            return p == "relay" ? relay.pk :
                   p == "bob"   ? bob.pk : std::vector<uint8_t>{};
        });
        sender.set_is_connected_fn([](const std::string&) { return true; });
        sender.register_relay_candidate("relay", 32, 4, true);

        OverlayRouter relayer(make_cfg());
        relayer.set_local_identity("relay", relay.pk, relay.sk);
        relayer.set_peer_key_fn([&](const std::string& p) {
            return p == "alice" ? alice.pk :
                   p == "bob"   ? bob.pk : std::vector<uint8_t>{};
        });
        relayer.set_is_connected_fn([](const std::string&) { return true; });
        // relayer must opt in to forwarding.
        relayer.set_relay_enabled(true);

        std::string delivered;
        OverlayRouter receiver(make_cfg());
        receiver.set_local_identity("bob", bob.pk, bob.sk);
        receiver.set_peer_key_fn([&](const std::string& p) {
            return p == "alice" ? alice.pk :
                   p == "relay" ? relay.pk : std::vector<uint8_t>{};
        });
        receiver.set_deliver_fn([&delivered](const std::string& origin, const std::string& payload) {
            CHECK(origin == "alice", "obfuscated delivery origin");
            delivered = payload;
        });
        receiver.set_is_connected_fn([](const std::string&) { return true; });

        auto observe = [&](const std::string& to, const std::string& wire) {
            {
                std::lock_guard<std::mutex> lk(wire_mu);
                observed_wire.push_back(wire);
            }
            if (to == "alice") sender.on_frame("relay", wire);
            else if (to == "relay") relayer.on_frame("alice", wire);
            else if (to == "bob") receiver.on_frame("relay", wire);
            return true;
        };
        sender.set_send_fn(observe);
        relayer.set_send_fn(observe);
        receiver.set_send_fn(observe);

        sender.start();
        relayer.start();
        receiver.start();

        std::string fid;
        const auto rc = sender.send("bob", "hidden in plain sight", false, false, fid);
        CHECK(rc == OverlayRouter::SendResult::Ok, "obfuscated send accepted");
        CHECK(delivered == "hidden in plain sight", "obfuscated delivery round-trip");
        CHECK(receiver.stats().obf_ok_total == 1, "receiver unwrapped one envelope");
        CHECK(relayer.stats().obf_ok_total == 1, "relay unwrapped + re-wrapped");

        {
            std::lock_guard<std::mutex> lk(wire_mu);
            CHECK(observed_wire.size() >= 2, "transport observed both hops");
            for (const auto& w : observed_wire) {
                CHECK(w.find("LPX2") == std::string::npos, "LPX2 never visible on the wire");
                CHECK(w.size() % 128 == 0, "wire frames land on the padding bucket");
            }
        }
        sender.stop();
        relayer.stop();
        receiver.stop();
    }

    return suite_exit("overlay_test");
}
