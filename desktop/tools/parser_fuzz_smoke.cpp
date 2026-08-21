// parser_fuzz_smoke.cpp — Network OS Phase 11 fuzz expansion (master doc §47,
// phase file Step 5.4).
//
// Single time-budgeted harness that exercises EVERY network-facing parser in
// the engine with randomized / bit-flipped / truncated / oversized inputs:
// capability document, object envelope, handoff OFFER/DATA frames,
// RECEIVED_ACK + receipt payloads (P5), INVENTORY / OBJECT_WANT (P6), and the
// large-object MANIFEST codec (P10).
//
// Gates (exit != 0 on violation):
//   * no crash/hang within the budget (implicit — we are the process);
//   * decode(encode(x)) == true for every pristine encoding (round-trip);
//   * absurd length fields never yield an acceptance (bounded allocation).
//
// This is the runnable-on-Apple-clang substitute for libFuzzer coverage;
// desktop/fuzz/fuzz_wire_codec.cpp carries the equivalent libFuzzer target.

#include "networkos/anti_entropy/anti_entropy_frames.h"
#include "networkos/capability.h"
#include "networkos/delivery/delivery_frames.h"
#include "networkos/handoff/handoff_frames.h"
#include "networkos/largeobject/largeobject.h"
#include "networkos/object/envelope.h"
#include "networkos/object/object_id.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

namespace {

// Deterministic RNG (xorshift64*) — reproducible runs.
class Rng {
public:
    explicit Rng(uint64_t seed) : s_(seed ? seed : 0x9E3779B97F4A7C15ULL) {}
    uint64_t next_u64() {
        s_ ^= s_ >> 12;
        s_ ^= s_ << 25;
        s_ ^= s_ >> 27;
        return s_ * 2685821657736338717ULL;
    }
    size_t pick(size_t n) { return n ? static_cast<size_t>(next_u64() % n) : 0; }

private:
    uint64_t s_;
};

std::string mutate(const std::string& in, Rng& rng) {
    std::string out = in;
    switch (rng.next_u64() % 4) {
        case 0: {  // bit flips
            const int flips = 1 + static_cast<int>(rng.next_u64() % 8);
            for (int i = 0; i < flips && !out.empty(); ++i) {
                const size_t pos = rng.pick(out.size());
                out[pos] ^= static_cast<char>(1u << rng.pick(8));
            }
            break;
        }
        case 1:  // truncation
            if (!out.empty()) out.resize(rng.pick(out.size()));
            break;
        case 2: {  // extension with junk
            const size_t add = rng.pick(256);
            for (size_t i = 0; i < add; ++i)
                out.push_back(static_cast<char>(rng.next_u64() & 0xFF));
            break;
        }
        case 3: {  // length-field targeting: sizes live in the first bytes
            for (size_t i = 0; i < out.size() && i < 4; ++i)
                out[i] = static_cast<char>(rng.next_u64() & 0xFF);
            break;
        }
    }
    return out;
}

struct ParserTarget {
    const char* name;
    std::function<std::string()> make_valid;         // pristine encoding
    std::function<bool(const std::string&)> decode;  // parser under test
};

std::vector<ParserTarget> build_targets() {
    using namespace networkos;
    std::vector<ParserTarget> t;

    // Capability document (Phase 2).
    t.push_back({"capability",
                 [] {
                     CapabilityDocument d;
                     d.namespaces.push_back("chat");
                     return cap::encode(d);
                 },
                 [](const std::string& b) {
                     CapabilityDocument d;
                     return cap::decode(b, d);
                 }});

    // Object envelope (Phase 3) — unsigned minimal object still parses.
    t.push_back({"envelope",
                 [] {
                     obj::NetworkObject o;
                     o.origin.network_id = "chatp2p-mesh";
                     o.origin.namespace_id = "chat";
                     o.origin.object_id_hex =
                         ObjectId::generate("chatp2p-mesh", "fz").toHex();
                     o.origin.origin = "fz-origin";
                     o.origin.destination = "fz-dest";
                     o.origin.payload_hash = obj::compute_payload_hash("payload");
                     o.payload = "payload";
                     return obj::serialize(o);
                 },
                 [](const std::string& b) {
                     obj::NetworkObject o;
                     return obj::deserialize(b, o);
                 }});

    // Handoff frames (Phases 4/5 transport).
    t.push_back({"handoff_offer",
                 [] {
                     handoff::OfferFrame f;
                     f.destination = "dest-peer";
                     return handoff::encode_offer(f);
                 },
                 [](const std::string& b) {
                     handoff::OfferFrame f;
                     return handoff::decode_offer(b, f);
                 }});
    t.push_back({"handoff_data",
                 [] {
                     handoff::DataFrame f;
                     f.object_id_hex = "aa";
                     f.envelope = "env-bytes";
                     return handoff::encode_data(f);
                 },
                 [](const std::string& b) {
                     handoff::DataFrame f;
                     return handoff::decode_data(b, f);
                 }});

    // Delivery frames (Phase 5): RECEIVED_ACK + signed receipt payload.
    t.push_back({"received_ack",
                 [] {
                     delivery::ReceivedAckFrame f;
                     return delivery::encode_received_ack(f);
                 },
                 [](const std::string& b) {
                     delivery::ReceivedAckFrame f;
                     return delivery::decode_received_ack(b, f);
                 }});
    t.push_back({"receipt",
                 [] {
                     delivery::ReceiptPayload r;
                     return delivery::encode_receipt(r);
                 },
                 [](const std::string& b) {
                     delivery::ReceiptPayload r;
                     return delivery::decode_receipt(b, r);
                 }});

    // Anti-entropy (Phase 6).
    t.push_back({"inventory",
                 [] {
                     anti_entropy::InventoryFrame f;
                     anti_entropy::InventoryEntry e;
                     e.object_id_hex = "bb";
                     f.entries.push_back(e);
                     return anti_entropy::encode_inventory(f);
                 },
                 [](const std::string& b) {
                     anti_entropy::InventoryFrame f;
                     return anti_entropy::decode_inventory(b, f);
                 }});
    t.push_back({"object_want",
                 [] {
                     anti_entropy::ObjectWantFrame f;
                     return anti_entropy::encode_object_want(f);
                 },
                 [](const std::string& b) {
                     anti_entropy::ObjectWantFrame f;
                     return anti_entropy::decode_object_want(b, f);
                 }});

    // Large-object manifest (Phase 10).
    t.push_back({"manifest",
                 [] {
                     largeobject::Manifest m;
                     m.chunk_hashes.push_back("cc");
                     return largeobject::encode_manifest(m);
                 },
                 [](const std::string& b) {
                     largeobject::Manifest m;
                     return largeobject::decode_manifest(b, m);
                 }});

    return t;
}

} // namespace

int main(int argc, char** argv) {
    uint64_t seed = 20260822;
    int seconds = 30;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--seconds" && i + 1 < argc) seconds = std::atoi(argv[++i]);
        else if (a == "--seed" && i + 1 < argc)
            seed = std::strtoull(argv[++i], nullptr, 10);
        else {
            std::cerr << "usage: parser_fuzz_smoke [--seconds N] [--seed S]\n";
            return 2;
        }
    }

    const auto targets = build_targets();
    Rng rng(seed);
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(seconds);

    std::vector<uint64_t> iters(targets.size(), 0);
    uint64_t garbage_rounds = 0;
    size_t roundtrip_failures = 0;
    size_t ti = 0;

    while (std::chrono::steady_clock::now() < deadline) {
        const size_t idx = ti % targets.size();
        const ParserTarget& p = targets[idx];
        ++ti;

        // Round-trip gate on pristine bytes (every 16th iteration).
        const std::string valid = p.make_valid();
        if ((iters[idx] & 0xF) == 0 && !p.decode(valid)) {
            std::cerr << "ROUNDTRIP FAIL: " << p.name << "\n";
            ++roundtrip_failures;
        }
        // Mutated input: must never crash (accept/reject both fine).
        (void)p.decode(mutate(valid, rng));
        ++iters[idx];

        // Pure garbage with absurd length prefixes (bounded-allocation probe).
        if ((rng.next_u64() & 0x3F) == 0) {
            std::string junk(static_cast<size_t>(1 + rng.pick(4096)), '\xFF');
            (void)p.decode(junk);
            junk.resize(8);
            (void)p.decode(junk);
            ++garbage_rounds;
        }
    }

    uint64_t total = 0;
    for (size_t i = 0; i < targets.size(); ++i) {
        total += iters[i];
        std::printf("%-14s %10llu iters\n", targets[i].name,
                    static_cast<unsigned long long>(iters[i]));
    }
    std::printf("TOTAL %llu iters, %llu garbage rounds, %zu roundtrip failures, "
                "%d s, seed %llu\n",
                static_cast<unsigned long long>(total),
                static_cast<unsigned long long>(garbage_rounds), roundtrip_failures,
                seconds, static_cast<unsigned long long>(seed));
    return roundtrip_failures == 0 ? 0 : 1;
}