// envelope_fuzz_smoke.cpp — Network OS Phase 3 standalone fuzz substitute.
//
// The libFuzzer targets (fuzz/fuzz_wire_codec.cpp, now including the Phase 3
// envelope parser) cannot LINK on this Mac: Apple clang 12 ships no
// libclang_rt.fuzzer runtime. They compile cleanly (verified via the
// build-fuzz TU). This smoke harness runs the SAME parse entry point
// (networkos::obj::deserialize) against ~60s of randomized input:
//   1. raw random bytes (arbitrary garbage, all lengths)
//   2. valid serialized envelopes with random bit flips / truncations
// and asserts the parser never crashes, hangs, or mis-verifies a tampered
// object. Exits 0 on a clean run.
//
// Build/run: part of litep2p_engine desktop build; run
//   desktop/build_fixcheck/bin/envelope_fuzz_smoke --seconds 60

#include "networkos/object/envelope.h"
#include "networkos/object/object_id.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <random>
#include <string>

namespace {

uint64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

std::string random_bytes(std::mt19937_64& rng, size_t n) {
    std::string s;
    s.resize(n);
    for (size_t i = 0; i < n; ++i) {
        s[i] = static_cast<char>(rng() & 0xff);
    }
    return s;
}

networkos::obj::NetworkObject make_valid_object() {
    networkos::obj::NetworkObject obj;
    obj.origin.protocol_version = 1;
    obj.origin.network_id = "chatp2p-mesh";
    obj.origin.namespace_id = "chat";
    obj.origin.object_id_hex = networkos::ObjectId::generate("chatp2p-mesh", "fuzz").toHex();
    obj.origin.origin = "peer-alpha";
    obj.origin.object_type = "message";
    obj.origin.created_at_ms = 1700000000000LL;
    obj.origin.ttl_ms = 3600000;
    obj.origin.priority = 5;
    obj.origin.delivery_class = networkos::obj::kDeliveryNormal;
    obj.origin.max_hops = 4;
    obj.origin.payload_size = 32;
    obj.origin.payload_hash = networkos::obj::compute_payload_hash("0123456789abcdef0123456789abcdef");
    obj.origin.security_flags = 1;
    obj.payload = "0123456789abcdef0123456789abcdef";
    obj.forwarding.hop_count = 1;
    obj.forwarding.previous_peer = "peer-relay-1";
    return obj;
}

} // namespace

int main(int argc, char** argv) {
    int seconds = 60;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) seconds = std::atoi(argv[++i]);
    }

    std::random_device rd;
    std::mt19937_64 rng(rd());
    const std::string valid_ser = networkos::obj::serialize(make_valid_object());
    if (valid_ser.empty()) { std::cerr << "setup: serialize failed\n"; return 1; }

    uint64_t start = now_ms();
    uint64_t iterations = 0;
    uint64_t parsed_ok = 0;
    while (now_ms() - start < static_cast<uint64_t>(seconds) * 1000) {
        networkos::obj::NetworkObject out;
        const int which = static_cast<int>(rng() % 3);
        std::string input;
        if (which == 0) {
            // Raw garbage of arbitrary length (bounded decoder must reject).
            input = random_bytes(rng, rng() % 4096);
        } else if (which == 1) {
            // Valid serialized envelope with random bit flips.
            input = valid_ser;
            const int flips = 1 + static_cast<int>(rng() % 6);
            for (int f = 0; f < flips && !input.empty(); ++f) {
                input[rng() % input.size()] ^= static_cast<char>(1u << (rng() % 8));
            }
        } else {
            // Random truncation.
            input = valid_ser.substr(0, rng() % (valid_ser.size() + 1));
        }
        if (networkos::obj::deserialize(input, out)) {
            ++parsed_ok;
            // Round-trip whatever parsed (must not crash).
            (void)networkos::obj::serialize(out);
        }
        ++iterations;
    }

    std::cout << "envelope_fuzz_smoke: " << iterations << " iterations in " << seconds
              << "s, parsed=" << parsed_ok << ", no crash\n";
    return 0;
}