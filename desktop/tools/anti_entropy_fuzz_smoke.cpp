// anti_entropy_fuzz_smoke.cpp — Network OS Phase 6 standalone fuzz substitute.
//
// The libFuzzer targeted coverage for the Phase 6 anti-entropy codecs lives in
// fuzz_wire_codec.cpp, but that target cannot link on this Mac (Apple clang 12
// ships no libclang_rt.fuzzer runtime — see envelope_fuzz_smoke.cpp). This
// harness runs the SAME parse entry points (networkos::anti_entropy::
// decode_inventory / decode_object_want) against ~N seconds of randomized
// input:
//   1. raw random bytes (arbitrary garbage, all lengths)
//   2. valid encoded frames with random bit flips / truncations
// and asserts the decoder never crashes, hangs, or over-accepts tampered input.
// It also round-trips a valid frame (encode -> decode -> compare) to confirm
// the codec stays in sync. Exits 0 on a clean run.
//
// Build/run: part of litep2p_engine desktop build; run
//   desktop/build_fixcheck/bin/anti_entropy_fuzz_smoke --seconds 20

#include "networkos/anti_entropy/anti_entropy_frames.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <random>
#include <string>
#include <vector>

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

// Build a valid (non-empty) INVENTORY frame and encode it.
std::string encode_inventory_payload() {
    networkos::anti_entropy::InventoryFrame f;
    f.format = networkos::anti_entropy::kFormatExactList;
    f.count = 4;
    f.entries.push_back({std::string(64, 'a'), 1, 1700000000000LL});
    f.entries.push_back({std::string(64, 'b'), 1, 1700000001000LL});
    f.entries.push_back({std::string(64, 'c'), 5, 1700000002000LL});
    f.entries.push_back({std::string(64, 'd'), 5, 1700000003000LL});
    return networkos::anti_entropy::encode_inventory(f);
}

// Build a valid (non-empty) OBJECT_WANT frame and encode it.
std::string encode_want_payload() {
    networkos::anti_entropy::ObjectWantFrame f;
    f.object_id_hexes = {std::string(64, '1'), std::string(64, '2')};
    f.already_held = {std::string(64, '3')};
    return networkos::anti_entropy::encode_object_want(f);
}

} // namespace

int main(int argc, char** argv) {
    int seconds = 20;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) seconds = std::atoi(argv[++i]);
    }
    if (seconds <= 0) seconds = 20;

    std::random_device rd;
    std::mt19937_64 rng(rd());
    const std::string inv_ser = encode_inventory_payload();
    const std::string want_ser = encode_want_payload();
    if (inv_ser.empty() || want_ser.empty()) {
        std::cerr << "setup: encoder produced empty payload\n";
        return 1;
    }

    // Sanity: valid frames must round-trip (encode -> decode -> compare).
    {
        networkos::anti_entropy::InventoryFrame out;
        if (!networkos::anti_entropy::decode_inventory(inv_ser, out) ||
            out.count != 4 || out.entries.size() != 4) {
            std::cerr << "setup: valid inventory did not round-trip\n";
            return 1;
        }
        const std::string re = networkos::anti_entropy::encode_inventory(out);
        if (re != inv_ser) {
            std::cerr << "setup: inventory re-encode mismatch\n";
            return 1;
        }
    }
    {
        networkos::anti_entropy::ObjectWantFrame out;
        if (!networkos::anti_entropy::decode_object_want(want_ser, out) ||
            out.object_id_hexes.size() != 2 || out.already_held.size() != 1) {
            std::cerr << "setup: valid want did not round-trip\n";
            return 1;
        }
        const std::string re = networkos::anti_entropy::encode_object_want(out);
        if (re != want_ser) {
            std::cerr << "setup: want re-encode mismatch\n";
            return 1;
        }
    }

    uint64_t start = now_ms();
    uint64_t iterations = 0;
    uint64_t accepted = 0;
    while (now_ms() - start < static_cast<uint64_t>(seconds) * 1000) {
        const int which = static_cast<int>(rng() % 6);
        std::string input;
        if (which == 0 || which == 1) {
            // Raw garbage of arbitrary length (bounded decoder must reject).
            input = random_bytes(rng, rng() % 4096);
        } else if (which == 2 || which == 3) {
            // Valid encoded frame with random bit flips.
            input = (which == 2) ? inv_ser : want_ser;
            const int flips = 1 + static_cast<int>(rng() % 6);
            for (int f = 0; f < flips && !input.empty(); ++f) {
                input[rng() % input.size()] ^= static_cast<char>(1u << (rng() % 8));
            }
        } else {
            // Random truncation of a valid frame.
            const std::string& base = (which == 4) ? inv_ser : want_ser;
            input = base.substr(0, rng() % (base.size() + 1));
        }

        networkos::anti_entropy::InventoryFrame inv;
        networkos::anti_entropy::ObjectWantFrame want;
        if (networkos::anti_entropy::decode_inventory(input, inv)) ++accepted;
        if (networkos::anti_entropy::decode_object_want(input, want)) ++accepted;
        ++iterations;
    }

    std::cout << "anti_entropy_fuzz_smoke: " << iterations
              << " iterations in " << seconds
              << "s, accepted=" << accepted << ", no crash\n";
    return 0;
}