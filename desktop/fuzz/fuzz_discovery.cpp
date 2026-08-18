// Fuzz target for the discovery announcement parser.
//
// Exercises BOTH parse paths:
//   1. obfuscated form  (network.discovery_shared_key configured) — the
//      XChaCha20-Poly1305 AEAD decrypt + padding-trim path,
//   2. plaintext form   (no shared key) — magic + "peer:port" split,
//   3. legacy interop   (default magic fallback).
// ConfigManager is primed once with a fixed shared key so the AEAD path is
// reached; inputs that don't carry our magic fall through to the other paths.
//
// Build (desktop, clang):
//   cmake -S desktop -B desktop/build-fuzz -DLITEP2P_FUZZING=ON \
//         -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
//   cmake --build desktop/build-fuzz --target fuzz_discovery
//   ./desktop/build-fuzz/bin/fuzz_discovery -runs=100000

#include "discovery.h"
#include "config_manager.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace {
// 32-byte key in 64-hex form; enables the obfuscated/AEAD parse path.
constexpr const char* kSharedKeyHex =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

void prime_config() {
    // Idempotent: loadConfig replaces the config object wholesale.
    ConfigManager::getInstance().loadConfig("unused.json");
    ConfigManager::getInstance().setValueAtPath({"network", "discovery_shared_key"}, kSharedKeyHex);
    ConfigManager::getInstance().setValueAtPath({"network", "discovery_magic"}, "xK9f2Qz7");
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static bool primed = [] { prime_config(); return true; }();
    (void)primed;

    const std::string raw(reinterpret_cast<const char*>(data), size);
    std::string peer_id;
    int port = 0;
    (void)parse_discovery_announcement(raw, peer_id, port);
    return 0;
}
