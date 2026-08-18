// Fuzz target for the Noise NK handshake + decrypt paths.
//
// Feeds arbitrary bytes into:
//   - NoiseNKSession::process_handshake  (initiator and responder roles),
//   - NoiseNKSession::decrypt            (post-handshake ciphertext path).
// The engine's own key derivation (libsodium X25519/ChaChaPoly) is exercised;
// all sizes/authentications must fail gracefully, never crash or leak.
//
// Build (desktop, clang):
//   cmake -S desktop -B desktop/build-fuzz -DLITEP2P_FUZZING=ON \
//         -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
//   cmake --build desktop/build-fuzz --target fuzz_noise_handshake
//   ./desktop/build-fuzz/bin/fuzz_noise_handshake -runs=100000

#include "noise_nk.h"

#include <cstddef>
#include <cstdint>
#include <vector>
#include <sodium.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const auto responder_keys = [] {
        (void)sodium_init();
        return NoiseNKManager::generate_static_keypair();
    }();

    const std::vector<uint8_t> msg(data, data + size);

    // Initiator session: expects the responder's static pk, feeds message-2.
    {
        NoiseNKSession initiator("fuzz-init", NoiseNKSession::Role::INITIATOR,
                                 responder_keys.first, responder_keys.first);
        (void)initiator.process_handshake(msg);
    }

    // Responder session: needs local static sk; feeds message-1.
    {
        NoiseNKSession responder("fuzz-resp", NoiseNKSession::Role::RESPONDER,
                                 responder_keys.first, responder_keys.first,
                                 responder_keys.second);
        (void)responder.process_handshake(msg);
    }

    // Post-handshake ciphertext path (raw bytes as AEAD ciphertext+tag).
    {
        NoiseNKSession session("fuzz-dec", NoiseNKSession::Role::INITIATOR,
                               responder_keys.first, responder_keys.first);
        bool replay_drop = false;
        (void)session.decrypt(msg, &replay_drop);
    }

    return 0;
}
