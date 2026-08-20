#pragma once

// Network OS — E2E payload encryption key model (master doc §19.4, locked
// decision 4; Phase 3 Step 3.4).
//
// Model:
//   - Each object gets a random 256-bit CONTENT KEY.
//   - The payload is encrypted with XChaCha20-Poly1305 using the content key
//     (the engine's bundled AEAD primitive via libsodium).
//   - The content key is WRAPPED for each recipient/origin with crypto_box_seal
//     using their public key; wrappers live in the envelope's
//     recipient_keys section.
//   - Storage/relay peers see ciphertext + envelope metadata ONLY — never the
//     plaintext or the content key.
//
// Never add ad-hoc crypto (locked decision 3): this uses the engine's own
// primitives only.

#include <cstdint>
#include <string>

namespace networkos {
namespace e2e {

struct ContentKey {
    uint8_t bytes[32]{0};
};

// Random 256-bit content key.
bool generate_content_key(ContentKey& out);

// Payload AEAD with XChaCha20-Poly1305 (libsodium crypto_aead_xchacha20poly1305_ietf).
// ct layout: [24-byte nonce][ciphertext+tag].
bool encrypt_payload(const std::string& plaintext, const ContentKey& key,
                     std::string& out_ct);
bool decrypt_payload(const std::string& ct, const ContentKey& key,
                     std::string& out_pt);

// Wrap/unwrap the content key for a recipient (crypto_box_seal with their
// 32-byte public key). wrapped is opaque to storage peers.
bool wrap_key(const ContentKey& key, const uint8_t recipient_pk[32],
              std::string& out_wrapped);
bool unwrap_key(const std::string& wrapped, const uint8_t sk[32],
                const uint8_t pk[32], ContentKey& out_key);

} // namespace e2e
} // namespace networkos
