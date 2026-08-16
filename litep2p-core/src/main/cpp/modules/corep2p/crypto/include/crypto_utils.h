#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
#include <cstdint>
#include <cstddef>

/**
 * Transport-layer encryption utilities.
 *
 * Security model (beta):
 *  - When libsodium is available (HAVE_NOISE_PROTOCOL builds, the default),
 *    messages are protected with ChaCha20-Poly1305 (IETF AEAD): random
 *    12-byte nonce per message + 16-byte authentication tag. Wire format:
 *        nonce(12) || ciphertext || tag(16)
 *  - The 32-byte transport key is resolved in this order:
 *        1. Config value `security.transport_key` (64 hex chars) - a shared
 *           "network key" that operators should provision identically on all
 *           devices that need to talk to each other.
 *        2. A persisted key file next to the Noise keystore
 *           (<key_store_path>/transport_key.hex), generated with a CSPRNG on
 *           first use (file permissions 0600). Peers sharing the same
 *           filesystem (e.g. local test instances) therefore interoperate.
 *        3. Last resort: an in-memory per-process key (logged as a warning);
 *           cross-device peers will NOT be able to decrypt traffic in this
 *           mode.
 *  - Builds without libsodium fall back to AES-256-CBC with a CSPRNG IV and
 *    the same key resolution, and log a prominent warning that transport
 *    encryption is unauthenticated in that configuration.
 *
 * Per-session keys (forward secrecy / per-peer isolation):
 *  - After the Noise NK handshake completes for a peer, the session layer
 *    derives a dedicated key pair (send/recv) from the Noise session keys and
 *    registers it here under the peer's identity (peer id and/or network id).
 *  - encrypt_message_for_peer()/decrypt_message_for_peer() use the per-peer
 *    key when one is registered, and fall back to the shared network key
 *    otherwise. The fallback covers handshake/bootstrap traffic and mixed
 *    networks where the peer has not completed a Noise handshake.
 *  - Keys are registered under every identity the session layer knows for the
 *    peer (logical id + active network ids) because transports only see
 *    network ids ("ip:port") on the wire.
 */

// Fill `buffer` with cryptographically secure random bytes.
// Uses libsodium when available, otherwise the strongest OS source.
void random_bytes(void* buffer, size_t length);

// Encrypt/decrypt using the active transport key.
// Returns an empty string on failure (bad ciphertext, key not resolved).
std::string encrypt_message(const std::string& plain_text);
std::string decrypt_message(const std::string& encrypted_text);

// UDP-specific encryption (same as regular for now, but allows future customization)
std::string encrypt_message_udp(const std::string& plain_text);
std::string decrypt_message_udp(const std::string& encrypted_text);

// Generate a random IV for each encryption session (legacy helper kept for
// API compatibility; now backed by random_bytes()).
void generate_random_iv(uint8_t* iv, size_t length);

// Resolve the active 32-byte transport key.
// Returns false if no key could be established.
bool transport_key_resolve(uint8_t* out_key_32);

// ---------------------------------------------------------------------------
// Per-peer transport keys (derived from the Noise session after handshake)
// ---------------------------------------------------------------------------

/**
 * @brief Register per-peer transport keys.
 * Both keys must be 32 bytes. Once registered, encrypt_message_for_peer()
 * uses send_key and decrypt_message_for_peer() uses recv_key for `id`
 * (the Noise NK handshake guarantees the peers agree: our send key equals
 * the peer's recv key and vice versa).
 * @return true on success.
 */
bool set_peer_transport_keys(const std::string& id,
                             const uint8_t* send_key_32,
                             const uint8_t* recv_key_32);

/**
 * @brief Remove per-peer transport keys for one identity.
 */
void clear_peer_transport_keys(const std::string& id);

/**
 * @brief True when per-peer transport keys are registered for `id`.
 */
bool has_peer_transport_keys(const std::string& id);

/**
 * @brief Encrypt for a specific peer identity.
 * Uses the per-peer send key when registered, else the shared network key.
 */
std::string encrypt_message_for_peer(const std::string& id, const std::string& plain_text);

/**
 * @brief Decrypt a message received from a specific peer identity.
 * Uses the per-peer recv key when registered, else the shared network key.
 */
std::string decrypt_message_for_peer(const std::string& id, const std::string& encrypted_text);

#endif // CRYPTO_UTILS_H
