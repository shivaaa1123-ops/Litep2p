#include "noise_protocol.h"
#include "logger.h"
#include <cstring>
#include <sodium.h>
#include <memory>
#include <cstdlib>

// Noise Protocol NN state machine implementation
// Message pattern NN:
//   -> e
//   <- e, ee
//   -> nothing (complete)

class NoiseSession::Impl {
public:
    // Curve25519 and ChaCha20-Poly1305 constants
    static constexpr size_t DH_LEN = 32;      // Curve25519 key size
    static constexpr size_t HASH_LEN = 32;    // SHA256
    static constexpr size_t TAGLEN = 16;      // Poly1305 tag
    static constexpr size_t CIPHERTEXT_LEN = TAGLEN; // For empty plaintext in NN pattern

    struct NoiseState {
        uint8_t h[HASH_LEN];           // handshake hash
        uint8_t ck[HASH_LEN];          // chaining key
        uint8_t k[32];                 // symmetric key (ChaCha20)
        uint64_t n;                    // nonce counter
        bool key_set;
    };

    Impl(Role role, const std::string& static_pubkey) 
        : m_role(role), m_static_pubkey(static_pubkey), m_handshake_complete(false) {
        
        // Initialize libsodium if not already done
        static int sodium_init_done = sodium_init();
        (void)sodium_init_done;

        // Generate ephemeral keypair for this session
        auto [ephemeral_private, ephemeral_public] = generate_ephemeral_keypair();
        m_ephemeral_private = ephemeral_private;
        m_ephemeral_public = ephemeral_public;

        // Initialize Noise state
        memset(&m_noise_state, 0, sizeof(m_noise_state));
        m_noise_state.key_set = false;
        m_noise_state.n = 0;

        // Protocol name for Noise NN
        const char* protocol_name = "Noise_NN_25519_ChaChaPoly_SHA256";
        size_t proto_len = strlen(protocol_name);
        
        // Initialize h and ck
        if (proto_len <= HASH_LEN) {
            memcpy(m_noise_state.h, protocol_name, proto_len);
            memset(m_noise_state.h + proto_len, 0, HASH_LEN - proto_len);
        } else {
            crypto_hash_sha256(m_noise_state.h, (const uint8_t*)protocol_name, proto_len);
        }
        
        // ck = h
        memcpy(m_noise_state.ck, m_noise_state.h, HASH_LEN);
    }

    std::string initiate_handshake() {
        if (m_role != Role::INITIATOR) {
            nativeLog("Noise Error: Only initiator can call initiate_handshake");
            return "";
        }

        // Message: e
        // Send ephemeral public key
        std::string message(m_ephemeral_public.begin(), m_ephemeral_public.end());
        
        // Mix ephemeral public into handshake hash
        mix_hash(m_ephemeral_public);

        nativeLog("Noise: Initiator handshake message generated");
        return message;
    }

    std::string process_handshake_message(const std::string& message) {
        if (m_role == Role::INITIATOR) {
            // INITIATOR receives: e, ee
            if (message.length() < DH_LEN + CIPHERTEXT_LEN) {
                nativeLog("Noise Error: Invalid responder handshake message length");
                return "";
            }

            std::string responder_ephemeral(message.begin(), message.begin() + DH_LEN);
            std::string encrypted_empty(message.begin() + DH_LEN, message.end());

            // Mix responder ephemeral
            mix_hash(responder_ephemeral);

            // Perform ECDH
            if (!perform_dh(m_ephemeral_private, responder_ephemeral)) {
                nativeLog("Noise Error: ECDH failed for ee");
                return "";
            }

            // Decrypt empty message to verify authentication
            if (!decrypt_empty(encrypted_empty)) {
                nativeLog("Noise Error: Failed to decrypt responder message (authentication failed)");
                return "";
            }

            m_handshake_complete = true;
            nativeLog("Noise: Initiator handshake complete");
            return "";
        } else {
            // RESPONDER receives: e
            if (message.length() != DH_LEN) {
                nativeLog("Noise Error: Invalid initiator handshake message length");
                return "";
            }

            std::string initiator_ephemeral(message.begin(), message.end());
            
            // Mix initiator ephemeral
            mix_hash(initiator_ephemeral);

            // Perform ECDH
            if (!perform_dh(m_ephemeral_private, initiator_ephemeral)) {
                nativeLog("Noise Error: ECDH failed for ee");
                return "";
            }

            // Send response: e, ee (e already set, ee from ECDH above)
            std::string response(m_ephemeral_public.begin(), m_ephemeral_public.end());
            
            // Mix our ephemeral
            mix_hash(m_ephemeral_public);

            // Encrypt empty message
            std::string encrypted_empty = encrypt_empty();
            if (encrypted_empty.empty()) {
                nativeLog("Noise Error: Failed to encrypt responder message");
                return "";
            }

            response.append(encrypted_empty);
            m_handshake_complete = true;
            nativeLog("Noise: Responder handshake complete");
            return response;
        }
    }

    std::string encrypt_message(const std::string& plaintext) {
        if (!m_handshake_complete) {
            nativeLog("Noise Error: Handshake not complete");
            return "";
        }

        if (!m_noise_state.key_set) {
            nativeLog("Noise Error: Encryption key not set");
            return "";
        }

        // Prepare nonce for ChaCha20
        uint8_t nonce[12];
        memset(nonce, 0, sizeof(nonce));
        memcpy(nonce + 4, &m_noise_state.n, 8);
        m_noise_state.n++;

        // Allocate ciphertext buffer
        std::string ciphertext(plaintext.length() + TAGLEN, 0);
        unsigned long long clen;

        // Encrypt with ChaCha20-Poly1305
        int result = crypto_aead_chacha20poly1305_ietf_encrypt(
            (unsigned char*)ciphertext.data(),
            &clen,
            (const unsigned char*)plaintext.data(),
            plaintext.length(),
            nullptr,  // ad
            0,        // adlen
            nullptr,  // nsec
            m_noise_state.k,
            nonce
        );

        if (result != 0) {
            nativeLog("Noise Error: ChaCha20-Poly1305 encryption failed");
            return "";
        }

        ciphertext.resize(clen);
        return ciphertext;
    }

    std::string decrypt_message(const std::string& ciphertext) {
        if (!m_handshake_complete) {
            nativeLog("Noise Error: Handshake not complete");
            return "";
        }

        if (!m_noise_state.key_set) {
            nativeLog("Noise Error: Decryption key not set");
            return "";
        }

        if (ciphertext.length() < TAGLEN) {
            nativeLog("Noise Error: Ciphertext too short");
            return "";
        }

        // Prepare nonce
        uint8_t nonce[12];
        memset(nonce, 0, sizeof(nonce));
        memcpy(nonce + 4, &m_noise_state.n, 8);
        m_noise_state.n++;

        // Allocate plaintext buffer
        std::string plaintext(ciphertext.length() - TAGLEN, 0);
        unsigned long long mlen;

        // Decrypt with ChaCha20-Poly1305
        int result = crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char*)plaintext.data(),
            &mlen,
            nullptr,  // nsec
            (const unsigned char*)ciphertext.data(),
            ciphertext.length(),
            nullptr,  // ad
            0,        // adlen
            m_noise_state.k,
            nonce
        );

        if (result != 0) {
            nativeLog("Noise Error: ChaCha20-Poly1305 decryption failed (authentication failed)");
            return "";
        }

        plaintext.resize(mlen);
        return plaintext;
    }

private:
    Role m_role;
    std::string m_static_pubkey;
    std::string m_ephemeral_private;
    std::string m_ephemeral_public;
    NoiseState m_noise_state;
    bool m_handshake_complete;

    // Mix data into handshake hash
    void mix_hash(const std::string& data) {
        uint8_t h_temp[HASH_LEN];
        // h = SHA256(h || data)
        uint8_t input[HASH_LEN + 32]; // Max data size 32 bytes
        memcpy(input, m_noise_state.h, HASH_LEN);
        memcpy(input + HASH_LEN, data.data(), data.length());
        crypto_hash_sha256(h_temp, input, HASH_LEN + data.length());
        memcpy(m_noise_state.h, h_temp, HASH_LEN);
    }

    // Mix DH output into chaining key and encryption key
    void mix_key(const std::string& dh_result) {
        // HKDF-SHA256 expansion
        uint8_t okm[64];
        uint8_t prk[HASH_LEN];

        // Extract: prk = HMAC-SHA256(salt=h, input=dh_result)
        // For simplicity using libsodium's HKDF
        uint8_t info[] = {0}; // Empty info
        
        crypto_kdf_hkdf_sha256_extract(
            prk,
            m_noise_state.h,
            HASH_LEN,
            (const uint8_t*)dh_result.data(),
            dh_result.length()
        );

        // Expand: ck || k = HKDF-Expand(prk, info="", L=64)
        crypto_kdf_hkdf_sha256_expand(
            okm,
            64,
            prk,
            info,
            sizeof(info)
        );

        memcpy(m_noise_state.ck, okm, HASH_LEN);
        memcpy(m_noise_state.k, okm + HASH_LEN, 32);
        m_noise_state.key_set = true;
        m_noise_state.n = 0; // Reset nonce for new key
    }

    // Perform Curve25519 ECDH
    bool perform_dh(const std::string& private_key, const std::string& public_key) {
        if (private_key.length() != DH_LEN || public_key.length() != DH_LEN) {
            nativeLog("Noise Error: Invalid DH key sizes");
            return false;
        }

        uint8_t shared_secret[DH_LEN];
        int result = crypto_scalarmult_curve25519(
            shared_secret,
            (const uint8_t*)private_key.data(),
            (const uint8_t*)public_key.data()
        );

        if (result != 0) {
            nativeLog("Noise Error: ECDH computation failed");
            return false;
        }

        std::string dh_result((const char*)shared_secret, DH_LEN);
        mix_key(dh_result);
        return true;
    }

    // Encrypt empty message (for authentication)
    std::string encrypt_empty() {
        uint8_t nonce[12];
        memset(nonce, 0, sizeof(nonce));
        memcpy(nonce + 4, &m_noise_state.n, 8);
        m_noise_state.n++;

        std::string ciphertext(CIPHERTEXT_LEN, 0);
        unsigned long long clen;

        int result = crypto_aead_chacha20poly1305_ietf_encrypt(
            (unsigned char*)ciphertext.data(),
            &clen,
            nullptr,
            0,
            nullptr,
            0,
            nullptr,
            m_noise_state.k,
            nonce
        );

        return (result == 0) ? ciphertext : "";
    }

    // Decrypt empty message
    bool decrypt_empty(const std::string& ciphertext) {
        if (ciphertext.length() != CIPHERTEXT_LEN) {
            return false;
        }

        uint8_t nonce[12];
        memset(nonce, 0, sizeof(nonce));
        memcpy(nonce + 4, &m_noise_state.n, 8);
        m_noise_state.n++;

        unsigned long long mlen;
        int result = crypto_aead_chacha20poly1305_ietf_decrypt(
            nullptr,
            &mlen,
            nullptr,
            (const unsigned char*)ciphertext.data(),
            ciphertext.length(),
            nullptr,
            0,
            m_noise_state.k,
            nonce
        );

        return result == 0;
    }
};

// Public interface implementation
NoiseSession::NoiseSession(Role role, const std::string& local_static_key)
    : m_role(role), m_state(State::INITIALIZED), m_nonce_counter(0) {
    m_impl = std::make_unique<Impl>(role, local_static_key);
}

NoiseSession::~NoiseSession() = default;

std::string NoiseSession::initiate_handshake() {
    auto result = m_impl->initiate_handshake();
    if (result.empty() && m_state != State::HANDSHAKE_PENDING) {
        set_state(State::HANDSHAKE_PENDING);
    }
    return result;
}

std::string NoiseSession::process_handshake_message(const std::string& message) {
    auto result = m_impl->process_handshake_message(message);
    if (m_impl->m_handshake_complete) {
        set_state(State::HANDSHAKE_COMPLETE);
    }
    return result;
}

std::string NoiseSession::encrypt_message(const std::string& plaintext) {
    if (!is_handshake_complete()) {
        m_error = "Handshake not complete";
        return "";
    }
    return m_impl->encrypt_message(plaintext);
}

std::string NoiseSession::decrypt_message(const std::string& ciphertext) {
    if (!is_handshake_complete()) {
        m_error = "Handshake not complete";
        return "";
    }
    return m_impl->decrypt_message(ciphertext);
}

void NoiseSession::reset() {
    m_state = State::INITIALIZED;
    m_error = "";
    m_nonce_counter = 0;
}

namespace noise_utils {
    std::string generate_static_keypair(std::string& out_private_key) {
        uint8_t private_key[32];
        uint8_t public_key[32];

        crypto_box_seed_keypair(public_key, private_key, nullptr);

        out_private_key = std::string((const char*)private_key, 32);
        return std::string((const char*)public_key, 32);
    }

    std::string get_public_key(const std::string& private_key) {
        if (private_key.length() != 32) {
            nativeLog("Noise Error: Invalid private key size");
            return "";
        }

        uint8_t public_key[32];
        crypto_scalarmult_base(public_key, (const uint8_t*)private_key.data());
        return std::string((const char*)public_key, 32);
    }

    std::pair<std::string, std::string> generate_ephemeral_keypair() {
        uint8_t private_key[32];
        uint8_t public_key[32];

        crypto_box_keypair(public_key, private_key);

        return {
            std::string((const char*)private_key, 32),
            std::string((const char*)public_key, 32)
        };
    }
}
