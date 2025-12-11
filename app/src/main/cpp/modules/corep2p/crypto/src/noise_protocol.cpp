#include "noise_protocol.h"
#include "logger.h"
#include <cstring>
#include <memory>
#include <cstdlib>
#include <sodium.h>

// Noise Protocol NN state machine implementation
// Message pattern NN:
//   -> e
//   <- e, ee
//   -> nothing (complete)

class NoiseSession::Impl {
public:
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
        if (sodium_init() < 0) {
            nativeLog("Libsodium initialization failed!");
            throw std::runtime_error("Libsodium init failed");
        }

        // Generate ephemeral keypair for this session
        m_ephemeral_private.resize(DH_LEN);
        m_ephemeral_public.resize(DH_LEN);
        crypto_box_keypair((unsigned char*)m_ephemeral_public.data(), (unsigned char*)m_ephemeral_private.data());

        // Initialize Noise state
        memset(&m_noise_state, 0, sizeof(m_noise_state));
        m_noise_state.key_set = false;
        m_noise_state.n = 0;

        // Protocol name for Noise NN
        const char* protocol_name = "Noise_NN_25519_ChaChaPoly_SHA256";
        size_t proto_len = strlen(protocol_name);

        // Initialize h and ck with hash of protocol name
        crypto_hash_sha256(m_noise_state.h, (const unsigned char*)protocol_name, proto_len);
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

        unsigned char nonce[12] = {0};
        memcpy(nonce + 4, &m_noise_state.n, 8); // 64-bit nonce in lower 8 bytes
        std::string ciphertext(plaintext.size() + TAGLEN, '\0');
        unsigned long long clen;
        crypto_aead_chacha20poly1305_ietf_encrypt((unsigned char*)ciphertext.data(), &clen,
            (const unsigned char*)plaintext.data(), plaintext.size(),
            nullptr, 0, nullptr, nonce, m_noise_state.k);
        m_noise_state.n++;
        return ciphertext;
    }

    std::string decrypt_message(const std::string& ciphertext) {
        if (!m_handshake_complete || !m_noise_state.key_set || ciphertext.size() < TAGLEN) return "";
        unsigned char nonce[12] = {0};
        memcpy(nonce + 4, &m_noise_state.n, 8);
        std::string plaintext(ciphertext.size() - TAGLEN, '\0');
        unsigned long long plen;
        if (crypto_aead_chacha20poly1305_ietf_decrypt((unsigned char*)plaintext.data(), &plen,
            nullptr, (const unsigned char*)ciphertext.data(), ciphertext.size(),
            nullptr, 0, nonce, m_noise_state.k) != 0) {
            return "";
        }
        m_noise_state.n++;
        return plaintext;
    }

private:
    Role m_role;
    std::string m_static_pubkey;
    std::string m_ephemeral_private;
    std::string m_ephemeral_public;
    NoiseState m_noise_state;
public:
    bool m_handshake_complete;

    // Mix data into handshake hash
    void mix_hash(const std::string& data) {
        // h = SHA256(h || data)
        uint8_t temp[HASH_LEN + data.size()];
        memcpy(temp, m_noise_state.h, HASH_LEN);
        memcpy(temp + HASH_LEN, data.data(), data.size());
        crypto_hash_sha256(m_noise_state.h, temp, HASH_LEN + data.size());
    }

    // Mix DH output into chaining key and encryption key
    void mix_key(const std::string& dh_result) {
        // ck, k = HKDF(ck, dh_result)
        uint8_t out[HASH_LEN + 32];
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, m_noise_state.ck, HASH_LEN);
        crypto_auth_hmacsha256_update(&state, (const unsigned char*)dh_result.data(), dh_result.size());
        crypto_auth_hmacsha256_final(&state, out);
        memcpy(m_noise_state.ck, out, HASH_LEN);
        memcpy(m_noise_state.k, out + HASH_LEN, 32);
        m_noise_state.key_set = true;
        m_noise_state.n = 0;
    }

    // Perform Curve25519 ECDH
    bool perform_dh(const std::string& private_key, const std::string& public_key) {
        if (private_key.length() != DH_LEN || public_key.length() != DH_LEN) {
            nativeLog("Noise Error: Invalid DH key sizes");
            return false;
        }

        uint8_t shared_secret[DH_LEN];
        if (crypto_scalarmult(shared_secret, (const unsigned char*)private_key.data(), (const unsigned char*)public_key.data()) != 0) {
            nativeLog("Noise Error: crypto_scalarmult failed");
            return false;
        }

        mix_key(std::string((char*)shared_secret, DH_LEN));
        return true;
    }

    // Encrypt empty message (for authentication)
    std::string encrypt_empty() {
        if (!m_noise_state.key_set) return std::string();
        unsigned char nonce[12] = {0};
        unsigned char ciphertext[TAGLEN];
        unsigned long long clen;
        crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &clen,
            nullptr, 0, nullptr, 0, nullptr, nonce, m_noise_state.k);
        return std::string((char*)ciphertext, TAGLEN);
    }

    // Decrypt empty message
    bool decrypt_empty(const std::string& ciphertext) {
        if (!m_noise_state.key_set || ciphertext.length() != TAGLEN) return false;
        unsigned char nonce[12] = {0};
        unsigned char decrypted[1];
        unsigned long long dlen;
        return crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, &dlen,
            nullptr, (const unsigned char*)ciphertext.data(), TAGLEN,
            nullptr, 0, nonce, m_noise_state.k) == 0;
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
        out_private_key.resize(32);
        std::string pubkey(32, '\0');
        crypto_box_keypair((unsigned char*)pubkey.data(), (unsigned char*)out_private_key.data());
        return pubkey;
    }

    std::string get_public_key(const std::string& private_key) {
        if (private_key.length() != 32) return "";
        std::string pubkey(32, '\0');
        crypto_scalarmult_base((unsigned char*)pubkey.data(), (const unsigned char*)private_key.data());
        return pubkey;
    }

    std::pair<std::string, std::string> generate_ephemeral_keypair() {
        std::string priv(32, '\0');
        std::string pub(32, '\0');
        crypto_box_keypair((unsigned char*)pub.data(), (unsigned char*)priv.data());
        return {priv, pub};
    }
}
