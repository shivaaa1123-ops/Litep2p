// e2e.cpp — E2E content-key + payload AEAD using the engine's bundled
// libsodium primitives.

#include "networkos/object/e2e.h"

#include <sodium.h>

namespace networkos {
namespace e2e {

bool generate_content_key(ContentKey& out) {
    randombytes_buf(out.bytes, sizeof(out.bytes));
    return true;
}

bool encrypt_payload(const std::string& plaintext, const ContentKey& key,
                     std::string& out_ct) {
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    out_ct.assign(reinterpret_cast<const char*>(nonce), sizeof(nonce));
    const size_t ct_len = plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    const size_t prev = out_ct.size();
    out_ct.resize(prev + ct_len);
    unsigned long long out_len = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(&out_ct[prev]), &out_len,
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
        nullptr, 0,             // no AD
        nullptr,                // no nsec
        nonce, key.bytes);
    if (rc != 0) return false;
    out_ct.resize(prev + out_len);
    return true;
}

bool decrypt_payload(const std::string& ct, const ContentKey& key,
                     std::string& out_pt) {
    if (ct.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) return false;
    const unsigned char* nonce = reinterpret_cast<const unsigned char*>(ct.data());
    const size_t body_len = ct.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    if (body_len < crypto_aead_xchacha20poly1305_ietf_ABYTES) return false;
    out_pt.resize(body_len - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long out_len = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        reinterpret_cast<unsigned char*>(&out_pt[0]), &out_len,
        nullptr,                // no nsec
        reinterpret_cast<const unsigned char*>(ct.data()) +
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
        body_len, nullptr, 0,   // no AD
        nonce, key.bytes);
    if (rc != 0) return false;
    out_pt.resize(out_len);
    return true;
}

bool wrap_key(const ContentKey& key, const uint8_t recipient_pk[32],
              std::string& out_wrapped) {
    if (!recipient_pk) return false;
    const size_t ct_len = sizeof(key.bytes) + crypto_box_SEALBYTES;
    out_wrapped.resize(ct_len);
    const int rc = crypto_box_seal(
        reinterpret_cast<unsigned char*>(&out_wrapped[0]),
        key.bytes, sizeof(key.bytes), recipient_pk);
    if (rc != 0) return false;
    out_wrapped.resize(ct_len);
    return true;
}

bool unwrap_key(const std::string& wrapped, const uint8_t sk[32],
                const uint8_t pk[32], ContentKey& out_key) {
    if (!sk || !pk || wrapped.size() != sizeof(out_key.bytes) + crypto_box_SEALBYTES) {
        return false;
    }
    const int rc = crypto_box_seal_open(
        out_key.bytes,
        reinterpret_cast<const unsigned char*>(wrapped.data()), wrapped.size(),
        pk, sk);
    return rc == 0;
}

} // namespace e2e
} // namespace networkos
