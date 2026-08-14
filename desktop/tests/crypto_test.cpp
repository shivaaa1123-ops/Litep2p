#include "noise_protocol.h"
#include "noise_nk.h"
#include "crypto_utils.h"
#include "sha1_md5.h"
#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <cstring>

static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAIL: " << msg << " [" << __FILE__ << ":" << __LINE__ << "]" << std::endl; \
            tests_failed++; \
            return false; \
        } \
    } while (0)

// Helper to convert string to vector
std::vector<uint8_t> str_to_vec(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// Helper to convert vector to string
std::string vec_to_str(const std::vector<uint8_t>& v) {
    return std::string(v.begin(), v.end());
}

static std::string to_hex(const std::vector<uint8_t>& v) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(v.size() * 2);
    for (uint8_t b : v) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

// ============================================================================
// Transport crypto tests (ChaCha20-Poly1305)
// ============================================================================

bool test_transport_crypto_roundtrip() {
    std::cout << "Testing transport crypto roundtrip..." << std::endl;

    const std::string plain = "Hello, LiteP2P transport crypto!";
    const std::string cipher = encrypt_message(plain);
    TEST_ASSERT(!cipher.empty(), "encrypt_message returned empty");

    // Format: nonce(12) + ciphertext + tag(16).
    TEST_ASSERT(cipher.size() >= 28, "ciphertext too short for nonce+tag");
    TEST_ASSERT(cipher.size() == 12 + plain.size() + 16, "ciphertext length mismatch");

    const std::string decrypted = decrypt_message(cipher);
    TEST_ASSERT(decrypted == plain, "decrypt_message roundtrip mismatch");
    TEST_ASSERT(encrypt_message_udp(plain).size() > 0, "udp encrypt failed");
    TEST_ASSERT(decrypt_message_udp(encrypt_message_udp(plain)) == plain, "udp roundtrip mismatch");

    std::cout << "Transport crypto roundtrip Passed!" << std::endl;
    return true;
}

bool test_transport_crypto_tamper_detection() {
    std::cout << "Testing transport crypto tamper detection..." << std::endl;

    const std::string plain = "attack at dawn";
    std::string cipher = encrypt_message(plain);
    TEST_ASSERT(!cipher.empty(), "encrypt failed");

    // Flip one bit in the ciphertext body (after the nonce).
    cipher[13] = static_cast<char>(cipher[13] ^ 0x01);
    TEST_ASSERT(decrypt_message(cipher).empty(), "tampered ciphertext must fail authentication");

    // Corrupt the tag.
    cipher = encrypt_message(plain);
    cipher[cipher.size() - 1] = static_cast<char>(cipher[cipher.size() - 1] ^ 0x01);
    TEST_ASSERT(decrypt_message(cipher).empty(), "corrupted tag must fail authentication");

    // Garbage input.
    TEST_ASSERT(decrypt_message("not-a-valid-ciphertext").empty(), "garbage must fail");
    TEST_ASSERT(decrypt_message("").empty(), "empty must fail");

    std::cout << "Transport crypto tamper detection Passed!" << std::endl;
    return true;
}

bool test_transport_crypto_nonce_uniqueness() {
    std::cout << "Testing transport crypto nonce uniqueness..." << std::endl;

    const std::string plain = "same plaintext, different nonces";
    const std::string c1 = encrypt_message(plain);
    const std::string c2 = encrypt_message(plain);
    TEST_ASSERT(c1 != c2, "two encryptions must differ (random nonce)");

    uint8_t key[32];
    TEST_ASSERT(transport_key_resolve(key), "transport key must resolve");
    TEST_ASSERT(decrypt_message(c1) == plain && decrypt_message(c2) == plain,
                "both ciphertexts decrypt");

    std::cout << "Transport crypto nonce uniqueness Passed!" << std::endl;
    return true;
}

bool test_noise_nn_handshake() {
    std::cout << "Testing Noise NN Handshake..." << std::endl;
    
    // Create initiator and responder
    // NN pattern doesn't use static keys for authentication, but the constructor might require a placeholder
    std::string init_static_key(32, 'A');
    std::string resp_static_key(32, 'B');
    
    NoiseSession initiator(NoiseSession::Role::INITIATOR, init_static_key);
    NoiseSession responder(NoiseSession::Role::RESPONDER, resp_static_key);
    
    // 1. Initiator starts handshake
    std::string msg1 = initiator.initiate_handshake();
    TEST_ASSERT(!msg1.empty(), "Initiator failed to generate first handshake message");
    
    // 2. Responder processes message 1
    std::string msg2 = responder.process_handshake_message(msg1);
    TEST_ASSERT(!msg2.empty(), "Responder failed to process message 1");
    
    // 3. Initiator processes message 2 (response)
    std::string msg3 = initiator.process_handshake_message(msg2);
    // Note: Depending on implementation, NN might be 2 or 3 messages. 
    // Usually NN is -> e, <- e, ee. So 2 messages.
    
    TEST_ASSERT(initiator.is_handshake_complete(), "Initiator handshake should be complete");
    TEST_ASSERT(responder.is_handshake_complete(), "Responder handshake should be complete");
    
    std::cout << "Noise NN Handshake Passed!" << std::endl;
    return true;
}

bool test_noise_encryption() {
    std::cout << "Testing Noise Encryption..." << std::endl;
    
    std::string init_static_key(32, 'A');
    std::string resp_static_key(32, 'B');
    
    NoiseSession initiator(NoiseSession::Role::INITIATOR, init_static_key);
    NoiseSession responder(NoiseSession::Role::RESPONDER, resp_static_key);
    
    // Perform handshake first
    std::string msg1 = initiator.initiate_handshake();
    std::string msg2 = responder.process_handshake_message(msg1);
    initiator.process_handshake_message(msg2);
    
    TEST_ASSERT(initiator.is_handshake_complete(), "Handshake failed");
    
    // Test encryption
    std::string plaintext = "Hello, World!";
    std::string ciphertext = initiator.encrypt_message(plaintext);
    TEST_ASSERT(!ciphertext.empty(), "Encryption failed");
    TEST_ASSERT(ciphertext != plaintext, "Ciphertext should not match plaintext");
    
    // Test decryption
    std::string decrypted = responder.decrypt_message(ciphertext);
    TEST_ASSERT(decrypted == plaintext, "Decryption failed or mismatch");
    
    std::cout << "Noise Encryption Passed!" << std::endl;
    return true;
}

// ============================================================================
// SHA-1 / MD5 / HMAC-SHA1 test vectors
// ============================================================================

bool test_sha1_vectors() {
    std::cout << "Testing SHA-1 vectors..." << std::endl;

    // RFC 3174: SHA1("abc")
    TEST_ASSERT(to_hex(litep2p_crypto::sha1(
                    reinterpret_cast<const uint8_t*>("abc"), 3)) ==
                    "a9993e364706816aba3e25717850c26c9cd0d89d",
                "SHA1('abc') mismatch");

    // RFC 3174: SHA1("") - empty string
    TEST_ASSERT(to_hex(litep2p_crypto::sha1(nullptr, 0)) ==
                    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "SHA1(empty) mismatch");

    // SHA1 of two blocks: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    const std::string two_block =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    TEST_ASSERT(to_hex(litep2p_crypto::sha1(
                    reinterpret_cast<const uint8_t*>(two_block.data()),
                    two_block.size())) ==
                    "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
                "SHA1(two-block) mismatch");

    std::cout << "SHA-1 vectors Passed!" << std::endl;
    return true;
}

bool test_md5_vectors() {
    std::cout << "Testing MD5 vectors..." << std::endl;

    // RFC 1321: MD5("abc")
    TEST_ASSERT(to_hex(litep2p_crypto::md5(
                    reinterpret_cast<const uint8_t*>("abc"), 3)) ==
                    "900150983cd24fb0d6963f7d28e17f72",
                "MD5('abc') mismatch");

    // RFC 1321: MD5("")
    TEST_ASSERT(to_hex(litep2p_crypto::md5(nullptr, 0)) ==
                    "d41d8cd98f00b204e9800998ecf8427e",
                "MD5(empty) mismatch");

    // RFC 1321: MD5("message digest")
    const std::string md = "message digest";
    TEST_ASSERT(to_hex(litep2p_crypto::md5(
                    reinterpret_cast<const uint8_t*>(md.data()), md.size())) ==
                    "f96b697d7cb7938d525a2f31aaf161d0",
                "MD5('message digest') mismatch");

    std::cout << "MD5 vectors Passed!" << std::endl;
    return true;
}

bool test_hmac_sha1_vectors() {
    std::cout << "Testing HMAC-SHA1 vectors..." << std::endl;

    // RFC 2202 test case 2: key="Jefe", data="what do ya want for nothing?"
    const std::string key = "Jefe";
    const std::string data = "what do ya want for nothing?";
    TEST_ASSERT(to_hex(litep2p_crypto::hmac_sha1(key, data)) ==
                    "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
                "HMAC-SHA1 (RFC 2202 #2) mismatch");

    // RFC 2202 test case 1: key = 0x0b * 20, data = "Hi There"
    const std::string key20(20, '\x0b');
    TEST_ASSERT(to_hex(litep2p_crypto::hmac_sha1(key20, "Hi There")) ==
                    "b617318655057264e28bc0b6fb378c8ef146be00",
                "HMAC-SHA1 (RFC 2202 #1) mismatch");

    std::cout << "HMAC-SHA1 vectors Passed!" << std::endl;
    return true;
}

bool test_ct_equal() {
    std::cout << "Testing constant-time compare..." << std::endl;

    const std::vector<uint8_t> a{1, 2, 3};
    const std::vector<uint8_t> b{1, 2, 3};
    const std::vector<uint8_t> c{1, 2, 4};
    const std::vector<uint8_t> d{1, 2};

    TEST_ASSERT(litep2p_crypto::ct_equal(a, b), "equal vectors must compare equal");
    TEST_ASSERT(!litep2p_crypto::ct_equal(a, c), "differing vectors must differ");
    TEST_ASSERT(!litep2p_crypto::ct_equal(a, d), "different sizes must differ");

    std::cout << "Constant-time compare Passed!" << std::endl;
    return true;
}

// ============================================================================
// Per-peer transport key tests (forward secrecy / per-peer isolation)
// ============================================================================

static void fill_key(uint8_t* k, uint8_t seed) {
    for (int i = 0; i < 32; ++i) k[i] = static_cast<uint8_t>(seed + i);
}

bool test_per_peer_transport_keys() {
    std::cout << "Testing per-peer transport keys..." << std::endl;

    uint8_t a_send[32], a_recv[32], b_send[32], b_recv[32];
    fill_key(a_send, 0x10);
    fill_key(a_recv, 0x10);  // same device: self-roundtrip uses same key
    fill_key(b_send, 0x30);
    fill_key(b_recv, 0x30);  // same device

    TEST_ASSERT(set_peer_transport_keys("peer-a", a_send, a_recv), "register A");
    TEST_ASSERT(set_peer_transport_keys("peer-b", b_send, b_recv), "register B");
    TEST_ASSERT(has_peer_transport_keys("peer-a"), "has A");
    TEST_ASSERT(has_peer_transport_keys("peer-b"), "has B");
    TEST_ASSERT(!has_peer_transport_keys("peer-c"), "no C");

    // Roundtrip for each peer.
    const std::string plain = "per-peer secret payload";
    const std::string c_a = encrypt_message_for_peer("peer-a", plain);
    const std::string c_b = encrypt_message_for_peer("peer-b", plain);
    TEST_ASSERT(!c_a.empty() && !c_b.empty(), "encrypt for peer");
    TEST_ASSERT(decrypt_message_for_peer("peer-a", c_a) == plain, "A roundtrip");
    TEST_ASSERT(decrypt_message_for_peer("peer-b", c_b) == plain, "B roundtrip");

    // Isolation: a ciphertext encrypted with a key that is NOT registered
    // cannot be decrypted by anyone (direct lookup, try-all-keys, or the
    // shared network key). This is the real security property: no matching
    // key => no plaintext.
    uint8_t rogue_send[32], rogue_recv[32];
    fill_key(rogue_send, 0xEE);
    fill_key(rogue_recv, 0xEE);
    set_peer_transport_keys("rogue", rogue_send, rogue_recv);
    const std::string c_rogue = encrypt_message_for_peer("rogue", plain);
    clear_peer_transport_keys("rogue");  // remove the only key that could decrypt it
    TEST_ASSERT(decrypt_message_for_peer("peer-a", c_rogue).empty(),
                "unregistered-key ciphertext must be undecryptable");
    TEST_ASSERT(decrypt_message_for_peer("peer-b", c_rogue).empty(),
                "unregistered-key ciphertext must be undecryptable (try-all)");

    // No per-peer key => falls back to the shared network key.
    const std::string c_fb = encrypt_message_for_peer("peer-c", plain);
    TEST_ASSERT(!c_fb.empty(), "fallback encrypt");
    TEST_ASSERT(decrypt_message(c_fb) == plain, "fallback decrypt via network key");

    // Clear and verify fallback after clearing.
    clear_peer_transport_keys("peer-a");
    TEST_ASSERT(!has_peer_transport_keys("peer-a"), "cleared A");
    TEST_ASSERT(decrypt_message_for_peer("peer-a", encrypt_message_for_peer("peer-a", plain)) == plain,
                "network-key fallback after clear");

    std::cout << "Per-peer transport keys Passed!" << std::endl;
    return true;
}

int main() {
    std::cout << "Running Crypto Tests..." << std::endl;

    test_noise_nn_handshake();
    test_noise_encryption();
    test_transport_crypto_roundtrip();
    test_transport_crypto_tamper_detection();
    test_transport_crypto_nonce_uniqueness();
    test_sha1_vectors();
    test_md5_vectors();
    test_hmac_sha1_vectors();
    test_ct_equal();
    test_per_peer_transport_keys();

    if (tests_failed == 0) {
        std::cout << "ALL CRYPTO TESTS PASSED" << std::endl;
        return 0;
    } else {
        std::cerr << tests_failed << " TESTS FAILED" << std::endl;
        return 1;
    }
}
