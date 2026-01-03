#include "noise_protocol.h"
#include "noise_nk.h"
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

int main() {
    std::cout << "Running Crypto Tests..." << std::endl;
    
    test_noise_nn_handshake();
    test_noise_encryption();
    
    if (tests_failed == 0) {
        std::cout << "ALL CRYPTO TESTS PASSED" << std::endl;
        return 0;
    } else {
        std::cerr << tests_failed << " TESTS FAILED" << std::endl;
        return 1;
    }
}
