#include "crypto_utils.h"
#include "aes.h"
#include "logger.h"
#include <cstring>
#include <random>
#include <vector>

// SECURITY WARNING: These keys are still hardcoded for this example.
// In production, keys should be:
// 1. Derived from a key exchange protocol (e.g., ECDH)
// 2. Stored in secure storage (Android Keystore, Encrypted SharedPreferences)
// 3. Never hardcoded in source
static const uint8_t g_aes_key[KEYLEN] = { 
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

// Generate random IV for each encryption operation
void generate_random_iv(uint8_t* iv, size_t length) {
    if (!iv || length != AES_BLOCKLEN) {
        nativeLog("Crypto Error: Invalid IV parameters");
        return;
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < length; ++i) {
        iv[i] = static_cast<uint8_t>(dis(gen));
    }
}

// Helper to apply PKCS7 padding
static void pkcs7_pad(std::string& data) {
    int padding = AES_BLOCKLEN - (data.length() % AES_BLOCKLEN);
    data.append(padding, (char)padding);
}

// Helper to remove PKCS7 padding
static void pkcs7_unpad(std::string& data) {
    if (data.empty()) return;

    int padding = data.back();
    if (padding > 0 && padding <= AES_BLOCKLEN) {
        bool padding_ok = true;
        for (int i = 0; i < padding; ++i) {
            if (data[data.length() - 1 - i] != padding) {
                padding_ok = false;
                break;
            }
        }
        if (padding_ok) {
            data.resize(data.length() - padding);
        }
    }
}

std::string encrypt_message(const std::string& plain_text) {
    struct AES_ctx ctx;
    uint8_t random_iv[AES_BLOCKLEN];
    generate_random_iv(random_iv, AES_BLOCKLEN);
    
    AES_init_ctx_iv(&ctx, g_aes_key, random_iv);
    
    std::string encrypted_text = plain_text;
    pkcs7_pad(encrypted_text);
    
    AES_CBC_encrypt_buffer(&ctx, (uint8_t*)encrypted_text.data(), encrypted_text.length());
    
    // Prepend IV to ciphertext so recipient can decrypt
    std::string result(reinterpret_cast<const char*>(random_iv), AES_BLOCKLEN);
    result.append(encrypted_text);
    
    return result;
}

std::string decrypt_message(const std::string& encrypted_text) {
    if (encrypted_text.length() < AES_BLOCKLEN) {
        nativeLog("AES Error: Ciphertext too short to contain IV.");
        return "";
    }

    // Extract IV from beginning of ciphertext
    uint8_t iv[AES_BLOCKLEN];
    std::memcpy(iv, encrypted_text.data(), AES_BLOCKLEN);
    
    // Extract actual ciphertext
    std::string ciphertext = encrypted_text.substr(AES_BLOCKLEN);
    
    if (ciphertext.length() % AES_BLOCKLEN != 0) {
        nativeLog("AES Error: Ciphertext is not a multiple of block size.");
        return "";
    }

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, g_aes_key, iv);

    std::string decrypted_text = ciphertext;
    AES_CBC_decrypt_buffer(&ctx, (uint8_t*)decrypted_text.data(), decrypted_text.length());
    
    pkcs7_unpad(decrypted_text);
    
    return decrypted_text;
}

std::string encrypt_message_udp(const std::string& plain_text) {
    return encrypt_message(plain_text);
}

std::string decrypt_message_udp(const std::string& encrypted_text) {
    return decrypt_message(encrypted_text);
}
