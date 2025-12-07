#include "aes.h"
#include <string>
#include <vector>
#include <cstring>
#include "logger.h"

// Key and IV should be securely managed, but are hardcoded for this example
static const uint8_t g_aes_key[KEYLEN] = { 
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

static const uint8_t g_aes_iv[AES_BLOCKLEN] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

// Helper to apply PKCS7 padding
void pkcs7_pad(std::string& data) {
    int padding = AES_BLOCKLEN - (data.length() % AES_BLOCKLEN);
    data.append(padding, (char)padding);
}

// Helper to remove PKCS7 padding
void pkcs7_unpad(std::string& data) {
    if (data.empty()) return;

    int padding = data.back();
    if (padding > 0 && padding <= AES_BLOCKLEN) {
        // Additional check for valid padding
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
        // If padding is invalid, we might want to log an error or handle it,
        // but for now, we'll just leave the data as is to avoid crashing.
    }
}


std::string encrypt_message(const std::string& plain_text) {
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, g_aes_key, g_aes_iv);
    
    std::string encrypted_text = plain_text;
    pkcs7_pad(encrypted_text);
    
    AES_CBC_encrypt_buffer(&ctx, (uint8_t*)encrypted_text.data(), encrypted_text.length());
    return encrypted_text;
}

std::string decrypt_message(const std::string& encrypted_text) {
    if (encrypted_text.length() % AES_BLOCKLEN != 0) {
        nativeLog("AES Error: Ciphertext is not a multiple of block size.");
        return "";
    }

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, g_aes_key, g_aes_iv);

    std::string decrypted_text = encrypted_text;
    
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
