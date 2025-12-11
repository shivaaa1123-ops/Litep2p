#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
#include <cstdint>

// Encryption/decryption utilities with proper IV handling
std::string encrypt_message(const std::string& plain_text);
std::string decrypt_message(const std::string& encrypted_text);

// UDP-specific encryption (same as regular for now, but allows future customization)
std::string encrypt_message_udp(const std::string& plain_text);
std::string decrypt_message_udp(const std::string& encrypted_text);

// Generate a random IV for each encryption session
void generate_random_iv(uint8_t* iv, size_t length);

#endif // CRYPTO_UTILS_H
