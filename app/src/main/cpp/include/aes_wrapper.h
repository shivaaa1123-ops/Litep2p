#ifndef AES_WRAPPER_H
#define AES_WRAPPER_H

#include <string>

std::string encrypt_message(const std::string& plain_text);
std::string decrypt_message(const std::string& encrypted_text);

#endif // AES_WRAPPER_H
