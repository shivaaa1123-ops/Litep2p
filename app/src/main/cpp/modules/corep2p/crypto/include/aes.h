#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

#define CBC 1
#define ECB 0
#define CTR 0

// AES192 is the default mode, but you can override it
#if !(defined(AES256) || defined(AES192) || defined(AES128))
    #define AES192 1
#endif

#if defined(AES256) && (AES256 == 1)
    #define KEYLEN 32
    #define N_ROUNDS 14
#elif defined(AES192) && (AES192 == 1)
    #define KEYLEN 24
    #define N_ROUNDS 12
#else
    #define KEYLEN 16
    #define N_ROUNDS 10
#endif

#define AES_BLOCKLEN 16 

#ifdef __cplusplus
extern "C" {
#endif

struct AES_ctx {
    uint8_t RoundKey[(N_ROUNDS + 1) * AES_BLOCKLEN];
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
    uint8_t Iv[AES_BLOCKLEN];
#endif
};

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);

#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
#endif

#if defined(ECB) && (ECB == 1)
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);
#endif

#if defined(CBC) && (CBC == 1)
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);
#endif

#if defined(CTR) && (CTR == 1)
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);
#endif

#ifdef __cplusplus
}
#endif

#endif // _AES_H_
