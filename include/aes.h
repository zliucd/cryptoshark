/**
 * Cryptoshark is an open source and educational crypto library under GPL v2 license.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#ifndef CRYPTODEMO_AES_H
#define CRYPTODEMO_AES_H

#include <iostream>

// AES context
typedef struct _aes_ctx_t
{
    uint8_t   key[32];     // iv, max 32 bytes
    size_t    key_bits;    // keybits: 128, 192, 256
    size_t    key_bytes;
    size_t    block_bytes;  // always 16 bytes
    size_t    round;        // rounds: 128: 11, 192: 13, 256:15
    size_t    sr;          //  schedule rounds, 4 * round
    uint32_t  rk[60];      //  little-endian of round keys
}aes_ctx_t;


void aes_ctx_init(aes_ctx_t *aes);

void aes_ctx_free(aes_ctx_t *aes);

int aes_set_key(aes_ctx_t *aes, uint8_t *keybuf, size_t keybits);

int aes_encrypt_cbc(aes_ctx_t *aes, uint8_t *input, size_t ilen, uint8_t iv[16], uint8_t *output, size_t *olen);

int aes_decrypt_cbc(aes_ctx_t *aes, uint8_t *ciphertext, size_t ilen, uint8_t iv[16], uint8_t *output, size_t *olen);

int aes_ctr_internal(aes_ctx_t *aes, uint8_t *input, size_t ilen,
                    uint8_t nonce_counter[16], uint8_t stream_block[16],
                    uint8_t *output, size_t *offset);

int aes_encrypt_internal(const uint8_t *plaintext, size_t ilen, aes_ctx_t *aes, uint8_t *output);

int aes_decrypt_internal(uint8_t *input, size_t ilen, aes_ctx_t *aes, uint8_t *output);

int g_mix_column(uint8_t *r);

#endif //CRYPTODEMO_AES_H

