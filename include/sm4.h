/**
 * Cryptoshark is an open source and educational crypto library under GPL v2 license.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#ifndef CRYPTODEMO_SM4_H
#define CRYPTODEMO_SM4_H

#include <iostream>

// sm4 context
typedef struct _sm4_ctx
{
    uint8_t key[16];     // encrypt/decrypt key
    size_t keybits;      // always 128 bits
    uint32_t rk[32];     // round keys for 32 rounds
    uint32_t X[36];      // encryption/decryption X
}sm4_ctx;

void sm4_ctx_init(sm4_ctx *ctx);

void sm4_ctx_free(sm4_ctx *ctx);

void sm4_ctx_setkey(sm4_ctx *ctx, uint8_t key[16], size_t keybits);

void sm4_encrypt(sm4_ctx *ctx, uint8_t *input, uint8_t *output);


#endif //CRYPTODEMO_SM4_H
