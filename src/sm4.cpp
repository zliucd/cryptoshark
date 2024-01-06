/**
 * Cryptoshark is an open source and educational crypto library under Apache License V2.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#include <iostream>
#include <string.h>
#include <assert.h>

#include "sm4.h"
#include "util.h"

using namespace std;

const static uint32_t FK[4] = {0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC};

const static uint32_t CK[32] =
{
   0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
   0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
   0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
   0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
   0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
   0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
   0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
   0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

// sbox table
const static uint8_t sm4_sbox[][16] =
{
        {0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05},
        {0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},
        {0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62},
        {0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6},
        {0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8},
        {0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35},
        {0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87},
        {0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E},
        {0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1},
        {0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3},
        {0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F},
        {0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51},
        {0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8},
        {0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0},
        {0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84},
        {0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48}
};

// look up sbox of a given byte
#define LOOKUP_SM4_SBOX(c) ( sm4_sbox[(c >> 4) & 0x0f][(c >> 0) & 0x0f] )

// replace bytes inplace from sbox
#define REPLACE_SM4_SBOX(bytes)                      \
  do {                                               \
    for (int i = 0; i < 4 ; i++)                     \
         bytes[i] = LOOKUP_SM4_SBOX(bytes[i]);        \
  } while(0);


/**
 * Internal function L used in SM4_T for encryption and decryption. L is a linear transformation.
 *      L(B) =𝐵 ⨁ 𝐵⋘2 ⨁ 𝐵⋘10 ⨁ 𝐵⋘18 ⨁𝐵⋘24.
 * @param p [in] memory of 4-byte word
 * @return transformed value
 */
static uint32_t sm4_L_transform(uint8_t *p)
{
    uint32_t be;

    be = XX_GET_UINT32_BE(p, 0);

    be = (be ^ LEFT_ROTATE(be, 2)  ^ LEFT_ROTATE(be, 10)  \
             ^ LEFT_ROTATE(be, 18) ^ LEFT_ROTATE(be, 24));

    return be;
}

/**
 * Internal function L' used in SM4_T for key schedule
 *      L(B) =𝐵 ⨁ 𝐵⋘13 ⨁ 𝐵⋘23
 * @param p [in] memory of 4-byte word as input
 * @return transformed value
 */
static uint32_t sm4_L_p_transform(uint8_t *p)
{
    uint32_t be;

    be = XX_GET_UINT32_BE(p, 0);
    be = ( be ^ LEFT_ROTATE(be, 13)  ^ LEFT_ROTATE(be, 23) );

    return be;
}

/**
 * SM4 T function used in encryption and decryption
 *  1) non-linear transformation (A and B are four-byte words)
 *     A = (a0, a1, a2, a3) => B (sbox(a0), sbox(a1), sbox(a2), sbox(a3))
 *
 *  2) linear transformation
 *     result = L(B) = B ⊕ (B <<< 2) ⊕ (B <<< 10) ⊕ (B <<< 18) ⊕ (B <<< 24)
 *
 * @param p [in,out] 4-byte words to transform in big-endian
 * @return transformed value which is little-endian in memory
 */
static inline uint32_t sm4_T(uint8_t *p)
{
    uint32_t ret;

    REPLACE_SM4_SBOX(p);
    ret = sm4_L_transform(p);

    return ret;
}

/**
 * SM4 T' transformation used in key schedule
 * Similar to T, T' has two operations:
 * 1) non-linear transformation: identical to T
 * 2) linear transformation: B XOR (B <<< 13) XOR (B <<< 23)
 *
 * @param p [in] memory of 4-byte words to transform in big-endian
 * @return transformed value which is little-endian in memory
 */
static inline uint32_t sm4_T2(uint8_t *p)
{
    uint32_t ret;

    // replace 4 bytes of p inplace
    REPLACE_SM4_SBOX(p);
    ret = sm4_L_p_transform(p);

    return ret;
}

/**
 * SM4 F function for encryption and decryption
 *   Xi+4 = F(Xi,Xi+1,Xi+2,Xi+3,rki)= Xi ⊕T(Xi+1 ⊕Xi+2 ⊕Xi+3 ⊕rki), i=0,1,...,31.
 *
 * @param X0 [in] the first param
 * @param X1 [in] the second param
 * @param X2 [in] the third param
 * @param X3 [in] the fourth param
 * @param rk [in] round key
 * @return transformed 4-byte words, saved in little endian
 */
static uint32_t sm4_F(uint32_t X0, uint32_t X1, uint32_t X2, uint32_t X3, uint32_t rk)
{
    uint32_t r, ret;

    r = X1 ^ X2 ^ X3 ^ rk;

    // input of sm4_T is big-endian, so transform t1 into big_endian
    util_swap_order( (uint8_t *)&r );
    ret = X0 ^ sm4_T( (uint8_t *)&r );

    // Caution: ret is in little-endian
    return ret;
}

/**
 * SM4 key schedule, which fills 32 round keys; each round key is used for only one round.
 * @param ctx [in,out] sm4 context.
 * notes: round keys are updated in ctx->rk[32]
 */
static void sm4_key_schedule(sm4_ctx *ctx)
{
    uint32_t K[36];
    uint32_t MK[4];    // MK[0..3] = ctx->key[0...3]
    uint32_t i, tmp;

    MK[0] = XX_GET_UINT32_BE(ctx->key, 0);
    MK[1] = XX_GET_UINT32_BE(ctx->key, 4);
    MK[2] = XX_GET_UINT32_BE(ctx->key, 8);
    MK[3] = XX_GET_UINT32_BE(ctx->key, 12);

    // printf("MK[0]: %x\nMK[1]: %x\nMK[2]: %x\nMK[3]:%x\n", MK[0], MK[1], MK[2], MK[3]);

    // K[0...3]
    for (i = 0; i < 4; i++)
    {
        K[i] = MK[i] ^ FK[i];
    }

    // K[4:36]
    for (i = 4; i < 36; i++)
    {
        // rk[i] = K[i+4] =  K_i XOR T'(K_i+1 XOR K_i+2 XOR K_i+3)
        tmp = ( K[i-1] ^ K[i-2] ^ K[i-3] ^ CK[i-4]);

        // tmp is in little-endian, but the input of sm4_T2() is big-endian
        util_swap_order( (uint8_t *)&tmp );
        tmp = sm4_T2( (uint8_t *)&tmp );
        K[i] = K[i -4] ^ tmp;
    }

    for (i = 0; i < 32; i++)
    {
        ctx->rk[i] = K[i + 4];
        // printf("RK[%ld]: 0x%X\n", i, ctx->rk[i]);
    }
}

void sm4_ctx_init(sm4_ctx *ctx)
{
    memset( ctx, 0, sizeof(sm4_ctx) );
}

void sm4_ctx_free(sm4_ctx *ctx)
{
    memset( ctx, 0, sizeof(sm4_ctx) );
}

/**
 * Setup SM4 key, and generate round keys using 'key schedule'
 * @param ctx       [in,out] sm4 context
 * @param key       [in] encrypt/decrypt key, always 16 bytes
 * @param keybits   [in] 128bits. not used so far
 */
void sm4_ctx_setkey(sm4_ctx *ctx, uint8_t key[16], size_t keybits)
{
    memcpy(ctx->key, key, 16);
    ctx->keybits = 128;

    sm4_key_schedule(ctx);
}

/**
 * SM4 encrypt main function
 * @param ctx   [in] SM4 context
 * @param input [in] input
 * @param output [out] output
 */
void sm4_encrypt(sm4_ctx *ctx, uint8_t *input, uint8_t *output)
{
    uint32_t *X;
    uint32_t *out;
    size_t i;

    X = ctx->X;
    X[0] = XX_GET_UINT32_BE(input, 0);
    X[1] = XX_GET_UINT32_BE(input, 4);
    X[2] = XX_GET_UINT32_BE(input, 8);
    X[3] = XX_GET_UINT32_BE(input, 12);

    for (i = 0; i < 32; i++)
    {
        X[i + 4] = sm4_F(X[i], X[i + 1], X[i + 2], X[i + 3], ctx->rk[i]);
        // printf("X[%ld]: %x\n", i, X[i+4]);
    }

    // convert X[35..32] in big-endian and then save to output
    // i.e., translate number in literal representation,
    // e.g., a = 0x12345678, mem: 78 56 34 12, GET_UINT32_BE(a) = 0x78 56 34 12, mem: 12 34 56 78
    out = (uint32_t *)output;
    *(out + 0) = GET_UINT32_BE(X[35]);
    *(out + 1) = GET_UINT32_BE(X[34]);
    *(out + 2) = GET_UINT32_BE(X[33]);
    *(out + 3) = GET_UINT32_BE(X[32]);
}