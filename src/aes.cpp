/**
 * Cryptoshark is an open source and educational crypto library under Apache License V2.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#include <string.h>
#include <assert.h>

#include "aes.h"
#include "util.h"

/**
 *  AES implementation references.
 *     https://en.wikipedia.org/wiki/AES_key_schedule
 *     https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
 */

/*
 * AES have three major modes: CBC, CTR and GCM.
 * ECB is the fundamental mode, which should not be used for security considerations.
 * Cryptoshark only implements 128-bits encryption.
 *
 *   [Y] ECB
 *   [Y] CBC
 *   [Y] CTR
 *   [N] GCM
 */

// RCON table.
const uint32_t static rcon_constants[11] =
{
       0L,                          // 0
       0x01 << 24 & MAX_UINT32,     // 1
       0x02 << 24 & MAX_UINT32,     // 2
       0x04 << 24 & MAX_UINT32,     // 3
       0x08 << 24 & MAX_UINT32,     // 4
       0x10 << 24 & MAX_UINT32,     // 5
       0x20 << 24 & MAX_UINT32,     // 6
       0x40 << 24 & MAX_UINT32,     // 7
       0x80 << 24 & MAX_UINT32,     // 8
       0x1b << 24 & MAX_UINT32,     // 9
       0x36 << 24 & MAX_UINT32,     // 10
};

// 16x16 table of S box
const static uint8_t s_box[][16] =
{
        {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
        {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

// 16x16 table of reverse S box
const static uint8_t s_r_box[][16] =
{
        {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
        {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
        {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
        {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
        {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
        {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
        {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
        {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
        {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
        {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
        {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
        {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
        {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
        {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
        {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
        {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
};

// get RCON constants
#define GET_RECON(i)    ( (uint32_t)rcon_constants[i] )

// look up rcon table, get one byte's mapping byte in big-endian
#define LOOKUP_RCON(i) ( XX_GET_UINT32_BE((uint8_t *)s_box[i], 0) )

// look up sbox of a given byte
#define LOOKUP_SBOX(c) ( s_box[(c >> 4) & 0x0f][(c >> 0) & 0x0f] )

// lookup s_r_box of a given byte
#define LOOKUP_R_SBOX(c) ( s_r_box[(c >> 4) & 0x0f][(c >> 0) & 0x0f] )

// replace bytes inplace from S box
#define REPLACE_SBOX(bytes, len)                    \
  do {                                               \
    for (int i = 0; i < len ; i++)                   \
         bytes[i] = LOOKUP_SBOX(bytes[i]);           \
  } while(0);                                        \

// replace bytes inplace from reverse S box
#define REPLACE_R_SBOX(bytes, len)                   \
  do {                                               \
    for (int i = 0; i < len ; i++)                   \
         bytes[i] = LOOKUP_R_SBOX(bytes[i]);         \
  } while(0);                                        \

////////////////////////
/// Internal functions
///////////////////////

/**
* AES add round key operation.
*     input[i] = input[i] ^ round_key[i]    i = [0...16]
* @param input [in,out] 16-byte buffer, which also saves output buffer
* @param rk    [in] 16-byte round key
* @return
*/
static int add_round_key(uint8_t input[16], uint32_t rk[4])
{
    uint8_t *p;
    int i;

    p = (uint8_t *)&rk[0];
    for (i = 0; i < 16; i++)
    {
        input[i] ^= p[i];
    }

    return 0;
}

/**
 *  Multiplication on Galois Field
 *  @param a [in] the first input
 *  @param b [in] the second input
 *  @return result
 */
static uint8_t g_mul(uint8_t a, uint8_t b)
{
    int c;              // result
    int hi_flag;

    c = 0;

    // 8 rounds
    for (int i = 0; i < 8; i++)
    {
        if ( (b & 0x1) == 1)
            c ^= a;

        hi_flag = (a & 0x80);
        a = (a << 1);

        if (hi_flag == 0x80)
            a ^= 0x1b;

        b = b >> 1;
    }

    return c;
}

/**
 * AES mix single column on Galois Field
 * @param r [in] input, always 4 bytes
 * @return 0 on success
 */
int g_mix_column(uint8_t *r)
{
    uint8_t a[4];
    int i;

    for (i = 0; i < 4; i++)
        a[i] = r[i];

    r[0] = g_mul(a[0], 2) ^ g_mul(a[1], 3) ^ g_mul(a[2], 1) ^ g_mul(a[3], 1);
    r[1] = g_mul(a[0], 1) ^ g_mul(a[1], 2) ^ g_mul(a[2], 3) ^ g_mul(a[3], 1);
    r[2] = g_mul(a[0], 1) ^ g_mul(a[1], 1) ^ g_mul(a[2], 2) ^ g_mul(a[3], 3);
    r[3] = g_mul(a[0], 3) ^ g_mul(a[1], 1) ^ g_mul(a[2], 1) ^ g_mul(a[3], 2);

    return 0;
}

/**
 * Inverse mix column
 * @param r [in] input, always 4 bytes
 * @return 0 on success
 */
static int inverse_g_mix_column(uint8_t *r)
{
    uint8_t a[4];
    int i;

    for (i = 0; i < 4; i++)
        a[i] = r[i];

    /**
     *  Matrix
     *  0E   0B   0D   09
     *  09   0E   0B   0D
     *  0D   09   0E   0B
     *  0B   0D   09   0E
     */
    r[0] = g_mul(a[0],14) ^ g_mul(a[3],9) ^ g_mul(a[2],13) ^ g_mul(a[1],11);
    r[1] = g_mul(a[1],14) ^ g_mul(a[0],9) ^ g_mul(a[3],13) ^ g_mul(a[2],11);
    r[2] = g_mul(a[2],14) ^ g_mul(a[1],9) ^ g_mul(a[0],13) ^ g_mul(a[3],11);
    r[3] = g_mul(a[3],14) ^ g_mul(a[2],9) ^ g_mul(a[1],13) ^ g_mul(a[0],11);

    return 0;
}


/**
 * AES shift rows in-place of 4x4 array.
 * @param p [in] input array in 16 bytes
 */
static void shift_rows(uint32_t *p)
{
    p[1] = GET_UINT32_BE( LEFT_CIR_SHIFT8 ( GET_UINT32_BE(p[1]) ) );
    p[2] = GET_UINT32_BE( LEFT_CIR_SHIFT16 ( GET_UINT32_BE(p[2]) ) );
    p[3] = GET_UINT32_BE( LEFT_CIR_SHIFT24 ( GET_UINT32_BE(p[3]) ) );
}

/**
 * AES inverse shift rows in-place of 4x4 array, which shifts by right.
 * @param p [in] input array, 16 bytes, which should be column-based.
 */
static void inverse_shift_rows(uint32_t *p)
{
    p[1] = GET_UINT32_BE( RIGHT_CIR_SHIFT8 ( GET_UINT32_BE(p[1]) ) );
    p[2] = GET_UINT32_BE( RIGHT_CIR_SHIFT16( GET_UINT32_BE(p[2]) ) );
    p[3] = GET_UINT32_BE( RIGHT_CIR_SHIFT24( GET_UINT32_BE(p[3]) ) );
}

/**
 * Lookup S box of a given 4-byte word.
 * Notes: just replace each byte from S box, and leave endian unchanged
 * @param word [in] input
 * @return new(replaced) word for input
 */
static uint32_t subword(uint32_t word)
{
    uint8_t a, b, c, d;
    uint32_t ret;

    a = (word >> 24) & 0xff;
    b = (word >> 16) & 0xff;
    c = (word >> 8)  & 0xff;
    d = (word >> 0)  & 0xff;

    ret = 0;
    ret |= LOOKUP_SBOX(a) << 24;
    ret |= LOOKUP_SBOX(b) << 16;
    ret |= LOOKUP_SBOX(c) << 8;
    ret |= LOOKUP_SBOX(d) << 0;

    return ret;
}

static uint32_t inverse_subword(uint32_t word)
{
    uint8_t a, b, c, d;
    uint32_t ret;

    a = (word >> 24) & 0xff;
    b = (word >> 16) & 0xff;
    c = (word >> 8)  & 0xff;
    d = (word >> 0)  & 0xff;

    ret = 0;
    ret |= LOOKUP_R_SBOX(a) << 24;
    ret |= LOOKUP_R_SBOX(b) << 16;
    ret |= LOOKUP_R_SBOX(c) << 8;
    ret |= LOOKUP_R_SBOX(d) << 0;

    return ret;
}

/**
 * Transpose a 16 byte array from row-based to column-based
 * @param input [in, out] input also served as output
 */
static void matrix_transpose16(uint8_t *input)
{
    int i, j;
    uint8_t r[16];

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
            r[j * 4 + i] = input[(i * 4 + j)];
    }

    memcpy(input, r, 16);
}


/**
 * T operation for AES key schedule, https://en.wikipedia.org/wiki/AES_key_schedule
 * @param w       [in] round key word
 * @param round   [in] round
 * @return key schedule result
 */
uint32_t T(uint32_t w, uint8_t round)
{
    uint32_t ret;

    ret = LEFT_ROTATE(w, 8);
    ret = LOOKUP_SBOX(ret);
    ret ^= GET_UINT32_BE( LOOKUP_RCON(round) );

    return ret;
}

/**
 * AES key schedule, https://en.wikipedia.org/wiki/AES_key_schedule
 * Notes: This function is used internally only by aes_set_key(),.
 * @param aes [in,out] AES context that aes->rk holds scheduled keys
 */
static void aes_key_schedule(aes_ctx_t *aes)
{
    int i;
    size_t N;
    uint32_t *w;     // round key
    uint8_t *key;
    uint32_t t1, t2;

    // How many words(each word is 32bit)? 128:4, 192:6, 256:8
    N = aes->key_bits / 32;
    w = aes->rk;
    key = (uint8_t *)aes->key;

    for (i = 0; i < aes->sr; i++)
    {
        if (i < N)
        {
            // save w[i] in big-endian
            w[i] = XX_GET_UINT32_BE(key, i * 4);
        }
        else if ( (i >= N) and (i % N == 0) )
        {
            // i>=N and i % N ==0
            // w[i] = W[i-N] XOR subword(RotWord(w[i-1]) XOR (rcon[i/N])
            t1 = LEFT_CIR_SHIFT8(w[i-1]);
            t2 = GET_RECON(i/N);
            w[i] = w[i-N] ^ subword(t1) ^ t2;
        }
        else if ( (i >= N) and (N > 6) and (i % N == 4) )
        {
            // w[i-N] XOR subword(W[i-1])
            w[i] = w[i-N] ^ subword(w[i-1]);
        }
        else
        {
            w[i] =  w[i-N] ^ w[i-1];
        }
    }

    // w[i] is saved in little endian, convert w[i] to bigendian
    for (i = 0; i < (aes->round * 4); i++)
    {
        util_swap_order( (uint8_t *)w + 4 * i );
    }
}

/////////////////////////
// AES functions
////////////////////////

void aes_ctx_init(aes_ctx_t *aes)
{
    memset(aes, 0, sizeof(aes_ctx_t));
}

void aes_ctx_free(aes_ctx_t *aes)
{
    memset(aes, 0, sizeof(aes_ctx_t));
}

/**
 * Set AES key context and do key schedule
 * @param aes       [in] AES context
 * @param keybuf    [in] key buffer
 * @param keybits   [in] keybits, 128, 192 or 256. Only 128-bits is implemented.
 * @return 0 on success
 */
int aes_set_key(aes_ctx_t *aes, uint8_t *keybuf, size_t keybits)
{
    aes->key_bits = keybits;
    aes->key_bytes = keybits >> 3;
    aes->block_bytes = 16;

    if (keybits == 128)
        aes->round = 11;
    else if (keybits == 192)
        aes->round = 13;
    else if (keybits == 256)
        aes->round = 15;
    else
        aes->round = 0xff;

    aes->sr = 4 * aes->round;

    // fill key buf
    memcpy(aes->key, keybuf, aes->key_bytes);

    // key schedule and round keys are saved in aes->rk
    aes_key_schedule(aes);

    return 0;
}

/**
 * AES CBC encryption routine
 * @param aes       [in] AES context
 * @param raw_input [in] plaintext without padding
 * @param ilen      [in] input len without padding
 * @param iv       [in] IV
 * @param output   [out] output with same length of input
 * @return 0 on success
 */
int aes_encrypt_cbc(aes_ctx_t *aes, uint8_t *raw_input, size_t ilen, uint8_t iv[16], uint8_t *output, size_t *olen)
{
    size_t real_len;            // real_len in bits
    uint8_t *input;
    uint8_t *original_input;

    uint8_t curr_iv[16];

    // padding input
    padding_cms(raw_input, ilen, 16, &input, &real_len);
    original_input = input;
    *olen = (real_len - 16) >> 3;

    // process 16 bytes as a block each time
    memcpy(curr_iv, iv, 16);
    while (real_len > 0)
    {
        // before AES encryption, XOR input with *** curr IV ***
        for (int i = 0; i < 16; i++)
            input[i] ^= curr_iv[i];

        aes_encrypt_internal(input, 16, aes, output);

        // write output to iv for next XOR
        memcpy(curr_iv, output, 16);

        real_len -= 16;
        input += 16;
        output += 16;
    }

    delete [](original_input);

    return 0;
}

/**
 * AES CBC decryption routine, which process multiple 16-byte blocks
 * @param aes           [in] AES context
 * @param ciphertext    [in] cipher text, NOT including padding
 * @param ilen          [in] ciphertext len, which must be multiple of 16
 * @param iv            [in] IV, same as encryption IV
 * @param output        [in,out] output of plaintext
 * @param olen          [in,out] actual output len
 * @return 0 on success
 */
int aes_decrypt_cbc(aes_ctx_t *aes, uint8_t *ciphertext, size_t ilen, uint8_t iv[16], uint8_t *output, size_t *olen)
{
    size_t real_len, len;
    uint8_t *input;              // locally allocated buffer, which should be freed within this function
    uint8_t *original_input;
    uint8_t *output_initial;
    uint8_t curr_iv[16];
    uint8_t curr_block[16];

    // check input length alignment of 16
    assert (ilen % 16 == 0);

    input = new uint8_t[ilen];
    original_input = input;
    memcpy(input, ciphertext, ilen);

    real_len = ilen;
    len = 0;
    output_initial = output;

    // process 16 bytes as a block each time
    memcpy(curr_iv, iv, 16);
    while (real_len > 0)
    {
        /**
         *  input is ciphertext, which will be changed by aes_decrypt_internal();
         *  but we need the ciphertext as IV, which is saved in curr_block
         */
        memcpy(curr_block, input, 16);

        aes_decrypt_internal(input, 16, aes, output);

        for (int i = 0; i < 16; i++)
            output[i] ^= curr_iv[i];

        // update curr_iv with unmodified ciphertext which has been processed in this iteration
        memcpy(curr_iv, curr_block, 16);

        real_len -= 16;
        len += 16;
        input += 16;
        output += 16;
    }

    *olen = ilen;
    delete [](original_input);

    return 0;
}

/**
 * AES encryption internal function, which encrypts a block (16 bytes)
 * This function is essentially ECB mode, which is used in:
 *  - CBC
 *  - CTR
 *  - GCM
 * @param plaintext[in]    input buffer, which will not be modified during encryption
 * @param ilen[in]         input len, which must be 16 required by AES
 * @param rk[in]           round key. 15 words(60 bytes), AES-128 uses 11 words(44 bytes).
 * @param output[in, out]  output buffer
 * @return 0 on success
 */
int aes_encrypt_internal(const uint8_t *plaintext, size_t ilen, aes_ctx_t *aes, uint8_t *output)
{
    int i, j;
    uint32_t *rk;
    uint8_t input[16];
    size_t rounds;

    rk = aes->rk;
    rounds = aes->round;

    /**
     * In order not to scramble @param plaintext, we use a dedicated buffer
     * for process.
     */
    memcpy(input, plaintext, 16);

    /**
     *  Round 0
     *  input = input ^ rk[0]   // rk[0]: first 4 bytes
     */
    add_round_key(input, rk + 0);

    /**
     * Middle rounds
     *   1) sub bytes:
     *   2) shift rows
     *   3) mix columns
     *   4) add round key
     */
    for (i = 1; i < rounds - 1; i++)     // when loop is finished, i remembers the last rk index
    {
        /**
         * 1. Substitute bytes
         */
        REPLACE_SBOX(input, 16);

        // util_print_bytes(input, 16, "before 1st round shift rows");

        /**
         * 2. Left shift rows
         *     Notes: whenever do shift_rows(), using following order:
         *     1) transpose input
         *     2) shift_rows(input)
         *     3) transpose input
         *
         *       see https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf, pp 32
         */
        matrix_transpose16(input);   // convert to column-wise for row shifts (actually shifting columns)
        shift_rows((uint32_t *)input);
        matrix_transpose16(input);   // convert back to row-wise

        /**
         *  3. Mix columns
         */
        for (j = 0; j < 4; j++)
            g_mix_column((uint8_t *)input + 4 * j);

        /**
         * rk to be used is 16 bytes (4 words) beyond current rk;
         * that is to say, each iteration consumes 16 bytes of rk.
         */
        add_round_key(input, rk + 4 * i);
    }

    // final round
    REPLACE_SBOX(input, 16);

    matrix_transpose16(input);
    shift_rows((uint32_t *)input);
    matrix_transpose16(input);

    // add last round key, i is the last index of rk
    add_round_key(input, rk + 4 * i);

    // AES encryption is over
    memcpy(output, input, 16);

    // util_print_bytes(output, 16, "output");

    return 0;
}

/**
 * AES decryption internal routine, which process a 16-byte block.
 * @param input   [in] ciphertext, which will be scrambled during processing
 * @param ilen    [in] input len, must be 16
 * @param aes     [in] AES context that saved round keys
 * @param output  [in,out] deciphered text
 * @return 0 on success
 */
int aes_decrypt_internal(uint8_t *input, size_t ilen, aes_ctx_t *aes, uint8_t *output)
{
    /**
     *  Process
     *    1. round N: add **last** round key rk[N]
     *    2. round i(i = [9, 8, ...1]: add_round_key(state, round key)
     *      1) inverse_mix_columns
     *      2) inverse_shift rows
     *      3) invert_sub_bytes
     *    3. round 0: add round key rk[0]
     */

    int i, j;
    uint32_t *rk;
    size_t rounds;

    rk = aes->rk;
    rounds = aes->round;

    // round 0
    // AES-128  rounds: 11, rounds -1 = 10, 4 * 10 = 40 words, 160 bytes,
    add_round_key(input, rk + (rounds - 1) * 4);

    matrix_transpose16(input);
    inverse_shift_rows((uint32_t *)input);
    matrix_transpose16(input);

    REPLACE_R_SBOX(input, 16);

    for (i = rounds - 2; i >= 1; i--)
    {
        add_round_key(input, rk + 4 * i);

        for (j = 0; j < 4; j++)
            inverse_g_mix_column((uint8_t *)input + 4 * j);

        matrix_transpose16(input);     // convert to column-wise for row shifts (actually shifting columns)
        inverse_shift_rows((uint32_t *)input);
        matrix_transpose16(input);     // convert back to row-wise

        REPLACE_R_SBOX(input, 16);
    }

    // final round
    add_round_key(input, rk + 0);
    memcpy(output, input, 16);

    return 0;
}


/**
 * AES CTR internal routine, used for both encryption and decryption
 *
 * Notes on nonce counter
 *    nonce counter = 12 - bytes IV + 4 - bytes nonce
 *    - IV and nonce can be arbitrary values; though nonce may starts from 1.
 *    - RFC 3686: "The least significant 32 bits of the counter block are initially set to one."
 *
 *    But if nonce is not one for the first block, it's ok and hopefully we can resume encryption/decryption with the
 *    nonce counter.
 *
 * @param aes             [in] AES context
 * @param input           [in] input
 * @param ilen            [in] ilen, which might not be aligned of 16 bytes
 * @param nonce_counter   [in] 16-byte nonce counter
 * @param stream_block    [in,out] byte array that holds transformed input in each interation
 * @param output          [out] output, which has exacty same legnth of input
 * @param offset          [in] offset of the last block. 0 for 16-byte aligned input
 * @return 0 on success
 */
int aes_ctr_internal(aes_ctx_t *aes, uint8_t *input, size_t ilen,
                     uint8_t nonce_counter[16], uint8_t stream_block[16],
                     uint8_t *output, size_t *offset)
{
    uint8_t c;
    size_t i, n;

    n = *offset;
    while (ilen--)        // if ilen == 0, break loop
    {
        if (n == 0)
        {
            aes_encrypt_internal(nonce_counter, 16, aes, stream_block);

            // nonce_counter increments. What does this code mean?
            for (i = 16; i > 0; i--)
            {
                if (++nonce_counter[i - 1] != 0)
                    break;
            }
        }

        c = *input++;
        *output++ = (c ^ stream_block[n]);

        n = (n + 1) & 0x0f;
    }

    *offset = n;
    return 0;
}
