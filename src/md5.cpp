/**
 * Cryptoshark is an open source and educational crypto library under Apache License V2.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#include <iostream>
#include <assert.h>
#include <string.h>
#include <math.h>

#include "md5.h"
#include "util.h"

using namespace std;

// shift table for md5
const static uint8_t md5_shifts[64] = {
        7, 12, 17, 22, 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20, 5, 9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21};

// constants for md5
const static uint32_t md5_constants[64] =
    {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
     0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
     0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
     0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
     0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
     0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
     0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
     0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
     0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
     0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
     0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
     0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
     0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
     0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
     0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
     0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

// initial values of A, B, C, D
const static uint32_t md5_a0 = 0x67452301;
const static uint32_t md5_b0 = 0xefcdab89;
const static uint32_t md5_c0 = 0x98badcfe;
const static uint32_t md5_d0 = 0x10325476;

#define FF(x, y, z)   ((x & y) | (~x & z))
#define GG(x, y, z)   ((x & z) | (y & ~z))
#define HH(x, y, z)   (x ^ y ^ z)
#define II(x, y, z)   (y ^ (x | ~z))

/**
 * md5 main function
 * @param buf   [in] input
 * @param ilen  [in] buf len
 * @param out   [in,out] 128-bit md5 hash output
 * @return 0 on sucess
 */
int md5_hash(uint8_t *buf, size_t ilen, uint8_t *out)
{
    uint8_t *buffer, *p;
    size_t olen, i, k, n_chunks;
    uint32_t a, b, c, d;

    /**
     * 1. Set padding padding based on original input;
     *    'buffer' and 'olen' will be actual input and input len for further processing.
     */
    md5_preprocess(buf, ilen, &buffer, &olen);

    // a, b, c, d will be updated at the end of  each round
    a = md5_a0;
    b = md5_b0;
    c = md5_c0;
    d = md5_d0;

    // 512bits alignment, olen is in bytes

    assert ((olen * 8) % 512 == 0);
    n_chunks = (olen * 8) / 512;

    /**
     * 2. Process each 512-bit chunk
     */
    for (k = 0; k < n_chunks; k++)
    {
        p = (uint8_t *)buffer + BITS_2_BYTES(512) * k;
        uint8_t *data = p;

        // divide each chunk into 16 blocks; each block is 32 bits(4bytes)
        uint32_t M[16];
        M[ 0] = XX_GET_UINT32_LE(data, 0 );
        M[ 1] = XX_GET_UINT32_LE(data, 4 );
        M[ 2] = XX_GET_UINT32_LE(data, 8 );
        M[ 3] = XX_GET_UINT32_LE(data, 12 );
        M[ 4] = XX_GET_UINT32_LE(data, 16 );
        M[ 5] = XX_GET_UINT32_LE(data, 20 );
        M[ 6] = XX_GET_UINT32_LE(data, 24 );
        M[ 7] = XX_GET_UINT32_LE(data, 28 );
        M[ 8] = XX_GET_UINT32_LE(data, 32 );
        M[ 9] = XX_GET_UINT32_LE(data, 36 );
        M[10] = XX_GET_UINT32_LE(data, 40 );
        M[11] = XX_GET_UINT32_LE(data, 44 );
        M[12] = XX_GET_UINT32_LE(data, 48 );
        M[13] = XX_GET_UINT32_LE(data, 52 );
        M[14] = XX_GET_UINT32_LE(data, 56 );
        M[15] = XX_GET_UINT32_LE(data, 60 );

        uint32_t A = a;
        uint32_t B = b;
        uint32_t C = c;
        uint32_t D = d;

        /**
         *   3. 64 steps for each round
         *     F: F(x, y, z)
         *     g: index for M[index]
         *     i: rotation table index
         */
        for (i = 0; i < 64; i++)
        {
            uint32_t F, g;
            if (i >= 0 and i <=15)
            {
                F = FF(B, C, D);
                g = i;
            }
            else if (i >= 16 and i <= 31)
            {
                F = GG(B, C, D);
                g = (5 * i + 1) % 16;
            }
            else if (i >= 32 and i <= 47)
            {
                F = HH(B, C, D);
                g = (3 * i + 5) % 16;
            }
            else if (i >= 48 and i <= 63)
            {
                F = II(B, C, D);
                g = (7 * i) % 16;
            }

            // Important! update F, A, B, C, D by modular addition of 2^32
            F = CMOD_32(F + M[g]);
            F = CMOD_32(F + md5_constants[i]);
            F = CMOD_32(F + A);

            F = LEFT_ROTATE(F, md5_shifts[i]);
            F = CMOD_32(F + B);

            // swap A, B, C, D, F
            A = D;
            D = C;
            C = B;
            B = F;
        }

        /**
         *  Round epiology
         *  when 64 steps of this round are done, update a, b, c, d
         */
        a = CMOD_32(a + A);
        b = CMOD_32(b + B);
        c = CMOD_32(c + C);
        d = CMOD_32(d + D);

        // printf("\n=== Round: A:%x B:%x C:%x D:%x\n\n", a,  b, c, d);
    }

    // output = append (a, b, c, d)
    memcpy((uint8_t *)out, &a, 4);
    memcpy((uint8_t *)out + 4, &b, 4);
    memcpy((uint8_t *)out + 8, &c, 4);
    memcpy((uint8_t *)out + 12, &d, 4);

    delete [](buffer);

    return 0;
}

/**
 * MD5 preprocessing
 *  1. get actual input len by 448 modulo 512.
 *  2. allocate new buffer with actual len
 *  3. set padding
 *
 *  | ---- input ----| 80 00 00 .... |   ---- original len in little endian --- |
 *  [        x bits                  |             64 bits                      ]
 *
 *  (x + 64) mod 512 == 0
 *
 * @param buf [in]  input, it's likely buf is not 512-bits aligned
 * @param ilen [in] buf len
 * @param out  [out] output buffer with padding; caller should free 'out'
 * @param olen [out] actual len of 'out', 512-bit alignment
 * @return 0 on success
 */
int md5_preprocess(uint8_t *buf, size_t ilen, uint8_t **out, size_t *olen)
{
    // m, i are in bytes, padlen are in bits
    size_t m, i, padlen;
    uint64_t buflen_bits;
    uint8_t *p, *padding;

    i = 0;
    m = ilen * 8;
    while (1)
    {
        // expand m until m % 512 == 448
        if (m % 512 != 448)
        {
            i += 8;     // m and i are in bits
            m += 8;
        }
        else
        {
            break;
        }
    }

    // total len: ilen + padlen + 8
    assert (i % 8 == 0);
    padlen = i/8;       // padlen is in bytes

    // new buffer: ilen + padlen + 64bit(len of original input)
    p = new uint8_t[ilen + padlen + 8];

    // copy original buf
    memcpy(p, buf, ilen);

    // set padding
    if (padlen > 0)
    {
        padding = p + ilen;
        memset(padding, 0, padlen);
        padding[0] = 0x80;            // must use 0x80
    }

    // put buf len(ilen) at the end in little endian
    buflen_bits = ilen * 8;
    memcpy(p + ilen + padlen, &buflen_bits, 8);

    *out = p;
    *olen = ilen + padlen + 8;

    return 0;
}