/**
 * Cryptoshark is an open source and educational crypto library under Apache License V2.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#include <string.h>
#include <assert.h>

#include "sha1.h"
#include "util.h"

using namespace std;

// initial values of a, b, c, d
const static uint32_t sha1_a0 = 0x67452301;
const static uint32_t sha1_b0 = 0xEFCDAB89;
const static uint32_t sha1_c0 = 0x98BADCFE;
const static uint32_t sha1_d0 = 0x10325476;
const static uint32_t sha1_e0 = 0xC3D2E1F0;

#define FF(x, y, z)   ((x & y) | (~x & z))
#define GG(x, y, z)   (x ^ y ^ z)
#define HH(x, y, z)   ((x & y) | (x & z) | (y & z))
#define II(x, y, z)   (x ^ y ^ z)

/**
 * SHA1 main function
 * @param buf   [in] input
 * @param ilen  [in] input len
 * @param out   [out] output. Caller should provide allocated buffer.
 * @return 0 on success
 */
int sha1_hash(uint8_t *buf, size_t ilen, uint8_t *out)
{
    uint8_t *buffer, *p;
    size_t olen, i, k, n_chunks;
    uint32_t a, b, c, d, e, K;

    /**
     * 1. Set padding padding based on original input;
     *    'buffer' and 'olen' will be actual input and input len for further processing.
     */
    sha1_preprocess(buf, ilen, &buffer, &olen);

    // a, b, c, d, e will be updated at the end of each round
    // A, B, C, D, E are updated in each step
    a = sha1_a0;
    b = sha1_b0;
    c = sha1_c0;
    d = sha1_d0;
    e = sha1_e0;

    // 512-bits alignment, olen is in bytes
    assert ((olen * 8) % 512 == 0);
    n_chunks = (olen * 8) / 512;

    /**
     * 2. Process each 512-bit chunk
     */
    for (k = 0; k < n_chunks; k++)
    {
        p = (uint8_t *)buffer + BITS_2_BYTES(512) * k;
        uint8_t *data = p;

        // divide each chunk into 16 blocks, and extend to 80 blocks
        // M holds message in **bigendian**
        uint32_t M[80];
        M[ 0] = XX_GET_UINT32_BE(data, 0 );
        M[ 1] = XX_GET_UINT32_BE(data, 4 );
        M[ 2] = XX_GET_UINT32_BE(data, 8 );
        M[ 3] = XX_GET_UINT32_BE(data, 12 );
        M[ 4] = XX_GET_UINT32_BE(data, 16 );
        M[ 5] = XX_GET_UINT32_BE(data, 20 );
        M[ 6] = XX_GET_UINT32_BE(data, 24 );
        M[ 7] = XX_GET_UINT32_BE(data, 28 );
        M[ 8] = XX_GET_UINT32_BE(data, 32 );
        M[ 9] = XX_GET_UINT32_BE(data, 36 );
        M[10] = XX_GET_UINT32_BE(data, 40 );
        M[11] = XX_GET_UINT32_BE(data, 44 );
        M[12] = XX_GET_UINT32_BE(data, 48 );
        M[13] = XX_GET_UINT32_BE(data, 52 );
        M[14] = XX_GET_UINT32_BE(data, 56 );
        M[15] = XX_GET_UINT32_BE(data, 60 );

        for (int j = 16; j < 80; j++)
        {
            M[j] = LEFT_ROTATE(M[j-3] ^ M[j-8] ^ M[j-14] ^ M[j-16], 1);
        }

        // initialize values which will be updated in each round
        uint32_t A = a;
        uint32_t B = b;
        uint32_t C = c;
        uint32_t D = d;
        uint32_t E = e;

        for (i = 0; i < 80; i++)
        {
            uint32_t F;
            if (i >= 0 and i <=19)
            {
                F = FF(B, C, D);
                K = 0x5A827999;
            }
            else if (i >= 20 and i <= 39)
            {
                F = GG(B, C, D);
                K = 0x6ED9EBA1;
            }
            else if (i >= 40 and i <= 59)
            {
                F = HH(B, C, D);
                K = 0x8F1BBCDC;
            }
            else if (i >= 60 and i <= 79)
            {
                F = II(B, C, D);
                K = 0xCA62C1D6;
            }

            uint32_t temp;
            temp = LEFT_ROTATE(A, 5);
            temp = CMOD_32(temp + F);
            temp = CMOD_32(temp + K);
            temp = CMOD_32(temp + M[i]);
            temp = CMOD_32(temp + E);

            E = D;
            D = C;
            C = CMOD_32(LEFT_ROTATE(B, 30));
            B = A;
            A = temp;

            //  printf("[%d] A:%x, B:%x, C:%x, D:%x, E:%x\n", i, A, B, C, D, E);
        }

        // round epiology
        a = CMOD_32(a + A);
        b = CMOD_32(b + B);
        c = CMOD_32(c + C);
        d = CMOD_32(d + D);
        e = CMOD_32(e + E);

        // printf("\n=== Round: A:%x B:%x C:%x D:%x\n\n", a,  b, c, d);
    }

    // output = append (a, b, c, d, e) in bigendian
    uint32_t be;

    be = GET_UINT32_BE(a);
    memcpy((uint8_t *)out, &be, 4);

    be = GET_UINT32_BE(b);
    memcpy((uint8_t *)out + 4, &be, 4);

    be = GET_UINT32_BE(c);
    memcpy((uint8_t *)out + 8, &be, 4);

    be = GET_UINT32_BE(d);
    memcpy((uint8_t *)out + 12, &be, 4);

    be = GET_UINT32_BE(e);
    memcpy((uint8_t *)out + 16, &be, 4);

    delete [](buffer);

    return 0;
}

/**
 * SHA1 preprocessing
 * @param buf  [in] input
 * @param ilen [in] input len
 * @param out  [out] output, allocated in the function. Caller should manually free 'out'!
 * @param olen [out] output len
 * @return 0 on succes
 */
int sha1_preprocess(uint8_t *buf, size_t ilen, uint8_t **out, size_t *olen)
{
    // m, i are in bytes, padlen are in bytes
    size_t m, i, padlen;
    uint64_t buflen_bits;
    uint8_t *p, *padding;

    i = 0;         // i: padlen bits
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

    // put buf len(ilen) at the end in **BIG endian(md5 is little endian)**
    uint64_t be;
    buflen_bits = ilen * 8;
    be = GET_UINT64_BE(buflen_bits);
    memcpy(p + ilen + padlen, &be, 8);

    *out = p;
    *olen = ilen + padlen + 8;

    return 0;
}