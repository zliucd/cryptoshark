/**
 * Cryptoshark is an open source and educational crypto library under Apache License V2.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#include <iostream>
#include <string.h>
#include <assert.h>

#include "util.h"

/**
 *  References
 *     SM3 specification: https://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
 *     SM3 implementation in Python: # https://codeantenna.com/a/yyN2qaUW1e
 */

// IV
const static uint8_t sm3_iv[32] =
                            {0x73, 0x80, 0x16, 0x6f,
                             0x49, 0x14, 0xb2, 0xb9,
                             0x17, 0x24, 0x42, 0xd7,
                             0xda, 0x8a, 0x06, 0x00,
                             0xa9, 0x6f, 0x30, 0xbc,
                             0x16, 0x31, 0x38, 0xaa,
                             0xe3, 0x8d, 0xee, 0x4d,
                             0xb0, 0xfb, 0x0e, 0x4e};

#define T0 0x79cc4519
#define T1 0x7a879d8a

#define FF0(x, y, z)  ( x ^ y ^ z )
#define FF1(x, y, z)  ( (x & y) | (x & z) | (y & z) )

#define GG0(x, y, z)   ( x ^ y ^ z )
#define GG1(x, y, z)   ( (x & y) | (~x & z) )

#define P0(x) ( x ^ LEFT_ROTATE(x, 9)  ^ LEFT_ROTATE(x, 17) )
#define P1(x) ( x ^ LEFT_ROTATE(x, 15) ^ LEFT_ROTATE(x, 23) )

/**
 * SM3 preprocess that set paddings of a message, which is identical to SHA256
 * @param buf  [in] input
 * @param ilen [in] buf len
 * @param out  [in] new message with paddings
 * @param olen [out] output len
 * @return 0 on success
 */
int sm3_preprocess(uint8_t *buf, size_t ilen, uint8_t **out, size_t *olen)
{
    // m, i, ilen are in bytes, padlen are in bits
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

    // put buf len(ilen) at the end in **BIG endian(md5 is little endian)**
    uint64_t be;
    buflen_bits = ilen * 8;
    be = GET_UINT64_BE(buflen_bits);
    memcpy(p + ilen + padlen, &be, 8);

    *out = p;
    *olen = ilen + padlen + 8;

    return 0;
}

/**
 * SM3 main funciton that computes SM3 digest of a preprocessed buffer
 * @param buf   [in] preprocessed buffer with 512-bits alignment
 * @param ilen  [in] buflen
 * @param out   [in] hash
 * @return 0 on success
 */
int sm3(uint8_t *buf, size_t ilen, uint8_t *out)
{
    uint8_t *buffer, *p;
    size_t olen, j, k, n_chunks;

    // updated in each step (NOT step). ABCDEFGH are uint32_t types with little-endian representation
    uint32_t A, B, C, D, E, F, G, H;

    // big-endian of ABCDEFGH
    uint32_t a, b, c, d, e, f, g, h;

    uint32_t w[68];     // w
    uint32_t w_p[64];   // w'
    uint8_t curr_v[32]; // current and updated V in each round
    uint8_t tmp_v[32];  // temp V to store ABCDEFGH in big-endian array

    /**
     * 1. Set padding padding based on original input;
     *    'buffer' and 'olen' will be actual input and input len for further processing.
     */
    sm3_preprocess(buf, ilen, &buffer, &olen);

    // 512bits alignment, olen is in bytes
    assert ((olen * 8) % 512 == 0);
    n_chunks = (olen * 8) / 512;

    /**
     * 2. Process each 512-bit chunk
     */

    /**
     * 0. Init curr_v using sm3 IV
     */
    memcpy(curr_v, sm3_iv, 32);

    for (k = 0; k < n_chunks; k++)
    {
        /**
         * 1. Expand message
         *    132 uint32_t: w[68], w'[64]
         */
        p = (uint8_t *)buffer + BITS_2_BYTES(512) * k;
        uint32_t *dp = (uint32_t *)p;

        // a) w[0..16] = original M(message), w[i] should be **big-endian** from bytes
        for (j = 0; j < 16; j++)
        {
            w[j] = GET_UINT32_BE(dp[j]);
        }

        /**
         *  Notes on printing w and w_p
         *  As numbers in w[] and w_p[] are stored already in big-endian, printing them will show in little-endian
         *  e.g.,  w[0] = 0x 61 62 63 64
         *         mem:      64 64 62 61
         *         print:    64 63 62 61
         */
        //  util_print_bytes((uint8_t *)w, 64, "w[0-63]");

        // b) w[16...67]
        for (j = 16; j < 68; j++)
        {
            w[j] = ( P1( w[j-16] ^ w[j-9] ^ LEFT_ROTATE(w[j-3], 15)) ) ^ ( LEFT_ROTATE(w[j-13], 7) ) ^ ( w[j-6] );
        }

        //  util_print_bytes((uint8_t *)w + 64, 52*4, "w[16-68]");

        // c) w'[0...63]
        for (j = 0 ; j < 64; j++)
        {
            w_p[j] = ( w[j] ^ w[j+4] );
        }

        //  util_print_bytes((uint8_t *)w_p, 64*4, "w'[0-63]");

        // retrieve ABCDEFGH from V using big-endian
        A = XX_GET_UINT32_BE(curr_v, 0);
        B = XX_GET_UINT32_BE(curr_v, 4);
        C = XX_GET_UINT32_BE(curr_v, 8);
        D = XX_GET_UINT32_BE(curr_v, 12);
        E = XX_GET_UINT32_BE(curr_v, 16);
        F = XX_GET_UINT32_BE(curr_v, 20);
        G = XX_GET_UINT32_BE(curr_v, 24);
        H = XX_GET_UINT32_BE(curr_v, 28);

        // 2. Compression
        for (j = 0; j < 64; j++)
        {
            // temporary variables using names from SM3 specification
            uint32_t SS1, SS2, TT1, TT2, T;

            T = (j >= 0 and j <= 15) ? T0 : T1;
            ADD_UINT32_MOD_3( SS1, LEFT_ROTATE(A, 12), E, LEFT_ROTATE(T, j) );
            SS1 = LEFT_ROTATE(SS1, 7);
            SS2 = SS1 ^ LEFT_ROTATE(A, 12);

            // TT1
            if (j >= 0 && j <= 15)
                ADD_UINT32_MOD_4( TT1, FF0(A, B, C), D, SS2, w_p[j] );
            else
                ADD_UINT32_MOD_4( TT1, FF1(A, B, C) , D, SS2, w_p[j] );

            // TT2
            if (j >= 0 && j <= 15)
                ADD_UINT32_MOD_4( TT2, GG0(E, F, G), H, SS1, w[j] );
            else
                ADD_UINT32_MOD_4( TT2, GG1(E, F, G), H, SS1, w[j] );

            // reset ABCDEFGH
            D = C;
            C = LEFT_ROTATE(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LEFT_ROTATE(F, 19);
            F = E;
            E = P0(TT2);

            // printf("[%d] A:%08x, B:%08x, C:%08x, D:%08x, E:%08x, F:%08x, G:%08x, H:%08x\n", j, A, B, C, D, E, F, G, H);
        }

        /**
         *  3. Update V(i+1) with V(i)
         *     V(i+1) ← ABCDEFGH ⊕ V(i)
         *
         *     Because ABCDEFGH are saved in memory in bigendian, but it's saved in UINT32_T in little-endian;
         *     it's required to transform UINT32 in little-endian to compute ** ABCDEFGH ⊕ V(i) **
         *
         *     e.g., A:            0x12345678
         *           mem(uint32):  78 56 34 12 (little-endian)
         *           transformed:  12 34 56 78 (big-endian)
         */
        memset(tmp_v, 0, 32);    // not necessary though
        a = GET_UINT32_BE(A);
        b = GET_UINT32_BE(B);
        c = GET_UINT32_BE(C);
        d = GET_UINT32_BE(D);
        e = GET_UINT32_BE(E);
        f = GET_UINT32_BE(F);
        g = GET_UINT32_BE(G);
        h = GET_UINT32_BE(H);

        memcpy( (uint8_t *)tmp_v + 0,  &a, 4 );
        memcpy( (uint8_t *)tmp_v + 4,  &b, 4 );
        memcpy( (uint8_t *)tmp_v + 8,  &c, 4 );
        memcpy( (uint8_t *)tmp_v + 12, &d, 4 );
        memcpy( (uint8_t *)tmp_v + 16, &e, 4 );
        memcpy( (uint8_t *)tmp_v + 20, &f, 4 );
        memcpy( (uint8_t *)tmp_v + 24, &g, 4 );
        memcpy( (uint8_t *)tmp_v + 28, &h, 4 );

        // V(i+1) ← ABCDEFGH ⊕ V(i)
        for (j = 0; j < 32; j++)
            curr_v[j] = ( tmp_v[j] ^ curr_v[j] );

        // util_print_bytes((uint8_t *)tmp_v, 32, "ABCDEFGH in big-endian");

        // digest is saved in curr_v with 32 bytes, copy to output
        memcpy((uint8_t *)out, curr_v, 32);
    }

    // print in hex string
    // string hex = hex_bytes((uint8_t *)out, 32);
    // printf("hex: %s\n", hex.c_str());

    delete [](buffer);

    return 0;
}
