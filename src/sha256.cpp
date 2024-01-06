/**
 * Cryptoshark is an open source and educational crypto library under Apache License V2.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#include <iostream>
#include <string.h>
#include <assert.h>

#include "sha256.h"
#include "util.h"

const static uint32_t sha256_a0 = 0x6a09e667;
const static uint32_t sha256_b0 = 0xbb67ae85;
const static uint32_t sha256_c0 = 0x3c6ef372;
const static uint32_t sha256_d0 = 0xa54ff53a;
const static uint32_t sha256_e0 = 0x510e527f;
const static uint32_t sha256_f0 = 0x9b05688c;
const static uint32_t sha256_g0 = 0x1f83d9ab;
const static uint32_t sha256_h0 = 0x5be0cd19;

// constants for sha256
const static uint32_t sha256_constants[64] =
        {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};


#define F0(n) (RIGHT_ROTATE(n, 7) ^ RIGHT_ROTATE(n, 18) ^ SHR(n, 3))
#define F1(n) (RIGHT_ROTATE(n, 17) ^ RIGHT_ROTATE(n, 19) ^ SHR(n, 10))

int sha256_preprocess(uint8_t *buf, size_t ilen, uint8_t **out, size_t *olen)
{
    // m, i, padlen are in bytes
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
 * SHA256 main function
 * @param buf   [in] input
 * @param ilen  [in] input len
 * @param out   [out] output
 * @return 0 on success
 */
int sha256_hash(uint8_t *buf, size_t ilen, uint8_t *out)
{
    uint8_t *buffer, *p;
    size_t olen, i, k, n_chunks;
    uint32_t a, b, c, d, e, f, g, h;

    /**
     * 1. Set padding padding based on original input;
     *    'buffer' and 'olen' will be actual input and input len for further processing.
     */
    sha256_preprocess(buf, ilen, &buffer, &olen);

    // a, b, c, d, e, f, g, h will be updated at the end of  each round
    a = sha256_a0;
    b = sha256_b0;
    c = sha256_c0;
    d = sha256_d0;
    e = sha256_e0;
    f = sha256_f0;
    g = sha256_g0;
    h = sha256_h0;

    // 512-bits alignment, olen is in bytes
    assert ((olen * 8) % 512 == 0);
    n_chunks = (olen * 8) / 512;

    /**
     * 2. Process each 512-bit chunk
     */
    for (k = 0; k < n_chunks; k++)
    {
        p = (uint8_t *)buffer + BITS_2_BYTES(512) * k;
        uint32_t *dp = (uint32_t *)p;

        // divide each chunk into 16 blocks, and extend to 80 blocks
        // M holds message in **bigendian**
        uint32_t M[64];

        // 0. Copy chunk(512bits, 16 x 32bit words) into M[0:15]
        // save blocks in M in bigendian, as M blocks are already in bigendian, save them directly.
        for (int t = 0; t < 16; t++)
            M[t] = dp[t];

        // 2. M[16...63]
        for (int j = 16; j < 64; j++)
        {
            uint32_t s0, s1, be;

            // term1: s1, term3: s0
            // term2: M[j-7], term4: M[j-16]
            // [Caution] use bigendian of M[j] for computation
            be = GET_UINT32_BE(M[j - 15]);
            s0 = F0(be);

            be = GET_UINT32_BE(M[j - 2]);
            s1 = F1(be);

            // M[j] = M[j-16] + s0 + M[j-7] + s1;
            ADD_UINT32_MOD_4(M[j],
                             GET_UINT32_BE(M[j - 16]),   // must use bigendian
                             s0,
                             GET_UINT32_BE(M[j - 7]),    // must use bigendian
                             s1);

            // [Caution] convert M[j] in bigendian and assign it to M[j] in place
            M[j] = GET_UINT32_BE(M[j]);

            //printf("[%d] %s\n", j, hex_bytes((uint8_t *)&M[j], 4).c_str());
        }

        // initialize values which will be updated in each round
        uint32_t A = a;
        uint32_t B = b;
        uint32_t C = c;
        uint32_t D = d;
        uint32_t E = e;
        uint32_t F = f;
        uint32_t G = g;
        uint32_t H = h;

        // 64 steps
        for (i = 0; i < 64; i++)
        {
            uint32_t S0, S1, ch, temp1, temp2, maj;

            // use capptal-letter A, B, C, E, F, G(iterated by each step); not a, b, c, d(updated by each round)..
            S1 = RIGHT_ROTATE(E, 6) ^ RIGHT_ROTATE(E, 11) ^ RIGHT_ROTATE(E, 25);
            ch = (E & F) ^ (~E & G);

            /* [Caution] use M[i] at bigendian  */
            ADD_UINT32_MOD_5(temp1, H, S1, ch, sha256_constants[i], GET_UINT32_BE(M[i]));

            S0 = RIGHT_ROTATE(A, 2) ^ RIGHT_ROTATE(A, 13) ^ RIGHT_ROTATE(A, 22);
            maj = (A & B) ^ (A & C) ^ (B & C);
            temp2 = CMOD_32(S0 + maj);

            H = G;
            G = F;
            F = E;
            E = CMOD_32(D + temp1);
            D = C;
            C = B;
            B = A;
            A = CMOD_32(temp1 + temp2);

            // printf("[%d] A:%x, B:%x, C:%x, D:%x, E:%x, F:%x, G:%x, H:%x\n", i, A, B, C, D, E, F, G, H);
        }

        //  round epiology
        a = CMOD_32(a + A);
        b = CMOD_32(b + B);
        c = CMOD_32(c + C);
        d = CMOD_32(d + D);
        e = CMOD_32(e + E);
        f = CMOD_32(f + F);
        g = CMOD_32(g + G);
        h = CMOD_32(h + H);

        // printf("\n=== Round: a:%x b:%x c:%x d:%x, e:%x, f:%x, g:%x, h:%x\n", a, b, c, d, e, f, g, h);
    }

    // append result (a, b, c, d, e) in **bigendian**
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

    be = GET_UINT32_BE(f);
    memcpy((uint8_t *)out + 20, &be, 4);

    be = GET_UINT32_BE(g);
    memcpy((uint8_t *)out + 24, &be, 4);

    be = GET_UINT32_BE(h);
    memcpy((uint8_t *)out + 28, &be, 4);

    delete [](buffer);

    return 0;
}

