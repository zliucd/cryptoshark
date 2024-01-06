/**
 * Cryptoshark is an open source and educational crypto library under GPL v2 license.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#include <iostream>
#include <string.h>
#include <assert.h>

#include "sm4.h"

// test vectors from Appendix at SM4 specification, http://www.gmbz.org.cn/main/viewfile/20180108015408199368.html
const uint8_t test1_keybuf[16] =
{
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};

const uint32_t test1_rk[32] =
{
    0xF12186F9, 0x41662B61, 0x5A6AB19A, 0x7BA92077, 0x367360F4, 0x776A0C61, 0xB6BB89B3, 0x24763151,
    0xA520307C, 0xB7584DBD, 0xC30753ED, 0x7EE55B57, 0x6988608C, 0x30D895B7, 0x44BA14AF, 0x104495A1,
    0xD120B428, 0x73B55FA3, 0xCC874966, 0x92244439, 0xE89E641F, 0x98CA015A, 0xC7159060, 0x99E1FD2E,
    0xB79BD80C, 0x1D2115B0, 0x0E228AEB, 0xF1780C81, 0x428D3654, 0x62293496, 0x01CF72E5, 0x9124A012
};

const uint8_t test1_input[16] =
{
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};

const uint8_t test1_output[16] =
{
    0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
    0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46
};

// 100,000 times encryption using test1_input and test1_key
const uint8_t test2_output[16] =
{
    0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
    0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66
};

void test_sm4()
{
    sm4_ctx ctx;
    int i;
    uint8_t output[16];

    sm4_ctx_init(&ctx);
    sm4_ctx_setkey(&ctx, (uint8_t *)test1_keybuf, 128);

    // test if round keys are correct
    for (i = 0; i < 32; i++)
        assert (ctx.rk[i] == test1_rk[i]);

    // test encryption is ok
    sm4_encrypt(&ctx, (uint8_t *)test1_keybuf, (uint8_t *)output);

    if (memcmp(output, test1_output, 16) != 0)
    {
        printf("=== SM4 ECB encryption1 fail ===\n");
        assert (false);
    }
    printf("=== SM4 ECB encryption1(single pass) passed === \n");

    // test2
    memcpy(output, test1_keybuf, 16);
    for (i = 0; i < 1000000; i++)
    {
        sm4_encrypt(&ctx, (uint8_t *)output, (uint8_t *)output);
    }

    if (memcmp(output, test2_output, 16) != 0)
    {
        printf("=== SM4 ECB encryption2 fail ===\n");
        assert (false);
    }

    sm4_ctx_free(&ctx);
    printf("=== SM4 ECB encryption1(1M times pass) passed === \n");
}