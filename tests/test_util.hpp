/**
 * Cryptoshark is an open source and educational crypto library under GPL v2 license.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#include <iostream>
#include <string.h>
#include <assert.h>

#include "util.h"

using namespace std;

void test_padding_cms()
{
    uint8_t x[3] = {0x68, 0x65, 0x6c};
    uint8_t y[16];
    uint8_t *out;
    size_t olen;

    memcpy(y, x, 3);
    memset(y + 3, 0x0d, 13);

    padding_cms((uint8_t *)x, 3, 16, &out, &olen);

    assert(olen == 16);
    for (int i = 0 ; i < 16; i++)
        assert (out[i] == y[i]);

    delete [](out);

    // 2 blocks
    uint8_t x2[20];
    uint8_t y2[32];

    memcpy(y2, x2, 20);
    memset(y2 + 20, 0x0c, 12);

    padding_cms((uint8_t *)x2, 20, 16, &out, &olen);

    assert(olen == 32);
    for (int i = 0 ; i < 32; i++)
        assert (out[i] == y2[i]);

    delete [](out);

    // aligned input
    uint8_t x3[16];
    uint8_t y3[32];
    memcpy(y3, x3, 16);
    memset(y3 + 16, 0x10, 16);

    padding_cms((uint8_t *)x3, 16, 16, &out, &olen);

    assert(olen == 32);
    for (int i = 0 ; i < 32; i++)
        assert (out[i] == y3[i]);

    delete [](out);
}


// transpose a 16-byte array(4x4 matrix)
void test_util_matrix_transpose16()
{
    uint8_t input[16];
    uint8_t r[16];
    int i, j;

    for (i = 0; i < 16; i++)
        input[i] = i;

    memcpy(r, input, 16);
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
            r[j * 4 + i] = input[(i * 4 + j)];
    }

    util_print_bytes(r, 16, "Matrix transpose");
}
