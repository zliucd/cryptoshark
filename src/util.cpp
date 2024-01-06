/**
 * Cryptoshark is an open source and educational crypto library under Apache License V2.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#include <iostream>
#include <string.h>
#include <assert.h>
#include <vector>

#include "util.h"

using namespace std;

/**
 * Format bytes to hex representation, max print 0xffff bytes to avoid overflow.
 * @param data [in] data pointer
 * @param data_len [in] data length
 * @return hex string
 */
string hex_bytes(uint8_t *data, uint32_t data_len)
{
    string val = "";
    int j;
    char buf[16];

    if (data == NULL or data_len == 0)
    {
        return val;
    }

    for (j = 0; j < data_len and j < 0xffff; j++)
    {
        memset(buf, 0, 16);
        sprintf(buf, "%02x", data[j]);
        val += string(buf);
    }

    return val;
}

/**
 * Convert a hex string to raw bytes
 * notes: caller must free output 'data' manually
 * @param str       [in]  char string
 * @param len       [in]  str len
 * @param data      [out] bytes, memory allocated inside this function.
 * @param olen      [out] len of data. If NULL, do not set olen.
 */
int util_unhex_bytes(const char *str, size_t len, uint8_t **data, size_t *olen)
{
    uint8_t *p, *q;
    uint8_t result;
    int i;

    if (str == NULL or data == NULL)
    {
        return -1;
    }

    if (len == 0)
    {
        return 0;
    }

    if (len % 2 != 0)
    {
        *data = NULL;
        return -1;
    }

    p = new uint8_t[len / 2];
    q = p;

    // write a single byte every time
    for (i = 0; i < len; i += 2)
    {
        result = util_unhex_char(str[i]) * 16 + util_unhex_char(str[i+1]);
        memcpy(p, &result, 1);
        p++;
    }

    *data = q;
    if (olen != NULL)     // it's ok that olen is NULL, given the caller does not want to set olen.
    {
        *olen = len / 2;
    }

    return 0;
}

/**
 * Unhex a single char to uint8, which is case insensitive.
 * @param c  [in] input char
 * @return \int integer value of the char
 */
static uint8_t util_unhex_char(char c)
{
    uint8_t x;

    if (c >= '0' and c <= '9')
    {
        x = c - '0';
    }
    else
    {
        switch (c)
        {
            case 'a':
                x = 10;
                break;
            case 'A':
                x = 10;
                break;
            case 'b':
                x = 11;
                break;
            case 'B':
                x = 11;
                break;
            case 'c':
                x = 12;
                break;
            case 'C':
                x = 12;
                break;
            case 'd':
                x = 13;
                break;
            case 'D':
                x = 13;
                break;
            case 'e':
                x = 14;
                break;
            case 'E':
                x = 14;
                break;
            case 'f':
                x = 15;
                break;
            case 'F':
                x = 15;
                break;
            default:
                assert (false);  // on-purpose halt for debugging
                break;
        }
    }

    return x;
}

/**
 * Write a 64-bit value to memory in bigendian format
 * @param val   [in] input value
 * @param bytes [in,out] memory address to write
 */
void util_write_bigendian_64(uint64_t val, uint8_t *bytes)
{
    if (bytes == NULL)
    {
        return;
    }

    bytes[0] = (val >> 56) & 0xff;
    bytes[1] = (val >> 48) & 0xff;
    bytes[2] = (val >> 40) & 0xff;
    bytes[3] = (val >> 32) & 0xff;
    bytes[4] = (val >> 24) & 0xff;
    bytes[5] = (val >> 16) & 0xff;
    bytes[6] = (val >> 8) & 0xff;
    bytes[7] = val & 0xff;
}

void util_print_bytes(uint8_t* data, uint32_t len, string header)
{
    int i;

    printf("=== %s (%d bytes) ===\n", header.c_str(), len);

    for (i = 0; i < len; i++)
    {
        if (i == 0 or i % 16 != 0)
        {
            if (i == 0)
                printf("%04x  %02x  ", i, data[i]);
            else
                printf("%02x  ", data[i]);
        }
        else
        {
            printf("\n%04x  %02x  ", i, data[i]);
        }
    }
    printf("\n");
}


/**
 * Fill paddings with input, while generated n bytes output, where n % blocksize_bytes == 0
 * CMS: Cryptographic Message Syntax. Paddings are the same value of number of padding bytes
 *
 * Example: initial        abc  // 68 65 6c
 *          after padding  abc  // 68 65 6c [12 x 0xD]       // block in 16 bytes
 *
 * @param input [in] input
 * @param ilen  [in] input len in bytes
 * @param block_bytes [in] block size in bytes
 * @param output [out] output
 * @param olen   [out] output len
 * @return 0 on success
 */
int padding_cms(uint8_t *input, size_t ilen, size_t block_bytes, uint8_t **output, size_t *olen)
{
    uint8_t *p;
    uint8_t padding;
    size_t len;

    // add one more block with padding bytes if ilen % block_bytes == 0
    if (ilen % block_bytes == 0)
    {
        padding = block_bytes & 0xff;
        len = ilen + block_bytes;

        p = new uint8_t[len];
        memcpy(p, input, ilen);
        memset(p + ilen, padding, padding);
    }
    else
    {
        padding = (block_bytes - ilen % block_bytes) & 0xff;
        len =  (size_t)(ilen / block_bytes) + 1;
        len *= block_bytes;

        p = new uint8_t[len];
        memcpy(p, input, ilen);
        memset(p + ilen, padding, padding);
    }

    *output = p;
    *olen = len;

    return 0;
}

/**
 * Transpose 4x4 array (16 byte 1d array)
 * notes: this only works for 16 bytes, and we do not check length.
 * @param input [in]
 */
void util_matrix_transpose16(uint8_t *input)
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
 * Swap byte order inplace
 * a b c d ->  d c b a
 * @param p [in,out]
 */
void util_swap_order(uint8_t *p)
{
    uint8_t tmp;
    tmp = p[0];
    p[0] = p[3];
    p[3] = tmp;

    tmp = p[1];
    p[1] = p[2];
    p[2] = tmp;
}

/**
 * Compare if memory bytes are identical
 * @param p     [in] the first input
 * @param q     [in] the second input
 * @param len   [in] length to compare
 * @return 0 if equal, -1 if not equal
 */
int EQ_bytes(uint8_t *p, uint8_t *q, size_t len)
{
    for (int i = 0; i < len; i++)
    {
        if (p[i] != q[i])
            return -1;
    }

    return 0;
}
