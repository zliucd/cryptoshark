/**
 * Cryptoshark is an open source and educational crypto library under GPL v2 license.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#include <iostream>
#include <string.h>
#include <assert.h>

#include "aes.h"
#include "util.h"

using namespace std;

/**
 *  We use standard test vectors from RFC to validate AES encryption/decryption
 *
 *    AES CBC test vectors, Section 4 at RFC3602 https://datatracker.ietf.org/doc/html/rfc3602#page-6
 *    AES CTR test vectors, Section 6 at RFC3686 http://www.faqs.org/rfcs/rfc3686.html
 */

///// AES CBC test vectors

// AES CBC keys
static const unsigned char aes_test_cbc_key[4][16] =
        {
            {0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b, 0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06},
            {0xc2, 0x86, 0x69, 0x6d, 0x88, 0x7c, 0x9a, 0xa0, 0x61, 0x1b, 0xbb, 0x3e, 0x20, 0x25, 0xa4, 0x5a},
            {0x6c, 0x3e, 0xa0, 0x47, 0x76, 0x30, 0xce, 0x21, 0xa2, 0xce, 0x33, 0x4a, 0xa7, 0x46, 0xc2, 0xcd},
            {0x56, 0xe4, 0x7a, 0x38, 0xc5, 0x59, 0x89, 0x74, 0xbc, 0x46, 0x90, 0x3d, 0xba, 0x29, 0x03, 0x49}
        };

// AES CBC IVs
static const unsigned char aes_test_cbc_iv[4][16] =
        {
            {0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30, 0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41},
            {0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58},
            {0xc7, 0x82, 0xdc, 0x4c, 0x09, 0x8c, 0x66, 0xcb, 0xd9, 0xcd, 0x27, 0xd8, 0x25, 0x68, 0x2c, 0x81},
            {0x8c, 0xe8, 0x2e, 0xef, 0xbe, 0xa0, 0xda, 0x3c, 0x44, 0x69, 0x9e, 0xd7, 0xdb, 0x51, 0xb7, 0xd9}
        };

// AES CBC plain texts
static const unsigned char aes_test_cbc_pt[4][64] =
        {
            // "Single block msg"
            {0x53, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x6d, 0x73, 0x67},

            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},

             // "This is a 48-byte message (exactly 3 AES blocks)"
            {0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x34, 0x38, 0x2d, 0x62, 0x79, 0x74,
             0x65, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x28, 0x65, 0x78, 0x61, 0x63, 0x74,
             0x6c, 0x79, 0x20, 0x33, 0x20, 0x41, 0x45, 0x53, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x73, 0x29},

            {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
             0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
             0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
             0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf}
            };

// AES CBC cipher texts
static const unsigned char aes_test_cbc_ct[4][64] =
        {
            // "Single block msg" cipher text
            {0xe3, 0x53, 0x77, 0x9c, 0x10, 0x79, 0xae, 0xb8, 0x27, 0x08, 0x94, 0x2d, 0xbe, 0x77, 0x18, 0x1a},

            {0xd2, 0x96, 0xcd, 0x94, 0xc2, 0xcc, 0xcf, 0x8a, 0x3a, 0x86, 0x30, 0x28, 0xb5, 0xe1, 0xdc, 0x0a,
             0x75, 0x86, 0x60, 0x2d, 0x25, 0x3c, 0xff, 0xf9, 0x1b, 0x82, 0x66, 0xbe, 0xa6, 0xd6, 0x1a, 0xb1},

            // "This is a 48-byte message (exactly 3 AES blocks)" cipher text
            {0xd0, 0xa0, 0x2b, 0x38, 0x36, 0x45, 0x17, 0x53, 0xd4, 0x93, 0x66, 0x5d, 0x33, 0xf0, 0xe8, 0x86,
             0x2d, 0xea, 0x54, 0xcd, 0xb2, 0x93, 0xab, 0xc7, 0x50, 0x69, 0x39, 0x27, 0x67, 0x72, 0xf8, 0xd5,
             0x02, 0x1c, 0x19, 0x21, 0x6b, 0xad, 0x52, 0x5c, 0x85, 0x79, 0x69, 0x5d, 0x83, 0xba, 0x26, 0x84},

            {0xc3, 0x0e, 0x32, 0xff, 0xed, 0xc0, 0x77, 0x4e, 0x6a, 0xff, 0x6a, 0xf0, 0x86, 0x9f, 0x71, 0xaa,
             0x0f, 0x3a, 0xf0, 0x7a, 0x9a, 0x31, 0xa9, 0xc6, 0x84, 0xdb, 0x20, 0x7e, 0xb0, 0xef, 0x8e, 0x4e,
             0x35, 0x90, 0x7a, 0xa6, 0x32, 0xc3, 0xff, 0xdf, 0x86, 0x8b, 0xb7, 0xb2, 0x9d, 0x3d, 0x46, 0xad,
             0x83, 0xce, 0x9f, 0x9a, 0x10, 0x2e, 0xe9, 0x9d, 0x49, 0xa5, 0x3e, 0x87, 0xf4, 0xc3, 0xda, 0x55}
        };

///// AES CTR test vectors

// keys
static const unsigned char aes_test_ctr_key[3][16] =
        {
            { 0xAE, 0x68, 0x52, 0xF8, 0x12, 0x10, 0x67, 0xCC, 0x4B, 0xF7, 0xA5, 0x76, 0x55, 0x77, 0xF3, 0x9E },
            { 0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7, 0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63 },
            { 0x76, 0x91, 0xBE, 0x03, 0x5E, 0x50, 0x20, 0xA8, 0xAC, 0x6E, 0x61, 0x85, 0x29, 0xF9, 0xA0, 0xDC }
        };

// nonce counters
static const unsigned char aes_test_ctr_nonce_counter[3][16] =
        {
            { 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
            { 0x00, 0x6C, 0xB6, 0xDB, 0xC0, 0x54, 0x3B, 0x59, 0xDA, 0x48, 0xD9, 0x0B, 0x00, 0x00, 0x00, 0x01 },
            { 0x00, 0xE0, 0x01, 0x7B, 0x27, 0x77, 0x7F, 0x3F, 0x4A, 0x17, 0x86, 0xF0, 0x00, 0x00, 0x00, 0x01 }
        };

// plain texts
static const unsigned char aes_test_ctr_pt[3][48] =
        {
            { 0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62, 0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67 },

            { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F },

            { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
              0x20, 0x21, 0x22, 0x23 }
        };

// cipher texts
static const unsigned char aes_test_ctr_ct[3][48] =
        {
            { 0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79, 0x2D, 0x61, 0x75, 0xA3, 0x26, 0x13, 0x11, 0xB8 },

            { 0x51, 0x04, 0xA1, 0x06, 0x16, 0x8A, 0x72, 0xD9, 0x79, 0x0D, 0x41, 0xEE, 0x8E, 0xDA, 0xD3, 0x88,
              0xEB, 0x2E, 0x1E, 0xFC, 0x46, 0xDA, 0x57, 0xC8, 0xFC, 0xE6, 0x30, 0xDF, 0x91, 0x41, 0xBE, 0x28 },

            { 0xC1, 0xCF, 0x48, 0xA8, 0x9F, 0x2F, 0xFD, 0xD9, 0xCF, 0x46, 0x52, 0xE9, 0xEF, 0xDB, 0x72, 0xD7,
              0x45, 0x40, 0xA4, 0x2B, 0xDE, 0x6D, 0x78, 0x36, 0xD5, 0x9A, 0x5C, 0xEA, 0xAE, 0xF3, 0x10, 0x53,
              0x25, 0xB2, 0x07, 0x2F }
        };

static const int aes_test_ctr_len[3] = { 16, 32, 36 };

int test_aes_cbc()
{
    aes_ctx_t aes;
    uint8_t output[1024];       // for convenience, use local buffer to save output
    size_t i, out_len;

    /**
     * Validate RFC test vectors
     */
    for (i = 0; i < 4; i++)
    {
        aes_ctx_init(&aes);
        aes_set_key(&aes, (uint8_t *)aes_test_cbc_key[i], 128);

        // encryption
        aes_encrypt_cbc(&aes, (uint8_t *)aes_test_cbc_pt[i], (i + 1) * 128, (uint8_t *)aes_test_cbc_iv[i], output, &out_len);
        assert ( out_len == (i + 1) * 16 and ( EQ_bytes( (uint8_t *)aes_test_cbc_ct[i], output, out_len) == 0 ) );

        // decryption
        aes_decrypt_cbc(&aes, (uint8_t *)aes_test_cbc_ct[i], (i + 1) * 16, (uint8_t *)aes_test_cbc_iv[i], output, &out_len);
        assert ( out_len == (i + 1) * 16 and ( EQ_bytes( (uint8_t *)aes_test_cbc_pt[i], output, out_len) == 0 ) );

        aes_ctx_free(&aes);
    }

    printf("=== AES-128 CBC passed ===\n");

    return 0;
}

void test_aes_ctr()
{
    uint8_t key[32];
    uint8_t buf_plain[64];
    uint8_t buf_cipher[64];
    uint8_t iv[16];
    uint8_t nonce_counter[16];
    uint8_t stream_block[16];
    size_t i, len, offset;

    aes_ctx_t aes;
    aes_ctx_init(&aes);

    for (i = 0; i < 3; i++)
    {
        memcpy(nonce_counter, aes_test_ctr_nonce_counter[i], 16);
        memcpy(key, aes_test_ctr_key[i], 16);

        aes_set_key(&aes, key, 128);
        len = aes_test_ctr_len[i];

        // encryption
        memcpy(buf_plain, aes_test_ctr_pt[i], len);
        memcpy(buf_cipher, aes_test_ctr_ct[i], len);

        aes_ctr_internal(&aes, (uint8_t *)buf_plain, len, nonce_counter, stream_block, (uint8_t *)buf_plain, &offset);

        assert (EQ_bytes(buf_plain, buf_cipher, len) == 0);
    }

    printf("=== AES-128 CTR passed ===\n");
}

// test mix columns of given input
// input and output are from https://www.samiam.org/mix-column.html
void test_mix_columns()
{
    int i ;

    uint8_t input[24] =
            {0xdb, 0x13, 0x53, 0x45,
             0xf2, 0x0a, 0x22, 0x5c,
             0x01, 0x01, 0x01, 0x01,
             0xc6, 0xc6, 0xc6, 0xc6,
             0xd4, 0xd4, 0xd4, 0xd5,
             0x2d, 0x26, 0x31, 0x4c};

    uint8_t expected[24] =
            {0x8e, 0x4d, 0xa1, 0xbc,
             0x9f, 0xdc, 0x58, 0x9d,
             0x01, 0x01, 0x01, 0x01,
             0xc6, 0xc6, 0xc6, 0xc6,
             0xd5, 0xd5, 0xd7, 0xd6,
             0x4d, 0x7e, 0xbd, 0xf8};

    for (i = 0; i < 6; i++)
        g_mix_column( (uint8_t *)input + i * 4 );

    for (i = 0; i < 24; i++)
        assert ( input[i] == expected[i] );

    printf("Test mixed column success\n");
}

// test shift rows from https://github.com/amanske/aes-128/blob/master/aes.cpp
void test_shiftRows(){

    uint8_t p[] = {0x07, 0x96, 0xeb, 0xeb,
                  0x75, 0x07, 0x96, 0xeb,
                  0xeb, 0x75, 0x07, 0x96,
                  0xeb, 0xeb, 0x75, 0x07};

    unsigned char state[4][4];
    unsigned char temp; //use temp variable to store rows during shifting
    int i, j;

    //And just follow the illustration
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
            state[i][j] = p[4 * i + j];
    }

    //Row 2
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    //Row 3
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    //Row 4
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;

    util_print_bytes((uint8_t *)state, 16, "test_shift_rows");
}


/// test mixSingleColumn from https://github.com/amanske/aes-128/blob/master/aes.cpp
void mixSingleColumn(unsigned char *r) {
    unsigned char a[4];
    unsigned char b[4];
    unsigned char c;
    unsigned char h;
    /* The array 'a' is simply a copy of the input array 'r'
     * The array 'b' is each element of the array 'a' multiplied by 2
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */
    for(c =0 ;c < 4; c++) {
        a[c] = r[c];
        /* h is 0xff if the high bit of r[c] is set, 0 otherwise */
        h = (unsigned char)((signed char)r[c] >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
        b[c] = r[c] << 1; /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
        b[c] ^= 0x1B & h; /* Rijndael's Galois field */
    }
    r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
    r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
    r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
    r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
}

//  mix columns, theory from https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_MixColumns_step
void mixColumns(unsigned char** state)
{
    unsigned char *temp = new unsigned char[4];

    for(int i = 0; i < 4; ++i)
    {
        for(int j = 0; j < 4; ++j)
        {
            temp[j] = state[j][i]; //place the current state column in temp
        }

        mixSingleColumn(temp);      //mix it using the wiki implementation

        for(int j = 0; j < 4; ++j)
        {
            state[j][i] = temp[j]; //when the column is mixed, place it back into the state
        }
    }

    delete [](temp);
}

// test mixColumns()
void test_mix_columns2()
{
    uint8_t p[] = {0x07, 0x96, 0xeb, 0xeb,
                   0x07, 0x96, 0xeb, 0x75,
                   0x07, 0x96, 0xeb, 0x75,
                   0x07, 0xeb, 0xeb, 0x75};
    uint8_t q[16];

    uint8_t **state;
    unsigned char temp; //use temp variable to store rows during shifting
    int i, j;

    state = new uint8_t*[4];
    for (i = 0; i< 4; i++)
        state[i] = new uint8_t[4];

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
            state[i][j] = p[4 * i + j];
    }

    mixColumns(state);

    printf("after mixing columns\n");
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
             printf("%02x ", state[i][j]);
    }

    printf("\n");
}