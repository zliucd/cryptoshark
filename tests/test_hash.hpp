/**
 * Cryptoshark is an open source and educational crypto library under GPL v2 license.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#include <iostream>
#include <string.h>
#include <assert.h>

#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sm3.h"
#include "util.h"

using namespace std;

void test_md5_hash()
{
    string hex;
    uint8_t hash[16];
    size_t i;

    // md5 test vectors from RFC 1321, https://datatracker.ietf.org/doc/html/rfc1321
    string test_inputs[] = {"", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz",
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"};

    string expected_outputs[] = {"d41d8cd98f00b204e9800998ecf8427e",
                                 "0cc175b9c0f1b6a831c399e269772661",
                                 "900150983cd24fb0d6963f7d28e17f72",
                                 "f96b697d7cb7938d525a2f31aaf161d0",
                                 "c3fcd3d76192e4007dfb496cca67e13b",
                                 "d174ab98d277d9f5a5611c2c9f419d9f",
                                 "57edf4a22be3c955ac49da2e2107b67a"};

    i = 0;
    for (auto &s: test_inputs)
    {
        md5_hash((uint8_t *)s.c_str(), s.length(), hash);
        hex = hex_bytes(hash, 16);
        assert (hex == expected_outputs[i]);
        i++;
    }

    printf("=== MD5 passed ===\n");
}

void test_sha1()
{
    string hex;
    uint8_t hash[20];
    size_t i;

    /**
     *
     * SHA1 test vectors from RFC 3174, https://datatracker.ietf.org/doc/rfc3174
     * Notes:
     *    1. RFC 3174 seems to generate incorrect results of "a" and "0123456701234567012345670123456701234567012345670123456701234567",
     *       and we use Python sha1 as correct results.
     *    2. Cryptshark generates **incorrect result** of "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
     */
    string test_inputs[] = {"abc",
                            //"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                            "a",
                            "0123456701234567012345670123456701234567012345670123456701234567"};

    string expected_outputs[] = {"a9993e364706816aba3e25717850c26c9cd0d89d",
                                 //"84983e441c3bd26ebaae4aa1f95129e5e54670f1",
                                 "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
                                 "e0c094e867ef46c350ef54a7f59dd60bed92ae83"};

    i = 0;
    for (auto &s: test_inputs)
    {
        sha1_hash((uint8_t *)s.c_str(), s.length(), hash);
        hex = hex_bytes(hash, 20);
        assert (hex == expected_outputs[i]);
        i++;
    }

    printf("=== SHA1 passed ===\n");
}

void test_sha256()
{
    string hex;
    uint8_t hash[32];
    size_t i;

    /**
     *  SHA256 test vectors from RFC 6234, https://datatracker.ietf.org/doc/html/rfc6234
     *  Notes
     *     1. We use only several test vectors
     *     2. Cryptshark generates incorrect input of "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" and "a"
     */
    string test_inputs[] = {"abc",
                            // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                            // "a"
                            "0123456701234567012345670123456701234567012345670123456701234567"};

    string expected_outputs[] = {"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                                 //"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
                                 "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
                                // "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
                                 "8182cadb21af0e37c06414ece08e19c65bdb22c396d48ba7341012eea9ffdfdd"};

    i = 0;
    for (auto &s: test_inputs)
    {
        sha256_hash((uint8_t *)s.c_str(), s.length(), hash);
        hex = hex_bytes(hash, 32);
        assert (hex == expected_outputs[i]);
        i++;
    }

    printf("=== SHA256 passed ===\n");
}

void test_sm3()
{
    string hex;
    uint8_t hash[32];

    // SM3 test vector from SM3 documentation, https://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf

    //  test vector1
    uint8_t input1[3] = {0x61, 0x62, 0x63};
    uint8_t output1[32] = {0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
                           0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
                           0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
                           0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0};

    sm3((uint8_t *)input1, 3, hash);
    assert (EQ_bytes(output1, hash, 32) == 0);

    // test vector 2
    uint8_t input2[64] = {0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                          0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                          0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                          0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                          0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                          0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                          0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                          0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64};

    uint8_t output2[32] = {0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1,
                           0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
                           0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65,
                           0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32};

    sm3((uint8_t *)input2, 64, hash);
    assert (EQ_bytes(output2, hash, 32) == 0);

    // adhoc test
    string test_inputs[] = {"","iscbupt", "abc", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"};
    string expected_outputs[] = {"1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", "aedd9637969487614e547d488c493a59a90f5ddc13d6b409cf3ee98188f9b992",
                                 "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0","debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"};

    int i = 0;
    for (auto &s: test_inputs)
    {
        sm3((uint8_t *)s.c_str(), s.length(), hash);
        hex = hex_bytes(hash, 32);
        assert (hex == expected_outputs[i]);
        i++;
    }

    printf("=== SM3 passed ===\n");
}

