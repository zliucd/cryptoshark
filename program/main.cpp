/**
 * Cryptoshark is an open source and educational crypto library under GPL v2 license.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#include <iostream>

#include "test_aes.hpp"
#include "test_util.hpp"
#include "test_hash.hpp"
#include "test_sm4.hpp"


int main(int argc, char *argv[])
{
    printf("Cryptoshark is an open source and educational crypto library under GPL v2 license.\n"
           "Author: Zhi Liu, zliucd66@gmail.com\n\n");

    // test hash functions
    printf("Test hash digest\n\n");

    test_md5_hash();
    test_sha1();
    test_sha256();
    test_sm3();

    // test symmetric cipher
    printf("\n   Test symmetric ciphers\n\n");
    test_aes_cbc();
    test_aes_ctr();
    test_sm4();

    // test util functions, debugging only
    // test_padding_cms();
    // test_shiftRows();
    // test_mix_columns();
    // test_mix_columns2();
    // test_util_matrix_transpose16();

    printf("\n=== All passed ===\n\n");
}