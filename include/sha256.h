/**
 * Cryptoshark is an open source and educational crypto library under GPL v2 license.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#ifndef CRYPTODEMO_SHA256_H
#define CRYPTODEMO_SHA256_H

#include <iostream>

int sha256_preprocess(uint8_t *buf, size_t ilen, uint8_t **out, size_t *olen);

int sha256_hash(uint8_t *buf, size_t len, uint8_t *out);

#endif //CRYPTODEMO_SHA256_H
