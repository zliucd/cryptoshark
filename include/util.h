/**
 * Cryptoshark is an open source and educational crypto library under GPL v2 license.
 * Author: Zhi Liu <zliucd66@gmail.com>
 */

#ifndef CRYPTODEMO_UTIL_H
#define CRYPTODEMO_UTIL_H

using namespace std;

#define MAX_UINT32 0xFFFFFFFF

#define BITS_2_BYTES(n) (n / 8)

// bit operations
#define CMOD_32(n)       ((n) % 0xFFFFFFFF)
#define ADD_MOD32(a, b)  ((a + b) % 0xFFFFFFFF)

#define  SHR(x,n) (((x) & 0xFFFFFFFF) >> (n))

// left rotation n-bits of x
#define LEFT_ROTATE(x,n)                                                          \
    ( ( (x) << (n) ) | ( ( (x) & 0xFFFFFFFF) >> ( 32 - (n) ) ) )

// right rotation n-bits of x
#define  RIGHT_ROTATE(x, n) ( (x >> n) | ((x) << (32 - (n))))

/**
 *  Fast shift operations
 *   - LEFT_CIR_SHIFT8:   left shift by 8 bits
 *   - LEFT_CIR_SHIFT8:   left shift by 16 bits
 *   - LEFT_CIR_SHIFT24:  left shift by 24 bits
 *
 *  Notes:
 *   1. These shifts work on **** arithmetic *** byte order;
 *   2. caller should explicitly convert results to big-endian.
 */

// left circular shifts
#define  LEFT_CIR_SHIFT8(n) \
    ( ( (n << 8) & 0xffffffff ) | ((n >> 24)  & 0xffffffff ) )

#define  LEFT_CIR_SHIFT16(n) \
    ( ( (n << 16) & 0xffffffff ) | (n >> 16)  & 0xffffffff )

#define  LEFT_CIR_SHIFT24(n) \
    ( ( (n << 24) & 0xffffffff ) | (n >> 8)   & 0xffffffff )


// right circular shifts
#define  RIGHT_CIR_SHIFT8(n) \
    ( ( (n >> 8) & 0xffffffff ) | ((n << 24)  & 0xffffffff ) )

#define  RIGHT_CIR_SHIFT16(n) \
    ( ( (n >> 16) & 0xffffffff ) | (n << 16)  & 0xffffffff )

#define  RIGHT_CIR_SHIFT24(n) \
    ( ( (n >> 24) & 0xffffffff ) | (n << 8)   & 0xffffffff )

// XX_GET_UINT32_LE() and XX_GET_UINT32_BE() are helper functions from mbedtls
#define  XX_GET_UINT32_LE( data, offset )                   \
    (                                                           \
          ( (uint32_t)(data)[(offset) ] )         \
        | ( (uint32_t)(data)[(offset ) + 1] <<  8 )         \
        | ( (uint32_t)(data)[(offset) + 2] << 16 )         \
        | ( (uint32_t)(data)[(offset) + 3] << 24 )         \
    )

#define XX_GET_UINT32_BE( data , offset )                  \
    (                                                           \
          ( (uint32_t)(data)[( offset ) ] << 24 )         \
        | ( (uint32_t)(data)[( offset ) + 1] << 16 )         \
        | ( (uint32_t)(data)[( offset ) + 2] <<  8 )         \
        | ( (uint32_t)(data)[( offset ) + 3]       )         \
    )

/**
 * Reinterpret a 32-bit value using big-endian from x's memory
 * e.g., x = 0x34 56 78 12,
 *       mem: 12 78 34 56      (x might an immediate value, and its memory is faked)
 *       0x12 is considered the highest byte, following by 78, 34, 56
 */
#define GET_UINT32_BE(x)                                        \
        (                                                       \
            ((x & 0xff) << 24) | (((x >> 8) & 0xff) << 16) |    \
            (((x >> 16) & 0xff) << 8) | ((x>>24 & 0xff))        \
        )

// reinterpret a 64-bit value using big-endian from x's memory
#define GET_UINT64_BE(x)                                                \
        (                                                               \
            ((x & 0xff) << 56) | (((x >> 8) & 0xff) << 48) |            \
            (((x >> 16) & 0xff) << 40) | (((x >> 24) & 0xff) << 32) |    \
            (((x >> 32) & 0xff) << 24) | (((x >> 40) & 0xff) << 16) |   \
            (((x >> 48) & 0xff) << 8) | (((x >> 56) & 0xff))            \
        )

// modular add by 2^32 with 3 args(a,b,c,d,e), 'ret' is result
#define ADD_UINT32_MOD_3(ret, a, b, c)              \
       (                                            \
           ret = (CMOD_32(CMOD_32(a + b) + c))      \
       )

// modular add by 2^32 with 4 args(a,b,c,d,e), 'ret' is result
#define ADD_UINT32_MOD_4(ret, a, b, c, d)                   \
       (                                                    \
           ret = CMOD_32(CMOD_32(CMOD_32(a + b) + c) + d)   \
       )

// modular add by 2^32 with 5 args(a,b,c,d,e), 'ret' is result
#define ADD_UINT32_MOD_5(ret, a, b, c, d, e)                            \
       (                                                                \
           ret = CMOD_32(CMOD_32(CMOD_32(CMOD_32(a + b) + c) + d) + e)   \
       )

// rounddown (efficient when n is a power of 2), code from MIT OS course
#define ROUNDDOWN(a, n)						\
({								            \
	uint32_t __a = (uint32_t) (a);		    \
	(typeof(a)) (__a - __a % (n));			\
})

// roundup (efficient when n is a power of 2), code from MIT OS course, code from MIT OS course
#define ROUNDUP(a, n)						\
({								\
	uint32_t __n = (uint32_t) (n);				\
	(typeof(a)) (ROUNDDOWN((uint32_t) (a) + __n - 1, __n));	\
})

string hex_bytes(uint8_t *data, uint32_t data_len);

int util_unhex_bytes(const char *str, size_t len, uint8_t **data, size_t *olen);

static uint8_t util_unhex_char(char c);

void util_write_bigendian_64(uint64_t val, uint8_t *bytes);

void util_print_bytes(uint8_t* data, uint32_t len, string header);

void util_matrix_transpose16(uint8_t *input);

void util_swap_order(uint8_t *p);

int EQ_bytes(uint8_t *p, uint8_t *q, size_t len);

int padding_cms(uint8_t *input, size_t ilen, size_t blocksize_bytes, uint8_t **output, size_t *olen);

#endif //CRYPTODEMO_UTIL_H
