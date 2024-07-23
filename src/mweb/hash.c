#include "hash.h"
#include "const.h"
#include "../blake3/lcx_blake3.h"

static cx_blake3_t hash;

cx_err_t blake3_init()
{
    return cx_blake3_init(&hash, 0, NULL, NULL, 0);
}

cx_err_t blake3_update(const void *input, size_t input_len)
{
    return cx_blake3_update(&hash, input, input_len);
}

cx_err_t blake3_update_varint(uint64_t n)
{
    uint8_t buf[10];
    int len = 0;
    cx_err_t error;

    while (true) {
        buf[len] = (n & 0x7F) | (len ? 0x80 : 0x00);
        if (n <= 0x7F) break;
        n = (n >> 7) - 1;
        len++;
    }
    do {
        CX_CHECK(blake3_update(&buf[len], 1));
    } while (len--);
end:
    return error;
}

cx_err_t blake3_update_pubkey(const uint8_t *W)
{
    uint8_t odd = W[64] % 2 ? 3 : 2;
    cx_err_t error;

    CX_CHECK(blake3_update(&odd, 1));
    CX_CHECK(blake3_update(W + 1, 32));
end:
    return error;
}

cx_err_t blake3_final(hash_t output, bool check_overflow)
{
    int diff;
    cx_err_t error;

    CX_CHECK(cx_blake3_final(&hash, output, sizeof(hash_t)));
    if (check_overflow) {
        CX_CHECK(cx_math_cmp_no_throw(output, SECP256K1_CURVE_ORDER, 32, &diff));
        if (diff >= 0) error = CX_OVERFLOW;
    }
end:
    return error;
}
