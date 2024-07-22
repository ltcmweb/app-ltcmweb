#include "hash.h"
#include "const.h"
#include "apdu_constants.h"
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

cx_err_t blake3_final(hash_t output, bool check_overflow)
{
    int diff;
    cx_err_t error;

    CX_CHECK(cx_blake3_final(&hash, output, sizeof(hash_t)));
    if (check_overflow) {
        CX_CHECK(cx_math_cmp_no_throw(output, SECP256K1_CURVE_ORDER, 32, &diff));
        if (diff >= 0) error = SW_OVERFLOWED;
    }
end:
    return error;
}
