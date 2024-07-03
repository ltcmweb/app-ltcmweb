#include "hash.h"
#include "../blake3/lcx_blake3.h"

static cx_blake3_t hash;
static bool init;

cx_err_t blake3_update(const void *input, size_t input_len)
{
    cx_err_t error;

    if (!init) {
        CX_CHECK(cx_blake3_init(&hash, 0, NULL, NULL, 0));
        init = true;
    }
    CX_CHECK(cx_blake3_update(&hash, input, input_len));
end:
    return error;
}

cx_err_t blake3_final(hash_t output)
{
    init = false;
    return cx_blake3_final(&hash, output, sizeof(hash_t));
}
