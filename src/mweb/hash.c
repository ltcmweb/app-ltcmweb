#include "hash.h"

cx_err_t blake3_init(blake3_t *hash)
{
    return cx_blake3_init(hash, 0, NULL, NULL, 0);
}

cx_err_t blake3_update(blake3_t *hash, const void *input, size_t input_len)
{
    return cx_blake3_update(hash, input, input_len);
}

cx_err_t blake3_final(blake3_t *hash, hash_t output)
{
    return cx_blake3_final(hash, output, sizeof(hash_t));
}
