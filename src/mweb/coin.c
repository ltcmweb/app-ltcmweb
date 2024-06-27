#include "coin.h"

cx_err_t calculate_output_key(coin_t *coin, const secret_key_t spend_key)
{
    blake3_t hasher;
    hash_t hash;
    cx_err_t error;

    CX_CHECK(blake3_init(&hasher));
    CX_CHECK(blake3_update(&hasher, "O", 1));
    CX_CHECK(blake3_update(&hasher, coin->shared_secret, sizeof(secret_key_t)));
    CX_CHECK(blake3_final(&hasher, hash));
    CX_CHECK(sk_mul(coin->spend_key, hash, spend_key));
end:
    return error;
}
