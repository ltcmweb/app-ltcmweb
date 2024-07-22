#include "coin.h"

cx_err_t calculate_output_key(coin_t *coin, const secret_key_t spend_key)
{
    hash_t hash;
    cx_err_t error;

    CX_CHECK(blake3_init());
    CX_CHECK(blake3_update("O", 1));
    CX_CHECK(blake3_update(coin->shared_secret, sizeof(secret_key_t)));
    CX_CHECK(blake3_final(hash, true));
    CX_CHECK(sk_mul(coin->spend_key, hash, spend_key));
end:
    return error;
}
