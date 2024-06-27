#include "coin.h"
#include "input.h"
#include "sign.h"

#define MWEB_INPUT_STEALTH_KEY_FEATURE_BIT 1

cx_err_t mweb_input_create(mweb_input_t *input, const coin_t *coin, const secret_key_t input_key)
{
    blake3_t hasher;
    hash_t key_hash, msg_hash;
    secret_key_t sig_key;
    cx_err_t error;

    input->features = MWEB_INPUT_STEALTH_KEY_FEATURE_BIT;
    memcpy(input->output_id, coin->output_id, sizeof(hash_t));
    CX_CHECK(sk_pub(input->input_pubkey, input_key));
    CX_CHECK(sk_pub(input->output_pubkey, coin->spend_key));

    // Hash keys (K_i||K_o)
    CX_CHECK(blake3_init(&hasher));
    CX_CHECK(blake3_update(&hasher, input->input_pubkey, sizeof(public_key_t)));
    CX_CHECK(blake3_update(&hasher, input->output_pubkey, sizeof(public_key_t)));
    CX_CHECK(blake3_final(&hasher, key_hash));

    // Calculate aggregated key k_agg = k_i + HASH(K_i||K_o) * k_o
    CX_CHECK(sk_mul(sig_key, key_hash, coin->spend_key));
    CX_CHECK(sk_add(sig_key, input_key, sig_key));

    // Hash message
    CX_CHECK(blake3_init(&hasher));
    CX_CHECK(blake3_update(&hasher, &input->features, 1));
    CX_CHECK(blake3_update(&hasher, coin->output_id, sizeof(hash_t)));
    CX_CHECK(blake3_final(&hasher, msg_hash));

    CX_CHECK(mweb_sign(input->sig, sig_key, msg_hash));
end:
    return error;
}
