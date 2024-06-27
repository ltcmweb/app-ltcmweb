#include "kernel.h"

cx_err_t sign_mweb_kernel(
    blake3_t *kernel_msg_hasher,
    const blinding_factor_t kernel_blind,
    const blinding_factor_t stealth_blind,
    const public_key_t kernel_excess_pubkey,
    public_key_t stealth_excess_pubkey,
    signature_t sig)
{
    blake3_t hasher;
    secret_key_t key;
    hash_t hash;
    cx_err_t error;

    CX_CHECK(sk_pub(stealth_excess_pubkey, stealth_blind));

    CX_CHECK(blake3_init(&hasher));
    CX_CHECK(blake3_update(&hasher, kernel_excess_pubkey, sizeof(public_key_t)));
    CX_CHECK(blake3_update(&hasher, stealth_excess_pubkey, sizeof(public_key_t)));
    CX_CHECK(blake3_final(&hasher, key));

    CX_CHECK(sk_mul(key, key, kernel_blind));
    CX_CHECK(sk_add(key, stealth_blind, key));

    CX_CHECK(blake3_update(kernel_msg_hasher, stealth_excess_pubkey, sizeof(public_key_t)));
    CX_CHECK(blake3_final(kernel_msg_hasher, hash));

    CX_CHECK(mweb_sign(sig, key, hash));
end:
    return error;
}
