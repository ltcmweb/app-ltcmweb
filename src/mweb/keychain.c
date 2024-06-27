#include "keychain.h"
#include "hash.h"
#include "crypto_helpers.h"
#include "../bech32/segwit_addr.h"

cx_err_t keychain_init(keychain_t *k, uint32_t *path, size_t path_len)
{
    cx_ecfp_256_private_key_t priv_key;
    uint8_t chain_code[32];
    cx_err_t error;

    path[path_len++] = 1 << 31;
    CX_CHECK(bip32_derive_init_privkey_256(CX_CURVE_256K1, path, path_len, &priv_key, chain_code));
    memcpy(k->scan, priv_key.d, sizeof(secret_key_t));

    path[path_len - 1]++;
    CX_CHECK(bip32_derive_init_privkey_256(CX_CURVE_256K1, path, path_len, &priv_key, chain_code));
    memcpy(k->spend, priv_key.d, sizeof(secret_key_t));
end:
    return error;
}

static cx_err_t mi(const keychain_t *k, uint32_t index, secret_key_t result)
{
    blake3_t hasher;
    cx_err_t error;

    CX_CHECK(blake3_init(&hasher));
    CX_CHECK(blake3_update(&hasher, "A", 1));
    CX_CHECK(blake3_update(&hasher, &index, sizeof(uint32_t)));
    CX_CHECK(blake3_update(&hasher, k->scan, sizeof(secret_key_t)));
    CX_CHECK(blake3_final(&hasher, result));
end:
    return error;
}

cx_err_t keychain_spend_key(const keychain_t *k, uint32_t index, secret_key_t result)
{
    cx_err_t error;

    CX_CHECK(mi(k, index, result));
    CX_CHECK(sk_add(result, result, k->spend));
end:
    return error;
}

cx_err_t keychain_address(const keychain_t *k, uint32_t index, char *out)
{
    cx_ecfp_public_key_t spend_pub, pub;
    secret_key_t key;
    uint8_t W[65], prog[66];
    cx_err_t error;

    CX_CHECK(sk_pub2(&spend_pub, k->spend));
    CX_CHECK(mi(k, index, key));
    CX_CHECK(sk_pub2(&pub, key));
    CX_CHECK(cx_ecfp_add_point_no_throw(CX_CURVE_256K1, W, spend_pub.W, pub.W));
    compress_pubkey(prog + 33, W);
    CX_CHECK(cx_ecfp_scalar_mult_no_throw(CX_CURVE_256K1, W, k->scan, 32));
    compress_pubkey(prog, W);
    CX_CHECK(!segwit_addr_encode(out, "ltcmweb", 0, prog, sizeof(prog)));
end:
    return error;
}
