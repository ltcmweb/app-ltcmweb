#include "sign.h"
#include "const.h"

cx_err_t has_square_root(const uint8_t *point, bool *result)
{
    uint8_t e[32], one[32] = { 0 };
    cx_err_t error;

    memcpy(e, SECP256K1_CURVE_PRIME, 32);
    for (int i = 31; i >= 0; i--) {
        e[i] = e[i] >> 1 | (i ? e[i-1] << 7 : 0);
    }

    CX_CHECK(cx_math_powm_no_throw(e, point, e, 32, SECP256K1_CURVE_PRIME, 32));
    one[31] = 1;
    *result = !memcmp(e, one, 32);
end:
    return error;
}

cx_err_t mweb_sign(signature_t sig, const secret_key_t key, const hash_t msg)
{
    cx_sha256_t hasher;
    secret_key_t k, e;
    int diff;
    uint8_t point[65];
    bool has_sqrt;
    public_key_t pubkey;
    cx_err_t error;

    cx_sha256_init_no_throw(&hasher);
    CX_CHECK(cx_hash_no_throw((cx_hash_t*)&hasher, 0, key, 32, NULL, 0));
    CX_CHECK(cx_hash_no_throw((cx_hash_t*)&hasher, CX_LAST, msg, 32, k, 32));

    CX_CHECK(cx_math_cmp_no_throw(k, SECP256K1_CURVE_ORDER, 32, &diff));
    if (diff >= 0) CX_CHECK(CX_OVERFLOW);

    memcpy(point, SECP256K1_CURVE_BASE_POINT, sizeof(point));
    CX_CHECK(cx_ecfp_scalar_mult_no_throw(CX_CURVE_SECP256K1, point, k, 32));
    memcpy(sig, point + 1, 32);

    CX_CHECK(has_square_root(point + 33, &has_sqrt));
    if (!has_sqrt) {
        CX_CHECK(sk_sub(k, SECP256K1_CURVE_ORDER, k));
    }

    CX_CHECK(sk_pub(pubkey, key));

    cx_sha256_init_no_throw(&hasher);
    CX_CHECK(cx_hash_no_throw((cx_hash_t*)&hasher, 0, sig, 32, NULL, 0));
    CX_CHECK(cx_hash_no_throw((cx_hash_t*)&hasher, 0, pubkey, sizeof(pubkey), NULL, 0));
    CX_CHECK(cx_hash_no_throw((cx_hash_t*)&hasher, CX_LAST, msg, 32, e, 32));

    CX_CHECK(cx_math_cmp_no_throw(e, SECP256K1_CURVE_ORDER, 32, &diff));
    if (diff >= 0) CX_CHECK(CX_OVERFLOW);

    CX_CHECK(sk_mul(e, e, key));
    CX_CHECK(sk_add(sig + 32, k, e));
end:
    return error;
}
