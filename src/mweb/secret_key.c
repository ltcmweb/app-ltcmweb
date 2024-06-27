#include "secret_key.h"
#include "const.h"

cx_err_t sk_add(secret_key_t r, const secret_key_t a, const secret_key_t b)
{
    return cx_math_addm_no_throw(r, a, b, SECP256K1_CURVE_ORDER, 32);
}

cx_err_t sk_sub(secret_key_t r, const secret_key_t a, const secret_key_t b)
{
    return cx_math_subm_no_throw(r, a, b, SECP256K1_CURVE_ORDER, 32);
}

cx_err_t sk_mul(secret_key_t r, const secret_key_t a, const secret_key_t b)
{
    return cx_math_multm_no_throw(r, a, b, SECP256K1_CURVE_ORDER, 32);
}

cx_err_t sk_pub(public_key_t p, const secret_key_t k)
{
    cx_ecfp_public_key_t pub;
    cx_err_t error;

    CX_CHECK(sk_pub2(&pub, k));
    compress_pubkey(p, pub.W);
end:
    return error;
}

cx_err_t sk_pub2(cx_ecfp_public_key_t *p, const secret_key_t k)
{
    cx_ecfp_private_key_t key;
    cx_err_t error;

    CX_CHECK(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, k, 32, &key));
    CX_CHECK(cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, p, &key, 1));
end:
    return error;
}

void compress_pubkey(public_key_t p, const uint8_t *W)
{
    p[0] = W[64] % 2 ? 3 : 2;
    memcpy(p + 1, W + 1, 32);
}
