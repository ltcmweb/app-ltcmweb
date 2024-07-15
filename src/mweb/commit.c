#include "commit.h"
#include "const.h"
#include "sign.h"

cx_err_t new_commit(commitment_t commit, public_key_t pub,
    const blinding_factor_t blind, uint64_t value)
{
    uint8_t p1[65], p2[65];
    uint8_t v[32] = { 0 };
    bool has_sqrt;
    cx_err_t error;

    memcpy(p1, SECP256K1_CURVE_BASE_POINT, sizeof(p1));
    CX_CHECK(cx_ecfp_scalar_mult_no_throw(CX_CURVE_256K1, p1, blind, 32));
    memcpy(p2, GENERATOR_H, sizeof(p2));
    for (int i = 0; i < 8; i++) {
        v[31-i] = value >> i*8;
    }
    if (value) {
        CX_CHECK(cx_ecfp_scalar_mult_no_throw(CX_CURVE_256K1, p2, v, 32));
        CX_CHECK(cx_ecfp_add_point_no_throw(CX_CURVE_256K1, p1, p1, p2));
    }
    commit[0] = 8;
    memcpy(commit + 1, p1 + 1, 32);
    CX_CHECK(has_square_root(p1 + 33, &has_sqrt));
    if (!has_sqrt) commit[0]++;
    if (pub) compress_pubkey(pub, p1);
end:
    return error;
}

cx_err_t switch_commit(blinding_factor_t blind_switch,
    const blinding_factor_t blind, uint64_t value)
{
    commitment_t commit;
    uint8_t point[65];
    public_key_t pub;
    cx_sha256_t hasher;
    cx_err_t error;

    CX_CHECK(new_commit(commit, NULL, blind, value));

    memcpy(point, GENERATOR_J, sizeof(point));
    CX_CHECK(cx_ecfp_scalar_mult_no_throw(CX_CURVE_256K1, point, blind, 32));
    compress_pubkey(pub, point);

    cx_sha256_init_no_throw(&hasher);
    CX_CHECK(cx_hash_no_throw((cx_hash_t*)&hasher, 0, commit, 33, NULL, 0));
    CX_CHECK(cx_hash_no_throw((cx_hash_t*)&hasher, CX_LAST, pub, 33, blind_switch, 32));
    CX_CHECK(sk_add(blind_switch, blind_switch, blind));
end:
    return error;
}
