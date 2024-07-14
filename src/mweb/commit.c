#include "commit.h"
#include "const.h"
#include "sign.h"

cx_err_t new_commit(commitment_t commit, const blinding_factor_t blind, uint64_t value)
{
    uint8_t p1[65], p2[65];
    uint8_t v[32] = { 0 };
    bool has_sqrt;
    cx_err_t error;

    memcpy(p1, SECP256K1_CURVE_BASE_POINT, sizeof(p1));
    CX_CHECK(cx_ecfp_scalar_mult_no_throw(CX_CURVE_256K1, p1, blind, 32));
    memcpy(p2, GENERATOR_H, sizeof(p2));
    for (int i = 0; i < 8; i++) {
        v[i + 24] = value & 0xFF;
        value >>= 8;
    }
    CX_CHECK(cx_ecfp_scalar_mult_no_throw(CX_CURVE_256K1, p2, v, 32));
    CX_CHECK(cx_ecfp_add_point_no_throw(CX_CURVE_256K1, p1, p1, p2));
    commit[0] = 8;
    memcpy(commit + 1, p1 + 1, 32);
    CX_CHECK(has_square_root(p1 + 33, &has_sqrt));
    if (!has_sqrt) {
        commit[0]++;
    }
end:
    return error;
}
