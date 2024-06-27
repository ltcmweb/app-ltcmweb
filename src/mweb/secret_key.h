#pragma once

#include <stdint.h>
#include "cx.h"

typedef uint8_t secret_key_t[32];
typedef uint8_t public_key_t[33];
typedef uint8_t blinding_factor_t[32];

cx_err_t sk_add(secret_key_t r, const secret_key_t a, const secret_key_t b);
cx_err_t sk_sub(secret_key_t r, const secret_key_t a, const secret_key_t b);
cx_err_t sk_mul(secret_key_t r, const secret_key_t a, const secret_key_t b);
cx_err_t sk_pub(public_key_t p, const secret_key_t k);
cx_err_t sk_pub2(cx_ecfp_public_key_t *p, const secret_key_t k);
void compress_pubkey(public_key_t p, const uint8_t *W);
