#pragma once

#include <stdint.h>
#include "cx.h"
#include "../blake3/lcx_blake3.h"

typedef uint8_t hash_t[32];
typedef cx_blake3_t blake3_t;

cx_err_t blake3_init(blake3_t *hash);
cx_err_t blake3_update(blake3_t *hash, const void *input, size_t input_len);
cx_err_t blake3_final(blake3_t *hash, hash_t output);
