#pragma once

#include <stdint.h>
#include "cx.h"

typedef uint8_t hash_t[32];

cx_err_t blake3_init();
cx_err_t blake3_update(const void *input, size_t input_len);
cx_err_t blake3_final(hash_t output, bool check_overflow);
