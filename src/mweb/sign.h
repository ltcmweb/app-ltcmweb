#pragma once

#include "hash.h"
#include "secret_key.h"

typedef uint8_t signature_t[64];

cx_err_t has_square_root(const uint8_t *point, bool *result);
cx_err_t mweb_sign(signature_t sig, const secret_key_t key, const hash_t msg);
