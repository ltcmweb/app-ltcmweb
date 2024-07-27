#pragma once

#include "hash.h"
#include "secret_key.h"

typedef struct {
    blinding_factor_t blind;
    uint64_t value;
    hash_t output_id;
    uint64_t address_index;
    secret_key_t shared_secret;
    secret_key_t output_key;
} coin_t;

cx_err_t calculate_output_key(coin_t *coin, const secret_key_t child_spend_key);
