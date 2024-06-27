#pragma once

#include "hash.h"
#include "secret_key.h"

typedef struct {
    hash_t output_id;
    uint32_t address_index;
    secret_key_t shared_secret;
    secret_key_t spend_key;
} coin_t;

cx_err_t calculate_output_key(coin_t *coin, const secret_key_t spend_key);
