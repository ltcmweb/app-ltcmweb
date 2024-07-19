#pragma once

#include "coin.h"
#include "commit.h"
#include "sign.h"

typedef struct {
    uint8_t features;
    hash_t output_id;
    commitment_t commit;
    public_key_t input_pubkey;
    public_key_t output_pubkey;
    signature_t sig;
} mweb_input_t;

cx_err_t mweb_input_create(
    mweb_input_t *input, blinding_factor_t blind,
    const coin_t *coin, const secret_key_t input_key);
