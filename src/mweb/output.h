#pragma once

#include "commit.h"

typedef struct {
    uint8_t features;
    public_key_t key_exchange_pubkey;
    uint8_t view_tag;
    uint8_t masked_value[8];
    uint8_t masked_nonce[16];
} mweb_output_message_t;

typedef struct {
    commitment_t commit;
    public_key_t sender_pubkey;
    public_key_t receiver_pubkey;
    mweb_output_message_t message;
} mweb_output_t;

cx_err_t mweb_output_create(mweb_output_t *output,
    blinding_factor_t blind, uint64_t value,
    const uint8_t *pA, const uint8_t *pB,
    const secret_key_t sender_key);
