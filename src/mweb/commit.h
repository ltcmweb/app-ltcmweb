#pragma once

#include "secret_key.h"

typedef uint8_t commitment_t[33];

cx_err_t new_commit(commitment_t commit, public_key_t pub,
    const blinding_factor_t blind, uint64_t value);
