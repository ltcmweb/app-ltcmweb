#pragma once

#include "secret_key.h"

typedef struct {
    secret_key_t scan;
    secret_key_t spend;
} keychain_t;

cx_err_t keychain_init(keychain_t *k, uint32_t *path, size_t path_len);
cx_err_t keychain_spend_key(const keychain_t *k, uint32_t index, secret_key_t result);
cx_err_t keychain_address(const keychain_t *k, uint32_t index, char *out);
