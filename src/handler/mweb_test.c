#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"
#include "io.h"
#include "buffer.h"
#include "crypto_helpers.h"

#include "apdu_constants.h"
#include "context.h"
#include "extensions.h"

#include "../mweb/commit.h"
#include "../mweb/kernel.h"

unsigned short test_set_keychain(buffer_t *buffer) {
  if (!buffer_read(buffer, context.mwebKeychain.scan, sizeof(secret_key_t))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read(buffer, context.mwebKeychain.spend, sizeof(secret_key_t))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  return io_send_sw(SW_OK);
}

unsigned short test_calculate_output_key(buffer_t *buffer) {
  coin_t coin;
  secret_key_t spend_key;
  cx_err_t error;

  if (!buffer_read(buffer, coin.shared_secret, sizeof(coin.shared_secret))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read(buffer, spend_key, sizeof(spend_key))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  CX_CHECK(calculate_output_key(&coin, spend_key));
  return io_send_response_pointer(coin.spend_key, sizeof(coin.spend_key), SW_OK);
end:
  return io_send_sw(error);
}

unsigned short test_mweb_input_create(buffer_t *buffer) {
  mweb_input_t input;
  coin_t coin;
  secret_key_t input_key;
  cx_err_t error;

  if (!buffer_read(buffer, coin.output_id, sizeof(coin.output_id))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read(buffer, coin.spend_key, sizeof(coin.spend_key))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read(buffer, input_key, sizeof(input_key))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  CX_CHECK(mweb_input_create(&input, &coin, input_key));
  return io_send_response_pointer((uint8_t*)&input, sizeof(input), SW_OK);
end:
  return io_send_sw(error);
}

unsigned short test_mweb_sign(buffer_t *buffer) {
  signature_t sig;
  secret_key_t key;
  hash_t msg;
  cx_err_t error;

  if (!buffer_read(buffer, key, sizeof(key))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read(buffer, msg, sizeof(msg))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  CX_CHECK(mweb_sign(sig, key, msg));
  return io_send_response_pointer((uint8_t*)sig, sizeof(sig), SW_OK);
end:
  return io_send_sw(error);
}

unsigned short test_sk_pub(buffer_t *buffer) {
  public_key_t p;
  secret_key_t k;
  cx_err_t error;

  if (!buffer_read(buffer, k, sizeof(k))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  CX_CHECK(sk_pub(p, k));
  return io_send_response_pointer(p, sizeof(p), SW_OK);
end:
  return io_send_sw(error);
}

unsigned short test_keychain_spend_key(buffer_t *buffer) {
  uint32_t index;
  secret_key_t result;
  cx_err_t error;

  if (!buffer_read(buffer, context.mwebKeychain.scan, sizeof(secret_key_t))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read(buffer, context.mwebKeychain.spend, sizeof(secret_key_t))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read_u32(buffer, &index, LE)) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  CX_CHECK(keychain_spend_key(&context.mwebKeychain, index, result));
  return io_send_response_pointer(result, sizeof(result), SW_OK);
end:
  return io_send_sw(error);
}

unsigned short test_keychain_address(buffer_t *buffer) {
  uint32_t index;
  char address[130];
  cx_err_t error;

  if (!buffer_read(buffer, context.mwebKeychain.scan, sizeof(secret_key_t))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read(buffer, context.mwebKeychain.spend, sizeof(secret_key_t))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read_u32(buffer, &index, LE)) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  CX_CHECK(keychain_address(&context.mwebKeychain, index, address));
  return io_send_response_pointer((uint8_t*)address, strlen(address), SW_OK);
end:
  return io_send_sw(error);
}

unsigned short test_sign_mweb_kernel(buffer_t *buffer) {
  blinding_factor_t kernel_blind, stealth_blind;
  commitment_t kernel_excess;
  public_key_t kernel_excess_pubkey, stealth_excess;
  signature_t sig;
  cx_err_t error;

  if (!buffer_read(buffer, kernel_blind, sizeof(kernel_blind))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read(buffer, stealth_blind, sizeof(stealth_blind))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  CX_CHECK(new_commit(kernel_excess, kernel_excess_pubkey, kernel_blind, 0));
  CX_CHECK(blake3_update("\x10", 1));
  CX_CHECK(blake3_update(kernel_excess, sizeof(kernel_excess)));
  CX_CHECK(sign_mweb_kernel(kernel_blind, stealth_blind, kernel_excess_pubkey, stealth_excess, sig));
  return io_send_response_pointer(sig, sizeof(sig), SW_OK);
end:
  return io_send_sw(error);
}

unsigned short test_new_commit(buffer_t *buffer) {
  blinding_factor_t blind;
  uint64_t value;
  struct {
    commitment_t commit;
    public_key_t commit_pub;
  } data;
  cx_err_t error;

  if (!buffer_read(buffer, blind, sizeof(blind))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read_u64(buffer, &value, LE)) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  CX_CHECK(new_commit(data.commit, data.commit_pub, blind, value));
  return io_send_response_pointer((uint8_t*)&data, sizeof(data), SW_OK);
end:
  return io_send_sw(error);
}

unsigned short test_new_blind_switch(buffer_t *buffer) {
  blinding_factor_t blind, blind_switch;
  uint64_t value;
  cx_err_t error;

  if (!buffer_read(buffer, blind, sizeof(blind))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read_u64(buffer, &value, LE)) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  CX_CHECK(new_blind_switch(blind_switch, blind, value));
  return io_send_response_pointer(blind_switch, sizeof(blind_switch), SW_OK);
end:
  return io_send_sw(error);
}

unsigned short handler_mweb_test(buffer_t *buffer, uint8_t op) {
  switch (op) {
  case 0: return test_set_keychain(buffer);
  case 1: return test_calculate_output_key(buffer);
  case 2: return test_mweb_input_create(buffer);
  case 3: return test_mweb_sign(buffer);
  case 4: return test_sk_pub(buffer);
  case 5: return test_keychain_spend_key(buffer);
  case 6: return test_keychain_address(buffer);
  case 7: return test_sign_mweb_kernel(buffer);
  case 8: return test_new_commit(buffer);
  case 9: return test_new_blind_switch(buffer);
  }
  return io_send_sw(SW_INCORRECT_P1_P2);
}
