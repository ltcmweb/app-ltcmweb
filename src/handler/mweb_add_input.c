#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"
#include "buffer.h"

#include "apdu_constants.h"
#include "context.h"
#include "extensions.h"
#include "io.h"

unsigned short handler_mweb_add_input(buffer_t *buffer) {
  secret_key_t key;
  blinding_factor_t blind;
  cx_err_t error;

  if (!buffer_read(buffer, (uint8_t*)&context.mweb.input.coin, sizeof(coin_t) - sizeof(secret_key_t))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }

  CX_CHECK(keychain_spend_key(&context.mwebKeychain, context.mweb.input.coin.address_index, key));
  CX_CHECK(calculate_output_key(&context.mweb.input.coin, key));
  cx_rng(key, sizeof(key));
  CX_CHECK(mweb_input_create(&context.mweb.input.input, &context.mweb.input.coin, key));

  CX_CHECK(new_blind_switch(blind, context.mweb.input.coin.blind, context.mweb.input.coin.value));
  CX_CHECK(sk_sub(context.mwebBlindSum, context.mwebBlindSum, blind));

  CX_CHECK(sk_add(context.mwebStealthOffset, key, context.mwebStealthOffset));
  CX_CHECK(sk_sub(context.mwebStealthOffset, context.mwebStealthOffset, context.mweb.input.coin.spend_key));

  return io_send_response_pointer((uint8_t*)&context.mweb.input.input, sizeof(mweb_input_t), SW_OK);
end:
  return io_send_sw(error);
}
