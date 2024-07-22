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

bool buffer_read(buffer_t *buffer, uint8_t *out, size_t out_len) {
  if (!buffer_can_read(buffer, out_len)) return false;
  memcpy(out, buffer->ptr + buffer->offset, out_len);
  return buffer_seek_cur(buffer, out_len);
}

unsigned short handler_mweb_add_input(buffer_t *buffer) {
  coin_t coin;
  secret_key_t key;
  blinding_factor_t blind;
  cx_err_t error;

  if (!buffer_read(buffer, (uint8_t*)&coin, sizeof(coin) - sizeof(secret_key_t))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }

  CX_CHECK(keychain_spend_key(&context.mwebKeychain, coin.address_index, key));
  CX_CHECK(calculate_output_key(&coin, key));
  cx_rng(key, sizeof(key));
#ifdef TESTING
  memcpy(key, context.mwebKeychain.scan, 32);
#endif
  CX_CHECK(mweb_input_create(&context.mweb.input.input, blind, &coin, key));

  CX_CHECK(sk_sub(context.mwebKernelBlind, context.mwebKernelBlind, blind));
  CX_CHECK(sk_add(context.mwebStealthOffset, key, context.mwebStealthOffset));
  CX_CHECK(sk_sub(context.mwebStealthOffset, context.mwebStealthOffset, coin.spend_key));

  return io_send_response_pointer((uint8_t*)&context.mweb.input.input, sizeof(mweb_input_t), SW_OK);
end:
  return io_send_sw(error);
}
