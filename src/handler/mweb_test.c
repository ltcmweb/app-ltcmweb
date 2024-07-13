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

unsigned short handler_mweb_test(buffer_t *buffer, uint8_t op) {
  cx_err_t error;

  switch (op) {
  case 0:
    if (!buffer_read(buffer, context.mwebKeychain.scan, sizeof(secret_key_t))) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    if (!buffer_read(buffer, context.mwebKeychain.spend, sizeof(secret_key_t))) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    return io_send_sw(SW_OK);

  case 1: {
    coin_t coin;
    secret_key_t spend_key;

    if (!buffer_read(buffer, coin.shared_secret, sizeof(coin.shared_secret))) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    if (!buffer_read(buffer, spend_key, sizeof(spend_key))) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    CX_CHECK(calculate_output_key(&coin, spend_key));
    return io_send_response_pointer(coin.spend_key, sizeof(coin.spend_key), SW_OK);
  }

  case 2: {
    mweb_input_t input;
    coin_t coin;
    secret_key_t input_key;

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
  }

  case 3: {
    signature_t sig;
    secret_key_t key;
    hash_t msg;

    if (!buffer_read(buffer, key, sizeof(key))) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    if (!buffer_read(buffer, msg, sizeof(msg))) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    CX_CHECK(mweb_sign(sig, key, msg));
    return io_send_response_pointer((uint8_t*)sig, sizeof(sig), SW_OK);
  }
  }
end:
  return io_send_sw(error);
}
