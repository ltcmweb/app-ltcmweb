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
  }
end:
  return io_send_sw(error);
}
