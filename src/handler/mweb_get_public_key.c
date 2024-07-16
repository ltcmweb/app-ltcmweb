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

unsigned short handler_mweb_get_public_key(buffer_t *buffer, bool display) {
  uint32_t bip32_path[MAX_BIP32_PATH];
  uint8_t bip32_path_len;
  struct {
    secret_key_t scan;
    public_key_t spend;
  } data;
  cx_err_t error;

  if (!buffer_read_u8(buffer, &bip32_path_len) ||
      !buffer_read_bip32_path(buffer, bip32_path, bip32_path_len)) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  CX_CHECK(keychain_init(&context.mwebKeychain, bip32_path, bip32_path_len));

  memset(context.mwebKernelBlind, 0, sizeof(blinding_factor_t));
  memset(context.mwebStealthOffset, 0, sizeof(blinding_factor_t));

  if (display) {
    uint32_t address_index;
    char address[130];

    if (!buffer_read_u32(buffer, &address_index, BE)) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    CX_CHECK(keychain_address(&context.mwebKeychain, address_index, address));
    display_mweb_address(address);
    return 0;
  }

  memcpy(data.scan, context.mwebKeychain.scan, sizeof(secret_key_t));
  CX_CHECK(sk_pub(data.spend, context.mwebKeychain.spend));
  return io_send_response_pointer((uint8_t*)&data, sizeof(data), SW_OK);
end:
  return io_send_sw(error);
}
