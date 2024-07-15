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

#include "../mweb/coin.h"
#include "../mweb/input.h"
#include "../mweb/kernel.h"
#include "../mweb/keychain.h"

bool buffer_read(buffer_t *buffer, uint8_t *out, size_t out_len)
{
  if (buffer->size - buffer->offset < out_len) {
    return false;
  }
  memcpy(out, buffer->ptr + buffer->offset, out_len);
  return buffer_seek_cur(buffer, out_len);
}

unsigned short handler_mweb_sign_tx(buffer_t *buffer, uint8_t chunk, bool more) {
  uint32_t bip32_path[MAX_BIP32_PATH];
  uint8_t bip32_path_len;
  cx_err_t error;

  if (chunk == 0) {  // first APDU
    if (!buffer_read_u8(buffer, &bip32_path_len) ||
      !buffer_read_bip32_path(buffer, bip32_path, bip32_path_len)) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    CX_CHECK(keychain_init(&context.mwebKeychain, bip32_path, bip32_path_len));
    memset(context.mwebBlindSum, 0, sizeof(blinding_factor_t));
    memset(context.mwebStealthOffset, 0, sizeof(blinding_factor_t));

    return io_send_sw(SW_OK);

  } else if (more) {
    CX_CHECK(blake3_update(buffer->ptr, buffer->size));

    // more APDUs with transaction part are expected.
    // Send a SW_OK to signal that we have received the chunk
    return io_send_sw(SW_OK);

  } else {
    blinding_factor_t stealth_blind;
    struct {
      blinding_factor_t stealth_offset;
      public_key_t stealth_excess;
      signature_t kernel_sig;
    } data;

    // last APDU for this transaction, let's parse, display and request a sign confirmation
    CX_CHECK(blake3_update(buffer->ptr, buffer->size));

    cx_rng(stealth_blind, sizeof(stealth_blind));

    CX_CHECK(sk_sub(data.stealth_offset, context.mwebStealthOffset, stealth_blind));

    CX_CHECK(sign_mweb_kernel(context.mweb.kernel.blind, stealth_blind,
                              data.stealth_excess, data.kernel_sig));

    return io_send_response_pointer((uint8_t*)&data, sizeof(data), SW_OK);
  }

  return 0;
end:
  return io_send_sw(error);
}

int user_action_mweb_input(unsigned char confirming) {
  if (confirming) {
    return io_send_response_pointer((uint8_t*)&context.mweb.input.input, sizeof(mweb_input_t), SW_OK);
  } else {
    return io_send_sw(SW_CONDITIONS_OF_USE_NOT_SATISFIED);
  }
}
