/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

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

static bool buffer_read(buffer_t *buffer, uint8_t *out, size_t out_len)
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

    if (!buffer_read_u32(buffer, &context.mwebTxContext.n_inputs, LE)) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    if (!buffer_read(buffer, context.mwebTxContext.output_key, sizeof(secret_key_t))) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    if (!buffer_read(buffer, context.mwebTxContext.kernel_blind, sizeof(blinding_factor_t))) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    if (!buffer_read(buffer, context.mwebTxContext.kernel_excess_pubkey, sizeof(public_key_t))) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    CX_CHECK(keychain_init(&context.mwebKeychain, bip32_path, bip32_path_len));
    CX_CHECK(blake3_init(&context.mwebTxContext.kernel_msg_hasher));
    memset(context.mwebTxContext.input_key, 0, sizeof(secret_key_t));

    return io_send_sw(SW_OK);

  } else if (context.mwebTxContext.n_inputs) {  // parse inputs
    coin_t coin;
    secret_key_t key;

    if (!buffer_read(buffer, (uint8_t*)&coin, sizeof(coin))) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    CX_CHECK(keychain_spend_key(&context.mwebKeychain, coin.address_index, key));
    CX_CHECK(calculate_output_key(&coin, key));
    cx_rng(key, sizeof(key));
    CX_CHECK(mweb_input_create(&context.mwebTxContext.input, &coin, key));
    CX_CHECK(sk_add(context.mwebTxContext.input_key, key, context.mwebTxContext.input_key));
    CX_CHECK(sk_sub(context.mwebTxContext.input_key, context.mwebTxContext.input_key, coin.spend_key));

    context.mwebTxContext.n_inputs--;

    if (!request_mweb_input_approval(&coin)) {
      return io_send_sw(SW_TECHNICAL_PROBLEM);
    }

  } else if (more) {
    CX_CHECK(blake3_update(&context.mwebTxContext.kernel_msg_hasher, buffer->ptr, buffer->size));

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
    CX_CHECK(blake3_update(&context.mwebTxContext.kernel_msg_hasher, buffer->ptr, buffer->size));

    cx_rng(stealth_blind, sizeof(stealth_blind));

    CX_CHECK(sk_add(data.stealth_offset, context.mwebTxContext.input_key, context.mwebTxContext.output_key));
    CX_CHECK(sk_sub(data.stealth_offset, data.stealth_offset, stealth_blind));

    CX_CHECK(sign_mweb_kernel(&context.mwebTxContext.kernel_msg_hasher,
      context.mwebTxContext.kernel_blind, stealth_blind,
      context.mwebTxContext.kernel_excess_pubkey,
      data.stealth_excess, data.kernel_sig));

    return io_send_response_pointer((uint8_t*)&data, sizeof(data), SW_OK);
  }

  return 0;
end:
  return io_send_sw(error);
}

int user_action_mweb_input(unsigned char confirming) {
  if (confirming) {
    return io_send_response_pointer((uint8_t*)&context.mwebTxContext.input, sizeof(mweb_input_t), SW_OK);
  } else {
    return io_send_sw(SW_CONDITIONS_OF_USE_NOT_SATISFIED);
  }
}
