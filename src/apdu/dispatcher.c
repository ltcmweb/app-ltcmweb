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

#include <stdbool.h>
#include <stdint.h>

#include "buffer.h"
#include "io.h"
#include "ledger_assert.h"

#include "apdu_constants.h"
#include "context.h"
#include "dispatcher.h"

int apdu_dispatcher(const command_t *cmd) {
  LEDGER_ASSERT(cmd != NULL, "NULL cmd");

  if (cmd->cla == CLA_MWEB) {
    goto mweb;
  }

  if (cmd->cla != CLA) {
    return io_send_sw(SW_CLA_NOT_SUPPORTED);
  }

  buffer_t buf = {0};

  switch (cmd->ins) {
  case INS_GET_WALLET_PUBLIC_KEY:
    PRINTF("Get wallet public key\n");
    if (!cmd->data) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    buf.ptr = cmd->data;
    buf.size = cmd->lc;
    buf.offset = 0;
    return handler_get_wallet_public_key(&buf, cmd->p1, cmd->p2);

  case INS_GET_TRUSTED_INPUT:
    PRINTF("Get trusted input\n");
    if (!cmd->data) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    buf.ptr = cmd->data;
    buf.size = cmd->lc;
    buf.offset = 0;
    return handler_get_trusted_input(&buf, cmd->p1, cmd->p2);

  case INS_HASH_INPUT_START:
    PRINTF("Hash input start\n");
    if (!cmd->data) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    buf.ptr = cmd->data;
    buf.size = cmd->lc;
    buf.offset = 0;
    return handler_hash_input_start(&buf, cmd->p1, cmd->p2);

  case INS_HASH_SIGN:
    PRINTF("Hash sign\n");
    if (!cmd->data) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    buf.ptr = cmd->data;
    buf.size = cmd->lc;
    buf.offset = 0;
    return handler_hash_sign(&buf, cmd->p1, cmd->p2);

  case INS_HASH_INPUT_FINALIZE_FULL:
    PRINTF("Hash input finalize full\n");
    if (!cmd->data) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    buf.ptr = cmd->data;
    buf.size = cmd->lc;
    buf.offset = 0;
    return handler_hash_input_finalize_full(&buf, cmd->p1, cmd->p2);

  case INS_SIGN_MESSAGE:
    PRINTF("Sign message\n");
    if (!cmd->data) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    buf.ptr = cmd->data;
    buf.size = cmd->lc;
    buf.offset = 0;
    return handler_sign_message(&buf, cmd->p1, cmd->p2);

  case INS_GET_FIRMWARE_VERSION:
    PRINTF("Get firmware version\n");

    return handler_get_firmware_version();

  case INS_GET_COIN_VER:
    PRINTF("Get coin version\n");

    return handler_get_coin_version();

  case INS_GET_OPERATION_MODE:
    PRINTF("Get operation mode\n");

    return handler_get_operation_mode();

  case INS_SET_OPERATION_MODE:
    PRINTF("Set operation mode\n");

    buf.ptr = cmd->data;
    buf.size = cmd->lc;
    buf.offset = 0;

    return handler_set_operation_mode(&buf, cmd->p1, cmd->p2);

  default:
    PRINTF("Instruction not supported\n");
    return io_send_sw(SW_INS_NOT_SUPPORTED);
  }

mweb:
  context.mwebKernelHashValid = 0;

  switch (cmd->ins) {
  case INS_MWEB_GET_PUBLIC_KEY:
    PRINTF("MWEB Get public key\n");
    if (!cmd->data) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    buf.ptr = cmd->data;
    buf.size = cmd->lc;
    buf.offset = 0;
    return handler_mweb_get_public_key(&buf, (bool)cmd->p1);

  case INS_MWEB_ADD_INPUT:
    PRINTF("MWEB Add input\n");
    if (!cmd->data) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    buf.ptr = cmd->data;
    buf.size = cmd->lc;
    buf.offset = 0;
    return handler_mweb_add_input(&buf);

  case INS_MWEB_ADD_OUTPUT:
    PRINTF("MWEB Add output\n");
    if (!cmd->data) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    buf.ptr = cmd->data;
    buf.size = cmd->lc;
    buf.offset = 0;
    return handler_mweb_add_output(&buf);

  case INS_MWEB_SIGN_OUTPUT:
    PRINTF("MWEB Sign output\n");
    if (!cmd->data) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    buf.ptr = cmd->data;
    buf.size = cmd->lc;
    buf.offset = 0;
    return handler_mweb_sign_output(&buf);

  case INS_MWEB_SIGN_KERNEL:
    PRINTF("MWEB Sign kernel\n");
    if (!cmd->data) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    buf.ptr = cmd->data;
    buf.size = cmd->lc;
    buf.offset = 0;
    return handler_mweb_sign_kernel(&buf, (bool)cmd->p1);

#ifdef TESTING
  case INS_MWEB_TEST:
    PRINTF("MWEB Test\n");
    if (!cmd->data) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    buf.ptr = cmd->data;
    buf.size = cmd->lc;
    buf.offset = 0;
    return handler_mweb_test(&buf, cmd->p1);
#endif

  default:
    PRINTF("Instruction not supported\n");
    return io_send_sw(SW_INS_NOT_SUPPORTED);
  }
}
