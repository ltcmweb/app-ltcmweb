/*******************************************************************************
 *   Ledger App - Bitcoin Wallet
 *   (c) 2016-2019 Ledger
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
 ********************************************************************************/
#include "io.h"

#include "apdu_constants.h"
#include "context.h"

#define MODE_WALLET 0x01

/*
 * Function: handler_get_firmware_versi
 * ---------------------------------------
 * Retrieves the firmware version information.
 *
 * Returns:
 *   - -1 if the operation is unsuccessful.
 */
WEAK unsigned short handler_set_operation_mode(buffer_t *buffer, uint8_t p1,
                                               uint8_t p2) {

  UNUSED(p1);
  UNUSED(p2);

  if ((buffer->size != 1) && (buffer->ptr[0] != MODE_WALLET)) {
    return io_send_sw(SW_INCORRECT_DATA);
  } else {
    return io_send_sw(SW_OK);
  }
}