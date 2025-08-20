#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "cx.h"
#include "buffer.h"

#include "apdu_constants.h"
#include "context.h"
#include "customizable_ui.h"
#include "display_utils.h"
#include "display_variables.h"
#include "extensions.h"
#include "io.h"
#include "ui.h"

#include "../mweb/kernel.h"

#define FEE_FEATURE_BIT 0x01
#define PEGIN_FEATURE_BIT 0x02
#define PEGOUT_FEATURE_BIT 0x04
#define HEIGHT_LOCK_FEATURE_BIT 0x08
#define STEALTH_EXCESS_FEATURE_BIT 0x10

unsigned short handler_mweb_sign_kernel(buffer_t *buffer, bool start) {
  cx_err_t error;

  if (start) {
    if (!buffer_read_u64(buffer, &context.mweb.kernel.fee, LE)) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    if (!buffer_read_u64(buffer, &context.mweb.kernel.pegin, LE)) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    if (!buffer_read_u16(buffer, &context.mweb.kernel.pegouts, LE)) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    if (!buffer_read_u32(buffer, &context.mweb.kernel.lockHeight, LE)) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    context.mweb.kernel.features = STEALTH_EXCESS_FEATURE_BIT;
    if (context.mweb.kernel.fee) context.mweb.kernel.features |= FEE_FEATURE_BIT;
    if (context.mweb.kernel.pegin) context.mweb.kernel.features |= PEGIN_FEATURE_BIT;
    if (context.mweb.kernel.pegouts) context.mweb.kernel.features |= PEGOUT_FEATURE_BIT;
    if (context.mweb.kernel.lockHeight) context.mweb.kernel.features |= HEIGHT_LOCK_FEATURE_BIT;

    CX_CHECK(blake3_init());
    CX_CHECK(blake3_update(&context.mweb.kernel.features, 1));

    cx_rng(context.mweb.kernel.offset, sizeof(blinding_factor_t));
#ifdef TESTING
    memcpy(context.mweb.kernel.offset, context.mwebKeychain.scan, 32);
#endif
    CX_CHECK(sk_sub(context.mwebKernelBlind, context.mwebKernelBlind, context.mweb.kernel.offset));

    CX_CHECK(new_commit(context.mweb.kernel.excess,
                        context.mweb.kernel.excessPubkey,
                        context.mwebKernelBlind, 0));
    CX_CHECK(blake3_update(context.mweb.kernel.excess, sizeof(commitment_t)));

    if (context.mweb.kernel.fee) {
      CX_CHECK(blake3_update_varint(context.mweb.kernel.fee));
    }
    if (context.mweb.kernel.pegin) {
      CX_CHECK(blake3_update_varint(context.mweb.kernel.pegin));
    }

    context.mweb.kernel.pegoutsRemaining = context.mweb.kernel.pegouts;
    if (context.mweb.kernel.pegouts) {
      CX_CHECK(blake3_update(&context.mweb.kernel.pegouts, 1));
    } else {
      context.mwebConfirmOutput = 2;
      mweb_add_output_user_action(1);
      return 0;
    }

    return io_send_sw(SW_OK);

  } else if (context.mweb.kernel.pegoutsRemaining) {
    uint64_t value;
    uint8_t scriptLen;

    if (!buffer_read_u64(buffer, &value, LE)) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    if (!buffer_read_u8(buffer, &scriptLen)) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    if (!buffer_can_read(buffer, scriptLen)) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    context.mweb.kernel.pegoutsRemaining--;

    CX_CHECK(blake3_update_varint(value));
    CX_CHECK(blake3_update(buffer->ptr + buffer->offset - 1, scriptLen + 1));

    get_address_from_output_script(buffer->ptr + buffer->offset - 1, scriptLen + 1,
                                   vars.tmp.fullAddress, sizeof(vars.tmp.fullAddress));
    format_sats_amount(COIN_COINID_SHORT, value, vars.tmp.fullAmount);

    context.totalOutputs++;
    context.mwebConfirmOutput = 2;
    ui_confirm_single_flow();
    return 0;

  } else {
    blinding_factor_t stealthBlind;
    struct {
      blinding_factor_t kernelOffset;
      blinding_factor_t stealthOffset;
      uint8_t features;
      commitment_t kernelExcess;
      public_key_t stealthExcess;
      signature_t sig;
    } result;

    if (context.mweb.kernel.lockHeight) {
      CX_CHECK(blake3_update_varint(context.mweb.kernel.lockHeight));
    }

    cx_rng(stealthBlind, sizeof(stealthBlind));
#ifdef TESTING
    memcpy(stealthBlind, context.mwebKeychain.scan, 32);
#endif
    CX_CHECK(sk_sub(result.stealthOffset, context.mwebStealthOffset, stealthBlind));

    result.features = context.mweb.kernel.features;
    memcpy(result.kernelOffset, context.mweb.kernel.offset, sizeof(result.kernelOffset));
    memcpy(result.kernelExcess, context.mweb.kernel.excess, sizeof(result.kernelExcess));

    CX_CHECK(sign_mweb_kernel(context.mwebKernelBlind, stealthBlind,
                              context.mweb.kernel.excessPubkey,
                              result.stealthExcess, result.sig));

    CX_CHECK(blake3_init());
    CX_CHECK(blake3_update(&context.mweb.kernel.features, 1));
    if (context.mweb.kernel.fee) {
      CX_CHECK(blake3_update_varint(context.mweb.kernel.fee));
    }
    if (context.mweb.kernel.pegin) {
      CX_CHECK(blake3_update_varint(context.mweb.kernel.pegin));
    }
    if (context.mweb.kernel.lockHeight) {
      CX_CHECK(blake3_update_varint(context.mweb.kernel.lockHeight));
    }
    CX_CHECK(blake3_update(result.stealthExcess, sizeof(result.stealthExcess)));
    CX_CHECK(blake3_update(result.kernelExcess, sizeof(result.kernelExcess)));
    CX_CHECK(blake3_update(result.sig, sizeof(result.sig)));
    CX_CHECK(blake3_final(context.mweb.kernel.hash, false));
    context.mwebKernelHashValid = !context.mweb.kernel.pegouts;

    return io_send_response_pointer((uint8_t*)&result, sizeof(result), SW_OK);
  }

end:
  return io_send_sw(error);
}
