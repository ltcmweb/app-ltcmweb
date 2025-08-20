#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "cx.h"
#include "buffer.h"

#include "apdu_constants.h"
#include "context.h"
#include "display_utils.h"
#include "display_variables.h"
#include "extensions.h"
#include "io.h"
#include "segwit_addr.h"
#include "ui.h"

unsigned short handler_mweb_add_output(buffer_t *buffer) {
  uint64_t value;
  uint8_t pA[66], pB[66];
  blinding_factor_t blind;
  cx_err_t error;

  if (!buffer_read_u64(buffer, &value, LE)) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read(buffer, pA, 65)) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read(buffer, pB, 65)) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }

  cx_rng(context.mweb.output.senderKey, sizeof(secret_key_t));
#ifdef TESTING
  memcpy(context.mweb.output.senderKey, context.mwebKeychain.scan, 32);
#endif

  CX_CHECK(mweb_output_create(&context.mweb.output.result.output,
                              context.mweb.output.result.blind,
                              context.mweb.output.result.shared,
                              blind, value, pA, pB,
                              context.mweb.output.senderKey));

  CX_CHECK(sk_add(context.mwebKernelBlind, context.mwebKernelBlind, blind));
  CX_CHECK(sk_add(context.mwebStealthOffset, context.mweb.output.senderKey, context.mwebStealthOffset));

  pA[0] = pA[64] % 2 ? 3 : 2;
  compress_pubkey(pA + 33, pB);
  CX_CHECK(keychain_program(&context.mwebKeychain, 0, pB));

  if (memcmp(pA, pB, sizeof(pA))) {
    CX_CHECK(!segwit_addr_encode(vars.tmp.fullAddress, "ltcmweb", 0, pA, sizeof(pA)));
    format_sats_amount(COIN_COINID_SHORT, value, vars.tmp.fullAmount);
    context.totalOutputs++;
    context.mwebConfirmOutput = 1;
    ui_confirm_single_flow();
    return 0;
  }

  context.mwebConfirmOutput = 1;
  return mweb_add_output_user_action(1);
end:
  return io_send_sw(error);
}

unsigned short mweb_add_output_user_action(unsigned char confirming) {
  unsigned char confirmOutput = context.mwebConfirmOutput;
  cx_err_t error = SW_OK;

  context.mwebConfirmOutput = 0;

  if (!confirming) {
    context.totalOutputs = 0;
    context.remainingOutputs = 1;
    memset(&context.mweb, 0, sizeof(context.mweb));
    memset(context.mwebKernelBlind, 0, sizeof(context.mwebKernelBlind));
    memset(context.mwebStealthOffset, 0, sizeof(context.mwebStealthOffset));
    CX_CHECK(SW_CONDITIONS_OF_USE_NOT_SATISFIED);
  }

  switch (confirmOutput) {
  case 1:
    return io_send_response_pointer((uint8_t*)&context.mweb.output.result,
                                    sizeof(context.mweb.output.result), SW_OK);
  case 2:
    if (!context.mweb.kernel.pegoutsRemaining) {
      format_sats_amount(COIN_COINID_SHORT, context.mweb.kernel.fee, vars.tmp.feesAmount);
      context.mwebConfirmOutput = 3;
      ui_finalize_flow();
      return 1;
    }
  }
end:
  return io_send_sw(error);
}

unsigned short handler_mweb_sign_output(buffer_t *buffer) {
  hash_t rangeProofHash;
  signature_t sig;
  cx_err_t error;

  if (!buffer_read(buffer, rangeProofHash, sizeof(rangeProofHash))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }

  CX_CHECK(mweb_output_sign(sig, &context.mweb.output.result.output,
                            rangeProofHash, context.mweb.output.senderKey));

  return io_send_response_pointer(sig, sizeof(sig), SW_OK);
end:
  return io_send_sw(error);
}
