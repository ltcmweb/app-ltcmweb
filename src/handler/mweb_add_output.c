#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
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
                              value, pA, pB,
                              context.mweb.output.senderKey));

  CX_CHECK(new_blind_switch(blind, context.mweb.output.result.blind, value));
  CX_CHECK(sk_add(context.mwebKernelBlind, context.mwebKernelBlind, blind));
  CX_CHECK(sk_add(context.mwebStealthOffset, context.mweb.output.senderKey, context.mwebStealthOffset));

  pA[0] = pA[64] % 2 ? 3 : 2;
  compress_pubkey(pA + 33, pB);
  CX_CHECK(keychain_program(&context.mwebKeychain, 0, pB));
  vars.tmp.fullAddress[0] = 0;

  if (memcmp(pA, pB, sizeof(pA))) {
    CX_CHECK(!segwit_addr_encode(vars.tmp.fullAddress, "ltcmweb", 0, pA, sizeof(pA)));
    format_sats_amount(COIN_COINID_SHORT, value, vars.tmp.fullAmount);
    context.totalOutputs++;
  }

  return io_send_response_pointer((uint8_t*)&context.mweb.output.result,
                                  sizeof(context.mweb.output.result), SW_OK);
end:
  return io_send_sw(error);
}

unsigned short handler_mweb_sign_output(buffer_t *buffer) {
  if (!buffer_read(buffer, context.mweb.output.rangeProofHash, sizeof(hash_t))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }

  if (vars.tmp.fullAddress[0]) {
    ui_confirm_single_flow();
    return 0;
  }

  return mweb_sign_output_user_action(1);
}

unsigned short mweb_sign_output_user_action(unsigned char confirming) {
  signature_t sig;
  cx_err_t error;

  if (!confirming) {
    return io_send_sw(SW_CONDITIONS_OF_USE_NOT_SATISFIED);
  }

  CX_CHECK(mweb_output_sign(sig, &context.mweb.output.result.output,
                            context.mweb.output.rangeProofHash,
                            context.mweb.output.senderKey));

  return io_send_response_pointer(sig, sizeof(sig), SW_OK);
end:
  return io_send_sw(error);
}
