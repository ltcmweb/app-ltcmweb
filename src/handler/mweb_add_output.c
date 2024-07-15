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

unsigned short handler_mweb_add_output(buffer_t *buffer) {
  uint8_t pA[65], pB[65];
  cx_err_t error;

  if (!buffer_read_u64(buffer, &context.mweb.output.value, LE)) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read(buffer, pA, sizeof(pA))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }
  if (!buffer_read(buffer, pB, sizeof(pB))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }

  cx_rng(context.mweb.output.senderKey, sizeof(secret_key_t));
  CX_CHECK(mweb_output_create(&context.mweb.output.result.output,
                              context.mweb.output.result.blind,
                              context.mweb.output.result.shared,
                              context.mweb.output.value, pA, pB,
                              context.mweb.output.senderKey));

end:
  return io_send_sw(error);
}

unsigned short handler_mweb_sign_output(buffer_t *buffer) {
  hash_t range_proof_hash;
  blinding_factor_t blind;
  signature_t sig;
  cx_err_t error;

  if (!buffer_read(buffer, range_proof_hash, sizeof(range_proof_hash))) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }

  CX_CHECK(mweb_output_sign(sig, &context.mweb.output.result.output,
                            range_proof_hash, context.mweb.output.senderKey));

  CX_CHECK(new_blind_switch(blind, context.mweb.output.result.blind, context.mweb.output.value));
  CX_CHECK(sk_add(context.mwebBlindSum, context.mwebBlindSum, blind));

  CX_CHECK(sk_add(context.mwebStealthOffset, context.mweb.output.senderKey, context.mwebStealthOffset));

  return io_send_response_pointer(sig, sizeof(sig), SW_OK);
end:
  return io_send_sw(error);
}
