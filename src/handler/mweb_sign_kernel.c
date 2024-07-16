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

#include "../mweb/kernel.h"

#define FEE_FEATURE_BIT 0x01
#define PEGIN_FEATURE_BIT 0x02
#define PEGOUT_FEATURE_BIT 0x04
#define HEIGHT_LOCK_FEATURE_BIT 0x08
#define STEALTH_EXCESS_FEATURE_BIT 0x10

bool buffer_read(buffer_t *buffer, uint8_t *out, size_t out_len) {
  if (buffer->size - buffer->offset < out_len) {
    return false;
  }
  memcpy(out, buffer->ptr + buffer->offset, out_len);
  return buffer_seek_cur(buffer, out_len);
}

static cx_err_t hash_varint(uint64_t n) {
  uint8_t buf[10];
  int len = 0;
  cx_err_t error;

  while (true) {
    buf[len] = (n & 0x7F) | (len ? 0x80 : 0x00);
    if (n <= 0x7F) break;
    n = (n >> 7) - 1;
    len++;
  }
  do {
    CX_CHECK(blake3_update(&buf[len], 1));
  } while (len--);
end:
  return error;
}

unsigned short handler_mweb_sign_kernel(buffer_t *buffer, bool start) {
  uint8_t features = STEALTH_EXCESS_FEATURE_BIT;
  cx_err_t error;

  if (start) {
    if (!buffer_read_u64(buffer, &context.mweb.kernel.fee, LE)) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    if (!buffer_read_u64(buffer, &context.mweb.kernel.pegin, LE)) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    if (!buffer_read_u32(buffer, &context.mweb.kernel.pegouts, LE)) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }
    if (!buffer_read_u32(buffer, &context.mweb.kernel.lockHeight, LE)) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    if (context.mweb.kernel.fee) features |= FEE_FEATURE_BIT;
    if (context.mweb.kernel.pegin) features |= PEGIN_FEATURE_BIT;
    if (context.mweb.kernel.pegouts) features |= PEGOUT_FEATURE_BIT;
    if (context.mweb.kernel.lockHeight) features |= HEIGHT_LOCK_FEATURE_BIT;
    CX_CHECK(blake3_update(&features, 1));

    cx_rng(context.mweb.kernel.offset, sizeof(blinding_factor_t));
    CX_CHECK(sk_sub(context.mwebKernelBlind, context.mwebKernelBlind, context.mweb.kernel.offset));

    commitment_t kernelExcess;
    CX_CHECK(new_commit(kernelExcess, NULL, context.mwebKernelBlind, 0));
    CX_CHECK(blake3_update(kernelExcess, sizeof(kernelExcess)));

    if (context.mweb.kernel.fee) {
      CX_CHECK(hash_varint(context.mweb.kernel.fee));
    }
    if (context.mweb.kernel.pegin) {
      CX_CHECK(hash_varint(context.mweb.kernel.pegin));
    }
    if (context.mweb.kernel.pegouts) {
      CX_CHECK(blake3_update(&context.mweb.kernel.pegouts, 1));
      return io_send_sw(SW_OK);
    }
    goto pegouts_done;

  } else {
    uint64_t value;
    uint8_t scriptLen = buffer->size - 8;

    if (!buffer_read_u64(buffer, &value, LE)) {
      return io_send_sw(SW_INCORRECT_LENGTH);
    }

    CX_CHECK(hash_varint(value));
    CX_CHECK(blake3_update(&scriptLen, 1));
    CX_CHECK(blake3_update(buffer->ptr + 8, scriptLen));

    if (--context.mweb.kernel.pegouts) {
      return io_send_sw(SW_OK);
    }

pegouts_done:
    if (context.mweb.kernel.lockHeight) {
      CX_CHECK(hash_varint(context.mweb.kernel.lockHeight));
    }

    blinding_factor_t stealthBlind;
    struct {
      blinding_factor_t kernelOffset;
      blinding_factor_t stealthOffset;
      commitment_t kernelExcess;
      public_key_t stealthExcess;
      signature_t sig;
    } result;

    cx_rng(stealthBlind, sizeof(stealthBlind));
    CX_CHECK(sk_sub(result.stealthOffset, context.mwebStealthOffset, stealthBlind));
    memcpy(result.kernelOffset, context.mweb.kernel.offset, sizeof(result.kernelOffset));

    CX_CHECK(new_commit(result.kernelExcess, NULL, context.mwebKernelBlind, 0));
    CX_CHECK(sign_mweb_kernel(context.mwebKernelBlind, stealthBlind, result.stealthExcess, result.sig));

    return io_send_response_pointer((uint8_t*)&result, sizeof(result), SW_OK);
  }

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
