#include "output.h"

#define MWEB_OUTPUT_MESSAGE_STANDARD_FIELDS_FEATURE_BIT 1

cx_err_t mweb_output_create(mweb_output_t *output,
    blinding_factor_t blind, secret_key_t t,
    blinding_factor_t blind_switch, uint64_t v,
    const uint8_t *pA, const uint8_t *pB,
    const secret_key_t sender_key)
{
    hash_t h;
    uint8_t n[16], pt[65];
    cx_err_t error;

    // We only support standard feature fields for now
    output->message.features = MWEB_OUTPUT_MESSAGE_STANDARD_FIELDS_FEATURE_BIT;

    // Generate 128-bit secret nonce 'n' = Hash128(T_nonce, sender_privkey)
    CX_CHECK(blake3_init());
    CX_CHECK(blake3_update("N", 1));
    CX_CHECK(blake3_update(sender_key, sizeof(secret_key_t)));
    CX_CHECK(blake3_final(h, false));
    memcpy(n, h, sizeof(n));

    // Calculate unique sending key 's' = H(T_send, A, B, v, n)
    CX_CHECK(blake3_init());
    CX_CHECK(blake3_update("S", 1));
    CX_CHECK(blake3_update_pubkey(pA));
    CX_CHECK(blake3_update_pubkey(pB));
    CX_CHECK(blake3_update(&v, sizeof(v)));
    CX_CHECK(blake3_update(n, sizeof(n)));
    CX_CHECK(blake3_final(h, true));

    // Key exchange public key 'Ke' = s*B
    memcpy(pt, pB, sizeof(pt));
    CX_CHECK(cx_ecfp_scalar_mult_no_throw(CX_CURVE_256K1, pt, h, 32));
    compress_pubkey(output->message.key_exchange_pubkey, pt);

    // Derive shared secret 't' = H(T_derive, s*A)
    memcpy(pt, pA, sizeof(pt));
    CX_CHECK(cx_ecfp_scalar_mult_no_throw(CX_CURVE_256K1, pt, h, 32));
    CX_CHECK(blake3_init());
    CX_CHECK(blake3_update("D", 1));
    CX_CHECK(blake3_update_pubkey(pt));
    CX_CHECK(blake3_final(t, false));

    // Derive view tag as first byte of H(T_tag, s*A)
    CX_CHECK(blake3_init());
    CX_CHECK(blake3_update("T", 1));
    CX_CHECK(blake3_update_pubkey(pt));
    CX_CHECK(blake3_final(h, false));
    output->message.view_tag = h[0];

    // Construct one-time public key for receiver 'Ko' = H(T_outkey, t)*B
    CX_CHECK(blake3_init());
    CX_CHECK(blake3_update("O", 1));
    CX_CHECK(blake3_update(t, sizeof(secret_key_t)));
    CX_CHECK(blake3_final(h, true));
    memcpy(pt, pB, sizeof(pt));
    CX_CHECK(cx_ecfp_scalar_mult_no_throw(CX_CURVE_256K1, pt, h, 32));
    compress_pubkey(output->receiver_pubkey, pt);

    // Calc blinding factor and mask nonce and amount
    CX_CHECK(blake3_init());
    CX_CHECK(blake3_update("B", 1));
    CX_CHECK(blake3_update(t, sizeof(secret_key_t)));
    CX_CHECK(blake3_final(blind, true));

    CX_CHECK(blake3_init());
    CX_CHECK(blake3_update("Y", 1));
    CX_CHECK(blake3_update(t, sizeof(secret_key_t)));
    CX_CHECK(blake3_final(h, false));
    for (size_t i = 0; i < sizeof(v); i++) {
        output->message.masked_value[i] = (v >> i*8 & 0xFF) ^ h[i];
    }

    CX_CHECK(blake3_init());
    CX_CHECK(blake3_update("X", 1));
    CX_CHECK(blake3_update(t, sizeof(secret_key_t)));
    CX_CHECK(blake3_final(h, false));
    for (size_t i = 0; i < sizeof(n); i++) {
        output->message.masked_nonce[i] = n[i] ^ h[i];
    }

    // Commitment 'C' = r*G + v*H
    CX_CHECK(new_blind_switch(blind_switch, blind, v));
    CX_CHECK(new_commit(output->commit, NULL, blind_switch, v));

    // Calculate the ephemeral send pubkey 'Ks' = ks*G
    CX_CHECK(sk_pub(output->sender_pubkey, sender_key));
end:
    return error;
}

cx_err_t mweb_output_sign(signature_t sig, const mweb_output_t *output,
    const hash_t range_proof_hash, const secret_key_t sender_key)
{
    hash_t hash;
    cx_err_t error;

    CX_CHECK(blake3_init());
    CX_CHECK(blake3_update(&output->message, sizeof(mweb_output_message_t)));
    CX_CHECK(blake3_final(hash, false));

    CX_CHECK(blake3_init());
    CX_CHECK(blake3_update(output->commit, sizeof(commitment_t)));
    CX_CHECK(blake3_update(output->sender_pubkey, sizeof(public_key_t)));
    CX_CHECK(blake3_update(output->receiver_pubkey, sizeof(public_key_t)));
    CX_CHECK(blake3_update(hash, sizeof(hash_t)));
    CX_CHECK(blake3_update(range_proof_hash, sizeof(hash_t)));
    CX_CHECK(blake3_final(hash, false));
    CX_CHECK(mweb_sign(sig, sender_key, hash));
end:
    return error;
}
