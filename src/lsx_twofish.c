/* This isn't exactly a cleanroom implementation. It is based on my own naive
   implementation, cross-bred with the public-domain GPG implementation. -SB */

#include "lsx.h"

#include <string.h>
#include <stdlib.h>

#include "gen/twofish_tables.h"

/* "splat" a byte into a word */
#define p(i) ((uint32_t)(i) | ((uint32_t)(i) << 8) | ((uint32_t)(i) << 16) | ((uint32_t)(i) << 24))

/* twofish is little endian */
#define bytes_to_word(p) ((uint32_t)(p)[0] | ((uint32_t)(p)[1] << 8) | ((uint32_t)(p)[2] << 16) | ((uint32_t)(p)[3] << 24))
#define word_to_bytes(word, p) ((p)[0] = (uint8_t)(word), (p)[1] = (uint8_t)((word)>>8), (p)[2] = (uint8_t)((word)>>16), (p)[3] = (uint8_t)((word)>>24))

#define rotate_right(a,i) (((a)>>i)|((a)<<(32-i)))
#define rotate_left(a,i) (((a)<<i)|((a)>>(32-i)))

#define subpaste(a,b) a##b
#define paste(a,b) subpaste(a,b)

// j is the number of key bytes to skip between words... so, 4 for Me/Mo and
// 0 for S
static inline void h_top_half(uint32_t X, const uint8_t* l, int k, int j, uint32_t o[4]) {
  uint8_t x[4];
  word_to_bytes(X, x);
  switch(k) {
  default:
    abort(); /* NOTREACHED; k is either 2, 3, or 4 */
  case 4:
    x[0] = q1[x[0]] ^ l[12 + j * 3];
    x[1] = q0[x[1]] ^ l[13 + j * 3];
    x[2] = q0[x[2]] ^ l[14 + j * 3];
    x[3] = q1[x[3]] ^ l[15 + j * 3];
  case 3:
    x[0] = q1[x[0]] ^ l[8 + j * 2];
    x[1] = q1[x[1]] ^ l[9 + j * 2];
    x[2] = q0[x[2]] ^ l[10 + j * 2];
    x[3] = q0[x[3]] ^ l[11 + j * 2];
  case 2:
    o[0] = mdsq[0][q0[q0[x[0]] ^ l[4 + j]] ^ l[0]];
    o[1] = mdsq[1][q0[q1[x[1]] ^ l[5 + j]] ^ l[1]];
    o[2] = mdsq[2][q1[q0[x[2]] ^ l[6 + j]] ^ l[2]];
    o[3] = mdsq[3][q1[q1[x[3]] ^ l[7 + j]] ^ l[3]];
  }
}

static inline uint32_t h(uint32_t X, const uint8_t* L, int k, int j) {
  uint32_t x[4];
  h_top_half(X, L, k, j, x);
  return x[0] ^ x[1] ^ x[2] ^ x[3];
}

#define key_bits 128
#include "lsx_setup_twofish.h"
#undef key_bits
#define key_bits 192
#include "lsx_setup_twofish.h"
#undef key_bits
#define key_bits 256
#include "lsx_setup_twofish.h"
#undef key_bits

static inline uint32_t g(lsx_twofish_context* ctx, uint32_t input) {
  uint8_t x[4];
  word_to_bytes(input, x);
  uint32_t y[4] = {ctx->s[0][x[0]], ctx->s[1][x[1]], ctx->s[2][x[2]], ctx->s[3][x[3]]};
  return y[0] ^ y[1] ^ y[2] ^ y[3];
}

void lsx_encrypt_twofish(lsx_twofish_context* ctx,
                         const uint8_t in[16], uint8_t out[16]) {
  unsigned round;
  /* whiten input */
  uint32_t R0 = bytes_to_word(in) ^ ctx->W[0];
  uint32_t R1 = bytes_to_word(in+4) ^ ctx->W[1];
  uint32_t R2 = bytes_to_word(in+8) ^ ctx->W[2];
  uint32_t R3 = bytes_to_word(in+12) ^ ctx->W[3];
  /* round function */
  for(round = 0; round < 16; round += 2) {
    uint32_t Fr0, Fr1, T0, T1;
#define F(R0, R1, round, F0, F1) \
    T0 = g(ctx, R0); T1 = g(ctx, rotate_left(R1,8)); \
    F0 = T0 + T1 + ctx->K[(round)*2]; \
    F1 = T0 + 2 * T1 + ctx->K[(round)*2+1];
    F(R0, R1, round, Fr0, Fr1);
    R2 = rotate_right(R2^Fr0, 1);
    R3 = rotate_left(R3, 1) ^ Fr1;
    F(R2, R3, round+1, Fr0, Fr1);
    R0 = rotate_right(R0^Fr0, 1);
    R1 = rotate_left(R1, 1) ^ Fr1;
  }
  /* whiten output */
  R2 ^= ctx->W[4]; R3 ^= ctx->W[5]; R0 ^= ctx->W[6]; R1 ^= ctx->W[7];
  word_to_bytes(R2, out);
  word_to_bytes(R3, out+4);
  word_to_bytes(R0, out+8);
  word_to_bytes(R1, out+12);
}

void lsx_decrypt_twofish(lsx_twofish_context* ctx,
                         const uint8_t in[16], uint8_t out[16]) {
  int round;
  /* whiten input */
  uint32_t R2 = bytes_to_word(in) ^ ctx->W[4];
  uint32_t R3 = bytes_to_word(in+4) ^ ctx->W[5];
  uint32_t R0 = bytes_to_word(in+8) ^ ctx->W[6];
  uint32_t R1 = bytes_to_word(in+12) ^ ctx->W[7];
  /* round function */
  for(round = 14; round >= 0; round -= 2) {
    uint32_t Fr0, Fr1, T0, T1;
#define F_(R0, R1, round, F0, F1) \
    T0 = g(ctx, R0); T1 = g(ctx, rotate_left(R1,8)); \
    F0 = T0 + T1 + ctx->K[(round)*2]; \
    F1 = T0 + 2 * T1 + ctx->K[(round)*2+1];
    F_(R2, R3, round+1, Fr0, Fr1);
    R0 = rotate_left(R0, 1) ^ Fr0;
    R1 = rotate_right(R1^Fr1, 1);
    F_(R0, R1, round, Fr0, Fr1);
    R2 = rotate_left(R2, 1) ^ Fr0;
    R3 = rotate_right(R3^Fr1, 1);
  }
  /* whiten output */
  R0 ^= ctx->W[0]; R1 ^= ctx->W[1]; R2 ^= ctx->W[2]; R3 ^= ctx->W[3];
  word_to_bytes(R0, out);
  word_to_bytes(R1, out+4);
  word_to_bytes(R2, out+8);
  word_to_bytes(R3, out+12);
}

