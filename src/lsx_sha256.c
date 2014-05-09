#include "lsx.h"

#include <string.h> /* memcpy */
#include <assert.h>

/* sha256 is big-endian */
#define bytes_to_word(p) (((uint32_t)(p)[0] << 24) | ((uint32_t)(p)[1] << 16) | ((uint32_t)(p)[2] << 8) | (uint32_t)(p)[3])
#define word_to_bytes(word, p) ((p)[0] = (uint8_t)((word)>>24), (p)[1] = (uint8_t)((word)>>16), (p)[2] = (uint8_t)((word)>>8), (p)[3] = (uint8_t)(word))
#define int64_to_bytes(word, p) ((p)[0] = (uint8_t)((word)>>56), (p)[1] = (uint8_t)((word)>>48), (p)[2] = (uint8_t)((word)>>40), (p)[3] = (uint8_t)((word)>>32), (p)[4] = (uint8_t)((word)>>24), (p)[5] = (uint8_t)((word)>>16), (p)[6] = (uint8_t)((word)>>8), (p)[7] = (uint8_t)(word))

#define rotate_right(a,i) (((a)>>i)|((a)<<(32-i)))
#define rotate_left(a,i) (((a)<<i)|((a)>>(32-i)))

static uint32_t k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void lsx_setup_sha256_expert(lsx_sha256_expert_context* ctx) {
  ctx->h[0] = 0x6a09e667;
  ctx->h[1] = 0xbb67ae85;
  ctx->h[2] = 0x3c6ef372;
  ctx->h[3] = 0xa54ff53a;
  ctx->h[4] = 0x510e527f;
  ctx->h[5] = 0x9b05688c;
  ctx->h[6] = 0x1f83d9ab;
  ctx->h[7] = 0x5be0cd19;
  ctx->bytes_so_far = 0;
}

void lsx_input_sha256_expert(lsx_sha256_expert_context* ctx,
                             const void* _input, size_t blocks) {
  /* these don't get sanitized because I can't bring myself to slow it down
     that much (and needlessly) on register-heavy architectures, so we'll put
     them as low on the stack as possible to improve their odds of being
     stomped */
  uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];
  uint32_t e = ctx->h[4], f = ctx->h[5], g = ctx->h[6], h = ctx->h[7];
  uint32_t s0, s1;
  uint32_t w[64];
  const uint8_t* input = (const uint8_t*)_input;
  ctx->bytes_so_far += blocks * SHA256_BLOCKBYTES;
  while(blocks-- > 0) {
    unsigned i;
    for(i = 0; i < 16; ++i)
      w[i] = bytes_to_word(input + i * 4);
    input += SHA256_BLOCKBYTES;
    for(; i < 64; ++i) {
      s0 = rotate_right(w[i-15],7) ^ rotate_right(w[i-15],18) ^ (w[i-15]>>3);
      s1 = rotate_right(w[i-2],17) ^ rotate_right(w[i-2],19) ^ (w[i-2]>>10);
      w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    for(i = 0; i < 64; ++i) {
      s1 = (rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25))
        + h + ((e & f) ^ (~e & g)) + k[i] + w[i];
      s0 = (rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22))
        + ((a & b) ^ (a & c) ^ (b & c));
      h = g; g = f; f = e; e = d + s1;
      d = c; c = b; b = a; a = s0 + s1;
    }
    ctx->h[0] = (a += ctx->h[0]); ctx->h[1] = (b += ctx->h[1]);
    ctx->h[2] = (c += ctx->h[2]); ctx->h[3] = (d += ctx->h[3]);
    ctx->h[4] = (e += ctx->h[4]); ctx->h[5] = (f += ctx->h[5]);
    ctx->h[6] = (g += ctx->h[6]); ctx->h[7] = (h += ctx->h[7]);
  }
  lsx_explicit_bzero(w, sizeof(w));
}

void lsx_finish_sha256_expert(lsx_sha256_expert_context* ctx,
                              const void* input, size_t bytes,
                              uint8_t out[SHA256_HASHBYTES]) {
  unsigned i;
  uint8_t buf[SHA256_BLOCKBYTES];
  if(bytes >= SHA256_BLOCKBYTES) {
    size_t blocks = bytes / SHA256_BLOCKBYTES;
    lsx_input_sha256_expert(ctx, input, blocks);
    input = (const uint8_t*)input + SHA256_BLOCKBYTES * blocks;
    bytes = bytes - SHA256_BLOCKBYTES * blocks;
  }
  /* assert(bytes < SHA256_BLOCKBYTES) */
  uint64_t actual_bits_out = (ctx->bytes_so_far + bytes) * 8;
  memcpy(buf, input, bytes);
  buf[bytes] = 0x80;
  if(bytes > SHA256_BLOCKBYTES - 9) {
    lsx_explicit_bzero(buf + bytes + 1, 64 - bytes - 1);
    lsx_input_sha256_expert(ctx, buf, 1);
    lsx_explicit_bzero(buf, bytes + 1);
  }
  else {
    lsx_explicit_bzero(buf + bytes + 1, 64 - 8 - bytes - 1);
  }
  int64_to_bytes(actual_bits_out, buf + SHA256_BLOCKBYTES - 8);
  lsx_input_sha256_expert(ctx, buf, 1);
  for(i = 0; i < 8; ++i) {
    word_to_bytes(ctx->h[i], out + i * 4);
  }
  lsx_explicit_bzero(buf, sizeof(buf));
}

void lsx_setup_sha256(lsx_sha256_context* ctx) {
  lsx_setup_sha256_expert(&ctx->expert);
  ctx->num_buffered_bytes = 0;
}

void lsx_input_sha256(lsx_sha256_context* ctx,
                      const void* input, size_t bytes) {
  if(ctx->num_buffered_bytes) {
    size_t bytes_to_add = bytes;
    if(ctx->num_buffered_bytes + bytes_to_add > SHA256_BLOCKBYTES)
      bytes_to_add = SHA256_BLOCKBYTES - ctx->num_buffered_bytes;
    memcpy(ctx->buf + ctx->num_buffered_bytes, input, bytes_to_add);
    ctx->num_buffered_bytes += bytes_to_add;
    bytes -= bytes_to_add;
    input = (const uint8_t*)input + bytes_to_add;
    if(ctx->num_buffered_bytes == SHA256_BLOCKBYTES) {
      lsx_input_sha256_expert(&ctx->expert, ctx->buf, 1);
      ctx->num_buffered_bytes = 0;
    }
  }
  if(bytes >= SHA256_BLOCKBYTES) {
    /* after taking care of any leftover fraction of a block, there was more
       than one full block of data; use it without buffering it first */
    size_t blocks = bytes / SHA256_BLOCKBYTES;
    lsx_input_sha256_expert(&ctx->expert, input, blocks);
    input = (const uint8_t*)input + SHA256_BLOCKBYTES * blocks;
    bytes = bytes - SHA256_BLOCKBYTES * blocks;
  }
  if(bytes > 0) {
    /* we've processed as many blocks as we can, and a fraction of a block is
       still left; buffer it for later */
    assert(ctx->num_buffered_bytes == 0);
    memcpy(ctx->buf, input, (ctx->num_buffered_bytes = bytes));
  }
}

void lsx_finish_sha256(lsx_sha256_context* ctx,
                       uint8_t out[SHA256_HASHBYTES]) {
  lsx_finish_sha256_expert(&ctx->expert,
                           ctx->buf, ctx->num_buffered_bytes,
                           out);
}

void lsx_calculate_sha256(const void* message, size_t bytes,
                          uint8_t out[SHA256_HASHBYTES]) {
  lsx_sha256_expert_context ctx;
  lsx_setup_sha256_expert(&ctx);
  lsx_finish_sha256_expert(&ctx, message, bytes, out);
  lsx_destroy_sha256_expert(&ctx);
}

