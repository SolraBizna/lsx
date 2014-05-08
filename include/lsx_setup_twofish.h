#define k (key_bits / 64)
void paste(lsx_setup_twofish,key_bits)(lsx_twofish_context* ctx, const uint8_t in[16]) {
  uint8_t S[k*4];
  memset(S, 0, sizeof(S));
  for(int i = 0; i < k; ++i) {
#define s (S+(k-i-1)*4)
#define RS_MUL_COLUMN(column, a, b, c, d) \
    if(in[i*8+column]) { \
      uint8_t exp = rs_poly_to_exp[in[i*8+column]-1]; \
      s[0] ^= rs_poly_from_exp[exp + a]; \
      s[1] ^= rs_poly_from_exp[exp + b]; \
      s[2] ^= rs_poly_from_exp[exp + c]; \
      s[3] ^= rs_poly_from_exp[exp + d]; \
    }
    /* multiply by Richard Simmons */
    RS_MUL_COLUMN(0, RS_1_1, RS_2_1, RS_3_1, RS_4_1);
    RS_MUL_COLUMN(1, RS_1_2, RS_2_2, RS_3_2, RS_4_2);
    RS_MUL_COLUMN(2, RS_1_3, RS_2_3, RS_3_3, RS_4_3);
    RS_MUL_COLUMN(3, RS_1_4, RS_2_4, RS_3_4, RS_4_4);
    RS_MUL_COLUMN(4, RS_1_5, RS_2_5, RS_3_5, RS_4_5);
    RS_MUL_COLUMN(5, RS_1_6, RS_2_6, RS_3_6, RS_4_6);
    RS_MUL_COLUMN(6, RS_1_7, RS_2_7, RS_3_7, RS_4_7);
    RS_MUL_COLUMN(7, RS_1_8, RS_2_8, RS_3_8, RS_4_8);
#undef RS_MUL_COLUMN
#undef s
  }
  /* calculate s[...] */
  for(int x = 0; x < 256; ++x) {
    uint32_t rows[4];
    h_top_half(p(x), S, k, 0, rows);
    ctx->s[0][x] = rows[0];
    ctx->s[1][x] = rows[1];
    ctx->s[2][x] = rows[2];
    ctx->s[3][x] = rows[3];
  }
  /* calculate K[0..7] */
  for(int i = 0; i < 4; ++i) {
    uint32_t A = h(p(2*i), in, k, 4);
    uint32_t B = h(p(2*i+1), in+4, k, 4);
    B = rotate_left(B, 8); // avoid calling h twice
    ctx->W[2*i] = A + B;
    ctx->W[2*i+1] = rotate_left(A + (2 * B), 9);
  }
  /* calculate K[8..39] */
  for(int i = 0; i < 16; ++i) {
    uint32_t A = h(p(2*(i+4)), in, k, 4);
    uint32_t B = h(p(2*(i+4)+1), in+4, k, 4);
    B = rotate_left(B, 8); // avoid calling h twice
    ctx->K[2*i] = A + B;
    ctx->K[2*i+1] = rotate_left(A + (2 * B), 9);
  }
}
#undef k

