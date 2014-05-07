#ifndef LSX_H
#define LSX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/*** TWOFISH ***/

typedef struct lsx_twofish_key {
  /* The S-boxes, composed with the MDS matrix */
  uint32_t s[4][256];
  /* The "whitening" subkeys */
  uint32_t W[8];
  /* The round subkeys */
  uint32_t K[32];
} lsx_twofish_key;

/* Calculate the key-dependent data for 128-, 192-, and 256-bit Twofish. */
extern void lsx_setup_twofish128(lsx_twofish_key* out, const uint8_t in[16]);
extern void lsx_setup_twofish192(lsx_twofish_key* out, const uint8_t in[24]);
extern void lsx_setup_twofish256(lsx_twofish_key* out, const uint8_t in[32]);

/* Encrypt/decrypt a block with the given key-dependent data.
   Note: in and out may safely point to the same memory. */
extern void lsx_encrypt_twofish(lsx_twofish_key* key,
                                const uint8_t in[16], uint8_t out[16]);
extern void lsx_decrypt_twofish(lsx_twofish_key* key,
                                const uint8_t in[16], uint8_t out[16]);

/* Convenience function to destroy key-dependent data. */
extern void lsx_destroy_twofish(lsx_twofish_key* key);
#define lsx_destroy_twofish128 lsx_destroy_twofish
#define lsx_destroy_twofish192 lsx_destroy_twofish
#define lsx_destroy_twofish256 lsx_destroy_twofish

/*** SHA-256 ***/



#ifdef __cplusplus
}
#endif

#endif /* LSX_H */
