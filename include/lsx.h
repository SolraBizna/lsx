#ifndef LSX_H
#define LSX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h> /* for size_t */
#include <stdint.h> /* for uintX_t */

/* Why is this not present on all OSes? */
extern void lsx_explicit_bzero(void* p, size_t n);

/* This is not ideal for generation of long-lived keys. */
extern void lsx_get_random(void* p, size_t n);

/*** TWOFISH ***/

/* Defines for people to use if they're nice */
#define TWOFISH128_KEYBYTES 16
#define TWOFISH192_KEYBYTES 24
#define TWOFISH256_KEYBYTES 32

#define TWOFISH_BLOCKBYTES 16
#define TWOFISH128_BLOCKBYTES TWOFISH_BLOCKBYTES
#define TWOFISH192_BLOCKBYTES TWOFISH_BLOCKBYTES
#define TWOFISH256_BLOCKBYTES TWOFISH_BLOCKBYTES

/* The key-dependent S-boxes and subkeys for a given Twofish key */
/* The same structure is used for all three Twofish variants, but convenience
   macros exist in case programmers want to be more explicit */
typedef struct lsx_twofish_context {
  /* The S-boxes, composed with the MDS matrix */
  uint32_t s[4][256];
  /* The "whitening" subkeys */
  uint32_t W[8];
  /* The round subkeys */
  uint32_t K[32];
} lsx_twofish_context;
#define lsx_twofish128_context lsx_twofish_context
#define lsx_twofish192_context lsx_twofish_context
#define lsx_twofish256_context lsx_twofish_context

/* Calculate the key-dependent data for 128-, 192-, and 256-bit Twofish. */
extern void lsx_setup_twofish128(lsx_twofish_context* ctx,
                                 const uint8_t in[TWOFISH128_KEYBYTES]);
extern void lsx_setup_twofish192(lsx_twofish_context* ctx,
                                 const uint8_t in[TWOFISH192_KEYBYTES]);
extern void lsx_setup_twofish256(lsx_twofish_context* ctx,
                                 const uint8_t in[TWOFISH256_KEYBYTES]);

/* Encrypt/decrypt a block with the given key-dependent data.
   Note: in and out may safely point to the same memory. */
extern void lsx_encrypt_twofish(lsx_twofish_context* ctx,
                                const uint8_t in[TWOFISH_BLOCKBYTES],
                                uint8_t out[TWOFISH_BLOCKBYTES]);
#define lsx_encrypt_twofish128 lsx_encrypt_twofish
#define lsx_encrypt_twofish192 lsx_encrypt_twofish
#define lsx_encrypt_twofish256 lsx_encrypt_twofish
extern void lsx_decrypt_twofish(lsx_twofish_context* ctx,
                                const uint8_t in[TWOFISH_BLOCKBYTES],
                                uint8_t out[TWOFISH_BLOCKBYTES]);
#define lsx_decrypt_twofish128 lsx_decrypt_twofish
#define lsx_decrypt_twofish192 lsx_decrypt_twofish
#define lsx_decrypt_twofish256 lsx_decrypt_twofish

/* Convenience function to destroy key-dependent data. When you're finished
   with a context, you should either call this on it or re-use it immediately
   for a different key. */
#define lsx_destroy_twofish(ctx) lsx_explicit_bzero(ctx, sizeof(*(ctx)))
#define lsx_destroy_twofish128 lsx_destroy_twofish
#define lsx_destroy_twofish192 lsx_destroy_twofish
#define lsx_destroy_twofish256 lsx_destroy_twofish

/*** SHA-256 ***/

/* Defines for people to use if they're nice */
#define SHA256_HASHBYTES 32
/* You add data to the message in units of BLOCKBYTES. */
#define SHA256_BLOCKBYTES 64

/* This is the "expert" interface for LSX's SHA-256 implementation. Scroll down
   for an interface that's easier to use. */
/* The internal state for a given message */
typedef struct lsx_sha256_expert_context {
  uint32_t h[8];
  uint64_t bytes_so_far;
} lsx_sha256_expert_context;
/* Set up the initial state */
extern void lsx_setup_sha256_expert(lsx_sha256_expert_context* ctx);
/* Add complete blocks of message data
   (number of bytes = `SHA256_BLOCKBYTES` * `blocks`) */
extern void lsx_input_sha256_expert(lsx_sha256_expert_context* ctx,
                                    const void* input, size_t blocks);
/* Add any remaining data and compute the hash.
   This leaves `ctx` in an unusable state. Call `lsx_setup_sha256_expert` on it
   if you want to use it again, or `lsx_destroy_sha256_expert` if you don't. */
extern void lsx_finish_sha256_expert(lsx_sha256_expert_context* ctx,
                                     const void* input, size_t bytes,
                                     uint8_t out[SHA256_HASHBYTES]);
/* Convenience function to destroy any remaining important data. */
#define lsx_destroy_sha256_expert(ctx) lsx_explicit_bzero(ctx, sizeof(*(ctx)))

/* This is the easy interface. It's a thin layer on the above. If all you want
   to do is hash a complete message in memory, there's an even easier interface
   farther down. */
typedef struct lsx_sha256_context {
  lsx_sha256_expert_context expert;
  uint8_t buf[SHA256_BLOCKBYTES];
  unsigned int num_buffered_bytes;
} lsx_sha256_context;
/* Set up the initial state */
extern void lsx_setup_sha256(lsx_sha256_context* ctx);
/* Add message data */
extern void lsx_input_sha256(lsx_sha256_context* ctx,
                             const void* input, size_t bytes);
/* Calculate the hash.
   This leaves `ctx` in an unusable state. Call `lsx_setup_sha256` on it
   if you want to use it again, or `lsx_destroy_sha256` if you don't. */
extern void lsx_finish_sha256(lsx_sha256_context* ctx,
                              uint8_t out[SHA256_HASHBYTES]);
/* Convenience function to destroy any remaining important data. */
#define lsx_destroy_sha256(ctx) lsx_explicit_bzero(ctx, sizeof(*(ctx)))

/* This is the easiest interface. If your message does not already reside
   entirely in memory, or if it is particularly long, please use one of the
   above interfaces instead of reading it all in at once. */
extern void lsx_calculate_sha256(const void* message, size_t bytes,
                                 uint8_t out[SHA256_HASHBYTES]);

/*** SRP-6a ***/
/* TODO */

#ifdef __cplusplus
}
#endif

#endif /* LSX_H */
