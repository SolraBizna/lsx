#ifndef LSX_HH
#define LSX_HH

/* This is the preferred way to use LSX from C++. */

#include "lsx.h"

namespace lsx {
  /*** TWOFISH ***/
  /* All variants of Twofish are identical except for the key schedule.
     There are two ways to use this interface:
     1. Instantiate a `twofish_uninitialized` and manually ensure that you
        `rekey*()` and `sanitize()` as needed
     OR
     2. Instantiate a `twofish128`/`twofish192`/`twofish256` and let C++ do all
        the work for you
     Either way, when the instance is destructed, it is sanitized.
     You can explicitly `rekey*()`/`sanitize()` no matter which class you
     instantiate if you really want to. */
  class twofish : protected lsx_twofish_context {
  protected:
    inline twofish() {}
  public:
    static const unsigned block_bytes = TWOFISH_BLOCKBYTES;
    inline ~twofish() { sanitize(); }
    inline twofish& encrypt(const uint8_t in[TWOFISH_BLOCKBYTES],
                        uint8_t out[TWOFISH_BLOCKBYTES]) {
      lsx_encrypt_twofish(this, in, out);
      return *this;
    }
    inline twofish& decrypt(const uint8_t in[TWOFISH_BLOCKBYTES],
                        uint8_t out[TWOFISH_BLOCKBYTES]) {
      lsx_decrypt_twofish(this, in, out);
      return *this;
    }
    inline twofish& rekey128(const uint8_t key[TWOFISH128_KEYBYTES]) {
      lsx_setup_twofish128(this, key);
      return *this;
    }
    inline twofish& rekey192(const uint8_t key[TWOFISH192_KEYBYTES]) {
      lsx_setup_twofish192(this, key);
      return *this;
    }
    inline twofish& rekey256(const uint8_t key[TWOFISH256_KEYBYTES]) {
      lsx_setup_twofish256(this, key);
      return *this;
    }
    /* This is explicitly called by the destructor, so you don't need to call
       it unless the instance will outlive the usefulness of the current key */
    inline twofish& sanitize() {
      lsx_destroy_twofish(this);
      return *this;
    }
  };
  class twofish128 : public twofish {
  public:
    static const unsigned KEY_BYTES = TWOFISH128_KEYBYTES;
    inline twofish128(const uint8_t key[KEY_BYTES]) {
      rekey128(key);
    }
  };
  class twofish192 : public twofish {
  public:
    static const unsigned KEY_BYTES = TWOFISH192_KEYBYTES;
    inline twofish192(const uint8_t key[KEY_BYTES]) {
      rekey192(key);
    }
  };
  class twofish256 : public twofish {
  public:
    static const unsigned KEY_BYTES = TWOFISH256_KEYBYTES;
    inline twofish256(const uint8_t key[KEY_BYTES]) {
      rekey256(key);
    }
  };
  class twofish_uninitialized : public twofish {
  public:
    inline twofish_uninitialized() {}
  };
  /*** SHA-256 ***/
  /* "expert" interface: provide all data but the terminating data in blocks */
  class sha256_expert : protected lsx_sha256_expert_context {
  public:
    static const unsigned block_bytes = SHA256_BLOCKBYTES;
    static const unsigned hash_bytes = SHA256_HASHBYTES;
    inline sha256_expert(bool initialize = true) {
      if(initialize) reinit();
    }
    inline ~sha256_expert() { sanitize(); }
    /* Add complete blocks of message data
       (number of bytes = `block_bytes` * blocks */
    inline sha256_expert& input(const void* input, size_t blocks) {
      lsx_input_sha256_expert(this, input, blocks);
      return *this;
    }
    /* Add any remaining data and compute the hash.
       This leaves the instance in an unusable state. Call `reinit` on it if
       you want to use it again before destruction. */
    inline sha256_expert& finish(uint8_t out[hash_bytes],
                                 const void* input = nullptr,
                                 size_t bytes = 0) {
      lsx_finish_sha256_expert(this, input, bytes, out);
      return *this;
    }
    /* Initialize the instance for a new message. */
    inline sha256_expert& reinit() {
      lsx_setup_sha256_expert(this);
      return *this;
    }
    /* This is explicitly called by the destructor, so you don't need to call
       it unless the instance will continue existing. */
    inline sha256_expert& sanitize() {
      lsx_destroy_sha256_expert(this);
      return *this;
    }
  };
  /* easy interface; provide message data in any quantities you want */
  class sha256 : protected lsx_sha256_context {
  public:
    static const unsigned block_bytes = SHA256_BLOCKBYTES;
    static const unsigned hash_bytes = SHA256_HASHBYTES;
    inline sha256(bool initialize = true) {
      if(initialize) reinit();
    }
    inline ~sha256() { sanitize(); }
    /* Add message data */
    inline sha256& input(const void* input, size_t bytes) {
      lsx_input_sha256(this, input, bytes);
      return *this;
    }
    /* Compute the hash.
       This leaves the instance in an unusable state. Call `reinit` on it if
       you want to use it again before destruction. */
    inline sha256& finish(uint8_t out[hash_bytes]) {
      lsx_finish_sha256(this, out);
      return *this;
    }
    /* Initialize the instance for a new message. */
    inline sha256& reinit() {
      lsx_setup_sha256(this);
      return *this;
    }
    /* This is explicitly called by the destructor, so you don't need to call
       it unless the instance will continue existing. */
    inline sha256& sanitize() {
      lsx_destroy_sha256(this);
      return *this;
    }
    /* "lazy" interface; pass in all message data at once */
    static inline void sum(const void* message, size_t bytes,
                           uint8_t out[hash_bytes]) {
      lsx_calculate_sha256(message, bytes, out);
    }
  };
}

#endif
