This is LibSolraXandria, a simple C99 implementation of Twofish and SHA-256, and a portable interface to the local operating system's CSPRNGs. Lua and C++ bindings are also provided.

This library is fairly simple, runs with reasonable speed, uses very little memory, and makes no use whatsoever of the heap. (You are, however, free to allocate its state objects on the heap, rather than in BSS or the stack.)

This library is distributed under the zlib license. This puts very few restrictions on use. See `LICENSE.md` for the complete, very short text of the license.

The C library also includes an implementation of a "secure" RAM erase function, like OpenBSD's `explicit_bzero`. The Lua library also includes a function for computing the binary XOR of two strings.

# Table Of Contents

- [Lua](#Lua)
    - [Installation](#Lua_Installation)
    - [API](#Lua_API)
        - [XOR](#Lua_API_XOR)
        - [Random Data](#Lua_API_Random_Data)
        - [Twofish](#Lua_API_Twofish)
        - [SHA-256](#Lua_API_SHA_256)
- [C](#C)
    - [Installation](#C_Installation)
    - [API](#C_API)
        - [bzero](#C_API_bzero)
        - [Random Data](#C_API_Random_Data)
        - [Twofish](#C_API_Twofish)
        - [SHA-256](#C_API_SHA_256)
            - [Simple](#C_API_SHA_256_Simple)
            - [Normal](#C_API_SHA_256_Normal)
            - [Expert](#C_API_SHA_256_Expert)
- [C++](#CXX)
    - [Installation](#CXX_Installation)
    - [API](#CXX_API)
        - [bzero](#CXX_API_bzero)
        - [Random Data](#CXX_API_Random_Data)
        - [Twofish](#CXX_API_Twofish)
        - [SHA-256](#CXX_API_SHA_256)
            - [Simple](#CXX_API_SHA_256_Simple)
            - [Normal](#CXX_API_SHA_256_Normal)
            - [Expert](#CXX_API_SHA_256_Expert)

# <a name="Lua" />Lua

## <a name="Lua_Installation" />Installation

Install using LuaRocks.

## <a name="Lua_API" />API

    local lsx = require "lsx"

### <a name="Lua_API_XOR" />XOR

    out = lsx.xor(a, b)

`a` and `b` must be strings of identical length. Returns a string of the same length. Each byte of the returned string is equal to the corresponding bytes from `a` and `b` XOR'd together.

This can be used to perform One-Time Pad encryption and decryption.

### <a name="Lua_API_Random_Data" />Random Data

    out = lsx.get_random(count)

Returns a string `count` bytes long, containing data from your local CSPRNG. On UNIX, this is typically `/dev/urandom`. On Windows, this is `RtlGenRandom`. According to some security practices, this data is suitable for ephemeral keys and password salts, but not strong enough for long-lived keys or one-time pads.

    out = lsx.get_extremely_random(count)

Returns a string `count` bytes long, containing data from the strongest local source of randomness available to the library. On UNIX, this is usually `/dev/srandom` or `/dev/random`. On Windows, this is still just `RtlGenRandom`. Where strong randomness is available, it is typically *very* slow to generate in large quantities. 

### <a name="Lua_API_Twofish" />Twofish

    state = lsx.twofish(false) -- uninitialized
    state = lsx.twofish(key) -- initialized

Creates a Twofish state object. If the parameter is `false`, the object is in the uninitialized state, and `setup` must be called before it can be used for anything. Otherwise, the parameter must be a 16-, 24-, or 32-byte string, exactly like the parameter to `setup`.

    state:setup(key)

Initializes a Twofish state object. Any previous state of this object is lost. The parameter must be a 16-, 24-, or 32-byte string, in which case it is a Twofish-128, -192, or -256 key, and the object becomes set up to perform encryption and decryption with that key.

    ciphertext = state:encrypt(plaintext[, start])

Encrypts some plaintext using this context's key. If `start` is provided, it is the one-based index of the first byte of the `plaintext` to encrypt, and 16 bytes will be encrypted. (Negative indices are not allowed.) Otherwise, plaintext must be exactly 16 bytes long, and it is the entire plaintext to encrypt.

A naive approach is to encrypt each 16-byte sequence of the plaintext using the same key. This is a mode of operation known as Electronic Code Book (ECB) mode. This is terribly insecure, as it maintains certain statistical properties of the plaintext. If you were about to implement ECB and consider it adequate, please read up on [block cipher modes of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) before proceeding. (If you wish to use CTR mode instead, this library provides an easy way to do so; see the `ctr` method.)

    plaintext = state:decrypt(ciphertext[, start])

The reverse of `encrypt`.

    output = state:ctr(counter, nonce, input[, start])

Encrypts OR decrypts a block using a straightforward implementation of CTR mode. The `input` and `start` parameters behave the same as the corresponding parameters to `encrypt`/`decrypt`, except that `ctr` can en-/decrypt a block smaller than 16 bytes. If `input` is plaintext, `output` will be ciphertext, and vice versa.

The `counter` parameter must be an integer between 0 and 2^64-1 (or 2^53-1 in Lua 5.2 and earlier). To be effective encryption, each block of output MUST have a different `counter` value. A simple index is sufficient to meet this requirement.

The optional `nonce` parameter is up to 16 bytes of (ideally) random data that is used to modify the counter, which is necessary if the same key will be used with multiple plaintexts. If the nonce is not random, or may be under an attacker's control, it should be 8 bytes in length or shorter.

Technically speaking, the `ctr` function encrypts a 16-byte block of data, where the first 8 bytes come from the nonce, and the last 8 bytes consist of the big-endian `counter` value, added together with the next 8 bytes of the nonce. (Missing nonce bytes are filled in with zeroes.) It then XORs the ciphertext with `input`, producing the `output`.

There is no corresponding function in the C/C++ API, because implementing CTR mode in pure C/C++ is much easier than implementing it in pure Lua.

    state:sanitize()

Makes the object uninitialized, sanitizing any sensitive data under this library's control. This is less important in Lua than it is in C, as there is no way to force the Lua runtime to sanitize the data that you provided to `lsx.twofish`/`state:setup` earlier.

### <a name="Lua_API_SHA_256" />SHA-256

    sum = lsx.sha256_sum(data)
    ... = lsx.sha256_sum(...)

Returns the SHA-256 sums for each parameter, as lowercase hexadecimal strings. Each result will be 64 characters long. 

    sum = lsx.sha256_sum_binary(data)
    ... = lsx.sha256_sum_binary(...)

Returns the SHA-256 sums for each parameter, in "raw" form. Each result will be 32 bytes long.

    state = lsx.sha256()
    state = lsx.sha256(false)
    state = lsx.sha256(true)

Creates a SHA-256 state object. If no parameter is provided, or the parameter is a true value, the object will already be initialized. If the parameter is a false value, you must call `setup` before using the object.

    state:setup()

Puts the given object into the initial state, making it ready to begin processing a message.

    state:input(...)

One after the other, incorporates each parameter into the state.

    result = state:finish()

Finishes the calculation, and returns the result as a 64-character lowercase hexadecimal string. This puts the object into the uninitialized state; you must call `setup` in order to use it again.

    result = state:finish_binary()

As with `finish`, but the result is a 32-byte "raw" string instead.

    state:sanitize()

Makes the object uninitialized, sanitizing any sensitive data under this library's control. This is less important in Lua than it is in C, as there is no way to force the Lua runtime to sanitize the data that you provided to `input` earlier.

    -- if lsx.sha256_sum / lsx.sha256_sum_binary were implemented in Lua, they
    -- would look like this:
    function lsx.sha256_sum(...)
      local arg = {...}
      local ret = {}
      local state = lsx.sha256(false)
      for n=1,#arg do
        state:setup()
        state:input(arg[n])
        ret[n] = state:finish()
      end
      state:sanitize()
      return table.unpack(ret)
    end

# <a name="C" />C

If you are programming in C++, you are strongly recommended to use the C++ interfaces instead of the corresponding C ones. In particular, they use constructor/destructor logic to ensure sensitive data under this library's control is sanitized when all is said and done.

## <a name="C_Installation" />Installation

The included GNU Makefile can be used, with minor modifications, to build a static and dynamic library on most UNIX platforms and on Cygwin/MinGW. It can also run the test suite automatically.

You can, instead, embed the relevant source files directly into your application. If you do so, and your application uses link-time optimization, you must ensure that link-time optimization does not wind up being applied to `lsx_bzero.c`.

## <a name="C_API" />API

    #include "lsx.h"

### <a name="C_API_bzero" />bzero

    lsx_explicit_bzero(ptr, len);

Zeroes `len` bytes, starting at `ptr`, sternly informing the compiler *not* to optimize the operation out.

You should sanitize sensitive data (passwords, keys, etc.) as soon as possible after working with it, using this function. This will help prevent cold boot attacks and some other, now-rare, exploits. As compilers and processors get smarter, this measure gets less effective.

### <a name="C_API_Random_Data" />Random Data

    lsx_get_random(ptr, len);

Returns `len` bytes of data, starting at `ptr`, from your local CSPRNG. On UNIX, this is typically `/dev/urandom`. On Windows, this is `RtlGenRandom`. According to some security practices, this data is suitable for ephemeral keys and password salts, but not strong enough for long-lived keys or one-time pads.

This function will always provide exactly the requested amount of data. If it can't obtain the data, it will **abort execution of your program** by calling `abort`. (The only sane circumstance where this will matter is if you are executing in a chroot that doesn't have a `/dev/urandom` device node, in which case the fix is simple.)

    lsx_get_extremely_random(ptr, len);

Returns `len` bytes of data, starting at `ptr`, from the strongest local source of randomness available to the library. On UNIX, this is usually `/dev/srandom` or `/dev/random`. On Windows, this is still just `RtlGenRandom`. Where strong randomness is available, it is typically *very* slow to generate in large quantities. 

As `lsx_get_random`, this will always either return *exactly* the requested amount of randomness or **abort execution of your program** by calling `abort`.

### <a name="C_API_Twofish" />Twofish

`TWOFISHx_KEYBYTES` and `TWOFISHx_BLOCKBYTES` constants, where x &#8712; {128, 192, 256}, are provided, in case you wish to avoid the use of magic numbers in your code. (All `TWOFISHx_BLOCKBYTES` constants are equal to `TWOFISH_BLOCKBYTES`, since each variant of Twofish differs only in its key setup.)

    struct lsx_twofish_context

A complete Twofish state. The same struct is used for Twofish-128, -192, and -256, but in case you wish to be explicit, `lsx_twofish128_context` and so forth are provided.

Call `lsx_sanitize_twofish` when you're finished with a context! Don't forget to `lsx_explicit_bzero` any other sensitive data as well!

    lsx_setup_twofish128(&ctx, key);
    lsx_setup_twofish192(&ctx, key);
    lsx_setup_twofish256(&ctx, key);

Initializes a context with the given 128-, 192, or 256-bit key.

    lsx_encrypt_twofish(&ctx, plain, cipher);
    lsx_decrypt_twofish(&ctx, cipher, plain);

Encrypts or decrypts a single block of data. It is safe to perform an in-place en-/decryption (where `plain` and `cipher` point to the same block).

The encryption and decryption logic for each variant of Twofish is the same, but `lsx_encrypt_twofish128` and etc. aliases are provided, in case you wish to be explicit.

A naive approach is to encrypt each 16-byte sequence of the plaintext using the same key. This is a mode of operation known as Electronic Code Book (ECB) mode. This is terribly insecure, as it maintains certain statistical properties of the plaintext. If you were about to implement ECB and consider it adequate, please read up on [block cipher modes of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) before proceeding.

    lsx_sanitize_twofish(&ctx);

Sanitizes all data (sensitive or otherwise) in the context. Be sure to call this when you're done with a context, to prevent cold boot attacks and other, now-rare, exploits. Don't forget to also use `lsx_explicit_bzero` on any sensitive data under your control. (This function is actually a macro that calls `lsx_explicit_bzero`.)

The destruction logic for each variant of Twofish is identical, but `lsx_sanitize_twofish128` and etc. aliases are provided, in case you wish to be explicit.

### <a name="C_API_SHA_256" />SHA-256

#### <a name="C_API_SHA_256_Simple" />Simple

    lsx_calculate_sha256(ptr, len, out);

If the entire message is already in memory, and you want to calculate its hash all at once, call this function. The raw SHA-256 hash value (`SHA256_HASHBYTES` = 32 bytes long) will be written starting at `out`.

Often times, reading the entire message into memory at once is unnecessary and inefficient. In those cases, use one of the following interfaces.

#### <a name="C_API_SHA_256_Normal" />Normal

This interface is slightly less efficient than the expert interface, but much easier to use. It is implemented using the expert interface internally, with a small buffer to allow it to give data one chunk at a time.

    struct lsx_sha256_context

A complete SHA-256 state.

Call `lsx_sanitize_sha256` when you're finished with a context! Don't forget to `lsx_explicit_bzero` any other sensitive data as well!

    lsx_setup_sha256(&ctx);

Puts the given context into the initial state, making it ready to begin processing a message.

    lsx_input_sha256(&ctx, buf, len);

Processes `len` bytes of message, starting at `buf`.

    lsx_finish_sha256(&ctx, out);

Finishes the message, calculates the final hash, and writes the raw hash value (`SHA256_HASHBYTES` = 32 bytes long) starting at `out`. This leaves the context in an invalid state, but *does not* erase its contents. Don't forget to call `lsx_sanitize_sha256` when you're finished with the context.

    lsx_sanitize_sha256(&ctx);

Sanitizes all data (sensitive or otherwise) in the context. Be sure to call this when you're done with a context, to prevent cold boot attacks and other, now-rare, exploits. Don't forget to also use `lsx_explicit_bzero` on any sensitive data under your control. (This function is actually a macro that calls `lsx_explicit_bzero`.)

#### <a name="C_API_SHA_256_Expert" />Expert

This interface is more memory efficient than the easy interface, and slightly faster. It is useful if it's already easy to process data in multiples of `SHA256_BLOCKBYTES` = 64 bytes for architectural reasons.

    struct lsx_sha256_expert_context

A complete SHA-256 state.

Call `lsx_sanitize_sha256_expert` when you're finished with a context! Don't forget to `lsx_explicit_bzero` any other sensitive data as well!

    lsx_setup_sha256_expert(&ctx);

Puts the given context into the initial state, making it ready to begin processing a message.

    lsx_input_sha256_expert(&ctx, buf, blockcount);

Processes `blockcount` `SHA256_BLOCKBYTES`-sized blocks, starting at `buf`.

    lsx_finish_sha256_expert(&ctx, final_input, final_length, out);

This function finishes the message, calculates the final hash, and writes the raw hash value (`SHA256_HASHBYTES` = 32 bytes long) starting at `out`. This leaves the context in an invalid state, but *does not* erase its contents. Don't forget to call `lsx_sanitize_sha256` when you're finished with the context.

If `final_length` is nonzero, it is the number of bytes of data (stored at `final_input`) at the end of the message. This value need not be a multiple of `SHA256_BLOCKBYTES`, and can be arbitrarily large or small. If the message was an exact multiple of `SHA256_BLOCKBYTES` long, and all data in the message has already been provided via `lsx_input_sha256_expert`, then `final_length` may be 0 and `final_input` may be NULL.

    lsx_sanitize_sha256_expert(&ctx);

Sanitizes all data (sensitive or otherwise) in the context. Be sure to call this when you're done with a context, to prevent cold boot attacks and other, now-rare, exploits. Don't forget to also use `lsx_explicit_bzero` on any sensitive data under your control. (This function is actually a macro that calls `lsx_explicit_bzero`.)

# <a name="CXX" />C++

Some things do not have a C++ specific binding. In those cases, use the C function. All such things are documented again here, for your convenience.

## <a name="CXX_Installation" />Installation

The included GNU Makefile can be used, with minor modifications, to build a static and dynamic library on most UNIX platforms and on Cygwin/MinGW. It can also run the test suite automatically.

You can, instead, embed the relevant source files directly into your application. If you do so, and your application uses link-time optimization, you must ensure that link-time optimization does not wind up being applied to `lsx_bzero.c`.

## <a name="CXX_API" />API

    #include "lsx.hh"

(note the .hh extension)

### <a name="CXX_API_bzero" />bzero

    lsx_explicit_bzero(ptr, len);

Zeroes `len` bytes, starting at `ptr`, sternly informing the compiler *not* to optimize the operation out.

You should sanitize sensitive data (passwords, keys, etc.) as soon as possible after working with it, using this function. This will help prevent cold boot attacks and some other, now-rare, exploits. As compilers and processors get smarter, this measure gets less effective.

### <a name="CXX_API_Random_Data" />Random Data

    lsx_get_random(ptr, len);

Returns `len` bytes of data, starting at `ptr`, from your local CSPRNG. On UNIX, this is typically `/dev/urandom`. On Windows, this is `RtlGenRandom`. According to some security practices, this data is suitable for ephemeral keys and password salts, but not strong enough for long-lived keys or one-time pads.

This function will always provide exactly the requested amount of data. If it can't obtain the data, it will **abort execution of your program** by calling `abort`. (The only sane circumstance where this will matter is if you are executing in a chroot that doesn't have a `/dev/urandom` device node, in which case the fix is simple.)

    lsx_get_extremely_random(ptr, len);

Returns `len` bytes of data, starting at `ptr`, from the strongest local source of randomness available to the library. On UNIX, this is usually `/dev/srandom` or `/dev/random`. On Windows, this is still just `RtlGenRandom`. Where strong randomness is available, it is typically *very* slow to generate in large quantities. 

As `lsx_get_random`, this will always either return *exactly* the requested amount of randomness or **abort execution of your program** by calling `abort`.

### <a name="CXX_API_Twofish" />Twofish

`TWOFISHx_KEYBYTES` and `TWOFISHx_BLOCKBYTES` constants, where x &#8712; {128, 192, 256}, are provided, in case you wish to avoid the use of magic numbers in your code. (All `TWOFISHx_BLOCKBYTES` constants are equal to `TWOFISH_BLOCKBYTES`, since each variant of Twofish differs only in its key setup.)

    class lsx::twofish_uninitialized
    class lsx::twofish128
    class lsx::twofish192
    class lsx::twofish256

A complete Twofish context. The classes are actually interchangeable. The main difference is in the constructor behavior. `twofish_uninitialized` constructs an uninitialized state, on which you must call `rekey*`. The others require a key as a parameter, and are the same as constructing a `twofish_uninitialized` and calling one of the `rekey*` functions.

Every method returns a reference to `*this`, so calls can be chained.

The context is automatically sanitized when it is destructed.

    context.rekey128(key);
    context.rekey192(key);
    context.rekey256(key);

Initializes a context with the given 128-, 192, or 256-bit key.

    context.encrypt(plain, cipher);
    context.decrypt(cipher, plain);

Encrypts or decrypts a single block of data. It is safe to perform an in-place en-/decryption (where `plain` and `cipher` point to the same block).

A naive approach is to encrypt each 16-byte sequence of the plaintext using the same key. This is a mode of operation known as Electronic Code Book (ECB) mode. This is terribly insecure, as it maintains certain statistical properties of the plaintext. If you were about to implement ECB and consider it adequate, please read up on [block cipher modes of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) before proceeding.

    context.sanitize();

Sanitizes all data (sensitive or otherwise) in the context. Call this when you're temporarily done with a context. The destructor calls it automatically, so if the object leaves scope soon after it is no longer needed, you don't have to worry about this.

#### <a name="CXX_API_SHA_256_Simple" />Simple

    lsx_calculate_sha256(ptr, len, out);

If the entire message is already in memory, and you want to calculate its hash all at once, call this function. The raw SHA-256 hash value (`SHA256_HASHBYTES` = 32 bytes long) will be written starting at `out`.

Often times, reading the entire message into memory at once is unnecessary and inefficient. In those cases, use one of the following interfaces.

#### <a name="CXX_API_SHA_256_Normal" />Normal

This interface is slightly less efficient than the expert interface, but much easier to use. It is implemented using the expert interface internally, with a small buffer to allow it to give data one chunk at a time.

    class lsx::sha256

A complete SHA-256 state. The constructor has an optional boolean parameter, defaulting to `true`. If true, the context is initialized at the beginning-of-memory state. If false, `reinit` must be called explicitly before use.

Every method returns a reference to `*this`, so calls can be chained.

    context.reinit();

Puts the given context into the initial state, making it ready to begin processing a message.

    context.input(buf, len);

Processes `len` bytes of message, starting at `buf`.

    context.finish(out);

Finishes the message, calculates the final hash, and writes the raw hash value (`SHA256_HASHBYTES` = 32 bytes long) starting at `out`. This leaves the context in an invalid state, but *does not* erase its contents. Don't forget to call `sanitize` if this instance of `sha256_expert` is going to sit around unused for a while.

    context.sanitize();

Sanitizes all data (sensitive or otherwise) in the context. Call this when you're temporarily done with a context. The destructor calls it automatically, so if the object leaves scope soon after it is no longer needed, you don't have to worry about this.

Don't forget to also use `lsx_explicit_bzero` on any sensitive data under your control. (This function is actually a macro that calls `lsx_explicit_bzero`.)
 
#### <a name="CXX_API_SHA_256_Expert" />Expert

This interface is more memory efficient than the easy interface, and slightly faster. It is useful if it's already easy to process data in multiples of `SHA256_BLOCKBYTES` = 64 bytes for architectural reasons.

    class lsx::sha256_expert

A complete SHA-256 state. The constructor has an optional boolean parameter, defaulting to `true`. If true, the context is initialized at the beginning-of-memory state. If false, `reinit` must be called explicitly before use.

Every method returns a reference to `*this`, so calls can be chained.

    context.reinit();

Puts the given context into the initial state, making it ready to begin processing a message.

    context.input(buf, blockcount);

Processes `blockcount` `SHA256_BLOCKBYTES`-sized blocks, starting at `buf`.

    context.finish(final_input, final_length, out);

This function finishes the message, calculates the final hash, and writes the raw hash value (`SHA256_HASHBYTES` = 32 bytes long) starting at `out`. This leaves the context in an invalid state, but *does not* erase its contents. Don't forget to call `sanitize` if this instance of `sha256_expert` is going to sit around unused for a while.

If `final_length` is nonzero, it is the number of bytes of data (stored at `final_input`) at the end of the message. This value need not be a multiple of `SHA256_BLOCKBYTES`, and can be arbitrarily large or small. If the message was an exact multiple of `SHA256_BLOCKBYTES` long, and all data in the message has already been provided via `lsx_input_sha256_expert`, then `final_length` may be 0 and `final_input` may be NULL.

    context.sanitize();

Sanitizes all data (sensitive or otherwise) in the context. Call this when you're temporarily done with a context. The destructor calls it automatically, so if the object leaves scope soon after it is no longer needed, you don't have to worry about this.

Don't forget to also use `lsx_explicit_bzero` on any sensitive data under your control. (This function is actually a macro that calls `lsx_explicit_bzero`.)

