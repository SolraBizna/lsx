#include "lsx.h"

#include <lua.h>
#include <lauxlib.h>
#include <string.h>

#if LUA_VERSION_NUM < 502
#define lua_rawlen lua_objlen
#endif

/* used to mark uninitialized Twofish contexts */
#define DESTROYED_MDS_RESULT 0
/* used to mark uninitialized SHA-256 contexts */
#define IMPOSSIBLE_BYTES_OUT (~(uint64_t)0)

#define bytes_to_int64(p) (((uint64_t)(p)[0] << 56) | ((uint64_t)(p)[1] << 48) | ((uint64_t)(p)[2] << 40) | ((uint64_t)(p)[3] << 32) | ((uint64_t)(p)[4] << 24) | ((uint64_t)(p)[5] << 16) | ((uint64_t)(p)[6] << 8) | (uint64_t)(p)[7])
#define int64_to_bytes(word, p) ((p)[0] = (uint8_t)(word), (p)[1] = (uint8_t)((word)>>8), (p)[2] = (uint8_t)((word)>>16), (p)[3] = (uint8_t)((word)>>24), (p)[4] = (uint8_t)((word)>>32), (p)[5] = (uint8_t)((word)>>40), (p)[6] = (uint8_t)((word)>>48), (p)[7] = (uint8_t)((word)>>56))

static const char digits[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

static int f_sha256_sum(lua_State* L) {
  unsigned n, i;
  unsigned argcount = lua_gettop(L);
  for(n = 1; n <= argcount; ++n) {
    size_t length;
    const char* message = luaL_checklstring(L, n, &length);
    uint8_t hash[SHA256_HASHBYTES];
    lsx_calculate_sha256(message, length, hash);
    char buf[SHA256_HASHBYTES*2];
    for(i = 0; i < SHA256_HASHBYTES; ++i) {
      buf[i*2] = digits[hash[i]>>4];
      buf[i*2+1] = digits[hash[i]&15];
    }
    lua_pushlstring(L, buf, sizeof(buf));
  }
  return argcount;
}

static int f_sha256_sum_binary(lua_State* L) {
  unsigned n, i;
  unsigned argcount = lua_gettop(L);
  for(n = 1; n <= argcount; ++n) {
    size_t length;
    const char* message = luaL_checklstring(L, n, &length);
    uint8_t hash[SHA256_HASHBYTES];
    lsx_calculate_sha256(message, length, hash);
    lua_pushlstring(L, hash, sizeof(hash));
  }
  return argcount;
}

static int f_sha256_setup(lua_State* L) {
  lsx_sha256_context* ctx = (lsx_sha256_context*)luaL_checkudata(L, 1, "lsx_sha256_context");
  lsx_setup_sha256(ctx);
  return 0;
}

static int f_sha256_input(lua_State* L) {
  lsx_sha256_context* ctx = (lsx_sha256_context*)luaL_checkudata(L, 1, "lsx_sha256_context");
  unsigned n;
  if(ctx->expert.bytes_so_far == IMPOSSIBLE_BYTES_OUT) return luaL_error(L, "lsx_sha256_context not currently initalized; you must call :setup() at the beginning of every message");
  for(n = 2; n <= lua_gettop(L); ++n) {
    size_t length;
    const char* input = luaL_checklstring(L, n, &length);
    lsx_input_sha256(ctx, input, length);
  }
  return 0;
}

static int f_sha256_finish(lua_State* L) {
  lsx_sha256_context* ctx = (lsx_sha256_context*)luaL_checkudata(L, 1, "lsx_sha256_context");
  uint8_t hash[SHA256_HASHBYTES];
  unsigned i;
  if(ctx->expert.bytes_so_far == IMPOSSIBLE_BYTES_OUT) return luaL_error(L, "lsx_sha256_context not currently initalized; you must call :setup() at the beginning of every message");
  lsx_finish_sha256(ctx, hash);
  char buf[SHA256_HASHBYTES*2];
  for(i = 0; i < SHA256_HASHBYTES; ++i) {
    buf[i*2] = digits[hash[i]>>4];
    buf[i*2+1] = digits[hash[i]&15];
  }
  lua_pushlstring(L, buf, sizeof(buf));
  ctx->expert.bytes_so_far = IMPOSSIBLE_BYTES_OUT;
  return 1;
}

static int f_sha256_finish_binary(lua_State* L) {
  lsx_sha256_context* ctx = (lsx_sha256_context*)luaL_checkudata(L, 1, "lsx_sha256_context");
  uint8_t hash[SHA256_HASHBYTES];
  if(ctx->expert.bytes_so_far == IMPOSSIBLE_BYTES_OUT) return luaL_error(L, "context not currently initalized; you must call :setup() at the beginning of every message");
  lsx_finish_sha256(ctx, hash);
  lua_pushlstring(L, hash, sizeof(hash));
  ctx->expert.bytes_so_far = IMPOSSIBLE_BYTES_OUT;
  return 1;
}

static int f_sha256_destroy(lua_State* L) {
  lsx_sha256_context* ctx = (lsx_sha256_context*)luaL_checkudata(L, 1, "lsx_sha256_context");
  lsx_destroy_sha256(ctx);
  return 0;
}

static const struct luaL_Reg sha256_methods[] = {
  {"setup",f_sha256_setup},
  {"input",f_sha256_input},
  {"finish",f_sha256_finish},
  {"finish_binary",f_sha256_finish_binary},
  {"destroy",f_sha256_destroy}, // this is a bit pointless, isn't it?
  {NULL, NULL},
};

static int f_sha256(lua_State* L) {
  int initialize = lua_gettop(L) >= 1 ? lua_toboolean(L, 1) : 1;
  lsx_sha256_context* ctx = (lsx_sha256_context*)lua_newuserdata(L, sizeof(lsx_sha256_context));
  if(initialize) lsx_setup_sha256(ctx);
  else ctx->expert.bytes_so_far = IMPOSSIBLE_BYTES_OUT;
  if(luaL_newmetatable(L, "lsx_sha256_context")) {
    lua_pushliteral(L, "__index");
    lua_newtable(L);
#if LUA_VERSION_NUM < 502
    luaL_register(L, NULL, sha256_methods);
#else
    luaL_setfuncs(L, sha256_methods, 0);
#endif
    lua_settable(L, -3);
    lua_pushliteral(L, "__gc");
    lua_pushcfunction(L, f_sha256_destroy);
    lua_settable(L, -3);
  }
  lua_setmetatable(L, -2);
  return 1;
}

static int f_twofish_setup(lua_State* L) {
  lsx_twofish_context* ctx = (lsx_twofish_context*)luaL_checkudata(L, 1, "lsx_twofish_context");
  size_t length;
  const char* key = luaL_checklstring(L, 2, &length);
  switch(length) {
  case 16: lsx_setup_twofish128(ctx, key); break;
  case 24: lsx_setup_twofish192(ctx, key); break;
  case 32: lsx_setup_twofish256(ctx, key); break;
  default:
    return luaL_error(L, "Twofish keys must be 16, 24, or 32 bytes in length. (Consider using a hash function to generate your key.");
  }
  return 0;
}

static int f_twofish_encrypt(lua_State* L) {
  lsx_twofish_context* ctx = (lsx_twofish_context*)luaL_checkudata(L, 1, "lsx_twofish_context");
  size_t length;
  const char* plaintext = luaL_checklstring(L, 2, &length);
  int start;
  // Doesn't work?
  //if(ctx->s[0][0] == DESTROYED_MDS_RESULT) return luaL_error(L, "lsx_twofish_context not currently initalized; you must call :setup() to set up a key");
  if(lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
    start = luaL_checkinteger(L, 3);
    if(start < 0 || start > length) return luaL_error(L, "`start' parameter must be between 1 and the length of the ciphertext string");
    start -= 1;
    if(start + TWOFISH_BLOCKBYTES > length)
      return luaL_error(L, "twofish encrypts %d bytes at a time", TWOFISH_BLOCKBYTES);
  }
  else if(length != TWOFISH_BLOCKBYTES)
    return luaL_error(L, "twofish encrypts %d bytes at a time", TWOFISH_BLOCKBYTES);
  else start = 0;
  uint8_t ciphertext[TWOFISH_BLOCKBYTES];
  lsx_encrypt_twofish(ctx, plaintext + start, ciphertext);
  lua_pushlstring(L, ciphertext, TWOFISH_BLOCKBYTES);
  return 1;
}

static int f_twofish_decrypt(lua_State* L) {
  lsx_twofish_context* ctx = (lsx_twofish_context*)luaL_checkudata(L, 1, "lsx_twofish_context");
  size_t length;
  const char* ciphertext = luaL_checklstring(L, 2, &length);
  int start;
  // Doesn't work?
  //if(ctx->s[0][0] == DESTROYED_MDS_RESULT) return luaL_error(L, "lsx_twofish_context not currently initalized; you must call :setup() to set up a key");
  if(lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
    start = luaL_checkinteger(L, 3);
    if(start < 0 || start > length) return luaL_error(L, "`start' parameter must be between 1 and the length of the ciphertext string");
    start -= 1;
    if(start + TWOFISH_BLOCKBYTES > length)
      return luaL_error(L, "twofish decrypts %d bytes at a time", TWOFISH_BLOCKBYTES);
  }
  else if(length != TWOFISH_BLOCKBYTES)
    return luaL_error(L, "twofish decrypts %d bytes at a time", TWOFISH_BLOCKBYTES);
  else start = 0;
  uint8_t plaintext[TWOFISH_BLOCKBYTES];
  lsx_decrypt_twofish(ctx, ciphertext + start, plaintext);
  lua_pushlstring(L, plaintext, TWOFISH_BLOCKBYTES);
  return 1;
}

static int f_twofish_ctr(lua_State* L) {
  unsigned i;
  lsx_twofish_context* ctx = (lsx_twofish_context*)luaL_checkudata(L, 1, "lsx_twofish_context");
#if LUA_VERSION_NUM >= 503
  uint64_t counter = (uint64_t)luaL_checkinteger(L, 2);
#else
  uint64_t counter = (uint64_t)luaL_checknumber(L, 2);
#endif
  size_t noncelen;
  const char* nonce = luaL_optlstring(L, 3, NULL, &noncelen);
  size_t length;
  const char* message = luaL_checklstring(L, 4, &length);
  int start;
  // Doesn't work?
  //if(ctx->s[0][0] == DESTROYED_MDS_RESULT) return luaL_error(L, "lsx_twofish_context not currently initalized; you must call :setup() to set up a key");
  if(lua_gettop(L) >= 5 && !lua_isnil(L, 5)) {
    start = luaL_checkinteger(L, 5);
    if(start < 0 || start > length) return luaL_error(L, "`start' parameter must be between 1 and the length of the ciphertext string");
    start -= 1;
    if(start + TWOFISH_BLOCKBYTES > length)
      return luaL_error(L, "twofish encrypts %d bytes at a time", TWOFISH_BLOCKBYTES);
  }
  else if(length != TWOFISH_BLOCKBYTES)
    return luaL_error(L, "twofish encrypts %d bytes at a time", TWOFISH_BLOCKBYTES);
  else start = 0;
  uint8_t buf[TWOFISH_BLOCKBYTES];
  if(nonce) {
    if(noncelen > TWOFISH_BLOCKBYTES) return luaL_error(L, "CTR nonce may not be longer than %d bytes", TWOFISH_BLOCKBYTES);
    memcpy(buf, nonce, noncelen);
    lsx_explicit_bzero(buf+noncelen, sizeof(buf)-noncelen);
  }
  else lsx_explicit_bzero(buf, sizeof(buf));
  counter = bytes_to_int64(buf+8) + counter;
  int64_to_bytes(counter, buf+8);
  lsx_encrypt_twofish(ctx, buf, buf);
  for(i = 0; i < TWOFISH_BLOCKBYTES; ++i) {
    buf[i] ^= message[i+start];
  }
  lua_pushlstring(L, buf, TWOFISH_BLOCKBYTES);
  return 1;
}

static int f_twofish_destroy(lua_State* L) {
  lsx_twofish_context* ctx = (lsx_twofish_context*)luaL_checkudata(L, 1, "lsx_twofish_context");
  lsx_destroy_twofish(ctx);
  return 0;
}

static const struct luaL_Reg twofish_methods[] = {
  {"setup",f_twofish_setup},
  {"encrypt",f_twofish_encrypt},
  {"decrypt",f_twofish_decrypt},
  {"ctr",f_twofish_ctr},
  {"destroy",f_twofish_destroy},
  {NULL, NULL},
};

static int f_twofish(lua_State* L) {
  if(lua_gettop(L) == 0) return luaL_error(L, "twofish() requires an argument; either `false' or a 16-, 24-, or 32-byte key");
  lsx_twofish_context* ctx = (lsx_twofish_context*)lua_newuserdata(L, sizeof(lsx_twofish_context));
  if(luaL_newmetatable(L, "lsx_twofish_context")) {
    lua_pushliteral(L, "__index");
    lua_newtable(L);
#if LUA_VERSION_NUM < 502
    luaL_register(L, NULL, twofish_methods);
#else
    luaL_setfuncs(L, twofish_methods, 0);
#endif
    lua_settable(L, -3);
    lua_pushliteral(L, "__gc");
    lua_pushcfunction(L, f_twofish_destroy);
    lua_settable(L, -3);
  }
  lua_setmetatable(L, -2);
  if(lua_toboolean(L, 1) == 0)
    ctx->s[0][0] = DESTROYED_MDS_RESULT;
  else {
    lua_pushcfunction(L, f_twofish_setup);
    lua_pushvalue(L, -2);
    lua_pushvalue(L, 1);
    lua_call(L, 2, 0);
  }
  return 1;
}

static int f_xor(lua_State* L) {
  char* c, *p;
  int rem;
  const char* a = luaL_checkstring(L,1);
  const char* b = luaL_checkstring(L,2);
  if(lua_rawlen(L,1) != lua_rawlen(L,2))
    return luaL_error(L, "string lengths differ");
  rem = lua_rawlen(L,1);
  p = c = malloc(rem);
  if(!c)
    return luaL_error(L, "malloc error");
  while(rem-- > 0) {
    *p++ = *a++ ^ *b++;
  }
  lua_pushlstring(L, c, lua_rawlen(L,1));
  free(c);
  return 1;
}

static const struct luaL_Reg regs[] = {
  {"sha256_sum",f_sha256_sum},
  {"sha256_sum_binary",f_sha256_sum_binary},
  {"sha256",f_sha256},
  {"twofish",f_twofish},
  {"xor",f_xor},
  {NULL, NULL},
};

int luaopen_lsx(lua_State* L) {
#if LUA_VERSION_NUM < 502
  luaL_register(L, "lsx", regs);
#else
  lua_newtable(L);
  luaL_setfuncs(L, regs, 0);
#endif
  return 1;
}
