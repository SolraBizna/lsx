#include <stddef.h>

// Compile this file without optimizations, and, if needed, with -fno-builtins
extern
#if __cplusplus
"C"
#endif
void* memset(void* s, int c, size_t n);

#if __cplusplus
extern "C"
#endif
void lsx_explicit_bzero(void* p, size_t n) {
  memset(p, 0, n);
  // In case we were compiled with optimizations... borrow a trick from
  // BoringSSL
#if __GNUC__
  __asm__ volatile("" : : "r"(p) : "memory");
#elif _MSC_VER
  asm;
#endif
}
