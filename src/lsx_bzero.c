// Compile this file without optimizations, and, if needed, with -fno-builtins
extern void* memset(void* s, int c, size_t n);
void lsx_explicit_bzero(void* p, size_t n) {
  memset(p, 0, n);
}
