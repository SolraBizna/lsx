#include "lsx.h"

#include <string.h>

void lsx_explicit_bzero(void* p, size_t n) {
  memset(p, 0, n);
}
