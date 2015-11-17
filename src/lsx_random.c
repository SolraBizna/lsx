#include "lsx.h"

#if defined(__WIN32__) || defined(_WIN32) || defined(WIN32)

#error RtlGenRandom?

#elif defined(__unix) || defined(__linux) || defined(__posix)

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef RANDOM_SOURCE_DEVICE
#define RANDOM_SOURCE_DEVICE "/dev/urandom"
#endif

void lsx_get_random(void* p, size_t n) {
  static int fd = -1;
  size_t red;
  if(fd < 0) {
    fd = open(RANDOM_SOURCE_DEVICE, O_RDONLY);
    if(fd < 0) {
      fprintf(stderr, "While opening the random number source (%s): %s\n",
              RANDOM_SOURCE_DEVICE, strerror(errno));
      /* Don't let abort() fail, even on crappy C libraries. */
      while(1) abort();
    }
  }
  red = read(fd, p, n);
  if(red < 0) {
    if(errno == EINTR) return lsx_get_random(p, n);
    else {
      fprintf(stderr, "While reading from the random number source (%s): %s\n",
              RANDOM_SOURCE_DEVICE, strerror(errno));
      while(1) abort();
    }
  }
  else if(red == 0) {
    fprintf(stderr, "While reading from the random number source (%s): %s\n",
            RANDOM_SOURCE_DEVICE, "Unexpected EOF");
    while(1) abort();
  }
  else {
    n -= red;
    if(n > 0) return lsx_get_random((uint8_t*)p + red, n);
  }
}

#else

#error We don't know how to get random data on your platform

#endif
