#include "lsx.h"

#if defined(__WIN32__) || defined(_WIN32) || defined(WIN32)

#include <windows.h>
#include <stdio.h>

void lsx_get_random(void* p, size_t n) {
  static HMODULE hLib = NULL;
  static BOOLEAN (APIENTRY *pfn)(void*, ULONG);
  if(hLib == NULL) {
    hLib = LoadLibraryA("ADVAPI32.DLL");
    if(!hLib) {
      fprintf(stderr, "Could not open ADVAPI32.dll\n");
      /* Don't let abort() fail. */
      while(1) abort();
    }
    pfn = (BOOLEAN (APIENTRY *)(void*,ULONG))
      GetProcAddress(hLib,"SystemFunction036");
    if(!pfn) {
      fprintf(stderr, "Could not get RtlGenRandom from ADVAPI32.dll\n");
      /* Don't let abort() fail. */
      while(1) abort();
    }
  }
  if(!pfn(p, n)) {
    fprintf(stderr, "Could not get random data from RtlGenRandom\n");
    /* Don't let abort() fail. */
    while(1) abort();
  }
}

void lsx_get_extremely_random(void* p, size_t n) {
  lsx_get_random(p, n);
}

#elif defined(__unix) || defined(__linux) || defined(__posix) || defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))

#if defined(HAVE_ARC4RANDOM_BUF)
#error Use it
#endif

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#ifndef RANDOM_SOURCE_DEVICE
#define RANDOM_SOURCE_DEVICE "/dev/urandom"
#endif

void lsx_get_random(void* p, size_t n) {
  static int fd = -1;
  int red;
  if(fd < 0) {
    fd = open(RANDOM_SOURCE_DEVICE, O_RDONLY);
    if(fd < 0) {
      fprintf(stderr, "While opening the random number source (%s): %s\n",
              RANDOM_SOURCE_DEVICE, strerror(errno));
      /* Don't let abort() fail, even on crappy C libraries. */
      while(1) abort();
    }
  }
  if(n == 0) return;
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

#ifndef EXTREMELY_RANDOM_SOURCE_DEVICE
# ifdef __OpenBSD__
#  define EXTREMELY_RANDOM_SOURCE_DEVICE "/dev/srandom"
# else
#  define EXTREMELY_RANDOM_SOURCE_DEVICE "/dev/random"
# endif
#endif

void lsx_get_extremely_random(void* p, size_t n) {
  static int fd = -1;
  int red;
  if(fd < 0) {
    fd = open(EXTREMELY_RANDOM_SOURCE_DEVICE, O_RDONLY);
    if(fd < 0) {
      fprintf(stderr, "While opening the extremely random number source (%s):"
              " %s\n",
              EXTREMELY_RANDOM_SOURCE_DEVICE, strerror(errno));
      /* Don't let abort() fail, even on crappy C libraries. */
      while(1) abort();
    }
  }
  if(n == 0) return;
  red = read(fd, p, n);
  if(red < 0) {
    if(errno == EINTR) return lsx_get_extremely_random(p, n);
    else {
      fprintf(stderr, "While reading from the extremely random number source"
              " (%s): %s\n",
              EXTREMELY_RANDOM_SOURCE_DEVICE, strerror(errno));
      while(1) abort();
    }
  }
  else if(red == 0) {
    fprintf(stderr, "While reading from the extremely random number source"
            " (%s): %s\n",
            EXTREMELY_RANDOM_SOURCE_DEVICE, "Unexpected EOF");
    while(1) abort();
  }
  else {
    n -= red;
    if(n > 0) return lsx_get_extremely_random((uint8_t*)p + red, n);
  }
}

#else

#error "We don't know how to get random data on your platform"

#endif
