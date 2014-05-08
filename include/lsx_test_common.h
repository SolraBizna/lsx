#define elementcount(arr) (sizeof(arr) / sizeof(*(arr)))

static inline void red() { fprintf(stderr, "\x1B[31;1m"); }
static inline void green() { fprintf(stderr, "\x1B[32m"); }
static inline void plain() { fprintf(stderr, "\x1B[0m"); }
#define output_datum(format, i, known, result) \
    if(known != result) red(); \
    else green(); \
    fprintf(stderr, format, i, known, result)

static inline int _test_8bit_table(const uint8_t* known, size_t known_size,
                                   const uint8_t* ours, size_t our_size,
                                   const char* table_name) {
  if(known_size != our_size) goto test_failed;
  for(unsigned i = 0; i < known_size; ++i) {
    if(known[i] != ours[i]) goto test_failed;
  }
  return 0;
 test_failed:
  fprintf(stderr, "%s comparison failed!\n", table_name);
  if(known_size != our_size) fprintf(stderr, "sizes differ (%u vs %u)\n",
                                     (unsigned)known_size, (unsigned)our_size);
  else {
    fprintf(stderr, "  datum | kn | re\n");
    for(unsigned i = 0; i < known_size; ++i) {
      output_datum(" t[%3i] | %02X | %02X\n", i, known[i], ours[i]);
    }
  }
  return 1;
}

#define test_8bit_table(known,ours) \
_test_8bit_table(known, sizeof(known), ours, sizeof(ours), #ours)

static inline int _test_32bit_table(const uint32_t* known, size_t known_size,
                                    const uint32_t* ours, size_t our_size,
                                    const char* table_name) {
  if(known_size != our_size) goto test_failed;
  for(unsigned i = 0; i < known_size; ++i) {
    if(known[i] != ours[i]) goto test_failed;
  }
  return 0;
 test_failed:
  fprintf(stderr, "%s comparison failed!\n", table_name);
  if(known_size != our_size) fprintf(stderr, "sizes differ (%u vs %u)\n",
                                     (unsigned)known_size, (unsigned)our_size);
  else {
    fprintf(stderr, "  datum |   known  |  result\n");
    for(unsigned i = 0; i < known_size; ++i) {
      output_datum(" t[%3i] | %08X | %08X\n", i, known[i], ours[i]);
    }
  }
  return 1;
}

#define test_32bit_table(known,ours) \
_test_32bit_table(known, sizeof(known)/4, ours, sizeof(ours)/4, #ours)

