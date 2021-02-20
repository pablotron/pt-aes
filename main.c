#include <stdbool.h>
#include <stdint.h>
#include <string.h> // memcmp()
#include <stdio.h> // printf()
#include "pt-aes.h"
#ifdef PT_AES_TEST
#include "pt-aes-test.h"
#endif /* PT_AES_TEST */

#define LEN(a) (sizeof(a) / sizeof(a[0]))

#ifdef PT_AES_TEST
// test vectors for pt_aes_mix_col()
// src: https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
static const struct {
  uint8_t src[4];
  uint8_t dst[4];
} AES_MIX_COL_TESTS[] = {{
  .src = { 0xdb, 0x13, 0x53, 0x45 },
  .dst = { 0x8e, 0x4d, 0xa1, 0xbc },
}, {
  .src = { 0xf2, 0x0a, 0x22, 0x5c },
  .dst = { 0x9f, 0xdc, 0x58, 0x9d },
}, {
  .src = { 0x01, 0x01, 0x01, 0x01 },
  .dst = { 0x01, 0x01, 0x01, 0x01 },
}, {
  .src = { 0xc6, 0xc6, 0xc6, 0xc6 },
  .dst = { 0xc6, 0xc6, 0xc6, 0xc6 },
}, {
  .src = { 0xd4, 0xd4, 0xd4, 0xd5 },
  .dst = { 0xd5, 0xd5, 0xd7, 0xd6 },
}, {
  .src = { 0x2d, 0x26, 0x31, 0x4c },
  .dst = { 0x4d, 0x7e, 0xbd, 0xf8 },
}};

static void fail_aes_mix_col_test(
  const size_t num,
  const uint8_t got[4]
) {
  const uint8_t *src = AES_MIX_COL_TESTS[num].src;
  const uint8_t *exp = AES_MIX_COL_TESTS[num].dst;

  printf("FAIL: AES_MIX_COL_TESTS[%zu]:\n", num);
  printf("  src = %02x %02x %02x %02x\n", src[0], src[1], src[2], src[3]);
  printf("  exp = %02x %02x %02x %02x\n", exp[0], exp[1], exp[2], exp[3]);
  printf("  got = %02x %02x %02x %02x\n", got[0], got[1], got[2], got[3]);
}
#endif /* PT_AES_TEST */

static void test_aes_mix_col(void) {
#ifdef PT_AES_TEST
  for (size_t i = 0; i < LEN(AES_MIX_COL_TESTS); i++) {
    // mix column
    uint8_t got[4];
    pt_aes_test_mix_col(got, AES_MIX_COL_TESTS[i].src);

    // check result
    if (memcmp(got, AES_MIX_COL_TESTS[i].dst, 4)) {
      fail_aes_mix_col_test(i, got);
    }
  }
#endif /* PT_AES_TEST */
}

#ifdef PT_AES_TEST
// test vectors for pt_aes_inv_mix_col()
// src: https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
static const struct {
  uint8_t src[4];
  uint8_t dst[4];
} AES_INV_MIX_COL_TESTS[] = {{
  .src = { 0x8e, 0x4d, 0xa1, 0xbc },
  .dst = { 0xdb, 0x13, 0x53, 0x45 },
}, {
  .src = { 0x9f, 0xdc, 0x58, 0x9d },
  .dst = { 0xf2, 0x0a, 0x22, 0x5c },
}, {
  .src = { 0x01, 0x01, 0x01, 0x01 },
  .dst = { 0x01, 0x01, 0x01, 0x01 },
}, {
  .src = { 0xc6, 0xc6, 0xc6, 0xc6 },
  .dst = { 0xc6, 0xc6, 0xc6, 0xc6 },
}, {
  .src = { 0xd5, 0xd5, 0xd7, 0xd6 },
  .dst = { 0xd4, 0xd4, 0xd4, 0xd5 },
}, {
  .src = { 0x4d, 0x7e, 0xbd, 0xf8 },
  .dst = { 0x2d, 0x26, 0x31, 0x4c },
}};

static void fail_aes_inv_mix_col_test(
  const size_t num,
  const uint8_t got[4]
) {
  const uint8_t *src = AES_INV_MIX_COL_TESTS[num].src;
  const uint8_t *exp = AES_INV_MIX_COL_TESTS[num].dst;

  printf("FAIL: AES_INV_MIX_COL_TESTS[%zu]:\n", num);
  printf("  src = %02x %02x %02x %02x\n", src[0], src[1], src[2], src[3]);
  printf("  exp = %02x %02x %02x %02x\n", exp[0], exp[1], exp[2], exp[3]);
  printf("  got = %02x %02x %02x %02x\n", got[0], got[1], got[2], got[3]);
}
#endif /* PT_AES_TEST */

static void test_aes_inv_mix_col(void) {
#ifdef PT_AES_TEST
  for (size_t i = 0; i < LEN(AES_INV_MIX_COL_TESTS); i++) {
    // mix column
    uint8_t got[4];
    pt_aes_test_inv_mix_col(got, AES_INV_MIX_COL_TESTS[i].src);

    // check result
    if (memcmp(got, AES_INV_MIX_COL_TESTS[i].dst, 4)) {
      fail_aes_inv_mix_col_test(i, got);
    }
  }
#endif /* PT_AES_TEST */
}

// src: NIST FIPS-197, A.1 (page 27)
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
static const struct {
  const uint8_t src[16];
  const uint32_t dst[44];
} AES128_KEYEX_TESTS[] = {{
  .src = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
  },

  .dst = {
    0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
    0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
    0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
    0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
    0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
    0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
    0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
    0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
    0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
    0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
    0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6,
  },
}};

static void print_aes128_keyex_key(
  const char * const name,
  const uint8_t src[static 16]
) {
  printf("  %s =\n    ", name);
  for (size_t i = 0; i < 16; i++) {
    printf("%02x%s", src[i], ((i % 4) == 3) ? " " : "");
  }
  printf("\n");
}

static void print_aes128_keyex_result(
  const char * const name,
  const uint32_t vals[static 44]
) {
  printf("  %s =\n", name);
  for (size_t i = 0; i < 11; i++) {
    printf("    %08x %08x %08x %08x\n", vals[4 * i + 0], vals[4 * i + 1], vals[4 * i + 2], vals[4 * i + 3]);
  }
}

static void fail_aes128_keyex_test(
  const size_t num,
  const uint32_t got[44]
) {
  const uint8_t *src = AES128_KEYEX_TESTS[num].src;
  const uint32_t *exp = AES128_KEYEX_TESTS[num].dst;

  printf("FAIL: AES128_KEYEX_TESTS[%zu]:\n", num);
  print_aes128_keyex_key("src", src);
  print_aes128_keyex_result("exp", exp);
  print_aes128_keyex_result("got", got);
}

static void test_aes128_keyex(void) {
  for (size_t i = 0; i < LEN(AES128_KEYEX_TESTS); i++) {
    // expand key
    uint32_t got[44];
    pt_aes128_keyex(got, AES128_KEYEX_TESTS[i].src);

    // check result
    if (memcmp(got, AES128_KEYEX_TESTS[i].dst, 44 * sizeof(uint32_t))) {
      fail_aes128_keyex_test(i, got);
    }
  }
}

static void print_block(
  const char * const name,
  const uint8_t vals[static 16]
) {
  printf("  %s =", name);
  for (size_t i = 0; i < 16; i++) {
    printf(" %02x", vals[i]);
  }
  printf("\n");
}

static const struct {
  const uint8_t src[16];
  const uint8_t key[16];
  const uint8_t dst[16];
} AES128_ENC_TESTS[] = {{
  // src: FIPS-197, Appendix B
  .src = {
    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
  },

  .key = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
  },

  .dst = {
    0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
    0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
  },
}, {
  // src: FIPS-197, Appendix C
  .src = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  },

  .key = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  },

  .dst = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
  },
}};

static void fail_aes128_enc_test(
  const size_t num,
  const uint8_t got[static 16]
) {
  const uint8_t *exp = AES128_ENC_TESTS[num].dst;

  printf("FAIL: AES128_ENC_TESTS[%zu]:\n", num);
  print_block("src", AES128_ENC_TESTS[num].src);
  print_block("key", AES128_ENC_TESTS[num].key);
  print_block("exp", exp);
  print_block("got", got);
}

static void test_aes128_enc(void) {
  for (size_t i = 0; i < LEN(AES128_ENC_TESTS); i++) {
    // expand key
    uint32_t key_data[44];
    pt_aes128_keyex(key_data, AES128_ENC_TESTS[i].key);

    // encrypt block
    uint8_t got[16];
    pt_aes128_enc(got, AES128_ENC_TESTS[i].src, key_data);

    // check result
    if (memcmp(got, AES128_ENC_TESTS[i].dst, 16)) {
      fail_aes128_enc_test(i, got);
    }
  }
}

static const struct {
  const uint8_t src[16];
  const uint8_t key[16];
  const uint8_t dst[16];
} AES128_DEC_TESTS[] = {{
  // src: FIPS-197, Appendix B
  .src = {
    0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
    0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
  },

  .key = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
  },

  .dst = {
    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
  },
}, {
  // src: FIPS-197, Appendix C
  .src = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
  },

  .key = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  },

  .dst = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  },
}};

static void fail_aes128_dec_test(
  const size_t num,
  const uint8_t got[static 16]
) {
  const uint8_t *exp = AES128_DEC_TESTS[num].dst;

  printf("FAIL: AES128_DEC_TESTS[%zu]:\n", num);
  print_block("src", AES128_DEC_TESTS[num].src);
  print_block("key", AES128_DEC_TESTS[num].key);
  print_block("exp", exp);
  print_block("got", got);
}

static void test_aes128_dec(void) {
  for (size_t i = 0; i < LEN(AES128_DEC_TESTS); i++) {
    // expand key
    uint32_t key_data[44];
    pt_aes128_keyex(key_data, AES128_DEC_TESTS[i].key);

    // decrypt block
    uint8_t got[16];
    pt_aes128_dec(got, AES128_DEC_TESTS[i].src, key_data);

    // check result
    if (memcmp(got, AES128_DEC_TESTS[i].dst, 16)) {
      fail_aes128_dec_test(i, got);
    }
  }
}

// aes128 cbc enc tests
// src: https://github.com/ircmaxell/quality-checker/blob/master/tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-cbc.test-vectors
static const struct {
  const uint8_t key[16];
  const uint8_t iv[16];
  const uint8_t src[16];
  const uint8_t dst[16];
} AES128_CBC_ENC_TESTS[] = {{
  .key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
  .iv = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
  .src = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a },
  .dst = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d },
}, {
  .key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
  .iv = { 0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D },
  .src = { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 },
  .dst = { 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2 },
}, {
  .key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
  .iv = { 0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2 },
  .src = { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef },
  .dst = { 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16 },
}, {
  .key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
  .iv = { 0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16 },
  .src = { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 },
  .dst = { 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 },
}};

static void fail_aes128_cbc_enc_test(
  const size_t num,
  const uint8_t got[static 16]
) {
  const uint8_t *exp = AES128_CBC_ENC_TESTS[num].dst;

  printf("FAIL: AES128_CBC_ENC_TESTS[%zu]:\n", num);
  print_block("src", AES128_CBC_ENC_TESTS[num].src);
  print_block("key", AES128_CBC_ENC_TESTS[num].key);
  print_block("exp", exp);
  print_block("got", got);
}

static void test_aes128_cbc_enc(void) {
  for (size_t i = 0; i < LEN(AES128_CBC_ENC_TESTS); i++) {
    // expand key
    pt_aes128_cbc_t state;
    pt_aes128_cbc_init(&state, AES128_CBC_ENC_TESTS[i].key, AES128_CBC_ENC_TESTS[i].iv);

    // encrypt block
    uint8_t got[16];
    pt_aes128_cbc_enc(&state, got, AES128_CBC_ENC_TESTS[i].src);

    // check result
    if (memcmp(got, AES128_CBC_ENC_TESTS[i].dst, 16)) {
      fail_aes128_cbc_enc_test(i, got);
    }
  }
}

// aes128 cbc dec tests
// src: https://github.com/ircmaxell/quality-checker/blob/master/tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-cbc.test-vectors
static const struct {
  const uint8_t key[16];
  const uint8_t iv[16];
  const uint8_t src[16];
  const uint8_t dst[16];
} AES128_CBC_DEC_TESTS[] = {{
  .key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
  .iv = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
  .src = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d },
  .dst = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a },
}, {
  .key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
  .iv = { 0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D },
  .src = { 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2 },
  .dst = { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 },
}, {
  .key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
  .iv = { 0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2 },
  .src = { 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16 },
  .dst = { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef },
}, {
  .key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
  .iv = { 0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16 },
  .src = { 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 },
  .dst = { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 },
}};

static void fail_aes128_cbc_dec_test(
  const size_t num,
  const uint8_t got[static 16]
) {
  const uint8_t *exp = AES128_CBC_DEC_TESTS[num].dst;

  printf("FAIL: AES128_CBC_DEC_TESTS[%zu]:\n", num);
  print_block("src", AES128_CBC_DEC_TESTS[num].src);
  print_block("key", AES128_CBC_DEC_TESTS[num].key);
  print_block("exp", exp);
  print_block("got", got);
}

static void test_aes128_cbc_dec(void) {
  for (size_t i = 0; i < LEN(AES128_CBC_DEC_TESTS); i++) {
    // expand key
    pt_aes128_cbc_t state;
    pt_aes128_cbc_init(&state, AES128_CBC_DEC_TESTS[i].key, AES128_CBC_DEC_TESTS[i].iv);

    // decrypt block
    uint8_t got[16];
    pt_aes128_cbc_dec(&state, got, AES128_CBC_DEC_TESTS[i].src);

    // check result
    if (memcmp(got, AES128_CBC_DEC_TESTS[i].dst, 16)) {
      fail_aes128_cbc_dec_test(i, got);
    }
  }
}

int main(void) {
  test_aes_mix_col();
  test_aes_inv_mix_col();
  test_aes128_keyex();
  test_aes128_enc();
  test_aes128_dec();
  test_aes128_cbc_enc();
  test_aes128_cbc_dec();
}
