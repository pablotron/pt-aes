#include <stdint.h>
#include <stdio.h>
#include "pt-aes.h"

static void print_u8s(const char * const name, const uint8_t m[static 16]) {
  printf("%s:\n", name);
  for (int i = 0; i < 16; i++) {
    printf("%02x%c", m[i], ((i % 4) == 3) ? '\n' : ' ');
  }
}

static const uint8_t TEST[16] = {
  0xdb, 0xf2, 0x01, 0xc6,
  0x13, 0x0a, 0x01, 0xc6,
  0x53, 0x22, 0x01, 0xc6,
  0x45, 0x5c, 0x01, 0xc6,
};

int main(int argc, char *argv[]) {
  (void) argc;
  (void) argv;

  uint8_t dst[16];
  aes_mix_test(dst, TEST);

  print_u8s("mix test", TEST);
  print_u8s("mix result", dst);

  return 0;
}
