#ifndef PT_AES_H
#define PT_AES_H

void aes_mix_test(
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16]
);

#endif /* PT_AES_H */
