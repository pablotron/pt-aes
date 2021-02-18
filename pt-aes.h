#ifndef PT_AES_H
#define PT_AES_H

void pt_aes128_keyex(
  uint32_t dst[static restrict 44],
  const uint8_t src[static restrict 16]
);

void pt_aes_mix_col(
  uint8_t dst[static restrict 4],
  const uint8_t src[static restrict 4]
);

void pt_aes128_enc(
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16],
  const uint32_t key_data[static restrict 44]
);

void pt_aes128_dec(
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16],
  const uint32_t key_data[static restrict 44]
);

#endif /* PT_AES_H */
