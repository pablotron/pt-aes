#ifndef PT_AES_H
#define PT_AES_H

void pt_aes128_keyex(
  uint32_t dst[static restrict 44],
  const uint8_t src[static restrict 16]
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

typedef struct {
  uint32_t key_data[44];
  uint8_t last[16];
} pt_aes128_cbc_t;

void pt_aes128_cbc_init(
  pt_aes128_cbc_t * const state,
  const uint8_t key[static restrict 16],
  const uint8_t iv[static restrict 16]
);

void pt_aes128_cbc_enc(
  pt_aes128_cbc_t *state,
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16]
);

void pt_aes128_cbc_dec(
  pt_aes128_cbc_t *state,
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16]
);

void pt_aes192_keyex(
  uint32_t dst[static restrict 52],
  const uint8_t src[static restrict 24]
);

void pt_aes192_enc(
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16],
  const uint32_t key_data[static restrict 52]
);

void pt_aes192_dec(
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16],
  const uint32_t key_data[static restrict 52]
);

typedef struct {
  uint32_t key_data[52];
  uint8_t last[16];
} pt_aes192_cbc_t;

void pt_aes192_cbc_init(
  pt_aes192_cbc_t * const state,
  const uint8_t key[static restrict 16],
  const uint8_t iv[static restrict 16]
);

void pt_aes192_cbc_enc(
  pt_aes192_cbc_t *state,
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16]
);

void pt_aes192_cbc_dec(
  pt_aes192_cbc_t *state,
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16]
);

#endif /* PT_AES_H */
