#ifndef PT_AES_TEST_H
#define PT_AES_TEST_H

void pt_aes_test_mix_col(
  uint8_t dst[static restrict 4],
  const uint8_t src[static restrict 4]
);

void pt_aes_test_inv_mix_col(
  uint8_t dst[static restrict 4],
  const uint8_t src[static restrict 4]
);

#endif /* PT_AES_TEST_H */
