#include <stdint.h>

// copy +num+ elements to +dst+ from +src+
#define COPY(dst, src, num) do { \
  for (unsigned int _i = 0; _i < (num); _i++) { \
    (dst)[_i] = (src)[_i]; \
  } \
} while (0)

// copy transposed 4x4 matrix to +dst+ from +src+
// (unused, delete)
#define TRANSPOSE(dst, src) do { \
  (dst)[ 0] = (src)[ 0]; \
  (dst)[ 1] = (src)[ 4]; \
  (dst)[ 2] = (src)[ 8]; \
  (dst)[ 3] = (src)[12]; \
  (dst)[ 4] = (src)[ 1]; \
  (dst)[ 5] = (src)[ 5]; \
  (dst)[ 6] = (src)[ 9]; \
  (dst)[ 7] = (src)[13]; \
  (dst)[ 8] = (src)[ 2]; \
  (dst)[ 9] = (src)[ 6]; \
  (dst)[10] = (src)[10]; \
  (dst)[11] = (src)[14]; \
  (dst)[12] = (src)[ 3]; \
  (dst)[13] = (src)[ 7]; \
  (dst)[14] = (src)[11]; \
  (dst)[15] = (src)[15]; \
} while (0)

/**
 * Multiply by two in GF8.
 */
static uint8_t xtime(const uint8_t a) {
  return (a << 1) ^ (((a >> 7) & 1) * 0x1b);
}

/**
 * Multiply two 8-bit values in GF8.
 */
static uint8_t gmul(const uint8_t a, const uint8_t b) {
  return (
    (((b     ) & 1) * a) ^
    (((b >> 1) & 1) * xtime(a)) ^
    (((b >> 2) & 1) * xtime(xtime(a))) ^
    (((b >> 3) & 1) * xtime(xtime(xtime(a))))
  );
}

/**
 * Substitution box (S-Box) used for SubBytes transformation from
 * FIPS-197, 5.1.1.
 */
static const uint8_t E_SBOX[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
  0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
  0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
  0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
  0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
  0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
  0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
  0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
  0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
  0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

/**
 * SubBytes and ShiftRows transformations from sections 5.1.1 and 5.1.2
 * of FIPS-197.
 *
 * Source:
 * - https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
 *
 */
static void pt_aes_enc_sub_and_shift(
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16]
) {
  uint8_t tmp[16] = {
    E_SBOX[src[ 0]], E_SBOX[src[ 5]], E_SBOX[src[10]], E_SBOX[src[15]],
    E_SBOX[src[ 4]], E_SBOX[src[ 9]], E_SBOX[src[14]], E_SBOX[src[ 3]],
    E_SBOX[src[ 8]], E_SBOX[src[13]], E_SBOX[src[ 2]], E_SBOX[src[ 7]],
    E_SBOX[src[12]], E_SBOX[src[ 1]], E_SBOX[src[ 6]], E_SBOX[src[11]],
  };

  COPY(dst, tmp, 16);
}

/**
 * Implement AES MixColumn transformation from FIPS-197.
 *
 * In other words, this transformation (represented in matrix form):
 *
 *   [ b_0 ]   [ 2 3 1 1 ] [ a_0 ]
 *   [ b_1 ] = [ 1 2 3 1 ] [ a_1 ]
 *   [ b_2 ]   [ 1 1 2 3 ] [ a_2 ]
 *   [ b_3 ]   [ 3 1 1 2 ] [ a_3 ]
 *
 * Where:
 * - Addition is done with XOR, like so:
 *
 *   = a + b
 *   = a ^ b
 *
 * - Multiplication by 2 is a shift, XORed against 0x1b on overflow,
 *   like so:
 *
 *     = 2 * x
 *     = (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00)
 *
 * - Multiplication by 3 is done as a multiply by two and an addition,
 *   like so:
 *
 *     = 3 * x
 *     = (2 + 1) * x                                // equivalent
 *     = (2 * x) + (1 * x)                          // distribute
 *     = (2 * x) + x                                // identity
 *     = (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00) ^ x  // convert
 *
 * Sources:
 * - https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
 * - https://en.wikipedia.org/wiki/Rijndael_MixColumns
 *
 */
static void pt_aes_mix_col(
  uint8_t dst[static restrict 4],
  const uint8_t src[static restrict 4]
) {
  const uint8_t a = src[0],
                b = src[1],
                c = src[2],
                d = src[3];

  const uint8_t tmp[4] = {
    // MixColumn r0: 2 3 1 1
    gmul(a, 2) ^ gmul(b, 3) ^ c ^ d,

    // MixColumn r1: 1 2 3 1
    a ^ gmul(b, 2) ^ gmul(c, 3) ^ d,

    // MixColumn r2: 1 1 2 3
    a ^ b ^ gmul(c, 2) ^ gmul(d, 3),

    // MixColumn r3: 3 1 1 2
    gmul(a, 3) ^ b ^ c ^ gmul(d, 2),
  };

  // copy to output
  COPY(dst, tmp, sizeof(tmp));
}

#ifdef PT_AES_TEST
void pt_aes_test_mix_col(
  uint8_t dst[static restrict 4],
  const uint8_t src[static restrict 4]
) {
  pt_aes_mix_col(dst, src);
}
#endif /* PT_AES_TEST */

static void pt_aes_mix(
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16]
) {
  uint8_t tmp[16];

  for (int i = 0; i < 4; i++) {
    pt_aes_mix_col(tmp + (4 * i), src + (4 * i));
  }

  COPY(dst, tmp, 16);
}

// round constants (used in rot_sub_u32())
//
// FIXME: we might want to  calculate this on the fly to avoid cache
// timing attacks.
static const uint32_t RCONS[11] = {
  0x01000000, 0x02000000, 0x04000000, 0x08000000,
  0x10000000, 0x20000000, 0x40000000, 0x80000000,
  0x1b000000, 0x36000000, 0x6c000000,
};

// rotate left, 32-bit
#define ROTL32(a, s) (((a) << (s)) | ((a) >> (32 - (s))))

static uint32_t rot_sub_u32(const uint32_t a, const uint32_t i) {
  // rotate left by 8 bits
  const uint32_t b = ROTL32(a, 8);

  return RCONS[(i - 1) >> 2] ^ (
    (E_SBOX[(b >>  0) & 0xff]) |
    (E_SBOX[(b >>  8) & 0xff] <<  8) |
    (E_SBOX[(b >> 16) & 0xff] << 16) |
    (E_SBOX[(b >> 24) & 0xff] << 24)
  );
}

/**
 * Expand 16 byte key into an array of 44 unsigned 32-bit key schedule
 * data.
 *
 * The output data is used by pt_aes128_enc().
 *
 * Parameters:
 * - dst: Destination buffer of 44 unsigned 32-bit integers for output
 *   key schedule data.
 * - src: Source buffer of 16 bytes of input key data.
 */
void pt_aes128_keyex(
  uint32_t dst[static restrict 44],
  const uint8_t src[static restrict 16]
) {
  uint32_t tmp[44] = {
    src[ 3] | (src[ 2] << 8) | (src[ 1] << 16) | (src[ 0] << 24),
    src[ 7] | (src[ 6] << 8) | (src[ 5] << 16) | (src[ 4] << 24),
    src[11] | (src[10] << 8) | (src[ 9] << 16) | (src[ 8] << 24),
    src[15] | (src[14] << 8) | (src[13] << 16) | (src[12] << 24),
  };

  // expand key data
  for (int i = 4; i < 44; i++) {
    uint32_t a = tmp[i - 1],
             b = rot_sub_u32(tmp[i - 1], i);
    tmp[i] = tmp[i - 4] ^ ((i & 0x3) ? a : b);
  }

  // copy to output
  COPY(dst, tmp, 44);
}

/**
 * Implementation of AddRoundKey transformation from FIPS-197.
 */
static void pt_aes128_add_round_key(
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16],
  const uint32_t key_data[static restrict 4]
) {
  // copy from source buffer
  uint8_t tmp[16];
  COPY(tmp, src, 16);

  // mix in key data
  for (int i = 0; i < 16; i++) {
    tmp[i] ^= (key_data[i >> 2] >> (24 - ((i & 0x3) << 3))) & 0xff;
  }

  // copy to output buffer
  COPY(dst, tmp, 16);
}

/**
 * Encrypt a single block (16 bytes) of data using AES128.
 *
 * Parameters:
 * - dst: destination buffer for output ciphertext block.
 * - src: source buffer for input plaintext block.
 * - key_data: Source buffer of 44 unsigned 32-bit integers containing
 *   key schedule data generated by pt_aes128_keyex().
 */
void pt_aes128_enc(
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16],
  const uint32_t key_data[static restrict 44]
) {
  uint8_t a[16], b[16];

  // add initial round key
  pt_aes128_add_round_key(a, src, key_data);

  // first 9 rounds
  for (int i = 0; i < 9; i++) {
    pt_aes_enc_sub_and_shift(b, a);
    pt_aes_mix(a, b);
    pt_aes128_add_round_key(b, a, key_data + 4 * (i + 1));
    COPY(a, b, 16);
  }

  // final round
  pt_aes_enc_sub_and_shift(b, a);
  pt_aes128_add_round_key(dst, b, key_data + 40);
}

static const uint8_t D_SBOX[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
  0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
  0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
  0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
  0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
  0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
  0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
  0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
  0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
  0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
  0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
  0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
  0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
  0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
  0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
  0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
  0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

static void pt_aes_dec_shift_and_sub(
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16]
) {
  (void) D_SBOX;
  uint8_t tmp[16] = {
    D_SBOX[src[ 0]], D_SBOX[src[13]], D_SBOX[src[10]], D_SBOX[src[ 7]],
    D_SBOX[src[ 4]], D_SBOX[src[ 1]], D_SBOX[src[14]], D_SBOX[src[11]],
    D_SBOX[src[ 8]], D_SBOX[src[ 5]], D_SBOX[src[ 2]], D_SBOX[src[15]],
    D_SBOX[src[12]], D_SBOX[src[ 9]], D_SBOX[src[ 6]], D_SBOX[src[ 3]],
  };

  COPY(dst, tmp, 16);
}

/**
 * Implement AES InvMixColumn transformation from FIPS-197, section
 * 5.3.3.
 *
 * In other words, this transformation (represented in matrix form):
 *
 *   [ b_0 ]   [ e b d 9 ] [ a_0 ]
 *   [ b_1 ] - [ 9 e b d ] [ a_1 ]
 *   [ b_2 ] - [ d 9 e b ] [ a_2 ]
 *   [ b_3 ]   [ b d 9 e ] [ a_3 ]
 *
 */
static void pt_aes_inv_mix_col(
  uint8_t dst[static restrict 4],
  const uint8_t src[static restrict 4]
) {
  const uint8_t a = src[0],
                b = src[1],
                c = src[2],
                d = src[3];

  // e b d 9
  // 9 e b d
  // d 9 e b
  // b d 9 e
  const uint8_t tmp[4] = {
    // InvMixColumn r0: e b d 9
    gmul(a, 0xe) ^ gmul(b, 0xb) ^ gmul(c, 0xd) ^ gmul(d, 0x9),

    // InvMixColumn r1: 9 e b d
    gmul(a, 0x9) ^ gmul(b, 0xe) ^ gmul(c, 0xb) ^ gmul(d, 0xd),

    // InvMixColumn r2: d 9 e b
    gmul(a, 0xd) ^ gmul(b, 0x9) ^ gmul(c, 0xe) ^ gmul(d, 0xb),

    // InvMixColumn r3: b d 9 e
    gmul(a, 0xb) ^ gmul(b, 0xd) ^ gmul(c, 0x9) ^ gmul(d, 0xe),
  };

  // copy to output
  COPY(dst, tmp, sizeof(tmp));
}

#ifdef PT_AES_TEST
void pt_aes_test_inv_mix_col(
  uint8_t dst[static restrict 4],
  const uint8_t src[static restrict 4]
) {
  pt_aes_inv_mix_col(dst, src);
}
#endif /* PT_AES_TEST */

static void pt_aes_inv_mix(
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16]
) {
  uint8_t tmp[16];

  for (int i = 0; i < 4; i++) {
    pt_aes_inv_mix_col(tmp + (4 * i), src + (4 * i));
  }

  COPY(dst, tmp, 16);
}

void pt_aes128_dec(
  uint8_t dst[static restrict 16],
  const uint8_t src[static restrict 16],
  const uint32_t key_data[static restrict 44]
) {
  uint8_t a[16], b[16];

  // add initial round key
  pt_aes128_add_round_key(a, src, key_data + 40);

  // first 9 rounds
  for (int i = 0; i < 9; i++) {
    pt_aes_dec_shift_and_sub(b, a);
    pt_aes128_add_round_key(a, b, key_data + 36 - 4 * i);
    pt_aes_inv_mix(b, a);
    COPY(a, b, 16);
  }

  // final round, copy to output
  pt_aes_dec_shift_and_sub(b, a);
  pt_aes128_add_round_key(dst, b, key_data);
}
