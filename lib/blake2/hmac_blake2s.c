/*
 * Author: Tomasz Babiuk, License: public domain
 */

#include "hmac_blake2s.h"
#include "blake2s.h"
#include "hkdf_blake2s.h"
#include <string.h>

#define BLOCKSIZE 64
#define HASHSIZE 32
#define IPAD_PATTERN 0x36
#define OPAD_PATTERN 0x5C

void BLAKE2s_hmac(const void *secret, size_t secretLen, const void *salt,
                  size_t saltLen, uint8_t *out) {
  BLAKE2s_context_t hashContext;
  uint8_t hashedSalt[64] = {0};

  uint8_t ipad[BLOCKSIZE] = {0};
  uint8_t opad[BLOCKSIZE] = {0};
  uint8_t digest[HASHSIZE] = {0};
  memset(&ipad, IPAD_PATTERN, BLOCKSIZE);
  memset(&opad, OPAD_PATTERN, BLOCKSIZE);

  uint8_t *saltToTake = (uint8_t *)salt;

  if (saltLen > BLOCKSIZE) {
    BLAKE2s_reset(&hashContext);
    BLAKE2s_update(&hashContext, salt, saltLen);
    BLAKE2s_finish(&hashContext, hashedSalt);
    saltToTake = hashedSalt;
  }

  for (size_t i = 0; i < HASHSIZE; i++) {
    ipad[i] = saltToTake[i] ^ IPAD_PATTERN;
    opad[i] = saltToTake[i] ^ OPAD_PATTERN;
  }

  BLAKE2s_reset(&hashContext);
  BLAKE2s_update(&hashContext, ipad, BLOCKSIZE);
  BLAKE2s_update(&hashContext, secret, secretLen);
  BLAKE2s_finish(&hashContext, digest);

  BLAKE2s_reset(&hashContext);
  BLAKE2s_update(&hashContext, opad, BLOCKSIZE);
  BLAKE2s_update(&hashContext, digest, HASHSIZE);
  BLAKE2s_finish(&hashContext, out);
}

void BLAKE2s_hkdf(const void *secret, size_t secretLen, const void *salt,
                  size_t saltLen) {
  uint8_t prk[32];
  BLAKE2s_hmac(secret, secretLen, salt, saltLen, prk);

  uint8_t blockN[32];
  memset(&blockN, 0, 32);

  uint8_t info[0];

  uint8_t i[1] = {0};
  uint8_t out[32];

  BLAKE2s_context_t hashContext;
  BLAKE2s_reset(&hashContext);
  BLAKE2s_update(&hashContext, prk, HASHSIZE);
  BLAKE2s_update(&hashContext, blockN, HASHSIZE);
  BLAKE2s_update(&hashContext, info, 0);
  BLAKE2s_update(&hashContext, i, 1);
  BLAKE2s_finish(&hashContext, out);

  //[]uint8 len: 32, cap: 32,
  //[200,199,89,86,174,155,128,172,253,172,87,226,175,4,236,141,40,56,167,23,38,90,184,132,174,91,158,131,36,217,201,51]
}