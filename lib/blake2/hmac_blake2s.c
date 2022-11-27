/*
 * Author: Tomasz Babiuk, License: public domain
 */

#include "hmac_blake2s.h"
#include "blake2s.h"
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