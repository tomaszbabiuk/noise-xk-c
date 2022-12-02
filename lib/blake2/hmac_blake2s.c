/*
 * Author: Tomasz Babiuk, License: public domain
 */

#include "hmac_blake2s.h"
#include "blake2s.h"
#include "hkdf_blake2s.h"
#include <string.h>

void HMAC_BLAKE2s_reset(HMAC_BLAKE2s_context_t *hmacContext, const void *salt,
                        size_t saltLen) {
  uint8_t hashedSalt[64] = {0};
  memset(hashedSalt, 0, BLOCKSIZE);

  memset(&hmacContext->ipad, IPAD_PATTERN, BLOCKSIZE);
  memset(&hmacContext->opad, OPAD_PATTERN, BLOCKSIZE);

  uint8_t *saltToTake = (uint8_t *)salt;

  if (saltLen > BLOCKSIZE) {
    BLAKE2s_context_t hashContext;
    BLAKE2s_reset(&hashContext);
    BLAKE2s_update(&hashContext, salt, saltLen);
    BLAKE2s_finish(&hashContext, hashedSalt);
    saltToTake = hashedSalt;
  }

  for (size_t i = 0; i < HASHSIZE; i++) {
    hmacContext->ipad[i] = saltToTake[i] ^ IPAD_PATTERN;
    hmacContext->opad[i] = saltToTake[i] ^ OPAD_PATTERN;
  }

  BLAKE2s_reset(&hmacContext->hashContext);
  BLAKE2s_update(&hmacContext->hashContext, &hmacContext->ipad, BLOCKSIZE);
}

void HMAC_BLAKE2s_update(HMAC_BLAKE2s_context_t *hmacContext,
                         const void *secret, size_t secretLen) {
  BLAKE2s_update(&hmacContext->hashContext, secret, secretLen);
}

void HMAC_BLAKE2s_sum(HMAC_BLAKE2s_context_t *hmacContext, uint8_t *out) {
  uint8_t digest[HASHSIZE] = {0};
  memset(digest, 0, HASHSIZE);
  BLAKE2s_finish(&hmacContext->hashContext, digest);

  BLAKE2s_context_t hashContext;
  BLAKE2s_reset(&hashContext);
  BLAKE2s_update(&hashContext, &hmacContext->opad, BLOCKSIZE);
  BLAKE2s_update(&hashContext, digest, HASHSIZE);
  BLAKE2s_finish(&hashContext, out);
}

void HMAC_BLAKE2s_alltogether(const void *secret, size_t secretLen,
                              const void *salt, size_t saltLen, uint8_t *out) {
  HMAC_BLAKE2s_context_t hmacContext;

  HMAC_BLAKE2s_reset(&hmacContext, salt, saltLen);
  HMAC_BLAKE2s_update(&hmacContext, secret, secretLen);
  HMAC_BLAKE2s_sum(&hmacContext, out);

  /*
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

    // init
    BLAKE2s_reset(&hashContext);
    BLAKE2s_update(&hashContext, ipad, BLOCKSIZE);

    // update
    BLAKE2s_update(&hashContext, secret, secretLen);

    // finish
    BLAKE2s_finish(&hashContext, digest);
    BLAKE2s_reset(&hashContext);
    BLAKE2s_update(&hashContext, opad, BLOCKSIZE);
    BLAKE2s_update(&hashContext, digest, HASHSIZE);
    BLAKE2s_finish(&hashContext, out);*/
}