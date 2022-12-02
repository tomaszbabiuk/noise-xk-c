/*
 * Author: Tomasz Babiuk, License: public domain
 */

#ifndef HMAC_BLAKE2s_H
#define HMAC_BLAKE2s_H

#include "blake2s.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BLOCKSIZE 64
#define HASHSIZE 32
#define IPAD_PATTERN 0x36
#define OPAD_PATTERN 0x5C

typedef struct {
  BLAKE2s_context_t hashContext;
  uint8_t ipad[BLOCKSIZE];
  uint8_t opad[BLOCKSIZE];
} HMAC_BLAKE2s_context_t;

void HMAC_BLAKE2s_alltogether(const void *secret, size_t secretLen,
                              const void *salt, size_t saltLen, uint8_t *out);

void HMAC_BLAKE2s_reset(HMAC_BLAKE2s_context_t *hmacContext, const void *salt,
                        size_t saltLen);

void HMAC_BLAKE2s_update(HMAC_BLAKE2s_context_t *hmacContext,
                         const void *secret, size_t secretLen);

void HMAC_BLAKE2s_sum(HMAC_BLAKE2s_context_t *hmacContext, uint8_t *out);

#ifdef __cplusplus
};
#endif

#endif
