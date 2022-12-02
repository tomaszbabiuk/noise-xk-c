/*
 * Author: Tomasz Babiuk, License: public domain
 */

#include "hkdf_blake2s.h"
#include "blake2s.h"
#include "hmac_blake2s.h"
#include <string.h>

#define HASHSIZE 32

void BLAKE2s_hkdf(const void *secret, size_t secretLen, const void *salt,
                  size_t saltLen) {
  // uint8_t prk[32];
  // BLAKE2s_hmac(secret, secretLen, salt, saltLen, prk);

  // uint8_t blockN[32];
  // memset(&blockN, 0, 32);

  // uint8_t info[0];

  // uint8_t i[1] = {0};
  // uint8_t out[32];

  // BLAKE2s_context_t hashContext;
  // BLAKE2s_reset(&hashContext);
  // BLAKE2s_update(&hashContext, prk, HASHSIZE);
  // BLAKE2s_update(&hashContext, blockN, HASHSIZE);
  // BLAKE2s_update(&hashContext, info, 0);
  // BLAKE2s_update(&hashContext, i, 1);
  // BLAKE2s_finish(&hashContext, out);

  //[]uint8 len: 32, cap: 32,
  //[200,199,89,86,174,155,128,172,253,172,87,226,175,4,236,141,40,56,167,23,38,90,184,132,174,91,158,131,36,217,201,51]
}