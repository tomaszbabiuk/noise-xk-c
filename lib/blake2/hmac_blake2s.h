/*
 * Author: Tomasz Babiuk, License: public domain
 */

#ifndef HMAC_BLAKE2b_H
#define HMAC_BLAKE2b_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void BLAKE2b_hmac(const uint8_t *secret, size_t secretLen, const uint8_t *salt,
                  size_t saltLen, uint8_t *prk);

#ifdef __cplusplus
};
#endif

#endif
