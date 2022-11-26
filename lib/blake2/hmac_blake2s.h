/*
 * Author: Tomasz Babiuk, License: public domain
 */

#ifndef HMAC_BLAKE2s_H
#define HMAC_BLAKE2s_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void BLAKE2s_hmac(const void *secret, size_t secretLen, const void *salt,
                  size_t saltLen, uint8_t *prk);

#ifdef __cplusplus
};
#endif

#endif
