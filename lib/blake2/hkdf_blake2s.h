/*
 * Author: Tomasz Babiuk, License: public domain
 */

#ifndef HKDF_BLAKE2s_H
#define HKDF_BLAKE2s_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void BLAKE2s_hkdf(const void *secret, size_t secretLen, const void *salt,
                  size_t saltLen);

#ifdef __cplusplus
};
#endif

#endif
