/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
    Cut-down BLAKE2b implementation, starting with the version from arduinolibs:

    https://github.com/rweather/arduinolibs
*/

#include "hmac_blake2s.h"
#include "blake2s.h"
#include <string.h>

void BLAKE2b_hmac(const uint8_t *secret, size_t secretLen, const uint8_t *salt,
                  size_t saltLen, uint8_t *prk) {
  BLAKE2s_context_t hashContext;
  uint8_t hashedSalt[64] = {0};

  uint8_t k_ipad[64] = {0};
  uint8_t k_opad[64] = {0};
  uint8_t digest[32] = {0};
  memset(&k_ipad, 0x36, 64);
  memset(&k_opad, 0x5c, 64);

  uint8_t *saltToTake = salt;

  if (saltLen > 64) {
    BLAKE2s_reset(&hashContext);
    BLAKE2s_update(&hashContext, salt, saltLen);
    BLAKE2s_finish(&hashContext, hashedSalt);
    saltToTake = hashedSalt;
  }

  for (size_t i = 0; i < saltLen; i++) {
    k_ipad[i] = saltToTake[i] ^ 0x36;
    k_opad[i] = saltToTake[i] ^ 0x5c;
  }

  BLAKE2s_reset(&hashContext);
  BLAKE2s_update(&hashContext, k_ipad, 64);
  BLAKE2s_update(&hashContext, secret, secretLen);
  BLAKE2s_finish(&hashContext, digest);

  BLAKE2s_reset(&hashContext);
  BLAKE2s_update(&hashContext, k_opad, 64);
  BLAKE2s_update(&hashContext, digest, 32);
  BLAKE2s_finish(&hashContext, prk);
}
