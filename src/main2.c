#include "hmac_blake2s.h"
#include <stdio.h>
#include <string.h>

uint8_t secret[32] = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                      2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
uint8_t salt[32] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

#define BLAKE2s_BLOCK_SIZE = 64

int main() {

  uint8_t prs[128] = {0};
  BLAKE2b_hmac(&secret, 32, &salt, 32, &prs);

  printf("Hello Noise XK");
}