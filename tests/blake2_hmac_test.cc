#include "hkdf_blake2s.h"
#include "hmac_blake2s.h"
#include "gmock/gmock.h"
#include <gtest/gtest.h>
#include <stdio.h>
#include <string.h>

using ::testing::ElementsAre;

TEST(HMAC_blake_test, SaltLowerOrEqual32Characters) {
  uint8_t prk[32] = {0};
  uint8_t salt[32] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  uint8_t secret[32] = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
  BLAKE2s_hmac(&secret, 32, &salt, 32, (uint8_t *)&prk);

  ASSERT_THAT(prk, ElementsAre(132, 8, 2, 160, 85, 73, 181, 155, 61, 238, 5,
                               166, 89, 26, 120, 28, 30, 91, 213, 124, 57, 118,
                               241, 44, 96, 108, 95, 64, 238, 61, 83, 137));

  uint8_t x;
}

TEST(HMAC_blake_test, SaltGreaterThan64Characters) {
  uint8_t prk[32] = {0};
  uint8_t salt[96] = {
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  uint8_t secret[32] = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

  BLAKE2s_hmac(&secret, 32, &salt, 96, (uint8_t *)&prk);

  ASSERT_THAT(prk,
              ElementsAre(234, 155, 121, 119, 132, 46, 216, 79, 204, 63, 97,
                          232, 210, 66, 146, 87, 180, 205, 164, 20, 174, 160,
                          139, 76, 105, 85, 142, 41, 233, 182, 74, 35));

  uint8_t x;
}

TEST(HKDF_blake_test, BasicHkdf) {
  uint8_t secret[32] = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
  uint8_t salt[32] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  BLAKE2s_hkdf(&secret, 32, &salt, 32);
}

int main(int argc, char *argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}