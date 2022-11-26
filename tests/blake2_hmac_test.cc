#include "hmac_blake2s.h"
#include "gmock/gmock.h"
#include <gtest/gtest.h>
#include <stdio.h>
#include <string.h>

using ::testing::ElementsAre;

uint8_t secret[32] = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                      2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
uint8_t salt_96[96] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

uint8_t salt_32[32] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

uint8_t expected_prk_32[32] = {
    132, 8,  2,   160, 85, 73,  181, 155, 61, 238, 5,  166, 89,  26, 120, 28,
    30,  91, 213, 124, 57, 118, 241, 44,  96, 108, 95, 64,  238, 61, 83,  137};

TEST(HMAC_blake_test, SaltLowerOrEqual32Characters) {
  uint8_t prk[32] = {0};
  BLAKE2s_hmac(&secret, 32, &salt_32, 32, (uint8_t *)&prk);

  ASSERT_THAT(prk, ElementsAre(132, 8, 2, 160, 85, 73, 181, 155, 61, 238, 5,
                               166, 89, 26, 120, 28, 30, 91, 213, 124, 57, 118,
                               241, 44, 96, 108, 95, 64, 238, 61, 83, 137));

  uint8_t x;
}

int main(int argc, char *argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}