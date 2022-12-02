#include "hkdf_blake2s.h"
#include "hmac_blake2s.h"
#include "gmock/gmock.h"
#include <gtest/gtest.h>
#include <stdio.h>
#include <string.h>

using ::testing::ElementsAre;

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