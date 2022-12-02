cmake_minimum_required(VERSION 3.12)
cmake_policy(SET CMP0048 NEW)
project(noise-xk LANGUAGES C CXX)

set(CMAKE_BUILD_TYPE Debug)
set(LIB_DIR ${CMAKE_SOURCE_DIR}/lib)
set(LIB_BLAKE2_DIR ${LIB_DIR}/blake2)
set(LIB_LIBSODIUM_DIR /opt/homebrew/Cellar/libsodium/1.0.18_1)
set(LIB_NOISE_XK_DIR ${LIB_DIR}/noise_xk)
set(TESTS_DIR ${CMAKE_SOURCE_DIR}/tests)


# Google Test
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
include(GoogleTest)


include_directories(
    ${LIB_LIBSODIUM_DIR}/include
    ${LIB_BLAKE2_DIR}
    ${LIB_HMAC_BLAKE2_DIR}
    ${LIB_NOISE_XK_DIR}
    )

add_library(blake2_lib
    ${LIB_BLAKE2_DIR}/blake2-endian.h
    ${LIB_BLAKE2_DIR}/blake2s.h
    ${LIB_BLAKE2_DIR}/blake2s.c   
    ${LIB_BLAKE2_DIR}/hmac_blake2s.h
    ${LIB_BLAKE2_DIR}/hmac_blake2s.c
    ${LIB_BLAKE2_DIR}/hkdf_blake2s.h
    ${LIB_BLAKE2_DIR}/hkdf_blake2s.c
)

add_library(noise_xk_lib
    ${LIB_NOISE_XK_DIR}/noise_xk.h
    ${LIB_NOISE_XK_DIR}/noise_xk.c
)

# add_executable(noise_xk_tester ${TESTS_DIR}/main.c)
# target_link_libraries(noise_xk_tester ${LIB_LIBSODIUM_DIR}/lib/libsodium.a blake2_lib noise_xk_lib)

enable_testing()

add_executable(
  hmac_blake2_tests
  ${TESTS_DIR}/hmac_blake2_tests.cc
)

target_link_libraries(
  hmac_blake2_tests
  GTest::gtest_main
  GTest::gmock_main
  blake2_lib
)



add_executable(
  hkdf_blake2_tests
  ${TESTS_DIR}/hkdf_blake2_tests.cc
)

target_link_libraries(
  hkdf_blake2_tests
  GTest::gtest_main
  GTest::gmock_main
  blake2_lib
)



add_executable(
  noise_xk_tests
  ${TESTS_DIR}/noise_xk_tests.cc
)

target_link_libraries(
  noise_xk_tests
  GTest::gtest_main
  GTest::gmock_main
  noise_xk_lib
  ${LIB_LIBSODIUM_DIR}/lib/libsodium.a
  blake2_lib
)


# add_executable(
#   noisexk_blake2_test
#   ${TESTS_DIR}/hkdf_blake2_test.cc
#   ${TESTS_DIR}/hmac_blake2_test.cc
# )



# gtest_discover_tests(hmac_blake2_tests)
# gtest_discover_tests(hkdf_blake2_tests)
