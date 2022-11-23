project(noise-xk C CXX)
cmake_minimum_required(VERSION 3.12)

set(CMAKE_BUILD_TYPE Debug)
set(LIB_DIR ${CMAKE_SOURCE_DIR}/lib)
set(LIB_BLAKE2_DIR ${LIB_DIR}/blake2)
set(LIB_LIBSODIUM_DIR /opt/homebrew/Cellar/libsodium/1.0.18_1)
set(LIB_NOISE_XK_DIR ${LIB_DIR}/noise_xk)
set(TARGET_TESTER_DIR ${CMAKE_SOURCE_DIR}/src)


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
)

add_library(noise_xk_lib
    ${LIB_NOISE_XK_DIR}/noise_xk.h
    ${LIB_NOISE_XK_DIR}/noise_xk.c
)

add_executable(noise_xk_tester ${TARGET_TESTER_DIR}/main.c)
target_link_libraries(noise_xk_tester ${LIB_LIBSODIUM_DIR}/lib/libsodium.a blake2_lib noise_xk_lib)


enable_testing()
add_executable(tester_hmac ${TARGET_TESTER_DIR}/tester_hmac.c)
target_link_libraries(tester_hmac blake2_lib)
add_test(Tester tester)


add_executable(
  blake2_test
  src/blake2_hmac_test.cc
)

target_link_libraries(
  blake2_test
  GTest::gtest_main
)

gtest_discover_tests(blake2_test)
