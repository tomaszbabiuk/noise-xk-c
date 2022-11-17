project(noise-xk C CXX)
cmake_minimum_required(VERSION 3.12)

set(CMAKE_BUILD_TYPE Debug)

set(LIB_DIR ${CMAKE_SOURCE_DIR}/lib)
set(LIB_BLAKE2_DIR ${LIB_DIR}/blake2)
set(LIB_LIBSODIUM_DIR /opt/homebrew/Cellar/libsodium/1.0.18_1)
set(LIB_NOISE_XK_DIR ${LIB_DIR}/noise_xk)
set(TARGET_TESTER_DIR ${CMAKE_SOURCE_DIR}/src)

include_directories(
    ${LIB_LIBSODIUM_DIR}/include
    ${LIB_BLAKE2_DIR}
    ${LIB_NOISE_XK_DIR}
    )

add_library(blake_lib
    ${LIB_BLAKE2_DIR}/blake2-endian.h
    ${LIB_BLAKE2_DIR}/blake2b.h
    ${LIB_BLAKE2_DIR}/blake2s.h
    ${LIB_BLAKE2_DIR}/blake2b.c
    ${LIB_BLAKE2_DIR}/blake2s.c   
)

add_library(noise_xk_lib
    ${LIB_NOISE_XK_DIR}/noise_xk.h
    ${LIB_NOISE_XK_DIR}/noise_xk.c
)


add_executable(noise_xk_tester ${TARGET_TESTER_DIR}/main.c)
target_link_libraries(noise_xk_tester ${LIB_LIBSODIUM_DIR}/lib/libsodium.a blake_lib noise_xk_lib)