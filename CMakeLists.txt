project(noise-xk C CXX)
cmake_minimum_required(VERSION 3.12)

set(CMAKE_BUILD_TYPE Debug)

set(LIB_DIR ${CMAKE_SOURCE_DIR}/lib)
set(LIB_DIR_BLAKE2 ${LIB_DIR}/blake2)
set(LIB_DIR_LIBSODIUM /opt/homebrew/Cellar/libsodium/1.0.18_1)
set(LIB_DIR_NOISE_XK ${LIB_DIR}/noise_xk)
set(TARGET_TESTER_DIR ${CMAKE_SOURCE_DIR}/src)

include_directories(
    ${LIB_DIR_LIBSODIUM}/include
    ${LIB_DIR_BLAKE2}
    )

add_library(blake_lib
    ${LIB_DIR_BLAKE2}/blake2-endian.h
    ${LIB_DIR_BLAKE2}/blake2b.h
    ${LIB_DIR_BLAKE2}/blake2s.h
    ${LIB_DIR_BLAKE2}/blake2b.c
    ${LIB_DIR_BLAKE2}/blake2s.c   
)

add_library(noise_xk_lib
    ${LIB_DIR_NOISE_XK}/noise_xk.h
    ${LIB_DIR_NOISE_XK}/noise_xk.c
)


add_executable(noise_xk_tester ${TARGET_TESTER_DIR}/main.c)
target_link_libraries(noise_xk_tester ${LIB_DIR_LIBSODIUM}/lib/libsodium.a blake_lib noise_xk_lib)