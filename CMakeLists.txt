project(noise-xk C CXX)
cmake_minimum_required(VERSION 3.12)

set(CMAKE_BUILD_TYPE Debug)

set(LIB_DIR ${CMAKE_SOURCE_DIR}/lib)
set(LIB_DIR_BLAKE2 ${LIB_DIR}/blake2)
set(LIB_DIR_LIBSODIUM ${LIB_DIR}/libsodium)
set(LIB_DIR_NOISE_XK ${LIB_DIR}/noise_xk)

include_directories(
    ${LIB_DIR_LIBSODIUM}/include
    ${LIB_DIR_BLAKE2}
    )


# add_library(noise
#     ${CMAKE_SOURCE_DIR}/noise_xk/NoiseXK.h
#     ${CMAKE_SOURCE_DIR}/noise_xk/NoiseXK.c
#     )


add_library(blake
    ${LIB_DIR_BLAKE2}/blake2-endian.h
    ${LIB_DIR_BLAKE2}/blake2b.h
    ${LIB_DIR_BLAKE2}/blake2s.h
    ${LIB_DIR_BLAKE2}/blake2b.c
    ${LIB_DIR_BLAKE2}/blake2s.c
)

add_executable(noise_xk main.c)
target_link_libraries(noise_xk ${LIB_DIR_LIBSODIUM}/lib/libsodium.a blake)