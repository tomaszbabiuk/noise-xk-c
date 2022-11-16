project(HelloWorld C CXX)
cmake_minimum_required(VERSION 3.12)
include_directories(${CMAKE_SOURCE_DIR}/libsodium/include)

set(CMAKE_BUILD_TYPE Debug)

# add_library(noise
#     ${CMAKE_SOURCE_DIR}/noise_xk/NoiseXK.h
#     ${CMAKE_SOURCE_DIR}/noise_xk/NoiseXK.c
#     )

add_executable(hello_world main.c)
target_link_libraries(hello_world ${CMAKE_SOURCE_DIR}/libsodium/lib/libsodium.a)