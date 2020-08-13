cmake_minimum_required(VERSION 2.8)
project(LRS)

find_library(cloudhsmpkcs11 STATIC)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(LRS LRS.c LRS_lib.c)

target_link_libraries(LRS cloudhsmpkcs11 ssl crypto)

add_test(LRS LRS --pin ${HSM_USER}:${HSM_PASSWORD}) 
