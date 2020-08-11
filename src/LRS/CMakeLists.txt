cmake_minimum_required(VERSION 2.8)
project(encrypt)

find_library(cloudhsmpkcs11 STATIC)

add_executable(LRS LRS.c LRS_lib.c)

target_link_libraries(LRS cloudhsmpkcs11)

add_test(LRS LRS --pin ${HSM_USER}:${HSM_PASSWORD}) 
