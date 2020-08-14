/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef PKCS11_EXAMPLES_ENCRYPT_AES_H
#define PKCS11_EXAMPLES_ENCRYPT_AES_H

#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/pem.h>
#include <openssl/err.h>

#include <common.h>

#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16

CK_RV generate_aes_key(CK_SESSION_HANDLE session,
                       CK_ULONG key_length_bytes,
                       CK_OBJECT_HANDLE_PTR key);

CK_RV generate_rsa_keypair(CK_SESSION_HANDLE session,
                           CK_ULONG key_length_bits,
                           CK_OBJECT_HANDLE_PTR public_key,
                           CK_OBJECT_HANDLE_PTR private_key);

CK_RV rsa_encrypt(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE key,
                                CK_MECHANISM_TYPE mechanism,
                                CK_BYTE_PTR data,
                                CK_ULONG data_length,
                                CK_BYTE_PTR ciphertext,
                                CK_ULONG_PTR ciphertext_length);

CK_RV rsa_decrypt(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE key,
                                CK_MECHANISM_TYPE mechanism,
                                CK_BYTE_PTR ciphertext,
                                CK_ULONG ciphertext_length,
                                CK_BYTE_PTR data,
                                CK_ULONG_PTR data_length);

RSA *read_RSA_PUBKEY(char *path);

int import_RSA_PUBKEY(CK_SESSION_HANDLE session,
                        char *path,
                        CK_OBJECT_HANDLE_PTR public_key);

void *write_RSA_PUBKEY(char *path, RSA rsa);

int export_RSA_PUBKEY(CK_SESSION_HANDLE session,
                        char *path,
                        CK_OBJECT_HANDLE_PTR public_key);

RSA *read_RSA_PRIVKEY(char *path);

int import_RSA_PRIVKEY(CK_SESSION_HANDLE session,
                        char *path,
                        CK_OBJECT_HANDLE_PTR private_key);

void *write_RSA_PRIVKEY(char *path, RSA rsa);

int export_RSA_PRIVKEY(CK_SESSION_HANDLE session,
                        char *path,
                        CK_OBJECT_HANDLE_PTR private_key);

#endif //PKCS11_EXAMPLES_ENCRYPT_AES_H
