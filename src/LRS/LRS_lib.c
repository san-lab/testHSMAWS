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
#include <stdio.h>
#include "LRS_lib.h"

/**
 * Generate an AES key with a template suitable for encrypting data.
 * The key is a Session key, and will be deleted once the HSM Session is closed.
 * @param session Active PKCS#11 session
 * @param key_length 16, 24, or 32 bytes
 * @param key Location where the key's handle will be written
 * @return CK_RV
 */
CK_RV generate_aes_key(CK_SESSION_HANDLE session,
                       CK_ULONG key_length_bytes,
                       CK_OBJECT_HANDLE_PTR key) {
    CK_MECHANISM mech;

    mech.mechanism = CKM_AES_KEY_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    CK_ATTRIBUTE template[] = {
            {CKA_TOKEN,       &false_val,            sizeof(CK_BBOOL)},
            {CKA_EXTRACTABLE, &true_val,             sizeof(CK_BBOOL)},
            {CKA_ENCRYPT,     &true_val,             sizeof(CK_BBOOL)},
            {CKA_DECRYPT,     &true_val,             sizeof(CK_BBOOL)},
            {CKA_VALUE_LEN,   &key_length_bytes, sizeof(CK_ULONG)},
    };

    return funcs->C_GenerateKey(session, &mech, template, sizeof(template) / sizeof(CK_ATTRIBUTE), key);
}

CK_RV generate_rsa_keypair(CK_SESSION_HANDLE session,
                           CK_ULONG key_length_bits,
                           CK_OBJECT_HANDLE_PTR public_key,
                           CK_OBJECT_HANDLE_PTR private_key) {
    CK_RV rv;
    CK_MECHANISM mech;
    CK_BYTE public_exponent[] = {0x01, 0x00, 0x01};

    mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;
    CK_KEY_TYPE keyTypePub = CKK_RSA;
    CK_KEY_TYPE keyTypePriv = CKK_RSA;

    /*CK_ATTRIBUTE public_key_template[] = {
            {CKA_DECRYPT,          &true_val,            sizeof(CK_BBOOL)},
            {CKA_MODULUS_BITS,    &key_length_bits, sizeof(CK_ULONG)},
            {CKA_PUBLIC_EXPONENT, &public_exponent, sizeof(public_exponent)},
    };

    CK_ATTRIBUTE private_key_template[] = {
            {CKA_ENCRYPT, &true_val, sizeof(CK_BBOOL)},
    };*/

    CK_ATTRIBUTE public_key_template[] = {
       {CKA_KEY_TYPE,           &keyTypePub,           sizeof(keyTypePub)},
       {CKA_TOKEN,              &false_val,            sizeof(CK_BBOOL)},
       {CKA_ENCRYPT,            &true_val,             sizeof(CK_BBOOL)},
       {CKA_MODULUS_BITS,       &key_length_bits,      sizeof(CK_ULONG)},
       {CKA_PUBLIC_EXPONENT,    &public_exponent,      sizeof(public_exponent)},
    };

    CK_ATTRIBUTE private_key_template[] = {
      {CKA_KEY_TYPE,       &keyTypePriv,          sizeof(keyTypePriv)},
      {CKA_TOKEN,          &false_val,            sizeof(CK_BBOOL)},
      {CKA_DECRYPT,        &true_val,             sizeof(CK_BBOOL)},
    };

    rv = funcs->C_GenerateKeyPair(session,
                                  &mech,
                                  public_key_template, sizeof(public_key_template) / sizeof(CK_ATTRIBUTE),
                                  private_key_template, sizeof(private_key_template) / sizeof(CK_ATTRIBUTE),
                                  public_key,
                                  private_key);
    return rv;
}

CK_RV rsa_encrypt(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE key,
                                CK_MECHANISM_TYPE mechanism,
                                CK_BYTE_PTR data,
                                CK_ULONG data_length,
                                CK_BYTE_PTR ciphertext,
                                CK_ULONG_PTR ciphertext_length) {
    CK_RV rv;

    rv = funcs->C_Encrypt(session, data, data_length, ciphertext, ciphertext_length);
    return rv;
}

CK_RV rsa_decrypt(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE key,
                                CK_MECHANISM_TYPE mechanism,
                                CK_BYTE_PTR ciphertext,
                                CK_ULONG ciphertext_length,
                                CK_BYTE_PTR data,
                                CK_ULONG_PTR data_length) {
    CK_RV rv;
    CK_MECHANISM mech;

    mech.mechanism = mechanism;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rv = funcs->C_DecryptInit(session, &mech, key);
    if (rv != CKR_OK) {
        return !CKR_OK;
    }

    rv = funcs->C_Decrypt(session, ciphertext, ciphertext_length, data, data_length);
    return rv;
}