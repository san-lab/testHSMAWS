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
 * Encrypt and decrypt a string using AES CBC.
 * @param session Active PKCS#11 session
 */
CK_RV aes_cbc_sample(CK_SESSION_HANDLE session) {
    CK_RV rv;

    // Generate a 256 bit AES key.
    CK_OBJECT_HANDLE aes_key;
    rv = generate_aes_key(session, 32, &aes_key);
    if (CKR_OK != rv) {
        printf("AES key generation failed: %lu\n", rv);
        return rv;
    }

    CK_BYTE_PTR plaintext = "aa";
    CK_ULONG plaintext_length = strlen(plaintext);

    printf("Plaintext: %s\n", plaintext);
    printf("Plaintext length: %lu\n", plaintext_length);

    // Prepare the mechanism 
    // The IV is hardcoded to all 0x01 bytes for this example.
    CK_BYTE iv[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    CK_MECHANISM mech = {CKM_AES_CBC_PAD, iv, 16};

    //**********************************************************************************************
    // Encrypt
    //**********************************************************************************************    

    rv = funcs->C_EncryptInit(session, &mech, aes_key);
    if (CKR_OK != rv) {
        printf("Encryption Init failed: %lu\n", rv);
        return rv;
    }

    // Determine how much memory will be required to hold the ciphertext.
    CK_ULONG ciphertext_length = 0;
    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, NULL, &ciphertext_length);
    if (CKR_OK != rv) {
        printf("Encryption failed: %lu\n", rv);
        return rv;
    }

    // Allocate the required memory.
    CK_BYTE_PTR ciphertext = malloc(ciphertext_length);
    if (NULL == ciphertext) {
        printf("Could not allocate memory for ciphertext\n");
        return rv;
    }
    memset(ciphertext, 0, ciphertext_length);
    CK_BYTE_PTR decrypted_ciphertext = NULL;

    // Encrypt the data.
    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, ciphertext, &ciphertext_length);
    if (CKR_OK != rv) {
        printf("Encryption failed: %lu\n", rv);
        goto done;
    }

    // Print just the ciphertext in hex format
    printf("Ciphertext: ");
    print_bytes_as_hex(ciphertext, ciphertext_length);
    printf("Ciphertext length: %lu\n", ciphertext_length);

done:
    if (NULL != decrypted_ciphertext) {
        free(decrypted_ciphertext);
    }

    if (NULL != ciphertext) {
        free(ciphertext);
    }
    return rv;
}

CK_RV rsa_encrypt_decrypt(CK_SESSION_HANDLE session) {
    CK_OBJECT_HANDLE encrypting_public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE decrypting_private_key = CK_INVALID_HANDLE;

    CK_RV rv = generate_rsa_keypair(session, 2048, &encrypting_public_key, &decrypting_private_key);
    if (rv != CKR_OK) {
        printf("RSA key generation failed: %lu\n", rv);
        return rv;
    }

    CK_BYTE_PTR data = "Here is some data to encrypt";
    CK_ULONG data_length = strlen(data);

    CK_BYTE ciphertext [MAX_SIGNATURE_LENGTH];
    CK_ULONG ciphertext_length = MAX_SIGNATURE_LENGTH;

    // Set the PKCS11 signature mechanism type.
    CK_MECHANISM_TYPE mechanism = CKM_RSA_PKCS;

    rv = rsa_encrypt(session, encrypting_public_key, mechanism,
                            data, data_length, ciphertext, &ciphertext_length);
    if (rv == CKR_OK) {
        unsigned char *hex_ciphertext = NULL;
        bytes_to_new_hexstring(ciphertext, ciphertext_length, &hex_ciphertext);
        if (!hex_ciphertext) {
            printf("Could not allocate hex array\n");
            return 1;
        }

        printf("Data: %s\n", data);
        printf("Ciphertext: %s\n", hex_ciphertext);
        free(hex_ciphertext);
        hex_ciphertext = NULL;
    } else {
        printf("Ciphertext generation failed: %lu\n", rv);
        return rv;
    }

    ////////DECRYPT///////

    CK_MECHANISM mech;

    mech.mechanism = mechanism;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rv = funcs->C_DecryptInit(session, &mech, decrypting_private_key);
    if (CKR_OK != rv) {
        printf("Decryption Init failed: %lu\n", rv);
        return rv;
    }

    CK_ULONG decrypted_ciphertext_length = 0;
    rv = funcs->C_Decrypt(session, ciphertext, ciphertext_length, NULL, &decrypted_ciphertext_length);
    if (CKR_OK != rv) {
        printf("Decryption failed: %lu\n", rv);
        return 1;
    }

    // Allocate memory for the decrypted ciphertext.
    CK_BYTE_PTR decrypted_ciphertext = NULL;
    decrypted_ciphertext = malloc(decrypted_ciphertext_length + 1); //We want to null terminate the raw chars later
    if (NULL == decrypted_ciphertext) {
        rv = 1;
        printf("Could not allocate memory for decrypted ciphertext\n");
        return 1;
    }

    rv = rsa_decrypt(session, decrypting_private_key, mechanism,
                          ciphertext, ciphertext_length, decrypted_ciphertext, &decrypted_ciphertext_length);
    if (rv == CKR_OK) {
        unsigned char *hex_plaintext = NULL;
        bytes_to_new_hexstring(decrypted_ciphertext, decrypted_ciphertext_length, &hex_plaintext);
        if (!hex_plaintext) {
            printf("Could not allocate hex array\n");
            return 1;
        }

        printf("Plaintext decrypted: %s\n", hex_plaintext);
        free(hex_plaintext);
        hex_plaintext = NULL;
    } else {
        printf("Decryption failed: %lu\n", rv);
        return rv;
    }

    return CKR_OK;
}

int main(int argc, char **argv) {
    CK_RV rv;
    CK_SESSION_HANDLE session;

    struct pkcs_arguments args = {};
    if (get_pkcs_args(argc, argv, &args) < 0) {
        return 1;
    }

    rv = pkcs11_initialize(args.library);
    if (CKR_OK != rv) {
        return 1;
    }
    rv = pkcs11_open_session(args.pin, &session);
    if (CKR_OK != rv) {
        return 1;
    }

    printf("\nOnly Encrypt AES\n");
    rv = aes_cbc_sample(session);
    if (CKR_OK != rv) {
        return rv;
    }

    printf("Encrypt with RSA\n");
    rv = rsa_encrypt_decrypt(session);
    if (rv != CKR_OK)
        return rv;

    pkcs11_finalize_session(session);

    return 0;
}
