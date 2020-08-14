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

/**
 * Read an RSA public key into an RSA structure.
 * @param path
 * @return
 */
RSA *read_RSA_PUBKEY(char *path)
{
    /* Read RSA Pub Key */
    RSA *rsa = RSA_new();
    if (rsa == NULL) {
        fprintf(stderr, "Failed to allocate RSA struct.\n%s\n", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    BIO *pubin = BIO_new_file(path, "r");
    if (pubin == NULL) {
        fprintf(stderr, "Failed to open RSA Pub Key, %s\n%s\n", path, ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    if (!PEM_read_bio_RSA_PUBKEY(pubin, &rsa, NULL, NULL)) {
        fprintf(stderr, "Failed to read RSA pub key.\n%s\n", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    BIO_free(pubin);

    return rsa;
}

int import_RSA_PUBKEY(CK_SESSION_HANDLE session,
                        char *path,
                        CK_OBJECT_HANDLE_PTR public_key) {
    CK_RV rv;
    int rc = 1;

    /* Read the pem file into an RSA struct to we can access the exponent and modulus */
    RSA *key = read_RSA_PUBKEY(path);
    if (NULL==key) {
        fprintf(stderr, "Could not read the RSA key\n");
        return rc;
    }

    CK_ULONG pub_exp_len = BN_num_bytes(key->e);
    CK_BYTE *pub_exp = malloc(pub_exp_len);
    if (pub_exp == NULL) {
        fprintf(stderr, "Failed to allocate memory for exponent: %s\n", strerror(errno));
        return rc;
    }
    BN_bn2bin(key->e, pub_exp);

    CK_ULONG modulus_len = BN_num_bytes(key->n);
    CK_BYTE *modulus = malloc(modulus_len);
    if (modulus == NULL) {
        fprintf(stderr, "Failed to allocate memory for modulus: %s\n", strerror(errno));
        return rc;
    }
    BN_bn2bin(key->n, modulus);

    RSA_free(key);

    /* Using the modulus and exponent from above, we can "import" the key by creating
     * an object with the appropriate attributes.
     */
    CK_OBJECT_CLASS pub_key_class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;

    CK_ATTRIBUTE pub_tmpl[] = {
            {CKA_KEY_TYPE,        &key_type,      sizeof(key_type)},
            {CKA_CLASS,           &pub_key_class, sizeof(pub_key_class)},
            {CKA_MODULUS,         modulus,        modulus_len},
            {CKA_PUBLIC_EXPONENT, pub_exp,        pub_exp_len},
            {CKA_TOKEN,           &true_val,      sizeof(CK_BBOOL)},
            {CKA_ENCRYPT,         &true_val,      sizeof(CK_BBOOL)}
    };
    rv = funcs->C_CreateObject(session, pub_tmpl, sizeof(pub_tmpl) / sizeof(CK_ATTRIBUTE), public_key);
    if (CKR_OK != rv) {
        fprintf(stderr, "Failed to create object %lu\n", rv);
        return rc;
    }

    return rv;
}

int write_RSA_PUBKEY(char *path, RSA rsa)
{
    /* Write RSA Pub Key */
    printf("Entro al write RSA_PUBKEY\n");

    BIO *pubout = BIO_new_file(path, "w");
    if (pubout == NULL) {
        fprintf(stderr, "Failed to open RSA Pub Key, %s\n%s\n", path, ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

    if (!PEM_write_bio_RSAPublicKey(pubout, &rsa)) {
        fprintf(stderr, "Failed to write RSA pub key.\n%s\n", ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

    return 0;
}

int export_RSA_PUBKEY(CK_SESSION_HANDLE session,
                        char *path,
                        CK_OBJECT_HANDLE_PTR public_key) {
    CK_RV rv;
    int rc = 1;

    CK_ATTRIBUTE pub_tmpl[] = {
            {CKA_MODULUS,         NULL,        0},
            {CKA_PUBLIC_EXPONENT, NULL,        0},
    };

    rv = funcs->C_GetAttributeValue(session, *public_key, pub_tmpl, 2);

    if (rv == CKR_OK) {
        CK_BYTE_PTR pModulus, pExponent;
        pModulus = (CK_BYTE_PTR) malloc(pub_tmpl[0].ulValueLen);
        pub_tmpl[0].pValue = pModulus;
        /* template[0].ulValueLen was set by C_GetAttributeValue */
         
        pExponent = (CK_BYTE_PTR) malloc(pub_tmpl[1].ulValueLen);
        pub_tmpl[1].pValue = pExponent;
        /* template[1].ulValueLen was set by C_GetAttributeValue */
         
        rv = funcs->C_GetAttributeValue(session, *public_key, pub_tmpl, 2);
    }
    else {
        fprintf(stderr, "Failed to create object %lu\n", rv);
        return rc;
    }

    RSA *pub_key = RSA_new();
    BN_bin2bn(pub_tmpl[0].pValue, pub_tmpl[0].ulValueLen ,pub_key->e);
    printf("After first var\n");
    BN_bin2bn(pub_tmpl[1].pValue, pub_tmpl[1].ulValueLen ,pub_key->n);
    printf("After setting vars\n");

    rv = write_RSA_PUBKEY(path, *pub_key);

    return rv;
}

/**
 * Read an RSA private key into an RSA structure.
 * @param path
 * @return
 */
RSA *read_RSA_PRIVKEY(char *path)
{
    /* Read RSA Priv Key */
    RSA *rsa = RSA_new();
    if (rsa == NULL) {
        fprintf(stderr, "Failed to allocate RSA struct.\n%s\n", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    BIO *privin = BIO_new_file(path, "r");
    if (privin == NULL) {
        fprintf(stderr, "Failed to open RSA Priv Key, %s\n%s\n", path, ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    if (!PEM_read_bio_RSAPrivateKey(privin, &rsa, NULL, NULL)) {
        fprintf(stderr, "Failed to read RSA priv key.\n%s\n", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    BIO_free(privin);

    return rsa;
}

int import_RSA_PRIVKEY(CK_SESSION_HANDLE session,
                        char *path,
                        CK_OBJECT_HANDLE_PTR private_key) {
    CK_RV rv;
    int rc = 1;

    /* Read the pem file into an RSA struct to we can access the exponent and modulus */
    RSA *key = read_RSA_PRIVKEY(path);
    if (NULL==key) {
        fprintf(stderr, "Could not read the RSA key\n");
        return rc;
    }

    CK_ULONG pub_exp_len = BN_num_bytes(key->e);
    CK_BYTE *pub_exp = malloc(pub_exp_len);
    if (pub_exp == NULL) {
        fprintf(stderr, "Failed to allocate memory for public exponent: %s\n", strerror(errno));
        return rc;
    }
    BN_bn2bin(key->e, pub_exp);

    CK_ULONG priv_exp_len = BN_num_bytes(key->d);
    CK_BYTE *priv_exp = malloc(priv_exp_len);
    if (priv_exp == NULL) {
        fprintf(stderr, "Failed to allocate memory for private exponent: %s\n", strerror(errno));
        return rc;
    }
    BN_bn2bin(key->d, priv_exp);

    CK_ULONG modulus_len = BN_num_bytes(key->n);
    CK_BYTE *modulus = malloc(modulus_len);
    if (modulus == NULL) {
        fprintf(stderr, "Failed to allocate memory for modulus: %s\n", strerror(errno));
        return rc;
    }
    BN_bn2bin(key->n, modulus);

    RSA_free(key);

    /* Using the modulus and exponent from above, we can "import" the key by creating
     * an object with the appropriate attributes.
     */
    CK_OBJECT_CLASS priv_key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;

    CK_ATTRIBUTE priv_tmpl[] = {
            {CKA_KEY_TYPE,        &key_type,      sizeof(key_type)},
            {CKA_CLASS,           &priv_key_class,sizeof(priv_key_class)},
            {CKA_MODULUS,         modulus,        modulus_len},
            {CKA_PUBLIC_EXPONENT, pub_exp,        pub_exp_len},
            {CKA_PRIVATE_EXPONENT,priv_exp,       priv_exp_len},
            {CKA_TOKEN,           &true_val,      sizeof(CK_BBOOL)},
            {CKA_DECRYPT,         &true_val,      sizeof(CK_BBOOL)}
    };
    rv = funcs->C_CreateObject(session, priv_tmpl, sizeof(priv_tmpl) / sizeof(CK_ATTRIBUTE), private_key);
    if (CKR_OK != rv) {
        fprintf(stderr, "Failed to create object %lu\n", rv);
        return rc;
    }

    return rv;
}

int write_RSA_PRIVKEY(char *path, RSA rsa)
{
    /* Write RSA Pub Key */

    BIO *privout = BIO_new_file(path, "w");
    if (privout == NULL) {
        fprintf(stderr, "Failed to open RSA Pub Key, %s\n%s\n", path, ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }

    if (!PEM_write_bio_RSAPrivateKey(privout, &rsa, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Failed to write RSA priv key.\n%s\n", ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }

    return 1;
}

int export_RSA_PRIVKEY(CK_SESSION_HANDLE session,
                        char *path,
                        CK_OBJECT_HANDLE_PTR private_key) {
    CK_RV rv;
    int rc = 1;

    CK_ATTRIBUTE priv_tmpl[] = {
            {CKA_MODULUS,           NULL,        0},
            {CKA_PUBLIC_EXPONENT,   NULL,        0},
            {CKA_PRIVATE_EXPONENT,  NULL,        0},
    };

    rv = funcs->C_GetAttributeValue(session, *private_key, priv_tmpl, 2);
    if (rv == CKR_OK) {
        CK_BYTE_PTR pModulus, pExponent, privExponent;
        pModulus = (CK_BYTE_PTR) malloc(priv_tmpl[0].ulValueLen);
        priv_tmpl[0].pValue = pModulus;
         
        pExponent = (CK_BYTE_PTR) malloc(priv_tmpl[1].ulValueLen);
        priv_tmpl[1].pValue = pExponent;

        privExponent = (CK_BYTE_PTR) malloc(priv_tmpl[2].ulValueLen);
        priv_tmpl[2].pValue = privExponent;
         
        rv = funcs->C_GetAttributeValue(session, *private_key, priv_tmpl, 2);
    }
    else {
        fprintf(stderr, "Failed to create object %lu\n", rv);
        return rc;
    }

    RSA *priv_key = RSA_new();
    priv_key->e = BN_bin2bn(priv_tmpl[0].pValue, priv_tmpl[0].ulValueLen , NULL);
    BN_bin2bn(priv_tmpl[1].pValue, priv_tmpl[1].ulValueLen ,priv_key->n);
    BN_bin2bn(priv_tmpl[2].pValue, priv_tmpl[2].ulValueLen ,priv_key->d);

    if (priv_key->e == NULL){
        printf("Not initialized\n");
    }

    rv = write_RSA_PRIVKEY(path, *priv_key);

    return rv;
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
    CK_MECHANISM mech;

    mech.mechanism = mechanism;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rv = funcs->C_EncryptInit(session, &mech, key);
    if (rv != CKR_OK) {
        return !CKR_OK;
    }

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

    rv = funcs->C_Decrypt(session, ciphertext, ciphertext_length, data, data_length);
    return rv;
}