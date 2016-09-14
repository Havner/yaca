/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Krzysztof Jackiewicz <k.jackiewicz@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */

/**
 * @file   yaca_simple.h
 * @brief  Simple API.
 *
 * @details  This is simple API.
 *           Design constraints:
 *           - All operations are single-shot (no streaming possible)
 *           - Context is not used
 *           - Only digest, signatures and symmetric ciphers are supported
 *           - Disabling PKCS#7 padding for ECB and CBC chaining is not supported
 *           - Changing the default PKCS#1 padding for sign/verify is not supported
 *           - GCM and CCM chaining is not supported
 *           - RC2 effective key bits property is not supported
 *           - All outputs are allocated by the library
 */

#ifndef YACA_SIMPLE_H
#define YACA_SIMPLE_H

#include <stddef.h>
#include <yaca_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup CAPI_YACA_SIMPLE_MODULE
 * @{
 */

/**
 * @brief  Encrypts data using a symmetric cipher.
 *
 * @since_tizen 3.0
 *
 * @remarks  yaca_simple_encrypt() doesn't support #YACA_BCM_GCM and #YACA_BCM_CCM
 *
 * @remarks  The @a ciphertext should be freed using yaca_free()
 *
 * @remarks  The @a plaintext can be NULL but then @a plaintext_len must be 0
 *
 * @param[in]  algo            Encryption algorithm (select #YACA_ENCRYPT_AES if unsure)
 * @param[in]  bcm             Chaining mode (select #YACA_BCM_CBC if unsure)
 * @param[in]  sym_key         Symmetric encryption key (see yaca_key.h for key generation functions)
 * @param[in]  iv              Initialization Vector
 * @param[in]  plaintext       Plaintext to be encrypted
 * @param[in]  plaintext_len   Length of the plaintext
 * @param[out] ciphertext      Encrypted data, will be allocated by the library
 * @param[out] ciphertext_len  Length of the encrypted data (may be larger than decrypted)
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0
 *                                       invalid algo, bcm, sym_key or iv)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_encrypt_algorithm_e
 * @see #yaca_block_cipher_mode_e
 * @see yaca_simple_decrypt()
 * @see yaca_free()
 */
int yaca_simple_encrypt(yaca_encrypt_algorithm_e algo,
                        yaca_block_cipher_mode_e bcm,
                        const yaca_key_h sym_key,
                        const yaca_key_h iv,
                        const char *plaintext,
                        size_t plaintext_len,
                        char **ciphertext,
                        size_t *ciphertext_len);

/**
 * @brief  Decrypts data using a symmetric cipher.
 *
 * @since_tizen 3.0
 *
 * @remarks  yaca_simple_decrypt() doesn't support #YACA_BCM_GCM and #YACA_BCM_CCM
 *
 * @remarks  The @a plaintext should be freed using yaca_free()
 *
 * @remarks  The @a ciphertext can be NULL but then @a ciphertext_len must be 0
 *
 * @param[in]  algo            Decryption algorithm that was used to encrypt the data
 * @param[in]  bcm             Chaining mode that was used to encrypt the data
 * @param[in]  sym_key         Symmetric encryption key that was used to encrypt the data
 * @param[in]  iv              Initialization Vector that was used to encrypt the data
 * @param[in]  ciphertext      Ciphertext to be decrypted
 * @param[in]  ciphertext_len  Length of ciphertext
 * @param[out] plaintext       Decrypted data, will be allocated by the library
 * @param[out] plaintext_len   Length of the decrypted data
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0
 *                                       invalid algo, bcm, sym_key or iv)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_encrypt_algorithm_e
 * @see #yaca_block_cipher_mode_e
 * @see yaca_simple_encrypt()
 * @see yaca_free()
 */
int yaca_simple_decrypt(yaca_encrypt_algorithm_e algo,
                        yaca_block_cipher_mode_e bcm,
                        const yaca_key_h sym_key,
                        const yaca_key_h iv,
                        const char *ciphertext,
                        size_t ciphertext_len,
                        char **plaintext,
                        size_t *plaintext_len);

/**
 * @brief  Calculates a digest of a message.
 *
 * @since_tizen 3.0
 *
 * @remarks  The @a digest should be freed using yaca_free()
 *
 * @remarks  The @a message can be NULL but then @a message_len must be 0
 *
 * @param[in]  algo         Digest algorithm (select #YACA_DIGEST_SHA256 if unsure)
 * @param[in]  message      Message from which the digest is to be calculated
 * @param[in]  message_len  Length of the message
 * @param[out] digest       Message digest, will be allocated by the library
 * @param[out] digest_len   Length of message digest (depends on algorithm)
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid algo)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_digest_algorithm_e
 * @see yaca_free()
 */
int yaca_simple_calculate_digest(yaca_digest_algorithm_e algo,
                                 const char *message,
                                 size_t message_len,
                                 char **digest,
                                 size_t *digest_len);

/**
 * @brief  Creates a signature using asymmetric private key.
 *
 * @since_tizen 3.0
 *
 * @remarks  For #YACA_DIGEST_SHA384 and #YACA_DIGEST_SHA512 the RSA key size must be bigger than
 *           #YACA_KEY_LENGTH_512BIT.
 *
 * @remarks  Using of #YACA_DIGEST_MD5 algorithm for DSA and ECDSA operations is prohibited.
 *
 * @remarks  The @a signature should be freed using yaca_free()
 *
 * @remarks  The @a message can be NULL but then @a message_len must be 0
 *
 * @param[in]  algo           Digest algorithm that will be used
 * @param[in]  prv_key        Private key that will be used, algorithm is
 *                            deduced based on key type, supported key types:
 *                            - #YACA_KEY_TYPE_RSA_PRIV,
 *                            - #YACA_KEY_TYPE_DSA_PRIV,
 *                            - #YACA_KEY_TYPE_EC_PRIV
 * @param[in]  message        Message to be signed
 * @param[in]  message_len    Length of the message
 * @param[out] signature      Message signature, will be allocated by the library
 * @param[out] signature_len  Length of the signature
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0
 *                                       invalid algo or key)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_key_type_e
 * @see #yaca_digest_algorithm_e
 * @see yaca_simple_verify_signature()
 * @see yaca_free()
 */
int yaca_simple_calculate_signature(yaca_digest_algorithm_e algo,
                                    const yaca_key_h prv_key,
                                    const char *message,
                                    size_t message_len,
                                    char **signature,
                                    size_t *signature_len);

/**
 * @brief  Verifies a signature using asymmetric public key.
 *
 * @since_tizen 3.0
 *
 * @remarks  The @a message can be NULL but then @a message_len must be 0
 *
 * @param[in]  algo           Digest algorithm that will be used
 * @param[in]  pub_key        Public key that will be used, algorithm is
 *                            deduced based on key type, supported key types:
 *                            - #YACA_KEY_TYPE_RSA_PUB,
 *                            - #YACA_KEY_TYPE_DSA_PUB,
 *                            - #YACA_KEY_TYPE_EC_PUB
 * @param[in]  message        Message
 * @param[in]  message_len    Length of the message
 * @param[in]  signature      Message signature to be verified
 * @param[in]  signature_len  Length of the signature
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0
 *                                       invalid algo or key)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 * @retval #YACA_ERROR_DATA_MISMATCH The verification failed
 *
 * @see #yaca_key_type_e
 * @see #yaca_digest_algorithm_e
 * @see yaca_simple_calculate_signature()
 */
int yaca_simple_verify_signature(yaca_digest_algorithm_e algo,
                                 const yaca_key_h pub_key,
                                 const char *message,
                                 size_t message_len,
                                 const char *signature,
                                 size_t signature_len);

/**
 * @brief  Calculates a HMAC of given message using symmetric key.
 *
 * @since_tizen 3.0
 *
 * @remarks  For verification, calculate message HMAC and compare with received MAC using
 *           yaca_memcmp().
 *
 * @remarks  The @a mac should be freed using yaca_free()
 *
 * @remarks  The @a message can be NULL but then @a message_len must be 0
 *
 * @param[in]  algo         Digest algorithm that will be used
 * @param[in]  sym_key      Key that will be used, supported key types:
 *                          - #YACA_KEY_TYPE_SYMMETRIC,
 *                          - #YACA_KEY_TYPE_DES
 * @param[in]  message      Message to calculate HMAC from
 * @param[in]  message_len  Length of the message
 * @param[out] mac          MAC, will be allocated by the library
 * @param[out] mac_len      Length of the MAC
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0
 *                                       invalid algo or key)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_key_type_e
 * @see #yaca_digest_algorithm_e
 * @see yaca_memcmp()
 * @see yaca_free()
 */
int yaca_simple_calculate_hmac(yaca_digest_algorithm_e algo,
                               const yaca_key_h sym_key,
                               const char *message,
                               size_t message_len,
                               char **mac,
                               size_t *mac_len);

/**
 * @brief  Calculates a CMAC of given message using symmetric key.
 *
 * @since_tizen 3.0
 *
 * @remarks  For verification, calculate message CMAC and compare with received MAC using
 *           yaca_memcmp().
 *
 * @remarks  The @a mac should be freed using yaca_free()
 *
 * @remarks  The @a message can be NULL but then @a message_len must be 0
 *
 * @param[in]  algo         Encryption algorithm that will be used
 * @param[in]  sym_key      Key that will be used, supported key types:
 *                          - #YACA_KEY_TYPE_SYMMETRIC,
 *                          - #YACA_KEY_TYPE_DES
 * @param[in]  message      Message to calculate CMAC from
 * @param[in]  message_len  Length of the message
 * @param[out] mac          MAC, will be allocated by the library
 * @param[out] mac_len      Length of the MAC
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0
 *                                       invalid algo or key)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_key_type_e
 * @see #yaca_encrypt_algorithm_e
 * @see yaca_memcmp()
 * @see yaca_free()
 */
int yaca_simple_calculate_cmac(yaca_encrypt_algorithm_e algo,
                               const yaca_key_h sym_key,
                               const char *message,
                               size_t message_len,
                               char **mac,
                               size_t *mac_len);

/**
  * @}
  */

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_SIMPLE_H */
