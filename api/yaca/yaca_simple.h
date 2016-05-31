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
 * @file yaca_simple.h
 * @brief
 */

#ifndef YACA_SIMPLE_H
#define YACA_SIMPLE_H

#include <stddef.h>
#include <yaca_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup  Simple-API  Simple API.
 *
 *  @remarks This is simple API.
 *           Design constraints:
 *           - All operations are single-shot (no streaming possible)
 *           - Context is not used
 *           - For now only digest and symmetric ciphers are supported
 *           - GCM and CCM chaining is not supported
 *           - All outputs are allocated by the library
 *
 * TODO: extended description and examples.
 *
 * @{
 */

/**
 * @brief  Calculate a digest of a buffer.
 *
 * @since_tizen 3.0
 *
 * @param[in]  algo        Digest algorithm (select #YACA_DIGEST_SHA256 if unsure)
 * @param[in]  data        Data from which the digest is to be calculated
 * @param[in]  data_len    Length of the data
 * @param[out] digest      Message digest, will be allocated by the library
 *                         (should be freed with yaca_free())
 * @param[out] digest_len  Length of message digest (depends on algorithm)
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_ARGUMENT Required parameters have bogus values (NULL, 0
 *                                      incorrect algo)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_digest_algo_e
 */
int yaca_digest_calc(yaca_digest_algo_e algo,
                     const char *data,
                     size_t data_len,
                     char **digest,
                     size_t *digest_len);

/**
 * @brief  Encrypt data using a symmetric cipher.
 *
 * @since_tizen 3.0
 *
 * @param[in]  algo        Encryption algorithm (select #YACA_ENC_AES if unsure)
 * @param[in]  bcm         Chaining mode (select #YACA_BCM_CBC if unsure)
 * @param[in]  sym_key     Symmetric encryption key (see key.h for key generation functions)
 * @param[in]  iv          Initialization vector
 * @param[in]  plain       Plain text to be encrypted
 * @param[in]  plain_len   Length of the plain text
 * @param[out] cipher      Encrypted data, will be allocated by the library
 *                         (should be freed with yaca_free())
 * @param[out] cipher_len  Length of the encrypted data (may be larger than decrypted)
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_ARGUMENT Required parameters have bogus values (NULL, 0
 *                                      incorrect algo, bcm, invalid sym_key, iv)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_enc_algo_e
 * @see #yaca_block_cipher_mode_e
 * @see yaca_decrypt()
 */
int yaca_encrypt(yaca_enc_algo_e algo,
                 yaca_block_cipher_mode_e bcm,
                 const yaca_key_h sym_key,
                 const yaca_key_h iv,
                 const char *plain,
                 size_t plain_len,
                 char **cipher,
                 size_t *cipher_len);

/**
 * @brief  Decrypt data using a symmetric cipher.
 *
 * @since_tizen 3.0
 *
 * @param[in]  algo        Decryption algorithm that was used to encrypt the data
 * @param[in]  bcm         Chaining mode that was used to encrypt the data
 * @param[in]  sym_key     Symmetric encryption key that was used to encrypt the data
 * @param[in]  iv          Initialization vector that was used to encrypt the data
 * @param[in]  cipher      Cipher text to be decrypted
 * @param[in]  cipher_len  Length of cipher text
 * @param[out] plain       Decrypted data, will be allocated by the library
 *                         (should be freed with yaca_free())
 * @param[out] plain_len   Length of the decrypted data
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_ARGUMENT Required parameters have bogus values (NULL, 0
 *                                      incorrect algo, bcm, invalid sym_key, iv)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_enc_algo_e
 * @see #yaca_block_cipher_mode_e
 * @see yaca_encrypt()
 */
int yaca_decrypt(yaca_enc_algo_e algo,
                 yaca_block_cipher_mode_e bcm,
                 const yaca_key_h sym_key,
                 const yaca_key_h iv,
                 const char *cipher,
                 size_t cipher_len,
                 char **plain,
                 size_t * plain_len);

/**
 * @brief  Create a signature using asymmetric private key.
 *
 * @since_tizen 3.0
 *
 * @param[in]  algo           Digest algorithm that will be used
 * @param[in]  key            Private key that will be used, algorithm is
 *                            deduced based on key type, supported key types:
 *                            - #YACA_KEY_TYPE_RSA_PRIV,
 *                            - #YACA_KEY_TYPE_DSA_PRIV,
 *                            - #YACA_KEY_TYPE_EC_PRIV
 * @param[in]  data           Data to be signed
 * @param[in]  data_len       Length of the data
 * @param[out] signature      Message signature, will be allocated by the
 *                            library (should be freed with yaca_free())
 * @param[out] signature_len  Length of the signature
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_ARGUMENT Required parameters have bogus values (NULL, 0
 *                                      incorrect algo, invalid key)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_key_type_e
 * @see #yaca_digest_algo_e
 * @see yaca_verify()
 */
int yaca_sign(yaca_digest_algo_e algo,
              const yaca_key_h key,
              const char *data,
              size_t data_len,
              char** signature,
              size_t* signature_len);

/**
 * @brief  Verify a signature using asymmetric public key.
 *
 * @since_tizen 3.0
 *
 * @param[in]  algo           Digest algorithm that will be used
 * @param[in]  key            Public key that will be used, algorithm is
 *                            deduced based on key type, supported key types:
 *                            - #YACA_KEY_TYPE_RSA_PUB,
 *                            - #YACA_KEY_TYPE_DSA_PUB,
 *                            - #YACA_KEY_TYPE_EC_PUB
 * @param[in]  data           Signed data
 * @param[in]  data_len       Length of the data
 * @param[in]  signature      Message signature
 * @param[in]  signature_len  Length of the signature
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_ARGUMENT Required parameters have bogus values (NULL, 0
 *                                      incorrect algo, invalid key)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 * @retval #YACA_ERROR_DATA_MISMATCH The verification failed
 *
 * @see #yaca_key_type_e
 * @see #yaca_digest_algo_e
 * @see yaca_sign()
 */
int yaca_verify(yaca_digest_algo_e algo,
                const yaca_key_h key,
                const char *data,
                size_t data_len,
                const char* signature,
                size_t signature_len);

/**
 * @brief  Calculate a HMAC of given message using symmetric key.
 *
 * @since_tizen 3.0
 *
 * @remarks For verification, calculate message HMAC and compare with received MAC using
 *          yaca_memcmp().
 *
 * @param[in]  algo      Digest algorithm that will be used
 * @param[in]  key       Key that will be used, supported key types:
 *                       - #YACA_KEY_TYPE_SYMMETRIC,
 *                       - #YACA_KEY_TYPE_DES
 * @param[in]  data      Data to calculate HMAC from
 * @param[in]  data_len  Length of the data
 * @param[out] mac       MAC, will be allocated by the library
 *                       (should be freed with yaca_free())
 * @param[out] mac_len   Length of the MAC
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_ARGUMENT Required parameters have bogus values (NULL, 0
 *                                      incorrect algo, invalid key)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_key_type_e
 * @see #yaca_digest_algo_e
 * @see yaca_memcmp()
 */
int yaca_hmac(yaca_digest_algo_e algo,
              const yaca_key_h key,
              const char *data,
              size_t data_len,
              char** mac,
              size_t* mac_len);

/**
 * @brief  Calculate a CMAC of given message using symmetric key.
 *
 * @since_tizen 3.0
 *
 * @remarks For verification, calculate message CMAC and compare with received MAC using
 *          yaca_memcmp().
 *
 * @param[in]  algo      Encryption algorithm that will be used
 * @param[in]  key       Key that will be used, supported key types:
 *                       - #YACA_KEY_TYPE_SYMMETRIC,
 *                       - #YACA_KEY_TYPE_DES
 * @param[in]  data      Data to calculate CMAC from
 * @param[in]  data_len  Length of the data
 * @param[out] mac       MAC, will be allocated by the library
 *                       (should be freed with yaca_free())
 * @param[out] mac_len   Length of the MAC
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_ARGUMENT Required parameters have bogus values (NULL, 0
 *                                      incorrect algo, invalid key)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_key_type_e
 * @see #yaca_enc_algo_e
 * @see yaca_memcmp()
 */
int yaca_cmac(yaca_enc_algo_e algo,
              const yaca_key_h key,
              const char *data,
              size_t data_len,
              char** mac,
              size_t* mac_len);

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_SIMPLE_H */
