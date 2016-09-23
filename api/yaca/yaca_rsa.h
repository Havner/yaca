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
 * @file   yaca_rsa.h
 * @brief  Advanced API for low-level RSA operations
 */

#ifndef YACA_RSA_H
#define YACA_RSA_H

#include <stddef.h>
#include <yaca_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup CAPI_YACA_RSA_MODULE
 * @{
 */

/**
 * @brief  Encrypts data using a RSA public key (low-level encrypt equivalent).
 *
 * @since_tizen 3.0
 *
 * @remarks  The @a ciphertext should be freed using yaca_free().
 *
 * @remarks  The @a pub_key used has to be of a #YACA_KEY_TYPE_RSA_PUB type.
 *
 * @remarks  The maximum length of plaintext depends on the key length and padding method.
 *           See #yaca_padding_e for details.
 *
 * @remarks  The @a plaintext can be NULL but then the @a plaintext_len must be 0.
 *
 * @param[in]  padding         Padding method
 * @param[in]  pub_key         Public RSA key (see yaca_key.h for key generation functions)
 * @param[in]  plaintext       Plaintext to be encrypted
 * @param[in]  plaintext_len   Length of the plaintext
 * @param[out] ciphertext      Encrypted data, will be allocated by the library
 * @param[out] ciphertext_len  Length of the encrypted data (may be larger than decrypted)
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0
 *                                       invalid @a padding, @a pub_key or @a plaintext_len)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_key_type_e
 * @see #yaca_padding_e
 * @see yaca_rsa_private_decrypt()
 * @see yaca_free()
 */
int yaca_rsa_public_encrypt(yaca_padding_e padding,
                            const yaca_key_h pub_key,
                            const char *plaintext,
                            size_t plaintext_len,
                            char **ciphertext,
                            size_t *ciphertext_len);

/**
 * @brief  Decrypts data using a RSA private key (low-level decrypt equivalent).
 *
 * @since_tizen 3.0
 *
 * @remarks  The @a plaintext should be freed using yaca_free().
 *
 * @remarks  The @a prv_key used has to be of a #YACA_KEY_TYPE_RSA_PRIV type.
 *
 * @param[in]  padding         Padding method
 * @param[in]  prv_key         Private RSA key matching the public one used to encrypt the data
 * @param[in]  ciphertext      Ciphertext to be decrypted
 * @param[in]  ciphertext_len  Length of ciphertext
 * @param[out] plaintext       Decrypted data, will be allocated by the library
 * @param[out] plaintext_len   Length of the decrypted data
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0
 *                                       invalid @a padding or @a prv_key), padding check failed
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_key_type_e
 * @see #yaca_padding_e
 * @see yaca_rsa_public_encrypt()
 * @see yaca_free()
 */
int yaca_rsa_private_decrypt(yaca_padding_e padding,
                             const yaca_key_h prv_key,
                             const char *ciphertext,
                             size_t ciphertext_len,
                             char **plaintext,
                             size_t *plaintext_len);

/**
 * @brief  Encrypts data using a RSA private key (low-level sign equivalent).
 *
 * @since_tizen 3.0
 *
 * @remarks  The @a ciphertext should be freed using yaca_free().
 *
 * @remarks  The @a prv_key used has to be of a #YACA_KEY_TYPE_RSA_PRIV type.
 *
 * @remarks  The maximum length of plaintext depends on the key length and padding method,
 *           see #yaca_padding_e for details.
 *
 * @remarks  The @a plaintext can be NULL but then the @a plaintext_len must be 0.
 *
 * @param[in]  padding         Padding method
 * @param[in]  prv_key         Private RSA key (see yaca_key.h for key generation functions)
 * @param[in]  plaintext       Plaintext to be encrypted
 * @param[in]  plaintext_len   Length of the plaintext
 * @param[out] ciphertext      Encrypted data, will be allocated by the library
 * @param[out] ciphertext_len  Length of the encrypted data (may be larger than decrypted)
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0
 *                                       invalid @a padding, @a prv_key or @a plaintext_len)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_key_type_e
 * @see #yaca_padding_e
 * @see yaca_rsa_public_decrypt()
 * @see yaca_free()
 */
int yaca_rsa_private_encrypt(yaca_padding_e padding,
                             const yaca_key_h prv_key,
                             const char *plaintext,
                             size_t plaintext_len,
                             char **ciphertext,
                             size_t *ciphertext_len);

/**
 * @brief  Decrypts data using a RSA public key (low-level verify equivalent).
 *
 * @since_tizen 3.0
 *
 * @remarks  The @a plaintext should be freed using yaca_free().
 *
 * @remarks  The @a pub_key used has to be of a #YACA_KEY_TYPE_RSA_PUB type.
 *
 * @param[in]  padding         Padding method
 * @param[in]  pub_key         Public RSA key matching the private one used to encrypt the data
 * @param[in]  ciphertext      Ciphertext to be decrypted
 * @param[in]  ciphertext_len  Length of ciphertext
 * @param[out] plaintext       Decrypted data, will be allocated by the library
 * @param[out] plaintext_len   Length of the decrypted data
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0
 *                                       invalid @a padding or @a pub_key), padding check failed
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_key_type_e
 * @see #yaca_padding_e
 * @see yaca_rsa_private_encrypt()
 * @see yaca_free()
 */
int yaca_rsa_public_decrypt(yaca_padding_e padding,
                            const yaca_key_h pub_key,
                            const char *ciphertext,
                            size_t ciphertext_len,
                            char **plaintext,
                            size_t *plaintext_len);

/**
 * @}
 */

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_RSA_H */
