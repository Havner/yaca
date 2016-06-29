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
 * @file yaca_encrypt.h
 */

#ifndef YACA_ENCRYPT_H
#define YACA_ENCRYPT_H

#include <stddef.h>
#include <yaca_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup CAPI_YACA_ENCRYPTION_MODULE
 * @{
 */

/**
 * Note:  Advanced-Encryption-Symmetric  Advanced API for the symmetric encryption.
 *
 *
 */

/**
 * @brief  Returns the recommended/default length of the IV for a given encryption configuration.
 *
 * @since_tizen 3.0
 *
 * @remarks  If returned iv_bit_len equals 0 that means that for this
 *           specific algorithm and its parameters IV is not used.
 *
 * @param[in]  algo         Encryption algorithm
 * @param[in]  bcm          Chain mode
 * @param[in]  key_bit_len  Key length in bits
 * @param[out] iv_bit_len   Recommended IV length in bits
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid algo, bcm or key_bit_len)
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 */
int yaca_encrypt_get_iv_bit_length(yaca_encrypt_algorithm_e algo,
                                   yaca_block_cipher_mode_e bcm,
                                   size_t key_bit_len,
                                   size_t *iv_bit_len);

/**
 * @brief  Initializes an encryption context.
 *
 * @since_tizen 3.0
 *
 * @remarks  The @a ctx should be released using yaca_context_destroy()
 *
 * @param[out] ctx      Newly created context
 * @param[in]  algo     Encryption algorithm that will be used
 * @param[in]  bcm      Chaining mode that will be used
 * @param[in]  sym_key  Symmetric key that will be used
 * @param[in]  iv       Initialization vector that will be used
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid algo, bcm, sym_key or iv)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_encrypt_algorithm_e
 * @see #yaca_block_cipher_mode_e
 * @see yaca_encrypt_update()
 * @see yaca_encrypt_finalize()
 * @see yaca_context_destroy()
 */
int yaca_encrypt_initialize(yaca_context_h *ctx,
                            yaca_encrypt_algorithm_e algo,
                            yaca_block_cipher_mode_e bcm,
                            const yaca_key_h sym_key,
                            const yaca_key_h iv);

/**
 * @brief  Encrypts chunk of the data.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx             Context created by yaca_encrypt_initialize()
 * @param[in]     plaintext       Plaintext to be encrypted
 * @param[in]     plaintext_len   Length of the plaintext
 * @param[out]    ciphertext      Buffer for the encrypted data
 *                                (must be allocated by client, see yaca_context_get_output_length())
 * @param[out]    ciphertext_len  Length of the encrypted data,
 *                                actual number of bytes written will be returned here
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0,
 *                                       invalid context)
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see yaca_encrypt_initialize()
 * @see yaca_encrypt_finalize()
 * @see yaca_context_get_output_length()
 */
int yaca_encrypt_update(yaca_context_h ctx,
                        const char *plaintext,
                        size_t plaintext_len,
                        char *ciphertext,
                        size_t *ciphertext_len);

/**
 * @brief  Encrypts the final chunk of the data.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx             A valid encrypt context
 * @param[out]    ciphertext      Final piece of the encrypted data
 *                                (must be allocated by client, see yaca_context_get_output_length())
 * @param[out]    ciphertext_len  Length of the final piece,
 *                                actual number of bytes written will be returned here
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid context)
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see yaca_encrypt_initialize()
 * @see yaca_encrypt_update()
 * @see yaca_context_get_output_length()
 */
int yaca_encrypt_finalize(yaca_context_h ctx,
                          char *ciphertext,
                          size_t *ciphertext_len);

/**
 * @brief  Initializes an decryption context.
 *
 * @since_tizen 3.0
 *
 * @remarks  The @a ctx should be released using yaca_context_destroy()
 *
 * @param[out] ctx      Newly created context
 * @param[in]  algo     Encryption algorithm that was used to encrypt the data
 * @param[in]  bcm      Chaining mode that was used to encrypt the data
 * @param[in]  sym_key  Symmetric key that was used to encrypt the data
 * @param[in]  iv       Initialization vector that was used to encrypt the data
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid algo, bcm, sym_key or iv)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_encrypt_algorithm_e
 * @see #yaca_block_cipher_mode_e
 * @see yaca_decrypt_update()
 * @see yaca_decrypt_finalize()
 * @see yaca_context_destroy()
 */
int yaca_decrypt_initialize(yaca_context_h *ctx,
                            yaca_encrypt_algorithm_e algo,
                            yaca_block_cipher_mode_e bcm,
                            const yaca_key_h sym_key,
                            const yaca_key_h iv);

/**
 * @brief  Decrypts chunk of the data.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx             Context created by yaca_decrypt_initialize()
 * @param[in]     ciphertext      Ciphertext to be decrypted
 * @param[in]     ciphertext_len  Length of the ciphertext
 * @param[out]    plaintext       Buffer for the decrypted data
 *                                (must be allocated by client, see yaca_context_get_output_length())
 * @param[out]    plaintext_len   Length of the decrypted data,
 *                                actual number of bytes written will be returned here
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0,
 *                                       invalid context)
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see yaca_decrypt_initialize()
 * @see yaca_decrypt_finalize()
 * @see yaca_context_get_output_length()
 */
int yaca_decrypt_update(yaca_context_h ctx,
                        const char *ciphertext,
                        size_t ciphertext_len,
                        char *plaintext,
                        size_t *plaintext_len);

/**
 * @brief  Decrypts the final chunk of the data.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx            A valid decrypt context
 * @param[out]    plaintext      Final piece of the decrypted data
 *                               (must be allocated by client, see yaca_context_get_output_length())
 * @param[out]    plaintext_len  Length of the final piece,
 *                               actual number of bytes written will be returned here
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid context)
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see yaca_decrypt_initialize()
 * @see yaca_decrypt_update()
 * @see yaca_context_get_output_length()
 */
int yaca_decrypt_finalize(yaca_context_h ctx,
                          char *plaintext,
                          size_t *plaintext_len);

/**
  * @}
  */

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_ENCRYPT_H */
