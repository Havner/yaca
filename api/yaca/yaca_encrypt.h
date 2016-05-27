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
 * @file encrypt.h
 * @brief
 */

#ifndef YACA_ENCRYPT_H
#define YACA_ENCRYPT_H

#include <stddef.h>
#include <yaca_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup  Advanced-Encryption-Symmetric  Advanced API for the symmetric encryption.
 *
 * TODO: extended description and examples.
 *
 * @{
 */

/**
 * @brief  Initializes an encryption context.
 *
 * @since_tizen 3.0
 *
 * @param[out] ctx      Newly created context (must be freed with yaca_ctx_free()).
 * @param[in]  algo     Encryption algorithm that will be used.
 * @param[in]  bcm      Chaining mode that will be used.
 * @param[in]  sym_key  Symmetric key that will be used.
 * @param[in]  iv       Initialization vector that will be used.
 *
 * @return YACA_ERROR_NONE on success, negative on error.
 * @see #yaca_enc_algo_e, #yaca_block_cipher_mode_e, yaca_encrypt_update(), yaca_encrypt_final()
 */
int yaca_encrypt_init(yaca_ctx_h *ctx,
                      yaca_enc_algo_e algo,
                      yaca_block_cipher_mode_e bcm,
                      const yaca_key_h sym_key,
                      const yaca_key_h iv);

/**
 * @brief  Encrypts chunk of the data.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx         Context created by yaca_encrypt_init().
 * @param[in]     plain       Plain text to be encrypted.
 * @param[in]     plain_len   Length of the plain text.
 * @param[out]    cipher      Buffer for the encrypted data (must be allocated by client, see
 *                            yaca_get_output_length()).
 * @param[out]    cipher_len  Length of the encrypted data, actual number of bytes written will be returned here.
 *
 * @return YACA_ERROR_NONE on success, negative on error.
 * @see yaca_encrypt_init(), yaca_encrypt_final()
 */
int yaca_encrypt_update(yaca_ctx_h ctx,
                        const char *plain,
                        size_t plain_len,
                        char *cipher,
                        size_t *cipher_len);

/**
 * @brief  Encrypts the final chunk of the data.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx         A valid encrypt context.
 * @param[out]    cipher      Final piece of the encrypted data (must be allocated by client, see
 *                            yaca_get_block_length()).
 * @param[out]    cipher_len  Length of the final piece, actual number of bytes written will be returned here.
 *
 * @return YACA_ERROR_NONE on success, negative on error.
 * @see yaca_encrypt_init(), yaca_encrypt_update()
 */
int yaca_encrypt_final(yaca_ctx_h ctx,
                       char *cipher,
                       size_t *cipher_len);

/**
 * @brief  Initializes an decryption context.
 *
 * @since_tizen 3.0
 *
 * @param[out] ctx      Newly created context (must be freed with yaca_ctx_free()).
 * @param[in]  algo     Encryption algorithm that was used to encrypt the data.
 * @param[in]  bcm      Chaining mode that was used to encrypt the data.
 * @param[in]  sym_key  Symmetric key that was used to encrypt the data.
 * @param[in]  iv       Initialization vector that was used to encrypt the data.
 *
 * @return YACA_ERROR_NONE on success, negative on error.
 * @see #yaca_enc_algo_e, #yaca_block_cipher_mode_e, yaca_decrypt_update(), yaca_decrypt_final()
 */
int yaca_decrypt_init(yaca_ctx_h *ctx,
                      yaca_enc_algo_e algo,
                      yaca_block_cipher_mode_e bcm,
                      const yaca_key_h sym_key,
                      const yaca_key_h iv);

/**
 * @brief  Decrypts chunk of the data.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx         Context created by yaca_decrypt_init().
 * @param[in]     cipher      Cipher text to be decrypted.
 * @param[in]     cipher_len  Length of the cipher text.
 * @param[out]    plain       Buffer for the decrypted data (must be allocated by client, see
 *                            yaca_get_output_length()).
 * @param[out]    plain_len   Length of the decrypted data, actual number of bytes written will be returned here.
 *
 * @return YACA_ERROR_NONE on success, negative on error.
 * @see yaca_decrypt_init(), yaca_decrypt_final()
 */
int yaca_decrypt_update(yaca_ctx_h ctx,
                        const char *cipher,
                        size_t cipher_len,
                        char *plain,
                        size_t *plain_len);

/**
 * @brief  Decrypts the final chunk of the data.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx        A valid decrypt context.
 * @param[out]    plain      Final piece of the decrypted data (must be allocated by client, see
 *                           yaca_get_block_length()).
 * @param[out]    plain_len  Length of the final piece, actual number of bytes written will be returned here.
 *
 * @return YACA_ERROR_NONE on success, negative on error.
 * @see yaca_decrypt_init(), yaca_decrypt_update()
 */
int yaca_decrypt_final(yaca_ctx_h ctx,
                       char *plain,
                       size_t *plain_len);

/**
 * @brief  Returns the recomended/default length of the IV for a given encryption configuration.
 *
 * @since_tizen 3.0
 *
 * @remarks If returned iv_bits equals 0 that means that for this
 *          specific algorithm and its parameters IV is not used.
 *
 * @param[in]  algo      Encryption algorithm.
 * @param[in]  bcm       Chain mode.
 * @param[in]  key_bits  Key length in bits.
 * @param[out] iv_bits   Recommended IV length in bits.
 *
 * @return YACA_ERROR_NONE on success, negative on error.
 */
int yaca_get_iv_bits(yaca_enc_algo_e algo,
                     yaca_block_cipher_mode_e bcm,
                     size_t key_bits,
                     size_t *iv_bits);

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_ENCRYPT_H */
