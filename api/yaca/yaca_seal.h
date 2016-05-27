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
 * @file seal.h
 * @brief
 */

#ifndef YACA_SEAL_H
#define YACA_SEAL_H

#include <stddef.h>
#include <yaca_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup  Advanced-Encryption-Asymmetric  Advanced API for the asymmetric encryption.
 *
 * TODO: extended description and examples.
 *
 * @remarks Seal does more than just encrypt. It first generates the encryption key and IV,
 *          then encrypts whole message using this key (and selected symmetric algorithm).
 *          Finally it encrypts symmetric key with public key.
 *
 * @{
 */

/**
 * @brief  Initializes an asymmetric encryption context.
 *
 * @since_tizen 3.0
 *
 * @param[out] ctx           Newly created context (must be freed with yaca_ctx_free()).
 * @param[in]  pub_key       Public key of the peer that will receive the encrypted data.
 * @param[in]  algo          Symmetric algorithm that will be used.
 * @param[in]  bcm           Block chaining mode for the symmetric algorithm.
 * @param[in]  sym_key_bits  Symmetric key length (in bits) that will be generated.
 * @param[out] sym_key       Generated symmetric key that will be used. It is encrypted with peer's public key.
 * @param[out] iv            Generated initialization vector that will be used.
 *
 * @return YACA_ERROR_NONE on success, negative on error.
 * @see #yaca_enc_algo_e, #yaca_block_cipher_mode_e, yaca_seal_update(), yaca_seal_final()
 */
int yaca_seal_init(yaca_ctx_h *ctx,
                   const yaca_key_h pub_key,
                   yaca_enc_algo_e algo,
                   yaca_block_cipher_mode_e bcm,
                   yaca_key_bits_e sym_key_bits,
                   yaca_key_h *sym_key,
                   yaca_key_h *iv);

/**
 * @brief  Encrypts piece of the data.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx         Context created by yaca_seal_init().
 * @param[in]     plain       Plain text to be encrypted.
 * @param[in]     plain_len   Length of the plain text.
 * @param[out]    cipher      Buffer for the encrypted data (must be allocated by client, see
 *                            yaca_get_output_length()).
 * @param[out]    cipher_len  Length of the encrypted data, actual number of bytes written will be returned here.
 *
 * @return YACA_ERROR_NONE on success, negative on error.
 * @see yaca_seal_init(), yaca_seal_final()
 */
int yaca_seal_update(yaca_ctx_h ctx,
                     const char *plain,
                     size_t plain_len,
                     char *cipher,
                     size_t *cipher_len);

/**
 * @brief  Encrypts the final piece of the data.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx         A valid seal context.
 * @param[out]    cipher      Final piece of the encrypted data (must be allocated by client, see
 *                            yaca_get_block_length()).
 * @param[out]    cipher_len  Length of the final piece, actual number of bytes written will be returned here.
 *
 * @return YACA_ERROR_NONE on success, negative on error.
 * @see yaca_seal_init(), yaca_seal_update()
 */
int yaca_seal_final(yaca_ctx_h ctx,
                    char *cipher,
                    size_t *cipher_len);

/**
 * @brief  Initializes an asymmetric decryption context.
 *
 * @since_tizen 3.0
 *
 * @param[out] ctx           Newly created context. Must be freed by yaca_ctx_free().
 * @param[in]  prv_key       Private key, part of the pair that was used for the encryption.
 * @param[in]  algo          Symmetric algorithm that was used for the encryption.
 * @param[in]  bcm           Block chaining mode for the symmetric algorithm.
 * @param[in]  sym_key_bits  Symmetric key length (in bits) that was used for the encryption.
 * @param[in]  sym_key       Symmetric key, encrypted with the public key, that was used to encrypt the data.
 * @param[in]  iv            Initialization vector that was used for the encryption.
 *
 * @return YACA_ERROR_NONE on success, negative on error.
 * @see #yaca_enc_algo_e, #yaca_block_cipher_mode_e, yaca_open_update(), yaca_open_final()
 */
int yaca_open_init(yaca_ctx_h *ctx,
                   const yaca_key_h prv_key,
                   yaca_enc_algo_e algo,
                   yaca_block_cipher_mode_e bcm,
                   yaca_key_bits_e sym_key_bits,
                   const yaca_key_h sym_key,
                   const yaca_key_h iv);

/**
 * @brief  Decrypts piece of the data.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx         Context created by yaca_open_init().
 * @param[in]     cipher      Cipher text to be decrypted.
 * @param[in]     cipher_len  Length of the cipher text.
 * @param[out]    plain       Buffer for the decrypted data (must be allocated by client, see
 *                            yaca_get_output_length()).
 * @param[out]    plain_len   Length of the decrypted data, actual number of bytes written will be returned here.
 *
 * @return YACA_ERROR_NONE on success, negative on error.
 * @see yaca_open_init(), yaca_open_final()
 */
int yaca_open_update(yaca_ctx_h ctx,
                     const char *cipher,
                     size_t cipher_len,
                     char *plain,
                     size_t *plain_len);

/**
 * @brief  Decrypts last chunk of sealed message.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx        A valid open context.
 * @param[out]    plain      Final piece of the decrypted data (must be allocated by client, see
 *                           yaca_get_block_length()).
 * @param[out]    plain_len  Length of the final piece, actual number of bytes written will be returned here.
 *
 * @return YACA_ERROR_NONE on success, negative on error.
 * @see yaca_open_init(), yaca_open_update()
 */
int yaca_open_final(yaca_ctx_h ctx,
                    char *plain,
                    size_t *plain_len);

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_SEAL_H */
