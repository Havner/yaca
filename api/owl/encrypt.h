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

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stddef.h>
#include <owl/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup  Advanced-Encryption-Symmetric  Advanced API for the symmetric encryption.
 *
 * TODO: extended description and examples.
 *
 * TODO: Let's describe how to set additional params (like GCM, CCM)
 *
 * @{
 */

/**
 * @brief owl_encrypt_init  Initializes an encryption context.
 *
 * @param[out] ctx      Newly created context (must be freed with @see owl_ctx_free).
 * @param[in]  algo     Encryption algorithm that will be used.
 * @param[in]  bcm      Chaining mode that will be used.
 * @param[in]  sym_key  Symmetric key that will be used.
 * @param[in]  iv       Initialization vector that will be used.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int owl_encrypt_init(owl_ctx_h *ctx,
		     owl_enc_algo_e algo,
		     owl_block_cipher_mode_e bcm,
		     const owl_key_h sym_key,
		     const owl_key_h iv);

/**
 * @brief owl_encrypt_update  Encrypts chunk of the data.
 *
 * @param[in,out] ctx         Context created by @see owl_encrypt_init.
 * @param[in]     plain       Plain text to be encrypted.
 * @param[in]     plain_len   Length of the plain text.
 * @param[out]    cipher      Buffer for the encrypted data (must be allocated by client, @see owl_get_output_length).
 * @param[out]    cipher_len  Length of the encrypted data, actual number of bytes written will be returned here.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int owl_encrypt_update(owl_ctx_h ctx,
		       const char *plain,
		       size_t plain_len,
		       char *cipher,
		       size_t *cipher_len);

/**
 * @brief owl_encrypt_final  Encrypts the final chunk of the data.
 *
 * @param[in,out] ctx         A valid encrypt context.
 * @param[out]    cipher      Final piece of the encrypted data (must be allocated by client, @see owl_get_block_length).
 * @param[out]    cipher_len  Length of the final piece, actual number of bytes written will be returned here.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int owl_encrypt_final(owl_ctx_h ctx,
		      char *cipher,
		      size_t *cipher_len);

/**
 * @brief owl_decrypt_init  Initializes an decryption context.
 *
 * @param[out] ctx      Newly created context (must be freed with @see owl_ctx_free).
 * @param[in]  algo     Encryption algorithm that was used to encrypt the data.
 * @param[in]  bcm      Chaining mode that was used to encrypt the data.
 * @param[in]  sym_key  Symmetric key that was used to encrypt the data.
 * @param[in]  iv       Initialization vector that was used to encrypt the data.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int owl_decrypt_init(owl_ctx_h *ctx,
		     owl_enc_algo_e algo,
		     owl_block_cipher_mode_e bcm,
		     const owl_key_h sym_key,
		     const owl_key_h iv);

/**
 * @brief owl_decrypt_update Decrypts chunk of the data.
 *
 * @param[in,out] ctx         Context created by @see owl_decrypt_init.
 * @param[in]     cipher      Cipher text to be decrypted.
 * @param[in]     cipher_len  Length of the cipher text.
 * @param[out]    plain       Buffer for the decrypted data (must be allocated by client, @see owl_get_output_length).
 * @param[out]    plain_len   Length of the decrypted data, actual number of bytes written will be returned here.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int owl_decrypt_update(owl_ctx_h ctx,
		       const char *cipher,
		       size_t cipher_len,
		       char *plain,
		       size_t *plain_len);

/**
 * @brief owl_decrypt_final  Decrypts the final chunk of the data.
 *
 * @param[in,out] ctx        A valid decrypt context.
 * @param[out]    plain      Final piece of the decrypted data (must be allocated by client, @see owl_get_block_length).
 * @param[out]    plain_len  Length of the final piece, actual number of bytes written will be returned here.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int owl_decrypt_final(owl_ctx_h ctx,
		      char *plain,
		      size_t *plain_len);

/**@}*/

/**
 * @defgroup  Advanced-Encryption-Asymmetric  Advanced API for the asymmetric encryption.
 *
 * TODO: extended description and examples.
 *
 * TODO: Seal does more than just encrypt. It first generates the encryption key and IV,
 * then encrypts whole message using this key (and selected symmetric algorithm).
 * Finally it encrypts symmetric key with public key.
 *
 * @{
 */

/**
 * @brief owl_seal_init  Initializes an asymmetric encryption context.
 *
 * @param[out] ctx      Newly created context (must be freed with @see owl_ctx_free).
 * @param[in]  pub_key  Public key of the peer that will receive the encrypted data.
 * @param[in]  algo     Symmetric algorithm that will be used.
 * @param[in]  bcm      Block chaining mode for the symmetric algorithm.
 * @param[out] sym_key  Generated symmetric key that will be used. It is encrypted with peer's public key.
 * @param[out] iv       Generated initialization vector that will be used.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int owl_seal_init(owl_ctx_h *ctx,
		  const owl_key_h pub_key,
		  owl_enc_algo_e algo,
		  owl_block_cipher_mode_e bcm,
		  owl_key_h *sym_key,
		  owl_key_h *iv);

/**
 * @brief owl_seal_update  Encrypts piece of the data.
 *
 * @param[in,out] ctx         Context created by @see owl_seal_init.
 * @param[in]     plain       Plain text to be encrypted.
 * @param[in]     plain_len   Length of the plain text.
 * @param[out]    cipher      Buffer for the encrypted data (must be allocated by client, @see owl_get_output_length).
 * @param[out]    cipher_len  Length of the encrypted data, actual number of bytes written will be returned here.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int owl_seal_update(owl_ctx_h ctx,
		    const char *plain,
		    size_t plain_len,
		    char *cipher,
		    size_t *cipher_len);

/**
 * @brief owl_seal_final  Encrypts the final piece of the data.
 *
 * @param[in,out] ctx         A valid seal context.
 * @param[out]    cipher      Final piece of the encrypted data (must be allocated by client, @see owl_get_block_length).
 * @param[out]    cipher_len  Length of the final piece, actual number of bytes written will be returned here.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int owl_seal_final(owl_ctx_h ctx,
		   char *cipher,
		   size_t *cipher_len);

/**
 * @brief owl_open_init  Initializes an asymmetric decryption context.
 *
 * @param[out] ctx      Newly created context. Must be freed by @see owl_ctx_free.
 * @param[in]  prv_key  Private key, part of the pair that was used for the encryption.
 * @param[in]  algo     Symmetric algorithm that was used for the encryption.
 * @param[in]  bcm      Block chaining mode for the symmetric algorithm.
 * @param[in]  sym_key  Symmetric key, encrypted with the public key, that was used to encrypt the data.
 * @param[in]  iv       Initialization vector that was used for the encryption.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int owl_open_init(owl_ctx_h *ctx,
		  const owl_key_h prv_key,
		  owl_enc_algo_e algo,
		  owl_block_cipher_mode_e bcm,
		  const owl_key_h sym_key,
		  const owl_key_h iv);

/**
 * @brief owl_open_update  Decrypts piece of the data.
 *
 * @param[in,out] ctx         Context created by @see owl_open_init.
 * @param[in]     cipher      Cipher text to be decrypted.
 * @param[in]     cipher_len  Length of the cipher text.
 * @param[out]    plain       Buffer for the decrypted data (must be allocated by client, @see owl_get_output_length).
 * @param[out]    plain_len   Length of the decrypted data, actual number of bytes written will be returned here.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int owl_open_update(owl_ctx_h ctx,
		    const char *cipher,
		    size_t cipher_len,
		    char *plain,
		    size_t *plain_len);

/**
 * @brief owl_open_final Decrypts last chunk of sealed message.
 *
 * @param[in,out] ctx        A valid open context.
 * @param[out]    plain      Final piece of the decrypted data (must be allocated by client, @see owl_get_block_length).
 * @param[out]    plain_len  Length of the final piece, actual number of bytes written will be returned here.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int owl_open_final(owl_ctx_h ctx,
		   char *plain,
		   size_t *plain_len);

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* ENCRYPT_H */
