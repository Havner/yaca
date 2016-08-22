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
 * @file   yaca_sign.h
 * @brief  Advanced API for the integrity handling - HMAC, CMAC and digital signature.
 */

#ifndef YACA_SIGN_H
#define YACA_SIGN_H

#include <stddef.h>
#include <yaca_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup CAPI_YACA_INTEGRITY_MODULE
 * @{
 */

/**
 * @brief  Initializes a signature context for asymmetric signatures.
 *
 * @since_tizen 3.0
 *
 * @remarks  For verification use yaca_verify_initialize(), yaca_verify_update() and
 *           yaca_verify_finalize() functions with matching public key.
 *
 * @remarks  The @a ctx should be released using yaca_context_destroy()
 *
 * @param[out] ctx      Newly created context
 * @param[in]  algo     Digest algorithm that will be used
 * @param[in]  prv_key  Private key that will be used, algorithm is deduced based
 *                      on key type, supported key types:
 *                      - #YACA_KEY_TYPE_RSA_PRIV,
 *                      - #YACA_KEY_TYPE_DSA_PRIV,
 *                      - #YACA_KEY_TYPE_EC_PRIV
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid algo or key)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_key_type_e
 * @see #yaca_digest_algorithm_e
 * @see yaca_sign_update()
 * @see yaca_sign_finalize()
 * @see yaca_verify_initialize()
 * @see yaca_verify_update()
 * @see yaca_verify_finalize()
 * @see yaca_context_destroy()
 */
int yaca_sign_initialize(yaca_context_h *ctx,
                         yaca_digest_algorithm_e algo,
                         const yaca_key_h prv_key);

/**
 * @brief  Initializes a signature context for HMAC.
 *
 * @since_tizen 3.0
 *
 * @remarks  For verification, calculate message HMAC and compare with received MAC using
 *           yaca_memcmp().
 *
 * @remarks  The @a ctx should be released using yaca_context_destroy()
 *
 * @param[out] ctx      Newly created context
 * @param[in]  algo     Digest algorithm that will be used
 * @param[in]  sym_key  Symmetric key that will be used, supported key types:
 *                      - #YACA_KEY_TYPE_SYMMETRIC,
 *                      - #YACA_KEY_TYPE_DES
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid algo or key)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_key_type_e
 * @see #yaca_digest_algorithm_e
 * @see yaca_sign_update()
 * @see yaca_sign_finalize()
 * @see yaca_memcmp()
 * @see yaca_context_destroy()
 */
int yaca_sign_initialize_hmac(yaca_context_h *ctx,
                              yaca_digest_algorithm_e algo,
                              const yaca_key_h sym_key);

/**
 * @brief  Initializes a signature context for CMAC.
 *
 * @since_tizen 3.0
 *
 * @remarks  For verification, calculate message CMAC and compare with received MAC using
 *           yaca_memcmp().
 *
 * @remarks  The @a ctx should be released using yaca_context_destroy()
 *
 * @param[out] ctx      Newly created context
 * @param[in]  algo     Encryption algorithm that will be used
 * @param[in]  sym_key  Symmetric key that will be used, supported key types:
 *                      - #YACA_KEY_TYPE_SYMMETRIC,
 *                      - #YACA_KEY_TYPE_DES
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid algo or key)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_key_type_e
 * @see #yaca_encrypt_algorithm_e
 * @see yaca_sign_update()
 * @see yaca_sign_finalize()
 * @see yaca_memcmp()
 * @see yaca_context_destroy()
 */
int yaca_sign_initialize_cmac(yaca_context_h *ctx,
                              yaca_encrypt_algorithm_e algo,
                              const yaca_key_h sym_key);

/**
 * @brief  Feeds the data into the digital signature or MAC algorithm.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx       Context created by yaca_sign_initialize(),
 *                          yaca_sign_initialize_hmac() or yaca_sign_initialize_cmac()
 * @param[in]     data      Data to be signed
 * @param[in]     data_len  Length of the data
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0,
 *                                       invalid context)
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see yaca_sign_initialize()
 * @see yaca_sign_finalize()
 * @see yaca_sign_initialize_hmac()
 * @see yaca_sign_initialize_cmac()
 */
int yaca_sign_update(yaca_context_h ctx,
                     const char *data,
                     size_t data_len);

/**
 * @brief  Calculates the final signature or MAC.
 *
 * @since_tizen 3.0
 *
 * @remarks  Skipping yaca_sign_update() and calling only yaca_sign_finalize() will produce a
 *           signature or MAC of an empty message.
 *
 * @param[in,out] ctx              A valid sign context
 * @param[out]    signature        Buffer for the MAC or the signature
 *                                 (must be allocated by client, see yaca_context_get_output_length())
 * @param[out]    signature_len    Length of the MAC or the signature,
 *                                 actual number of bytes written will be returned here
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid context)
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see yaca_sign_initialize()
 * @see yaca_sign_update()
 * @see yaca_sign_initialize_hmac()
 * @see yaca_sign_initialize_cmac()
 * @see yaca_context_get_output_length()
 */
int yaca_sign_finalize(yaca_context_h ctx,
                       char *signature,
                       size_t *signature_len);

/**
 * @brief  Initializes a signature verification context for asymmetric signatures
 *
 * @since_tizen 3.0
 *
 * @remarks  The @a ctx should be released using yaca_context_destroy()
 *
 * @param[out] ctx      Newly created context
 * @param[in]  algo     Digest algorithm that will be used
 * @param[in]  pub_key  Public key that will be used, algorithm is deduced based on
 *                      key type, supported key types:
 *                      - #YACA_KEY_TYPE_RSA_PUB,
 *                      - #YACA_KEY_TYPE_DSA_PUB,
 *                      - #YACA_KEY_TYPE_EC_PUB
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid algo or key)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_key_type_e
 * @see #yaca_digest_algorithm_e
 * @see yaca_verify_update()
 * @see yaca_verify_finalize()
 * @see yaca_context_destroy()
 */
int yaca_verify_initialize(yaca_context_h *ctx,
                           yaca_digest_algorithm_e algo,
                           const yaca_key_h pub_key);

/**
 * @brief  Feeds the data into the digital signature verification algorithm.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx       Context created by yaca_verify_initialize()
 * @param[in]     data      Data to be verified
 * @param[in]     data_len  Length of the data
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0,
 *                                       invalid context)
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see yaca_verify_initialize()
 * @see yaca_verify_finalize()
 */
int yaca_verify_update(yaca_context_h ctx,
                       const char *data,
                       size_t data_len);

/**
 * @brief  Performs the verification.
 *
 * @since_tizen 3.0
 *
 * @remarks  Skipping yaca_verify_update() and calling only yaca_verify_finalize() will verify
 *           the signature of an empty message.
 *
 * @param[in,out] ctx            A valid verify context
 * @param[in]     signature      Input signature (returned by yaca_sign_finalize())
 * @param[in]     signature_len  Size of the signature
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid context)
 * @retval #YACA_ERROR_INTERNAL Internal error
 * @retval #YACA_ERROR_DATA_MISMATCH The verification failed
 *
 * @see yaca_verify_initialize()
 * @see yaca_verify_update()
 * @see yaca_sign_finalize()
 */
int yaca_verify_finalize(yaca_context_h ctx,
                         const char *signature,
                         size_t signature_len);

/**
  * @}
  */

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_SIGN_H */
