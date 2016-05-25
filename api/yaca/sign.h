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
 * @file sign.h
 * @brief
 */

#ifndef YACA_SIGN_H
#define YACA_SIGN_H

#include <stddef.h>
#include <yaca/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup  Advanced-Integrity  Advanced API for the integrity handling - HMAC, CMAC and digital signature.
 *
 * TODO: extended description and examples.
 * TODO: add documentation how to set padding etc
 *
 * @{
 */

/**
 * @brief  Initializes a signature context for asymmetric signatures.
 *
 * @since_tizen 3.0
 *
 * @remarks For verification use yaca_verify_init(), yaca_verify_update() and
 *          yaca_verify_final() functions with matching public key.
 *
 * @param[out] ctx   Newly created context (must be freed with yaca_ctx_free()).
 * @param[in]  algo  Digest algorithm that will be used.
 * @param[in]  key   Private key that will be used. Algorithm is deduced based
 *                   on key type. Supported key types:
 *                   - #YACA_KEY_TYPE_RSA_PRIV,
 *                   - #YACA_KEY_TYPE_DSA_PRIV,
 *                   - #YACA_KEY_TYPE_EC_PRIV.
 *
 * @return 0 on success, negative on error.
 * @see #yaca_key_type_e, #yaca_digest_algo_e, yaca_sign_update(),
 *      yaca_sign_final(), yaca_verify_init(), yaca_verify_update(),
 *      yaca_verify_final()
 */
int yaca_sign_init(yaca_ctx_h *ctx,
                   yaca_digest_algo_e algo,
                   const yaca_key_h key);

/**
 * @brief  Initializes a signature context for HMAC.
 *
 * @since_tizen 3.0
 *
 * @remarks For verification, calculate message HMAC and compare with received MAC using
 *          yaca_memcmp().
 *
 * @param[out] ctx   Newly created context (must be freed with yaca_ctx_free()).
 * @param[in]  algo  Digest algorithm that will be used.
 * @param[in]  key   Symmetric key that will be used. Supported key types:
 *                   - #YACA_KEY_TYPE_SYMMETRIC,
 *                   - #YACA_KEY_TYPE_DES.
 *
 * @return 0 on success, negative on error.
 * @see #yaca_key_type_e, #yaca_digest_algo_e, yaca_sign_update(),
 *      yaca_sign_final(), yaca_memcmp()
 */
int yaca_sign_hmac_init(yaca_ctx_h *ctx,
                        yaca_digest_algo_e algo,
                        const yaca_key_h key);

/**
 * @brief  Initializes a signature context for CMAC.
 *
 * @since_tizen 3.0
 *
 * @remarks For verification, calculate message CMAC and compare with received MAC using
 *          yaca_memcmp().
 *
 * @param[out] ctx   Newly created context (must be freed with yaca_ctx_free()).
 * @param[in]  algo  Encryption algorithm that will be used.
 * @param[in]  key   Symmetric key that will be used. Supported key types:
 *                   - #YACA_KEY_TYPE_SYMMETRIC,
 *                   - #YACA_KEY_TYPE_DES.
 *
 * @return 0 on success, negative on error.
 * @see #yaca_key_type_e, #yaca_enc_algo_e, yaca_sign_update(),
 *      yaca_sign_final(), yaca_memcmp()
 */
int yaca_sign_cmac_init(yaca_ctx_h *ctx,
                        yaca_enc_algo_e algo,
                        const yaca_key_h key);

/**
 * @brief  Feeds the data into the digital signature or MAC algorithm.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx       Context created by yaca_sign_init(),
 *                          yaca_sign_hmac_init() or yaca_sign_cmac_init().
 * @param[in]     data      Data to be signed.
 * @param[in]     data_len  Length of the data.
 *
 * @return 0 on success, negative on error.
 * @see yaca_sign_init(), yaca_sign_final(), yaca_sign_hmac_init(),
 *      yaca_sign_cmac_init()
 */
int yaca_sign_update(yaca_ctx_h ctx,
                     const char *data,
                     size_t data_len);

/**
 * @brief  Calculates the final signature or MAC.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx              A valid sign context.
 * @param[out]    signature        Buffer for the MAC or the signature,
 *                                 (must be allocated by client, see yaca_get_sign_length()).
 * @param[out]    signature_len    Length of the MAC or the signature,
 *                                 actual number of bytes written will be returned here.
 *
 * @return 0 on success, negative on error.
 * @see yaca_sign_init(), yaca_sign_update(), yaca_sign_hmac_init(),
 *      yaca_sign_cmac_init()
 */
int yaca_sign_final(yaca_ctx_h ctx,
                    char *signature,
                    size_t *signature_len);

/**
 * @brief  Initializes a signature verification context for asymmetric signatures
 *
 * @since_tizen 3.0
 *
 * @param[out] ctx   Newly created context (must be freed with yaca_ctx_free()).
 * @param[in]  algo  Digest algorithm that will be used.
 * @param[in]  key   Public key that will be used. Algorithm is deduced based on
 *                   key type. Supported key types:
 *                   - #YACA_KEY_TYPE_RSA_PUB,
 *                   - #YACA_KEY_TYPE_DSA_PUB,
 *                   - #YACA_KEY_TYPE_EC_PUB.
 *
 * @return 0 on success, negative on error.
 * @see #yaca_key_type_e, #yaca_digest_algo_e, yaca_verify_update(),
 *      yaca_verify_final()
 */
int yaca_verify_init(yaca_ctx_h *ctx,
                     yaca_digest_algo_e algo,
                     const yaca_key_h key);

/**
 * @brief  Feeds the data into the digital signature verification algorithm.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx       Context created by yaca_verify_init().
 * @param[in]     data      Data to be verified.
 * @param[in]     data_len  Length of the data.
 *
 * @return 0 on success, negative on error.
 * @see yaca_verify_init(), yaca_verify_final()
 */
int yaca_verify_update(yaca_ctx_h ctx,
                       const char *data,
                       size_t data_len);

/**
 * @brief  Performs the verification.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx            A valid verify context.
 * @param[in]     signature      Input signature (returned by yaca_sign_final()).
 * @param[in]     signature_len  Size of the signature.
 *
 * @return 0 on success, YACA_ERROR_DATA_MISMATCH if verification fails,
 *         negative on error.
 * @see yaca_verify_init(), yaca_verify_update()
 */
int yaca_verify_final(yaca_ctx_h ctx,
                      const char *signature,
                      size_t signature_len);

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_SIGN_H */
