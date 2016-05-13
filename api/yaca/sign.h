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
 * @brief  Initializes a signature context.
 *
 * @param[out] ctx   Newly created context (must be freed with yaca_ctx_free()).
 * @param[in]  algo  Digest algorithm that will be used.
 * @param[in]  key   Private or symmetric key that will be used (algorithm is deduced based on key type).
 *
 * @return 0 on success, negative on error.
 * @see #yaca_digest_algo_e, yaca_sign_update(), yaca_sign_final()
 */
int yaca_sign_init(yaca_ctx_h *ctx,
                   yaca_digest_algo_e algo,
                   const yaca_key_h key);

/**
 * @brief  Feeds the data into the digital signature algorithm.
 *
 * @param[in,out] ctx       Context created by yaca_sign_init().
 * @param[in]     data      Data to be signed.
 * @param[in]     data_len  Length of the data.
 *
 * @return 0 on success, negative on error.
 * @see yaca_sign_init(), yaca_sign_final()
 */
int yaca_sign_update(yaca_ctx_h ctx,
                     const char *data,
                     size_t data_len);

/**
 * @brief  Calculates the final signature.
 *
 * @param[in,out] ctx      A valid sign context.
 * @param[out]    mac      Buffer for the MAC or the signature (must be allocated by client, see
 *                         yaca_get_sign_length()).
 * @param[out]    mac_len  Length of the MAC or the signature, actual number of bytes written will be returned here.
 *
 * @return 0 on success, negative on error.
 * @see yaca_sign_init(), yaca_sign_update()
 */
int yaca_sign_final(yaca_ctx_h ctx,
                    char *mac,
                    size_t *mac_len);

/**
 * @brief  Initializes a signature verification context.
 *
 * @param[out] ctx   Newly created context (must be freed with yaca_ctx_free()).
 * @param[in]  algo  Digest algorithm that will be used.
 * @param[in]  key   Private or symmetric key that will be used (algorithm is deduced based on key type).
 *
 * @return 0 on success, negative on error.
 * @see #yaca_digest_algo_e, yaca_verify_update(), yaca_verify_final()
 */
int yaca_verify_init(yaca_ctx_h *ctx,
                     yaca_digest_algo_e algo,
                     const yaca_key_h key);

/**
 * @brief  Feeds the data into the digital signature verification algorithm.
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
 * @param[in,out] ctx      A valid verify context.
 * @param[in]     mac      Input MAC or signature (returned by yaca_sign_final()).
 * @param[in]     mac_len  Size of the MAC or the signature.
 *
 * @return 0 on success, negative on error.
 * @see yaca_verify_init(), yaca_verify_update()
 */
int yaca_verify_final(yaca_ctx_h ctx,
                      const char *mac,
                      size_t mac_len);

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_SIGN_H */
