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
 * @file yaca_digest.h
 * @brief
 */

#ifndef YACA_DIGEST_H
#define YACA_DIGEST_H

#include <stddef.h>
#include <yaca_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup  Advanced-Digest  Advanced API for the message digests.
 *
 *
 * @{
 */

/**
 * @brief  Initializes a digest context.
 *
 * @since_tizen 3.0
 *
 * @param[out] ctx   Newly created context (must be freed with yaca_context_destroy())
 * @param[in]  algo  Digest algorithm that will be used
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid algo)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_digest_algorithm_e
 * @see yaca_digest_update()
 * @see yaca_digest_finalize()
 * @see yaca_context_destroy()
 */
int yaca_digest_initialize(yaca_context_h *ctx, yaca_digest_algorithm_e algo);

/**
 * @brief  Feeds the data into the message digest algorithm.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx       Context created by yaca_digest_initialize()
 * @param[in]     data      Data from which the digest is to be calculated
 * @param[in]     data_len  Length of the data
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0,
 *                                       invalid context)
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see yaca_digest_initialize()
 * @see yaca_digest_finalize()
 */
int yaca_digest_update(yaca_context_h ctx, const char *data, size_t data_len);

/**
 * @brief  Calculates the final digest.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx         A valid digest context
 * @param[out]    digest      Buffer for the message digest
 *                            (must be allocated by client, see yaca_context_get_output_length())
 * @param[out]    digest_len  Length of the digest,
 *                            actual number of bytes written will be returned here
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid context)
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see yaca_digest_initialize()
 * @see yaca_digest_update()
 * @see yaca_context_get_output_length()
 */
int yaca_digest_finalize(yaca_context_h ctx, char *digest, size_t *digest_len);

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_DIGEST_H */
