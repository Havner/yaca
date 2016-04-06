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
 * @file digest.h
 * @brief
 */

#ifndef DIGEST_H
#define DIGEST_H

#include <stddef.h>
#include <yaca/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup  Advanced-Digest  Advanced API for the message digests.
 *
 * TODO: extended description and examples.
 *
 * @{
 */

/**
 * @brief yaca_digest_init  Initializes a digest context.
 *
 * @param[out] ctx   Newly created context (must be freed with @see yaca_ctx_free).
 * @param[in]  algo  Digest algorithm that will be used.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int yaca_digest_init(yaca_ctx_h *ctx, yaca_digest_algo_e algo);

/**
 * @brief yaca_digest_update  Feeds the data into the message digest algorithm.
 *
 * @param[in,out] ctx       Context created by @see yaca_digest_init.
 * @param[in]     data      Data from which the digest is to be calculated.
 * @param[in]     data_len  Length of the data.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int yaca_digest_update(yaca_ctx_h ctx, const char *data, size_t data_len);

/**
 * @brief yaca_digest_final  Calculates the final digest.
 *
 * @param[in,out] ctx         A valid digest context.
 * @param[out]    digest      Buffer for the message digest (must be allocated by client, @see yaca_get_digest_length).
 * @param[out]    digest_len  Length of the digest, actual number of bytes written will be returned here.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int yaca_digest_final(yaca_ctx_h ctx, char *digest, size_t *digest_len);

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* DIGEST_H */