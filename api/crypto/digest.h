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
#include <crypto/types.h>

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
 * @brief owl_digest_init  Initializes a digest context.
 *
 * @param[out] ctx   Newly created context (must be freed with @see owl_ctx_free).
 * @param[in]  algo  Digest algorithm that will be used.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int owl_digest_init(owl_ctx_h *ctx, owl_digest_algo_e algo);

/**
 * @brief owl_digest_update  Feeds the data into the message digest algorithm.
 *
 * @param[in,out] ctx       Context created by @see owl_digest_init.
 * @param[in]     data      Data from which the digest is to be calculated.
 * @param[in]     data_len  Length of the data.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int owl_digest_update(owl_ctx_h ctx, const char *data, size_t data_len);

/**
 * @brief owl_digest_final  Calculates the final digest.
 *
 * @param[in,out] ctx         A valid digest context.
 * @param[out]    digest      Buffer for the message digest (must be allocated by client, @see owl_get_digest_length).
 * @param[out]    digest_len  Length of the digest, actual number of bytes written will be returned here.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int owl_digest_final(owl_ctx_h ctx, char *digest, size_t *digest_len);

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* DIGEST_H */
