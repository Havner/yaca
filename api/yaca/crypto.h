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
 * @file crypto.h
 * @brief
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <yaca/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup  Non-Crypto  Non crypto related functions.
 *
 * TODO: extended description and examples.
 *
 * @{
 */

/**
 * @brief YACA_CTX_NULL  NULL value for the crypto context.
 */
#define YACA_CTX_NULL ((yaca_ctx_h) NULL)

/**
 * @brief yaca_init  Initializes the library. Must be called before any other crypto function.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int yaca_init(void);

/**
 * @brief yaca_exit  Closes the library. Must be called before exiting the application.
 *
 */
void yaca_exit(void);

/**
 * @brief yaca_malloc  Allocates the memory.
 *
 * @param[in] size  Size of the allocation (bytes).
 *
 * @return NULL on failure, pointer to allocated memory otherwise.
 */
// TODO: this should be a macro to CRYPTO_*
void *yaca_malloc(size_t size);

/**
 * @brief yaca_realloc  Re-allocates the memory.
 *
 * @param[in] addr  Address of the memory to be reallocated.
 * @param[in] size  Size of the new allocation (bytes).
 *
 * @return NULL on failure, pointer to allocated memory otherwise.
 */
// TODO: this should be a macro to CRYPTO_*
void *yaca_realloc(void *addr, size_t size);

/**
 * @brief yaca_free  Frees the memory allocated by @see yaca_malloc
 *	             or one of the cryptographics operations.
 *
 * @param[in] ptr  Pointer to the memory to be freed.
 *
 */
// TODO: this should be a macro to CRYPTO_*
void yaca_free(void *ptr);

/**
 * @brief yaca_rand_bytes  Generates random data.
 *
 * @param[in,out] data      Pointer to the memory to be randomized.
 * @param[in]     data_len  Length of the memory to be randomized.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int yaca_rand_bytes(char *data, size_t data_len);

/**
 * @brief yaca_ctx_set_param  Sets the extended context parameters.
 *                            Can only be called on an initialized context.
 *
 * @param[in,out] ctx        Previously initialized crypto context.
 * @param[in]     param      Parameter to be set.
 * @param[in]     value      Parameter value.
 * @param[in]     value_len  Length of the parameter value.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int yaca_ctx_set_param(yaca_ctx_h ctx, yaca_ex_param_e param,
		       const void *value, size_t value_len);

/**
 * @brief yaca_ctx_get_param  Returns the extended context parameters.
 *                            Can only be called on an initialized context.
 *
 * @param[in]  ctx        Previously initialized crypto context.
 * @param[in]  param      Parameter to be read.
 * @param[out] value      Copy of the parameter value (must be freed with @see yaca_free).
 * @param[out] value_len  Length of the parameter value will be returned here.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int yaca_ctx_get_param(const yaca_ctx_h ctx, yaca_ex_param_e param,
		       void **value, size_t *value_len);

/**
 * @brief yaca_ctx_free  Destroys the crypto context. Must be called
 *                       on all contexts that are no longer used.
 *                       Passing YACA_CTX_NULL is allowed.
 *
 * @param[in,out] ctx  Crypto context.
 *
 */
void yaca_ctx_free(yaca_ctx_h ctx);

/**
 * @brief yaca_get_output_length  Returns the output length for a given algorithm.
 *                                Can only be called on an initialized context.
 *
 * @param[in] ctx        Previously initialized crypto context.
 * @param[in] input_len  Length of the input data to be processed.
 *
 * @return negative on error (@see error.h) or length of output.
 */
int yaca_get_output_length(const yaca_ctx_h ctx, size_t input_len);

/**
 * @brief yaca_get_digest_length  Wrapper - returns the length of the digest (for a given context).
 */
#define yaca_get_digest_length(ctxa) yaca_get_output_length((ctxa), 0)

/**
 * @brief yaca_get_sign_length  Wrapper - returns the length of the signature (for a given context).
 */
#define yaca_get_sign_length(ctxa) yaca_get_output_length((ctxa), 0)

/**
 * @brief yaca_get_block_length  Wrapper - returns the length of the block (for a given context).
 */
#define yaca_get_block_length(ctxa) yaca_get_output_length((ctxa), 0)

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* CRYPTO_H */
