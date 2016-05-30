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
 * @file yaca_crypto.h
 * @brief
 */

#ifndef YACA_CRYPTO_H
#define YACA_CRYPTO_H

#include <stddef.h>
#include <yaca_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup  Non-Crypto  Yet Another Crypto API - non crypto related functions.
 *
 * TODO: extended description and examples.
 *
 * @{
 */

/**
 * @brief  NULL value for the crypto context.
 *
 * @since_tizen 3.0
 */
#define YACA_CTX_NULL ((yaca_ctx_h) NULL)

/**
 * @brief  Initializes the library. Must be called before any other crypto function.
 *
 * @since_tizen 3.0
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Succesful
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see yaca_exit()
 */
int yaca_init(void);

/**
 * @brief  Closes the library. Must be called before exiting the application.
 *
 * @since_tizen 3.0
 *
 * @see yaca_init()
 */
void yaca_exit(void);

/**
 * @brief  Allocates the memory.
 *
 * @since_tizen 3.0
 *
 * @param[in] size  Size of the allocation (bytes)
 *
 * @return NULL on failure, pointer to allocated memory otherwise
 *
 * @see yaca_zalloc()
 * @see yaca_realloc()
 * @see yaca_free()
 */
void *yaca_malloc(size_t size);

/**
 * @brief  Allocates the zeroed memory.
 *
 * @since_tizen 3.0
 *
 * @param[in] size  Size of the allocation (bytes)
 *
 * @return NULL on failure, pointer to allocated and zeroed memory otherwise
 *
 * @see yaca_malloc()
 * @see yaca_realloc()
 * @see yaca_free()
 */
void *yaca_zalloc(size_t size);

/**
 * @brief  Re-allocates the memory.
 *
 * @since_tizen 3.0
 *
 * @param[in] addr  Address of the memory to be reallocated
 * @param[in] size  Size of the new allocation (bytes)
 *
 * @return NULL on failure, pointer to allocated memory otherwise
 *
 * @see yaca_malloc()
 * @see yaca_zalloc()
 * @see yaca_free()
 */
void *yaca_realloc(void *addr, size_t size);

/**
 * @brief  Frees the memory allocated by yaca_malloc(), yaca_zalloc(),
 *         yaca_realloc() or one of the cryptographic operations.
 *
 * @since_tizen 3.0
 *
 * @param[in] ptr  Pointer to the memory to be freed
 *
 * @see yaca_malloc()
 * @see yaca_zalloc()
 * @see yaca_realloc()
 */
void yaca_free(void *ptr);

/**
 * @brief  Generates random data.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] data      Pointer to the memory to be randomized
 * @param[in]     data_len  Length of the memory to be randomized
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Succesful
 * @retval #YACA_ERROR_INVALID_ARGUMENT Required parameters have bogus values (NULL, 0)
 * @retval #YACA_ERROR_INTERNAL Internal error
 */
int yaca_rand_bytes(char *data, size_t data_len);

/**
 * @brief  Sets the extended context parameters. Can only be called on an
 *         initialized context.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx        Previously initialized crypto context
 * @param[in]     param      Parameter to be set
 * @param[in]     value      Parameter value
 * @param[in]     value_len  Length of the parameter value
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Succesful
 * @retval #YACA_ERROR_INVALID_ARGUMENT Required parameters have bogus values (NULL, 0,
 *                                      incorrect context, invalid param)
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_ex_param_e
 * @see yaca_ctx_get_param()
 */
int yaca_ctx_set_param(yaca_ctx_h ctx,
                       yaca_ex_param_e param,
                       const void *value,
                       size_t value_len);

/**
 * @brief  Returns the extended context parameters. Can only be called on an
 *         initialized context.
 *
 * @since_tizen 3.0
 *
 * @param[in]  ctx        Previously initialized crypto context
 * @param[in]  param      Parameter to be read
 * @param[out] value      Copy of the parameter value (must be freed with yaca_free())
 * @param[out] value_len  Length of the parameter value will be returned here
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Succesful
 * @retval #YACA_ERROR_INVALID_ARGUMENT Required parameters have bogus values (NULL,
 *                                      incorrect context, invalid param)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_ex_param_e
 * @see yaca_ctx_set_param()
 */
int yaca_ctx_get_param(const yaca_ctx_h ctx,
                       yaca_ex_param_e param,
                       void **value,
                       size_t *value_len);

/**
 * @brief  Destroys the crypto context. Must be called on all contexts that are
 *         no longer used. Passing #YACA_CTX_NULL is allowed.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx  Crypto context
 *
 * @see #yaca_ctx_h
 *
 */
void yaca_ctx_free(yaca_ctx_h ctx);

/**
 * @brief  Returns the output length for a given algorithm. Can only be called
 *         on an initialized context.
 *
 * @since_tizen 3.0
 *
 * @param[in]  ctx         Previously initialized crypto context
 * @param[in]  input_len   Length of the input data to be processed
 * @param[out] output_len  Required length of the output
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Succesful
 * @retval #YACA_ERROR_INVALID_ARGUMENT Required parameters have bogus values (NULL,
 *                                      incorrect context, invalid input_len)
 * @retval #YACA_ERROR_INTERNAL Internal error
 */
int yaca_get_output_length(const yaca_ctx_h ctx, size_t input_len, size_t *output_len);

/**
 * @brief  Wrapper - returns the length of the digest (for a given context).
 *
 * @since_tizen 3.0
 */
#define yaca_get_digest_length(ctxa, output_len) yaca_get_output_length((ctxa), 0, (output_len))

/**
 * @brief  Wrapper - returns the length of the signature (for a given context).
 *
 * @since_tizen 3.0
 */
#define yaca_get_sign_length(ctxa, output_len) yaca_get_output_length((ctxa), 0, (output_len))

/**
 * @brief  Wrapper - returns the length of the block (for a given context).
 *
 * @since_tizen 3.0
 */
#define yaca_get_block_length(ctxa, output_len) yaca_get_output_length((ctxa), 0, (output_len))

/**
 * @brief  Safely compares first @b len bytes of two buffers.
 *
 * @since_tizen 3.0
 *
 * @param[in]  first  Pointer to the first buffer
 * @param[in]  second Pointer to the second buffer
 * @param[in]  len    Length to compare
 *
 * @return #YACA_ERROR_NONE when buffers are equal otherwise #YACA_ERROR_DATA_MISMATCH
 * @retval #YACA_ERROR_NONE Succesful
 * @retval #YACA_ERROR_DATA_MISMATCH Buffers are different
 */
int yaca_memcmp(const void *first, const void *second, size_t len);

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_CRYPTO_H */
