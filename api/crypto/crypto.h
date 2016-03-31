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
#include <crypto/types.h>

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
 * @brief CRYPTO_CTX_NULL  NULL value for the crypto context.
 */
#define CRYPTO_CTX_NULL ((crypto_ctx_h) NULL)

/**
 * @brief crypto_init  Initializes the library. Must be called before any other crypto function.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int crypto_init(void);

/**
 * @brief crypto_exit  Closes the library. Must be called before exiting the application.
 *
 */
void crypto_exit(void);

/**
 * @brief crypto_alloc  Allocates memory.
 *
 * @param[in] size  Size of the allocation (bytes).
 *
 * @return NULL on failure, pointer to allocated memory otherwise.
 */
void *crypto_alloc(size_t size);

/**
 * @brief crypto_free  Frees the memory allocated by @see crypto_alloc
 *	               or one of the cryptographics operations.
 *
 * @param[in] ptr  Pointer to the memory to be freed.
 *
 */
void crypto_free(void *ptr);

/**
 * @brief crypto_rand_bytes  Generates random data.
 *
 * @param[in,out] data      Pointer to the memory to be randomized.
 * @param[in]     data_len  Length of the memory to be randomized.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int crypto_rand_bytes(char *data, size_t data_len);

/**
 * @brief crypto_ctx_set_param  Sets the extended context parameters.
 *                              Can only be called on an initialized context.
 *
 * @param[in,out] ctx        Previously initialized crypto context.
 * @param[in]     param      Parameter to be set.
 * @param[in]     value      Parameter value.
 * @param[in]     value_len  Length of the parameter value.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int crypto_ctx_set_param(crypto_ctx_h ctx, crypto_ex_param_e param,
			 const void *value, size_t value_len);

/**
 * @brief crypto_ctx_get_param  Returns the extended context parameters.
 *                              Can only be called on an initialized context.
 *
 * @param[in]  ctx        Previously initialized crypto context.
 * @param[in]  param      Parameter to be read.
 * @param[out] value      Copy of the parameter value (must be freed with @see crypto_free).
 * @param[out] value_len  Length of the parameter value will be returned here.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int crypto_ctx_get_param(const crypto_ctx_h ctx, crypto_ex_param_e param,
			 void **value, size_t *value_len);

/**
 * @brief crypto_ctx_free  Destroys the crypto context. Must be called
 *                         on all contexts that are no longer used.
 *                         Passing CRYPTO_CTX_NULL is allowed.
 *
 * @param[in,out] ctx  Crypto context.
 *
 */
void crypto_ctx_free(crypto_ctx_h ctx);

/**
 * @brief crypto_get_output_length  Returns the output length for a given algorithm.
 *                                  Can only be called on an initialized context.
 *
 * @param[in] ctx        Previously initialized crypto context.
 * @param[in] input_len  Length of the input data to be processed.
 *
 * @return negative on error (@see error.h) or length of output.
 */
int crypto_get_output_length(const crypto_ctx_h ctx, size_t input_len);

/**
 * @brief crypto_get_digest_length  Wrapper - returns the length of the digest (for a given context).
 */
#define crypto_get_digest_length(ctxa) crypto_get_output_length((ctxa), 0)

/**
 * @brief crypto_get_sign_length  Wrapper - returns the length of the signature (for a given context).
 */
#define crypto_get_sign_length(ctxa) crypto_get_output_length((ctxa), 0)

/**
 * @brief crypto_get_block_length  Wrapper - returns the length of the block (for a given context).
 */
#define crypto_get_block_length(ctxa) crypto_get_output_length((ctxa), 0)

/**
 * @brief crypto_get_iv_length  Returns the recomended/default length of the IV for a given encryption configuration.
 *
 * @param[in] algo  Encryption algorithm.
 * @param[in] bcm   Chain mode.
 * @param[in] len   Key length (@see crypto_key_len_e).
 *
 * @return negative on error (@see error.h) or the IV length.
 */
int crypto_get_iv_length(crypto_enc_algo_e algo,
			 crypto_block_cipher_mode_e bcm,
			 size_t key_len);

/**@}*/
#ifdef __cplusplus
} /* extern */
#endif

#endif /* CRYPTO_H */
