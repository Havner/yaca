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
 */

#ifndef YACA_CRYPTO_H
#define YACA_CRYPTO_H

#include <stddef.h>
#include <yaca_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup CAPI_YACA_ENCRYPTION_MODULE
 * @{
 */

/**
 * Note:  Non-Crypto  Yet Another Crypto API - non crypto related functions.
 *
 *
 */

/**
 * @brief  NULL value for the crypto context.
 *
 * @since_tizen 3.0
 */
#define YACA_CONTEXT_NULL ((yaca_context_h) NULL)

/**
 * @brief  Initializes the library. Must be called before any other crypto
 *         function. Should be called once in each thread that uses yaca.
 *
 * @since_tizen 3.0
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see yaca_cleanup()
 */
int yaca_initialize(void);

/**
 * @brief  Cleans up the library. Must be called before exiting the thread that
 *         called yaca_initialize().
 *
 * @since_tizen 3.0
 *
 * @see yaca_initialize()
 */
void yaca_cleanup(void);

/**
 * @brief  Allocates the memory.
 *
 * @since_tizen 3.0
 *
 * @remarks  The @a memory should be freed using yaca_free()
 *
 * @param[in]  size   Size of the allocation (bytes)
 * @param[out] memory Allocated memory
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 *
 * @see yaca_zalloc()
 * @see yaca_realloc()
 * @see yaca_free()
 */
int yaca_malloc(size_t size, void **memory);

/**
 * @brief  Allocates the zeroed memory.
 *
 * @since_tizen 3.0
 *
 * @remarks  The @a memory should be freed using yaca_free()
 *
 * @param[in]  size    Size of the allocation (bytes)
 * @param[out] memory  Allocated memory
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 *
 * @see yaca_malloc()
 * @see yaca_realloc()
 * @see yaca_free()
 */
int yaca_zalloc(size_t size, void **memory);

/**
 * @brief  Re-allocates the memory.
 *
 * @since_tizen 3.0
 *
 * @remarks  In case of failure the function doesn't free the memory pointed by @a memory.
 *
 * @remarks  If @a memory is NULL then the call is equivalent to yaca_malloc().
 *
 * @remarks  If the function fails the contents of @a memory will be left unchanged.
 *
 * @remarks  The @a memory should be freed using yaca_free()
 *
 * @param[in]     size    Size of the new allocation (bytes)
 * @param[in,out] memory  Memory to be reallocated
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 *
 * @see yaca_malloc()
 * @see yaca_zalloc()
 * @see yaca_free()
 */
int yaca_realloc(size_t size, void **memory);

/**
 * @brief  Frees the memory allocated by yaca_malloc(), yaca_zalloc(),
 *         yaca_realloc() or one of the cryptographic operations.
 *
 * @since_tizen 3.0
 *
 * @param[in] memory  Pointer to the memory to be freed
 *
 * @see yaca_malloc()
 * @see yaca_zalloc()
 * @see yaca_realloc()
 */
void yaca_free(void *memory);

/**
 * @brief  Safely compares first @a len bytes of two buffers.
 *
 * @since_tizen 3.0
 *
 * @param[in]  first  Pointer to the first buffer
 * @param[in]  second Pointer to the second buffer
 * @param[in]  len    Length to compare
 *
 * @return #YACA_ERROR_NONE when buffers are equal otherwise #YACA_ERROR_DATA_MISMATCH
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0)
 * @retval #YACA_ERROR_DATA_MISMATCH Buffers are different
 */
int yaca_memcmp(const void *first, const void *second, size_t len);

/**
 * @brief  Generates random data.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] data      Pointer to the memory to be randomized
 * @param[in]     data_len  Length of the memory to be randomized
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0)
 * @retval #YACA_ERROR_INTERNAL Internal error
 */
int yaca_randomize_bytes(char *data, size_t data_len);

/**
 * @brief  Sets the non-standard context properties. Can only be called on an
 *         initialized context.
 *
 * @remarks  The @a value has to be of type appropriate for given property. See #yaca_property_e
 *           for details on corresponding types.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx        Previously initialized crypto context
 * @param[in]     property   Property to be set
 * @param[in]     value      Property value
 * @param[in]     value_len  Length of the property value
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL, 0,
 *                                       invalid ctx or property)
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_property_e
 * @see yaca_context_get_property()
 */
int yaca_context_set_property(yaca_context_h ctx,
                              yaca_property_e property,
                              const void *value,
                              size_t value_len);

/**
 * @brief  Returns the non-standard context properties. Can only be called on an
 *         initialized context.
 *
 * @since_tizen 3.0
 *
 * @remarks  The @a value should be freed using yaca_free()
 *
 * @remarks  The @a value has to be of type appropriate for given property. See #yaca_property_e
 *           for details on corresponding types.
 *
 * @remarks  @a value_len can be NULL if returned @a value is a single object (i.e. not an array/buffer)
 *
 * @param[in]  ctx        Previously initialized crypto context
 * @param[in]  property   Property to be read
 * @param[out] value      Copy of the property value
 * @param[out] value_len  Length of the property value will be returned here
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid ctx or property)
 * @retval #YACA_ERROR_OUT_OF_MEMORY Out of memory error
 * @retval #YACA_ERROR_INTERNAL Internal error
 *
 * @see #yaca_property_e
 * @see yaca_context_set_property()
 * @see yaca_free()
 */
int yaca_context_get_property(const yaca_context_h ctx,
                              yaca_property_e property,
                              void **value,
                              size_t *value_len);

/**
 * @brief  Destroys the crypto context. Must be called on all contexts that are
 *         no longer used. Passing #YACA_CONTEXT_NULL is allowed.
 *
 * @since_tizen 3.0
 *
 * @param[in,out] ctx  Crypto context
 *
 * @see #yaca_context_h
 *
 */
void yaca_context_destroy(yaca_context_h ctx);

/**
 * @brief  Returns the output length for a given algorithm. Can only be called
 *         on an initialized context.
 *
 * @since_tizen 3.0
 *
 * @remarks  This function can be used to learn the required size of the output buffer
 *           for a single operation (eg. *_update or *_finalize). In case the operation
 *           has no input (eg. *_finalize), the value of @a input_len has to be set to 0.
 *
 * @param[in]  ctx         Previously initialized crypto context
 * @param[in]  input_len   Length of the input data to be processed
 * @param[out] output_len  Required length of the output
 *
 * @return #YACA_ERROR_NONE on success, negative on error
 * @retval #YACA_ERROR_NONE Successful
 * @retval #YACA_ERROR_INVALID_PARAMETER Required parameters have incorrect values (NULL,
 *                                       invalid context or too big input_len)
 * @retval #YACA_ERROR_INTERNAL Internal error
 */
int yaca_context_get_output_length(const yaca_context_h ctx,
                                   size_t input_len,
                                   size_t *output_len);

/**
  * @}
  */

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_CRYPTO_H */
