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
 * @file internal.h
 * @brief
 */

#ifndef YACA_INTERNAL_H
#define YACA_INTERNAL_H

#include <stddef.h>

#include <openssl/ossl_typ.h>
#include <openssl/err.h>

#include <yaca_types.h>

#define API __attribute__ ((visibility("default")))
#define UNUSED __attribute__((unused))

enum yaca_ctx_type_e {
	YACA_CTX_INVALID = 0,
	YACA_CTX_DIGEST,
	YACA_CTX_SIGN,
	YACA_CTX_ENCRYPT
};

enum encrypt_op_type {
	OP_ENCRYPT = 0,
	OP_DECRYPT = 1,
	OP_SEAL    = 2,
	OP_OPEN    = 3
};

/* Base structure for crypto contexts - to be inherited */
struct yaca_context_s {
	enum yaca_ctx_type_e type;

	void (*ctx_destroy)(const yaca_context_h ctx);
	int (*get_output_length)(const yaca_context_h ctx, size_t input_len, size_t *output_len);
	int (*set_param)(yaca_context_h ctx, yaca_property_e param,
	                 const void *value, size_t value_len);
	int (*get_param)(const yaca_context_h ctx, yaca_property_e param,
	                 void **value, size_t *value_len);
};

struct yaca_encrypt_context_s {
	struct yaca_context_s ctx;

	EVP_CIPHER_CTX *cipher_ctx;
	enum encrypt_op_type op_type; /* Operation context was created for */
	size_t tag_len;
};

/* Base structure for crypto keys - to be inherited */
struct yaca_key_s {
	yaca_key_type_e type;
};

/**
 * Internal type for:
 * - YACA_KEY_TYPE_SYMMETRIC
 * - YACA_KEY_TYPE_DES
 * - YACA_KEY_TYPE_IV
 */
struct yaca_key_simple_s {
	struct yaca_key_s key;

	size_t bits;
	char d[];
};

/**
 * Internal type for:
 * - YACA_KEY_TYPE_RSA_PUB
 * - YACA_KEY_TYPE_RSA_PRIV
 * - YACA_KEY_TYPE_DSA_PUB
 * - YACA_KEY_TYPE_DSA_PRIV
 *
 */
struct yaca_key_evp_s {
	struct yaca_key_s key;

	EVP_PKEY *evp;
};

int digest_get_algorithm(yaca_digest_algorithm_e algo, const EVP_MD **md);

struct yaca_encrypt_context_s *get_encrypt_context(const yaca_context_h ctx);

void destroy_encrypt_context(const yaca_context_h ctx);

int get_encrypt_output_length(const yaca_context_h ctx, size_t input_len, size_t *output_len);

int set_encrypt_property(yaca_context_h ctx, yaca_property_e property,
                         const void *value, size_t value_len);

int get_encrypt_property(const yaca_context_h ctx, yaca_property_e property,
                         void **value, size_t *value_len);

int encrypt_get_algorithm(yaca_encrypt_algorithm_e algo,
                          yaca_block_cipher_mode_e bcm,
                          size_t key_bits,
                          const EVP_CIPHER **cipher);

int encrypt_update(yaca_context_h ctx,
                   const unsigned char *input, size_t input_len,
                   unsigned char *output, size_t *output_len,
                   enum encrypt_op_type op_type);

int encrypt_finalize(yaca_context_h ctx,
                     unsigned char *output, size_t *output_len,
                     enum encrypt_op_type op_type);

struct yaca_key_simple_s *key_get_simple(const yaca_key_h key);
struct yaca_key_evp_s *key_get_evp(const yaca_key_h key);

void error_dump(const char *file, int line, const char *function, int code);
#define ERROR_DUMP(code) error_dump(__FILE__, __LINE__, __func__, (code))
#define ERROR_CLEAR() ERR_clear_error()

/**
 * Function responsible for translating the openssl error to yaca error and
 * clearing/dumping the openssl error queue. Use only after openssl function
 * failure.
 *
 * The function checks only first error in the queue. If the function doesn't
 * find any error in openssl queue or is not able to translate it, it will
 * return YACA_ERROR_INTERNAL and dump openssl errors if any. If the
 * translation succeeds the function will clear the error queue and return the
 * result of translation.
 */
int error_handle(const char *file, int line, const char *function);
#define ERROR_HANDLE() error_handle(__FILE__, __LINE__, __func__)

#endif /* YACA_INTERNAL_H */
