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

#include <yaca/types.h>

#define API __attribute__ ((visibility ("default")))

enum yaca_ctx_type_e
{
	YACA_CTX_INVALID = 0,
	YACA_CTX_DIGEST,
	YACA_CTX_SIGN,
	YACA_CTX_ENCRYPT,
	YACA_CTX_SEAL
};

/* Base structure for crypto contexts - to be inherited */
struct yaca_ctx_s
{
	enum yaca_ctx_type_e type;

	void (*ctx_destroy)(const yaca_ctx_h ctx);
	int (*get_output_length)(const yaca_ctx_h ctx, size_t input_len, size_t *output_len);
	int (*set_param)(yaca_ctx_h ctx, yaca_ex_param_e param,
			 const void *value, size_t value_len);
	int (*get_param)(const yaca_ctx_h ctx, yaca_ex_param_e param,
			 void **value, size_t *value_len);
};


/* Base structure for crypto keys - to be inherited */
struct yaca_key_s
{
	yaca_key_type_e type;
};

/**
 * Internal type for:
 * - YACA_KEY_TYPE_SYMMETRIC
 * - YACA_KEY_TYPE_DES
 * - YACA_KEY_TYPE_IV
 */
struct yaca_key_simple_s
{
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
 * - YACA_KEY_TYPE_DH_PUB
 * - YACA_KEY_TYPE_DH_PRIV
 * - YACA_KEY_TYPE_EC_PUB
 * - YACA_KEY_TYPE_EC_PRIV
 *
 */
struct yaca_key_evp_s
{
	struct yaca_key_s key;

	EVP_PKEY *evp;
};

int digest_get_algorithm(yaca_digest_algo_e algo, const EVP_MD **md);

int encrypt_get_algorithm(yaca_enc_algo_e algo,
                          yaca_block_cipher_mode_e bcm,
                          size_t key_bits,
                          const EVP_CIPHER **cipher);

struct yaca_key_simple_s *key_get_simple(const yaca_key_h key);
struct yaca_key_evp_s *key_get_evp(const yaca_key_h key);

void error_dump(const char *file, int line, const char *function, int code);
#define ERROR_DUMP(code) error_dump(__FILE__, __LINE__, __func__, (code))
#define ERROR_CLEAR() ERR_clear_error()

#endif /* YACA_INTERNAL_H */
