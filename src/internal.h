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
 * @file encrypt.h
 * @brief Internal API
 */

#ifndef INTERNAL_H
#define INTERNAL_H

#include <stddef.h>
#include <openssl/ossl_typ.h>

#include <yaca/types.h>

#define API __attribute__ ((visibility ("default")))

enum yaca_ctx_type_e
{
	YACA_CTX_INVALID = 0,
	YACA_CTX_DIGEST,
	YACA_CTX_SIGN
};

/* Base structure for crypto contexts - to be inherited */
struct yaca_ctx_s
{
	enum yaca_ctx_type_e type;

	void (*ctx_destroy)(const yaca_ctx_h ctx);
	int (*get_output_length)(const yaca_ctx_h ctx, size_t input_len);
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
 *
 * TODO: and possibly others (for every key that uses EVP_PKEY)
 */
struct yaca_key_evp_s
{
	struct yaca_key_s key;

	EVP_PKEY *evp;
};

int digest_get_algorithm(yaca_digest_algo_e algo, const EVP_MD **md);

struct yaca_key_simple_s *key_get_simple(const yaca_key_h key);
struct yaca_key_evp_s *key_get_evp(const yaca_key_h key);

#endif
