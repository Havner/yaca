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
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <crypto/crypto.h>
#include <crypto/error.h>

#include "key_p.h"

// Sanity check on key
inline void key_sanity_check(const crypto_key_h key)
{
	assert(key->length);
	assert(key->length % 8 == 0);
}

int crypto_key_get_length(const crypto_key_h key)
{
	if (!key)
		return CRYPTO_ERROR_INVALID_ARGUMENT;
	key_sanity_check(key);

	return key->length;
}

int crypto_key_import(crypto_key_h *key,
		      crypto_key_fmt_e key_fmt,
		      crypto_key_type_e key_type,
		      const char *data,
		      size_t data_len)
{
	crypto_key_h nk = NULL;

	if (!key || !data || !data_len)
		return CRYPTO_ERROR_INVALID_ARGUMENT;

	if (key_type != CRYPTO_KEY_TYPE_SYMMETRIC)
		return CRYPTO_ERROR_NOT_IMPLEMENTED;

	if (key_fmt != CRYPTO_KEY_FORMAT_RAW)
		return CRYPTO_ERROR_NOT_IMPLEMENTED;

	if (sizeof(struct __crypto_key_s) + data_len < data_len)
		return CRYPTO_ERROR_TOO_BIG_ARGUMENT;

	nk = crypto_alloc(sizeof(struct __crypto_key_s) + data_len);
	if (!nk)
		return CRYPTO_ERROR_OUT_OF_MEMORY;

	memcpy(nk->d, data, data_len);
	nk->length = data_len * 8;
	nk->type = key_type;
	*key = nk;

	return 0;
}

int crypto_key_export(const crypto_key_h key,
		      crypto_key_fmt_e key_fmt,
		      char **data,
		      size_t *data_len)
{
	int byte_len;

	if (!key || !data || !data_len)
		return CRYPTO_ERROR_INVALID_ARGUMENT;

	if (key->type != CRYPTO_KEY_TYPE_SYMMETRIC)
		return CRYPTO_ERROR_NOT_IMPLEMENTED;

	if (key_fmt != CRYPTO_KEY_FORMAT_RAW)
		return CRYPTO_ERROR_NOT_IMPLEMENTED;

	key_sanity_check(key);

	byte_len = key->length / 8;
	*data = crypto_alloc(byte_len);
	memcpy(*data, key->d, byte_len);
	*data_len = byte_len;

	return 0;
}

int crypto_key_gen(crypto_key_h *sym_key,
		   crypto_key_type_e key_type,
		   size_t key_len)
{
	if (!sym_key || key_type != CRYPTO_KEY_TYPE_SYMMETRIC)
		return -1;

	*sym_key = crypto_alloc(sizeof(struct __crypto_key_s) + key_len);
	if (!*sym_key)
		return -1;

	(*sym_key)->length = key_len;
	(*sym_key)->type = key_type;
	return crypto_rand_bytes((*sym_key)->d, key_len);
}

int crypto_key_gen_pair(crypto_key_h *prv_key,
			crypto_key_h *pub_key,
			crypto_key_type_e key_type,
			size_t key_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

void crypto_key_free(crypto_key_h key)
{
	if (!key)
		return;

	crypto_free(key);
}

int crypto_key_derive_dh(const crypto_key_h prv_key,
			 const crypto_key_h pub_key,
			 crypto_key_h *sym_key)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_key_derive_kea(const crypto_key_h prv_key,
			  const crypto_key_h pub_key,
			  const crypto_key_h prv_key_auth,
			  const crypto_key_h pub_key_auth,
			  crypto_key_h *sym_key)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_key_derive_pbkdf2(const char *password,
			     const char *salt,
			     size_t salt_len,
			     int iter,
			     crypto_digest_algo_e algo,
			     crypto_key_len_e key_len,
			     crypto_key_h *key)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}
