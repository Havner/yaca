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

#include "config.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <yaca/crypto.h>
#include <yaca/error.h>
#include <yaca/key.h>

#include "key_p.h"

static inline void key_sanity_check(const yaca_key_h key)
{
	assert(key->length);
	assert(key->length % 8 == 0);
}

API int yaca_key_get_length(const yaca_key_h key)
{
	if (key == YACA_KEY_NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	key_sanity_check(key);

	return key->length;
}

API int yaca_key_import(yaca_key_h *key,
			yaca_key_fmt_e key_fmt,
			yaca_key_type_e key_type,
			const char *data,
			size_t data_len)
{
	yaca_key_h nk = NULL;

	if (key == NULL || data == NULL || data_len == 0)
		return YACA_ERROR_INVALID_ARGUMENT;

	if (key_type != YACA_KEY_TYPE_SYMMETRIC)
		return YACA_ERROR_NOT_IMPLEMENTED;

	if (key_fmt != YACA_KEY_FORMAT_RAW)
		return YACA_ERROR_NOT_IMPLEMENTED;

	/* TODO: Overflow on an unsigned value in an undefined behaviour, unless explicitly allowed by a compile flag. */
	if (sizeof(struct yaca_key_s) + data_len < data_len)
		return YACA_ERROR_TOO_BIG_ARGUMENT;

	nk = yaca_malloc(sizeof(struct yaca_key_s) + data_len);
	if (nk == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	memcpy(nk->d, data, data_len); /* TODO: CRYPTO_/OPENSSL_... */
	nk->length = data_len * 8;
	nk->type = key_type;
	*key = nk;

	return 0;
}

API int yaca_key_export(const yaca_key_h key,
			yaca_key_fmt_e key_fmt,
			char **data,
			size_t *data_len)
{
	size_t byte_len;

	if (key == YACA_KEY_NULL || data == NULL || data_len == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	if (key->type != YACA_KEY_TYPE_SYMMETRIC)
		return YACA_ERROR_NOT_IMPLEMENTED;

	if (key_fmt != YACA_KEY_FORMAT_RAW)
		return YACA_ERROR_NOT_IMPLEMENTED;

	key_sanity_check(key);

	byte_len = key->length / 8;
	*data = yaca_malloc(byte_len);
	memcpy(*data, key->d, byte_len);
	*data_len = byte_len;

	return 0;
}

API int yaca_key_gen(yaca_key_h *sym_key,
		     yaca_key_type_e key_type,
		     size_t key_len)
{
	int ret;

	if (sym_key == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	if (key_type != YACA_KEY_TYPE_SYMMETRIC)
		return YACA_ERROR_NOT_IMPLEMENTED;

	*sym_key = yaca_malloc(sizeof(struct yaca_key_s) + key_len);
	if (*sym_key == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	(*sym_key)->length = key_len;
	(*sym_key)->type = key_type;

	ret = yaca_rand_bytes((*sym_key)->d, key_len);
	if (ret == 0)
		return 0;

	yaca_free(*sym_key);
	return ret;
}

API int yaca_key_gen_pair(yaca_key_h *prv_key,
			  yaca_key_h *pub_key,
			  yaca_key_type_e key_type,
			  size_t key_len)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API void yaca_key_free(yaca_key_h key)
{
	if (key == YACA_KEY_NULL)
		return;

	yaca_free(key);
}

API int yaca_key_derive_dh(const yaca_key_h prv_key,
			   const yaca_key_h pub_key,
			   yaca_key_h *sym_key)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_key_derive_kea(const yaca_key_h prv_key,
			    const yaca_key_h pub_key,
			    const yaca_key_h prv_key_auth,
			    const yaca_key_h pub_key_auth,
			    yaca_key_h *sym_key)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_key_derive_pbkdf2(const char *password,
			       const char *salt,
			       size_t salt_len,
			       int iter,
			       yaca_digest_algo_e algo,
			       yaca_key_len_e key_len,
			       yaca_key_h *key)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}
