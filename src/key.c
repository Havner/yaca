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

#include <crypto/crypto.h>
#include <crypto/error.h>
#include <crypto/key.h>

#include "key_p.h"

static inline void key_sanity_check(const owl_key_h key)
{
	assert(key->length);
	assert(key->length % 8 == 0);
}

API int owl_key_get_length(const owl_key_h key)
{
	if (key == OWL_KEY_NULL)
		return OWL_ERROR_INVALID_ARGUMENT;

	key_sanity_check(key);

	return key->length;
}

API int owl_key_import(owl_key_h *key,
		   owl_key_fmt_e key_fmt,
		   owl_key_type_e key_type,
		   const char *data,
		   size_t data_len)
{
	owl_key_h nk = NULL;

	if (key == NULL || data == NULL || data_len == 0)
		return OWL_ERROR_INVALID_ARGUMENT;

	if (key_type != OWL_KEY_TYPE_SYMMETRIC)
		return OWL_ERROR_NOT_IMPLEMENTED;

	if (key_fmt != OWL_KEY_FORMAT_RAW)
		return OWL_ERROR_NOT_IMPLEMENTED;

	if (sizeof(struct owl_key_s) + data_len < data_len)
		return OWL_ERROR_TOO_BIG_ARGUMENT;

	nk = owl_malloc(sizeof(struct owl_key_s) + data_len);
	if (nk == NULL)
		return OWL_ERROR_OUT_OF_MEMORY;

	memcpy(nk->d, data, data_len);
	nk->length = data_len * 8;
	nk->type = key_type;
	*key = nk;

	return 0;
}

API int owl_key_export(const owl_key_h key,
		   owl_key_fmt_e key_fmt,
		   char **data,
		   size_t *data_len)
{
	size_t byte_len;

	if (key == OWL_KEY_NULL || data == NULL || data_len == NULL)
		return OWL_ERROR_INVALID_ARGUMENT;

	if (key->type != OWL_KEY_TYPE_SYMMETRIC)
		return OWL_ERROR_NOT_IMPLEMENTED;

	if (key_fmt != OWL_KEY_FORMAT_RAW)
		return OWL_ERROR_NOT_IMPLEMENTED;

	key_sanity_check(key);

	byte_len = key->length / 8;
	*data = owl_malloc(byte_len);
	memcpy(*data, key->d, byte_len);
	*data_len = byte_len;

	return 0;
}

API int owl_key_gen(owl_key_h *sym_key,
		owl_key_type_e key_type,
		size_t key_len)
{
	int ret;

	if (sym_key == NULL)
		return OWL_ERROR_INVALID_ARGUMENT;

	if (key_type != OWL_KEY_TYPE_SYMMETRIC)
		return OWL_ERROR_NOT_IMPLEMENTED;

	*sym_key = owl_malloc(sizeof(struct owl_key_s) + key_len);
	if (*sym_key == NULL)
		return OWL_ERROR_OUT_OF_MEMORY;

	(*sym_key)->length = key_len;
	(*sym_key)->type = key_type;

	ret = owl_rand_bytes((*sym_key)->d, key_len);
	if (ret == 0)
		return 0;

	owl_free(*sym_key);
	return ret;
}

API int owl_key_gen_pair(owl_key_h *prv_key,
		     owl_key_h *pub_key,
		     owl_key_type_e key_type,
		     size_t key_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

API void owl_key_free(owl_key_h key)
{
	if (key == OWL_KEY_NULL)
		return;

	owl_free(key);
}

API int owl_key_derive_dh(const owl_key_h prv_key,
		      const owl_key_h pub_key,
		      owl_key_h *sym_key)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

API int owl_key_derive_kea(const owl_key_h prv_key,
		       const owl_key_h pub_key,
		       const owl_key_h prv_key_auth,
		       const owl_key_h pub_key_auth,
		       owl_key_h *sym_key)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

API int owl_key_derive_pbkdf2(const char *password,
			  const char *salt,
			  size_t salt_len,
			  int iter,
			  owl_digest_algo_e algo,
			  owl_key_len_e key_len,
			  owl_key_h *key)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}
