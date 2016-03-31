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
static inline void key_sanity_check(const owl_key_h key)
{
	assert(key->length);
	assert(key->length % 8 == 0);
}

int owl_key_get_length(const owl_key_h key)
{
	if (!key)
		return OWL_ERROR_INVALID_ARGUMENT;
	key_sanity_check(key);

	return key->length;
}

int owl_key_import(owl_key_h *key,
		   owl_key_fmt_e key_fmt,
		   owl_key_type_e key_type,
		   const char *data,
		   size_t data_len)
{
	owl_key_h nk = NULL;

	if (!key || !data || !data_len)
		return OWL_ERROR_INVALID_ARGUMENT;

	if (key_type != OWL_KEY_TYPE_SYMMETRIC)
		return OWL_ERROR_NOT_IMPLEMENTED;

	if (key_fmt != OWL_KEY_FORMAT_RAW)
		return OWL_ERROR_NOT_IMPLEMENTED;

	if (sizeof(struct __owl_key_s) + data_len < data_len)
		return OWL_ERROR_TOO_BIG_ARGUMENT;

	nk = owl_alloc(sizeof(struct __owl_key_s) + data_len);
	if (!nk)
		return OWL_ERROR_OUT_OF_MEMORY;

	memcpy(nk->d, data, data_len);
	nk->length = data_len * 8;
	nk->type = key_type;
	*key = nk;

	return 0;
}

int owl_key_export(const owl_key_h key,
		   owl_key_fmt_e key_fmt,
		   char **data,
		   size_t *data_len)
{
	int byte_len;

	if (!key || !data || !data_len)
		return OWL_ERROR_INVALID_ARGUMENT;

	if (key->type != OWL_KEY_TYPE_SYMMETRIC)
		return OWL_ERROR_NOT_IMPLEMENTED;

	if (key_fmt != OWL_KEY_FORMAT_RAW)
		return OWL_ERROR_NOT_IMPLEMENTED;

	key_sanity_check(key);

	byte_len = key->length / 8;
	*data = owl_alloc(byte_len);
	memcpy(*data, key->d, byte_len);
	*data_len = byte_len;

	return 0;
}

int owl_key_gen(owl_key_h *sym_key,
		owl_key_type_e key_type,
		size_t key_len)
{
	if (!sym_key || key_type != OWL_KEY_TYPE_SYMMETRIC)
		return -1;

	*sym_key = owl_alloc(sizeof(struct __owl_key_s) + key_len);
	if (!*sym_key)
		return -1;

	(*sym_key)->length = key_len;
	(*sym_key)->type = key_type;
	return owl_rand_bytes((*sym_key)->d, key_len);
}

int owl_key_gen_pair(owl_key_h *prv_key,
		     owl_key_h *pub_key,
		     owl_key_type_e key_type,
		     size_t key_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

void owl_key_free(owl_key_h key)
{
	if (!key)
		return;

	owl_free(key);
}

int owl_key_derive_dh(const owl_key_h prv_key,
		      const owl_key_h pub_key,
		      owl_key_h *sym_key)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

int owl_key_derive_kea(const owl_key_h prv_key,
		       const owl_key_h pub_key,
		       const owl_key_h prv_key_auth,
		       const owl_key_h pub_key_auth,
		       owl_key_h *sym_key)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

int owl_key_derive_pbkdf2(const char *password,
			  const char *salt,
			  size_t salt_len,
			  int iter,
			  owl_digest_algo_e algo,
			  owl_key_len_e key_len,
			  owl_key_h *key)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}
