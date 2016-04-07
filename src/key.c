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

#include <yaca/crypto.h>
#include <yaca/error.h>
#include <yaca/key.h>
#include <yaca/types.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "internal.h"

/**
 * Internal type for:
 * - YACA_KEY_TYPE_SYMMETRIC
 * - YACA_KEY_TYPE_DES
 * - YACA_KEY_TYPE_IV
 */
struct yaca_key_simple_s
{
	struct yaca_key_s key;

	size_t length;
	char d[0];
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

static struct yaca_key_simple_s *get_simple_key(const yaca_key_h key)
{
	if (key == YACA_KEY_NULL)
		return NULL;

	switch (key->type)
	{
	case YACA_KEY_TYPE_SYMMETRIC:
	case YACA_KEY_TYPE_DES:
	case YACA_KEY_TYPE_IV:
		return (struct yaca_key_simple_s *)key;
	default:
		return NULL;
	}
}

static struct yaca_key_evp_s *get_evp_key(const yaca_key_h key)
{
	if (key == YACA_KEY_NULL)
		return NULL;

	switch (key->type)
	{
	case YACA_KEY_TYPE_RSA_PUB:
	case YACA_KEY_TYPE_RSA_PRIV:
	case YACA_KEY_TYPE_DSA_PUB:
	case YACA_KEY_TYPE_DSA_PRIV:
		return (struct yaca_key_evp_s *)key;
	default:
		return NULL;
	}
}

static inline void simple_key_sanity_check(const struct yaca_key_simple_s *key)
{
	assert(key->length);
	assert(key->length % 8 == 0);
}

// TODO: do we need a sanity check sanity for Evp keys?
static inline void evp_key_sanity_check(const struct yaca_key_evp_s *key)
{
}

// TODO: do we need this variant? or the two above are enough?
static inline void key_sanity_check(const yaca_key_h key)
{
	const struct yaca_key_simple_s *simple_key = get_simple_key(key);
	const struct yaca_key_evp_s *evp_key = get_evp_key(key);

	if (simple_key != NULL)
		simple_key_sanity_check(simple_key);

	if (evp_key != NULL)
		evp_key_sanity_check(evp_key);
}

API int yaca_key_get_length(const yaca_key_h key)
{
	const struct yaca_key_simple_s *simple_key = get_simple_key(key);
	const struct yaca_key_evp_s *evp_key = get_evp_key(key);

	if (simple_key != NULL) {
		simple_key_sanity_check(simple_key);
		return simple_key->length;
	}

	if (evp_key != NULL) {
		evp_key_sanity_check(evp_key);
		return YACA_ERROR_NOT_IMPLEMENTED;
	}

	return YACA_ERROR_INVALID_ARGUMENT;
}

API int yaca_key_import(yaca_key_h *key,
			yaca_key_fmt_e key_fmt,
			yaca_key_type_e key_type,
			const char *data,
			size_t data_len)
{
	if (key == NULL || data == NULL || data_len == 0)
		return YACA_ERROR_INVALID_ARGUMENT;

	if (key_fmt != YACA_KEY_FORMAT_RAW)
		return YACA_ERROR_NOT_IMPLEMENTED;

	if (key_type == YACA_KEY_TYPE_SYMMETRIC) {
		struct yaca_key_simple_s *nk = NULL;
		yaca_key_h k;

		if (sizeof(struct yaca_key_s) + data_len < data_len)
			return YACA_ERROR_TOO_BIG_ARGUMENT;

		nk = yaca_malloc(sizeof(struct yaca_key_simple_s) + data_len);
		if (nk == NULL)
			return YACA_ERROR_OUT_OF_MEMORY;

		memcpy(nk->d, data, data_len); /* TODO: CRYPTO_/EVP_... */
		nk->length = data_len * 8;

		k = (yaca_key_h)nk;
		k->type = key_type;
		*key = k;
		return 0;
	}

	if (key_type == YACA_KEY_TYPE_DES) {
		// TODO: ...
		return YACA_ERROR_NOT_IMPLEMENTED;
	}

	/* if (...) */ {
		// TODO: all the other key types
		return YACA_ERROR_NOT_IMPLEMENTED;
	}
}

API int yaca_key_export(const yaca_key_h key,
			yaca_key_fmt_e key_fmt,
			char **data,
			size_t *data_len)
{
	size_t byte_len;
	struct yaca_key_simple_s *simple_key = get_simple_key(key);
	struct yaca_key_evp_s *evp_key = get_evp_key(key);

	if (data == NULL || data_len == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	if (key_fmt != YACA_KEY_FORMAT_RAW)
		return YACA_ERROR_NOT_IMPLEMENTED;

	if (simple_key != NULL) {
		simple_key_sanity_check(simple_key);

		byte_len = simple_key->length / 8;
		*data = yaca_malloc(byte_len);
		memcpy(*data, simple_key->d, byte_len);
		*data_len = byte_len;

		return 0;
	}

	if (evp_key != NULL) {
		evp_key_sanity_check(evp_key);

		return YACA_ERROR_NOT_IMPLEMENTED;
	}

	return YACA_ERROR_INVALID_ARGUMENT;
}

API int yaca_key_gen(yaca_key_h *sym_key,
		     yaca_key_type_e key_type,
		     size_t key_len)
{
	int ret;
	struct yaca_key_simple_s *nk = NULL;

	if (sym_key == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	if (key_type != YACA_KEY_TYPE_SYMMETRIC &&
	    key_type != YACA_KEY_TYPE_IV)
		return YACA_ERROR_NOT_IMPLEMENTED;

	nk = yaca_malloc(sizeof(struct yaca_key_simple_s) + key_len);
	if (nk == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	nk->length = key_len;

	ret = yaca_rand_bytes(nk->d, key_len);
	if (ret != 0)
		goto free;

	*sym_key = (yaca_key_h)nk;
	(*sym_key)->type = key_type;

	ret = 0;

free:
	if (ret != 0)
		yaca_free(nk);

	return ret;
}

API int yaca_key_gen_pair(yaca_key_h *prv_key,
			  yaca_key_h *pub_key,
			  yaca_key_type_e key_type,
			  size_t key_len)
{
	int ret;
	struct yaca_key_evp_s *nk_prv = NULL;
	struct yaca_key_evp_s *nk_pub = NULL;
	RSA *rsa = NULL;
	BIGNUM *bne = NULL;

	if (prv_key == NULL || pub_key == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	if (key_type != YACA_KEY_TYPE_PAIR_RSA)
		return YACA_ERROR_NOT_IMPLEMENTED;

	nk_prv = yaca_malloc(sizeof(struct yaca_key_evp_s));
	if (nk_prv == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	nk_pub = yaca_malloc(sizeof(struct yaca_key_evp_s));
	if (nk_pub == NULL) {
		ret = YACA_ERROR_OUT_OF_MEMORY;
		goto free_prv;
	}

	// TODO: this NEEDS random number generator initialized
	// there is some other TODO elsewhere about it

	bne = BN_new();
	if (bne == NULL) {
		ret = YACA_ERROR_OUT_OF_MEMORY;
		goto free_pub;
	}

	ret = BN_set_word(bne, RSA_F4);
	if (ret != 1) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		goto free_bne;
	}

	rsa = RSA_new();
	if (rsa == NULL) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		goto free_bne;
	}

	ret = RSA_generate_key_ex(rsa, key_len, bne, NULL);
	if (ret != 1) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		goto free_rsa;
	}

	nk_prv->evp = EVP_PKEY_new();
	if (nk_prv->evp == NULL) {
		ret = YACA_ERROR_OUT_OF_MEMORY;
		goto free_rsa;
	}

	nk_pub->evp = EVP_PKEY_new();
	if (nk_prv->evp == NULL) {
		ret = YACA_ERROR_OUT_OF_MEMORY;
		goto free_evp_prv;
	}

	ret = EVP_PKEY_assign_RSA(nk_prv->evp, RSAPrivateKey_dup(rsa));
	if (ret != 1) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		goto free_evp_pub;
	}

	ret = EVP_PKEY_assign_RSA(nk_pub->evp, RSAPublicKey_dup(rsa));
	if (ret != 1) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		goto free_evp_pub;
	}

	*prv_key = (yaca_key_h)nk_prv;
	(*prv_key)->type = YACA_KEY_TYPE_RSA_PRIV;
	*pub_key = (yaca_key_h)nk_pub;
	(*pub_key)->type = YACA_KEY_TYPE_RSA_PUB;

	ret = 0;

free_evp_pub:
	if (ret != 0)
		EVP_PKEY_free(nk_pub->evp);
free_evp_prv:
	if (ret != 0)
		EVP_PKEY_free(nk_prv->evp);
free_rsa:
	RSA_free(rsa);
free_bne:
	BN_free(bne);
free_pub:
	if (ret != 0)
		yaca_free(nk_pub);
free_prv:
	if (ret != 0)
		yaca_free(nk_prv);

	return ret;
}

API void yaca_key_free(yaca_key_h key)
{
	struct yaca_key_simple_s *simple_key = get_simple_key(key);
	struct yaca_key_evp_s *evp_key = get_evp_key(key);

	if (simple_key != NULL)
		yaca_free(simple_key);

	if (evp_key != NULL) {
		EVP_PKEY_free(evp_key->evp);
		yaca_free(evp_key);
	}
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
