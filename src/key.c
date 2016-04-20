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
#include <stdint.h>

#include <openssl/evp.h>

#include <yaca/crypto.h>
#include <yaca/error.h>
#include <yaca/key.h>
#include <yaca/types.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "internal.h"

static inline void simple_key_sanity_check(const struct yaca_key_simple_s *key)
{
	assert(key->bits);
	assert(key->bits % 8 == 0);
}

// TODO: do we need a sanity check sanity for Evp keys?
static inline void evp_key_sanity_check(const struct yaca_key_evp_s *key)
{
}

// TODO: do we need this variant? or the two above are enough?
#if 0
static inline void key_sanity_check(const yaca_key_h key)
{
	const struct yaca_key_simple_s *simple_key = key_get_simple(key);
	const struct yaca_key_evp_s *evp_key = key_get_evp(key);

	if (simple_key != NULL)
		simple_key_sanity_check(simple_key);

	if (evp_key != NULL)
		evp_key_sanity_check(evp_key);
}
#endif

struct yaca_key_simple_s *key_get_simple(const yaca_key_h key)
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

struct yaca_key_evp_s *key_get_evp(const yaca_key_h key)
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

API int yaca_key_get_bits(const yaca_key_h key)
{
	const struct yaca_key_simple_s *simple_key = key_get_simple(key);
	const struct yaca_key_evp_s *evp_key = key_get_evp(key);

	if (simple_key != NULL) {
		simple_key_sanity_check(simple_key);
		return simple_key->bits;
	}

	if (evp_key != NULL) {
		int ret;

		evp_key_sanity_check(evp_key);

		// TODO: handle ECC keys when they're implemented
		ret = EVP_PKEY_bits(evp_key->evp);
		if (ret <= 0) {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			return ret;
		}

		return ret;
	}

	return YACA_ERROR_INVALID_ARGUMENT;
}

API int yaca_key_import(yaca_key_h *key,
                        yaca_key_type_e key_type,
                        const char *data,
                        size_t data_len)
{
	if (key == NULL || data == NULL || data_len == 0)
		return YACA_ERROR_INVALID_ARGUMENT;

	if (key_type == YACA_KEY_TYPE_SYMMETRIC) {
		struct yaca_key_simple_s *nk = NULL;

		if (data_len > SIZE_MAX - sizeof(struct yaca_key_simple_s))
			return YACA_ERROR_TOO_BIG_ARGUMENT;

		nk = yaca_zalloc(sizeof(struct yaca_key_simple_s) + data_len);
		if (nk == NULL)
			return YACA_ERROR_OUT_OF_MEMORY;

		memcpy(nk->d, data, data_len); /* TODO: CRYPTO_/EVP_... */
		nk->bits = data_len * 8;
		nk->key.type = key_type;

		*key = (yaca_key_h)nk;
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
                        yaca_key_file_fmt_e key_file_fmt,
                        char **data,
                        size_t *data_len)
{
	size_t byte_len;
	struct yaca_key_simple_s *simple_key = key_get_simple(key);
	struct yaca_key_evp_s *evp_key = key_get_evp(key);

	if (data == NULL || data_len == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	if (key_fmt != YACA_KEY_FORMAT_DEFAULT)
		return YACA_ERROR_NOT_IMPLEMENTED;

	if (key_file_fmt != YACA_KEY_FILE_FORMAT_RAW)
		return YACA_ERROR_NOT_IMPLEMENTED;

	if (simple_key != NULL) {
		simple_key_sanity_check(simple_key);

		byte_len = simple_key->bits / 8;
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
                     size_t key_bits)
{
	int ret;
	struct yaca_key_simple_s *nk = NULL;
	size_t key_byte_len = key_bits / 8;

	if (sym_key == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	switch(key_type)
	{
	case YACA_KEY_TYPE_SYMMETRIC:
	case YACA_KEY_TYPE_IV:
		break;
	case YACA_KEY_TYPE_DES:
	case YACA_KEY_TYPE_RSA_PUB:    /* RSA public key */
	case YACA_KEY_TYPE_RSA_PRIV:   /* RSA private key */
	case YACA_KEY_TYPE_DSA_PUB:    /* DSA public key */
	case YACA_KEY_TYPE_DSA_PRIV:   /* DSA private key */
	case YACA_KEY_TYPE_DH_PUB:     /* DH public key */
	case YACA_KEY_TYPE_DH_PRIV:    /* DH private key */
	case YACA_KEY_TYPE_ECDSA_PUB:  /* ECDSA public key */
	case YACA_KEY_TYPE_ECDSA_PRIV: /* ECDSA private key */
	case YACA_KEY_TYPE_ECDH_PUB:   /* ECDH public key */
	case YACA_KEY_TYPE_ECDH_PRIV:  /* ECDH private key */
	case YACA_KEY_TYPE_PAIR_RSA:   /* Pair of RSA keys */
	case YACA_KEY_TYPE_PAIR_DSA:   /* Pair of DSA keys */
	case YACA_KEY_TYPE_PAIR_DH:    /* Pair of DH keys */
	case YACA_KEY_TYPE_PAIR_ECDSA: /* Pair of ECDSA keys */
	case YACA_KEY_TYPE_PAIR_ECDH:  /* Pair of ECDH keys */
		return YACA_ERROR_NOT_IMPLEMENTED;
	default:
		return YACA_ERROR_INVALID_ARGUMENT;
	}

	if (key_byte_len > SIZE_MAX - sizeof(struct yaca_key_simple_s))
		return YACA_ERROR_TOO_BIG_ARGUMENT;

	nk = yaca_zalloc(sizeof(struct yaca_key_simple_s) + key_byte_len);
	if (nk == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	nk->bits = key_bits;
	nk->key.type = key_type;

	ret = yaca_rand_bytes(nk->d, key_byte_len);
	if (ret != 0)
		goto err;

	*sym_key = (yaca_key_h)nk;

	return 0;

err:
	yaca_free(nk);
	return ret;
}

API int yaca_key_gen_pair(yaca_key_h *prv_key,
                          yaca_key_h *pub_key,
                          yaca_key_type_e key_type,
                          size_t key_bits)
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

	nk_prv = yaca_zalloc(sizeof(struct yaca_key_evp_s));
	if (nk_prv == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	nk_pub = yaca_zalloc(sizeof(struct yaca_key_evp_s));
	if (nk_pub == NULL) {
		ret = YACA_ERROR_OUT_OF_MEMORY;
		goto free_prv;
	}

	// TODO: this NEEDS random number generator initialized
	// there is some other TODO elsewhere about it

	bne = BN_new();
	if (bne == NULL) {
		ret = YACA_ERROR_OUT_OF_MEMORY;
		ERROR_DUMP(ret);
		goto free_pub;
	}

	ret = BN_set_word(bne, RSA_F4);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto free_bne;
	}

	rsa = RSA_new();
	if (rsa == NULL) {
		ret = YACA_ERROR_OUT_OF_MEMORY;
		ERROR_DUMP(ret);
		goto free_bne;
	}

	ret = RSA_generate_key_ex(rsa, key_bits, bne, NULL);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto free_rsa;
	}

	nk_prv->evp = EVP_PKEY_new();
	if (nk_prv->evp == NULL) {
		ret = YACA_ERROR_OUT_OF_MEMORY;
		ERROR_DUMP(ret);
		goto free_rsa;
	}

	nk_pub->evp = EVP_PKEY_new();
	if (nk_prv->evp == NULL) {
		ret = YACA_ERROR_OUT_OF_MEMORY;
		ERROR_DUMP(ret);
		goto free_evp_prv;
	}

	ret = EVP_PKEY_assign_RSA(nk_prv->evp, RSAPrivateKey_dup(rsa));
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto free_evp_pub;
	}

	ret = EVP_PKEY_assign_RSA(nk_pub->evp, RSAPublicKey_dup(rsa));
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
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
	struct yaca_key_simple_s *simple_key = key_get_simple(key);
	struct yaca_key_evp_s *evp_key = key_get_evp(key);

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
                               size_t key_bits,
                               yaca_key_h *key)
{
	const EVP_MD *md;
	struct yaca_key_simple_s *nk;
	size_t key_byte_len = key_bits / 8;
	int ret;

	if (password == NULL || salt == NULL || salt_len == 0 ||
	    iter == 0 || key_bits == 0 || key == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = digest_get_algorithm(algo, &md);
	if (ret < 0)
		return ret;

	if (key_bits % 8) /* Key length must be multiple of 8-bits */
		return YACA_ERROR_INVALID_ARGUMENT;

	if (key_byte_len > SIZE_MAX - sizeof(struct yaca_key_simple_s))
		return YACA_ERROR_TOO_BIG_ARGUMENT;

	nk = yaca_zalloc(sizeof(struct yaca_key_simple_s) + key_byte_len);
	if (nk == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	nk->bits = key_bits;
	nk->key.type = YACA_KEY_TYPE_SYMMETRIC; // TODO: how to handle other keys?

	ret = PKCS5_PBKDF2_HMAC(password, -1, (const unsigned char*)salt,
	                        salt_len, iter, md, key_byte_len,
	                        (unsigned char*)nk->d);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto err;
	}

	*key = (yaca_key_h)nk;
	return 0;
err:
	yaca_free(nk);
	return ret;
}
