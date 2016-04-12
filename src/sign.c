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

#include <openssl/evp.h>

#include <yaca/crypto.h>
#include <yaca/error.h>

#include "internal.h"

/* Operation type saved in context to recognize what
 * type of operation is performed and how to perform it.
*/
enum sign_op_type {
	OP_SIGN = 0,
	OP_VERIFY_SYMMETRIC = 1,
	OP_VERIFY_ASYMMETRIC = 2
};

struct yaca_sign_ctx_s
{
	struct yaca_ctx_s ctx;

	EVP_MD_CTX *mdctx;
	enum sign_op_type op_type;
};

static struct yaca_sign_ctx_s *get_sign_ctx(const yaca_ctx_h ctx)
{
	if (ctx == YACA_CTX_NULL)
		return NULL;

	switch (ctx->type)
	{
	case YACA_CTX_SIGN:
		return (struct yaca_sign_ctx_s *)ctx;
	default:
		return NULL;
	}
}

static int get_sign_output_length(const yaca_ctx_h ctx, size_t input_len)
{
	struct yaca_sign_ctx_s *c = get_sign_ctx(ctx);

	if (c == NULL || c->mdctx == NULL || c->mdctx->pctx == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(c->mdctx->pctx);
	if (pkey == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	size_t len = EVP_PKEY_size(pkey);
	if (len <= 0)
		return YACA_ERROR_INVALID_ARGUMENT;

	return len;
}

static void destroy_sign_context(yaca_ctx_h ctx)
{
	struct yaca_sign_ctx_s *c = get_sign_ctx(ctx);

	if (c == NULL)
		return;

	EVP_MD_CTX_destroy(c->mdctx);
	c->mdctx = NULL;
}

static int create_sign_pkey(const yaca_key_h key, EVP_PKEY **pkey)
{
	const struct yaca_key_simple_s *simple_key = key_get_simple(key);
	const struct yaca_key_evp_s *evp_key = key_get_evp(key);

	if (pkey == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	if (simple_key != NULL)
	{
		*pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC,
					     NULL,
					     (unsigned char *)simple_key->d,
					     simple_key->bits / 8);
		if (*pkey == NULL)
			return YACA_ERROR_OPENSSL_FAILURE;

		return 0;
	}

	if (evp_key != NULL)
	{
		*pkey = evp_key->evp;
		/* Add a reference so we can free it afterwards anyway */
		CRYPTO_add(&(*pkey)->references, 1, CRYPTO_LOCK_EVP_PKEY);

		return 0;
	}

	return YACA_ERROR_INVALID_ARGUMENT;
}

/* TODO: error checking?
 * should DES and IV keys be rejected by us or silently let them work?
 */
API int yaca_sign_init(yaca_ctx_h *ctx,
		       yaca_digest_algo_e algo,
		       const yaca_key_h key)
{
	struct yaca_sign_ctx_s *nc = NULL;
	EVP_PKEY *pkey;
	const EVP_MD *md;
	int ret;

	if (ctx == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = create_sign_pkey(key, &pkey);
	if (ret != 0)
		return ret;

	// TODO: use zalloc when available
	nc = yaca_malloc(sizeof(struct yaca_sign_ctx_s));
	if (nc == NULL) {
		ret = YACA_ERROR_OUT_OF_MEMORY;
		goto free_key;
	}

	nc->ctx.type = YACA_CTX_SIGN;
	nc->ctx.ctx_destroy = destroy_sign_context;
	nc->ctx.get_output_length = get_sign_output_length;

	switch (key->type)
	{
	case YACA_KEY_TYPE_SYMMETRIC:
	case YACA_KEY_TYPE_RSA_PRIV:
		nc->op_type = OP_SIGN;
		break;
	case YACA_KEY_TYPE_DSA_PRIV:
	case YACA_KEY_TYPE_ECDSA_PRIV:
		ret = YACA_ERROR_NOT_IMPLEMENTED;
		goto free_ctx;
	default:
		ret = YACA_ERROR_INVALID_ARGUMENT;
		goto free_ctx;
	}

	ret = digest_get_algorithm(algo, &md);
	if (ret != 0)
		goto free_ctx;

	nc->mdctx = EVP_MD_CTX_create();
	if (nc->mdctx == NULL) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		goto free_ctx;
	}

	ret = EVP_DigestSignInit(nc->mdctx, NULL, md, NULL, pkey);
	if (ret == -2) {
		ret = YACA_ERROR_NOT_SUPPORTED;
		goto ctx;
	}
	if (ret != 1) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		goto ctx;
	}

	*ctx = (yaca_ctx_h)nc;

	ret = 0;

ctx:
	if (ret != 0)
		EVP_MD_CTX_destroy(nc->mdctx);
free_ctx:
	if (ret != 0)
		yaca_free(nc);
free_key:
	EVP_PKEY_free(pkey);

	return ret;
}

API int yaca_sign_update(yaca_ctx_h ctx,
			 const char *data,
			 size_t data_len)
{
	struct yaca_sign_ctx_s *c = get_sign_ctx(ctx);
	int ret;

	if (c == NULL || c->op_type != OP_SIGN ||
	    data == NULL || data_len == 0)
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = EVP_DigestSignUpdate(c->mdctx, data, data_len);
	if (ret == -2)
		return YACA_ERROR_NOT_SUPPORTED;
	if (ret != 1)
		return YACA_ERROR_OPENSSL_FAILURE;

	return 0;
}

API int yaca_sign_final(yaca_ctx_h ctx,
			char *mac,
			size_t *mac_len)
{
	struct yaca_sign_ctx_s *c = get_sign_ctx(ctx);
	int ret;

	if (c == NULL ||  c->op_type != OP_SIGN ||
	    mac == NULL || mac_len == NULL || *mac_len == 0)
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = EVP_DigestSignFinal(c->mdctx, (unsigned char *)mac, mac_len);
	if (ret == -2)
		return YACA_ERROR_NOT_SUPPORTED;
	if (ret != 1)
		return YACA_ERROR_OPENSSL_FAILURE;

	return 0;
}

API int yaca_verify_init(yaca_ctx_h *ctx,
			 yaca_digest_algo_e algo,
			 const yaca_key_h key)
{
	struct yaca_sign_ctx_s *nc = NULL;
	EVP_PKEY *pkey;
	const EVP_MD *md;
	int ret;

	if (ctx == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = create_sign_pkey(key, &pkey);
	if (ret != 0)
		return ret;

	// TODO: use zalloc when available
	nc = yaca_malloc(sizeof(struct yaca_sign_ctx_s));
	if (nc == NULL) {
		ret = YACA_ERROR_OUT_OF_MEMORY;
		goto free_key;
	}

	nc->ctx.type = YACA_CTX_SIGN;
	nc->ctx.ctx_destroy = destroy_sign_context;
	nc->ctx.get_output_length = NULL;

	switch (key->type)
	{
	case YACA_KEY_TYPE_SYMMETRIC:
		nc->op_type = OP_VERIFY_SYMMETRIC;
		break;
	case YACA_KEY_TYPE_RSA_PUB:
		nc->op_type = OP_VERIFY_ASYMMETRIC;
		break;
	case YACA_KEY_TYPE_DSA_PUB:
	case YACA_KEY_TYPE_ECDSA_PUB:
		ret = YACA_ERROR_NOT_IMPLEMENTED;
		goto free_ctx;
	default:
		ret = YACA_ERROR_INVALID_ARGUMENT;
		goto free_ctx;
	}

	ret = digest_get_algorithm(algo, &md);
	if (ret < 0)
		goto free_ctx;

	nc->mdctx = EVP_MD_CTX_create();
	if (nc->mdctx == NULL) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		goto free_ctx;
	}

	switch (nc->op_type)
	{
	case OP_VERIFY_SYMMETRIC:
		ret = EVP_DigestSignInit(nc->mdctx, NULL, md, NULL, pkey);
		break;
	case OP_VERIFY_ASYMMETRIC:
		ret = EVP_DigestVerifyInit(nc->mdctx, NULL, md, NULL, pkey);
		break;
	default:
		ret = YACA_ERROR_INVALID_ARGUMENT;
		goto ctx;
	}

	if (ret == -2) {
		ret = YACA_ERROR_NOT_SUPPORTED;
		goto ctx;
	}
	if (ret != 1) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		goto ctx;
	}

	*ctx = (yaca_ctx_h)nc;

	ret = 0;

ctx:
	if (ret != 0)
		EVP_MD_CTX_destroy(nc->mdctx);
free_ctx:
	if (ret != 0)
		yaca_free(nc);
free_key:
	EVP_PKEY_free(pkey);

	return ret;
}

API int yaca_verify_update(yaca_ctx_h ctx,
			   const char *data,
			   size_t data_len)
{
	struct yaca_sign_ctx_s *c = get_sign_ctx(ctx);
	int ret;

	if (c == NULL || data == NULL || data_len == 0)
		return YACA_ERROR_INVALID_ARGUMENT;

	switch (c->op_type)
	{
	case OP_VERIFY_SYMMETRIC:
		ret = EVP_DigestSignUpdate(c->mdctx, data, data_len);
		break;
	case OP_VERIFY_ASYMMETRIC:
		ret = EVP_DigestVerifyUpdate(c->mdctx, data, data_len);
		break;
	default:
		return YACA_ERROR_INVALID_ARGUMENT;
	}

	if (ret == -2)
		return YACA_ERROR_NOT_SUPPORTED;
	if (ret != 1)
		return YACA_ERROR_OPENSSL_FAILURE;

	return 0;
}

API int yaca_verify_final(yaca_ctx_h ctx,
			  const char *mac,
			  size_t mac_len)
{
	struct yaca_sign_ctx_s *c = get_sign_ctx(ctx);
	char mac_cmp[mac_len];
	size_t mac_cmp_len = mac_len;
	int ret;

	if (c == NULL || mac == NULL || mac_len == 0)
		return YACA_ERROR_INVALID_ARGUMENT;

	switch (c->op_type)
	{
	case OP_VERIFY_SYMMETRIC:
		ret = EVP_DigestSignFinal(c->mdctx,
					  (unsigned char *)mac_cmp,
					  &mac_cmp_len);
		if (ret == -2)
			return YACA_ERROR_NOT_SUPPORTED;
		if (ret != 1)
			return YACA_ERROR_OPENSSL_FAILURE;

		if (mac_len != mac_cmp_len ||
		    CRYPTO_memcmp(mac, mac_cmp, mac_len) != 0)
			return YACA_ERROR_SIGNATURE_INVALID;

		return 0;
	case OP_VERIFY_ASYMMETRIC:
		ret = EVP_DigestVerifyFinal(c->mdctx,
					    (unsigned char *)mac,
					    mac_len);
		if (ret == 0)
			return YACA_ERROR_SIGNATURE_INVALID;
		if (ret == -2)
			return YACA_ERROR_NOT_SUPPORTED;
		if (ret != 1)
			return YACA_ERROR_OPENSSL_FAILURE;

		return 0;
	default:
		return YACA_ERROR_INVALID_ARGUMENT;
	}
}
