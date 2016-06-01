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
 * @file sign.c
 * @brief
 */

#include <assert.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/cmac.h>

#include <yaca_crypto.h>
#include <yaca_sign.h>
#include <yaca_error.h>
#include <yaca_key.h>

#include "internal.h"

/* Operation type saved in context to recognize what
 * type of operation is performed and how to perform it.
 */
enum sign_op_type {
	OP_SIGN = 0,
	OP_VERIFY = 1
};

struct yaca_sign_ctx_s {
	struct yaca_ctx_s ctx;

	EVP_MD_CTX *mdctx;
	enum sign_op_type op_type;
};

static struct yaca_sign_ctx_s *get_sign_ctx(const yaca_ctx_h ctx)
{
	if (ctx == YACA_CTX_NULL)
		return NULL;

	switch (ctx->type) {
	case YACA_CTX_SIGN:
		return (struct yaca_sign_ctx_s *)ctx;
	default:
		return NULL;
	}
}

static int get_sign_output_length(const yaca_ctx_h ctx,
                                  size_t input_len,
                                  size_t *output_len)
{
	struct yaca_sign_ctx_s *c = get_sign_ctx(ctx);

	if (c == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	assert(c->mdctx != NULL);

	if (c->mdctx->pctx == NULL)
		return YACA_ERROR_INTERNAL;

	EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(c->mdctx->pctx);
	if (pkey == NULL) {
		ERROR_DUMP(YACA_ERROR_INVALID_ARGUMENT);
		return YACA_ERROR_INVALID_ARGUMENT;
	}

	size_t len = EVP_PKEY_size(pkey);
	if (len <= 0) {
		ERROR_DUMP(YACA_ERROR_INVALID_ARGUMENT);
		return YACA_ERROR_INVALID_ARGUMENT;
	}

	*output_len = len;
	return YACA_ERROR_NONE;
}

static void destroy_sign_context(yaca_ctx_h ctx)
{
	struct yaca_sign_ctx_s *c = get_sign_ctx(ctx);

	if (c == NULL)
		return;

	EVP_MD_CTX_destroy(c->mdctx);
	c->mdctx = NULL;
}

int set_sign_param(yaca_ctx_h ctx,
                   yaca_ex_param_e param,
                   const void *value,
                   size_t value_len)
{
	int ret;
	struct yaca_sign_ctx_s *c = get_sign_ctx(ctx);
	yaca_padding_e padding;
	int pad;
	EVP_PKEY *pkey;

	if (c == NULL || value == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	assert(c->mdctx != NULL);

	if (c->mdctx->pctx == NULL)
		return YACA_ERROR_INTERNAL;

	/* this function only supports padding */
	if (param != YACA_PARAM_PADDING || value_len != sizeof(yaca_padding_e))
		return YACA_ERROR_INVALID_ARGUMENT;

	padding = *(yaca_padding_e *)(value);

	// TODO: investigate whether it's possible to set
	// RSA_NO_PADDING or RSA_SSLV23_PADDING in some cases
	switch (padding) {
	case YACA_PADDING_X931:
		pad = RSA_X931_PADDING;
		break;
	case YACA_PADDING_PKCS1:
		pad = RSA_PKCS1_PADDING;
		break;
	case YACA_PADDING_PKCS1_PSS:
		pad = RSA_PKCS1_PSS_PADDING;
		break;
	default:
		return YACA_ERROR_INVALID_ARGUMENT;
	}

	pkey = EVP_PKEY_CTX_get0_pkey(c->mdctx->pctx);
	if (pkey == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	/* padding only works for RSA */
	if (pkey->type != EVP_PKEY_RSA)
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = EVP_PKEY_CTX_set_rsa_padding(c->mdctx->pctx, pad);
	if (ret <= 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return YACA_ERROR_NONE;
}

int get_sign_param(const yaca_ctx_h ctx,
                   yaca_ex_param_e param,
                   void **value,
                   size_t *value_len)
{
	int ret;
	struct yaca_sign_ctx_s *c = get_sign_ctx(ctx);
	EVP_PKEY *pkey;
	int pad;
	yaca_padding_e padding;

	if (c == NULL || value == NULL || value_len == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	assert(c->mdctx != NULL);

	if (c->mdctx->pctx == NULL)
		return YACA_ERROR_INTERNAL;

	/* this function only supports padding */
	if (param != YACA_PARAM_PADDING)
		return YACA_ERROR_INVALID_ARGUMENT;

	pkey = EVP_PKEY_CTX_get0_pkey(c->mdctx->pctx);
	if (pkey == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	/* padding only works for RSA */
	if (pkey->type != EVP_PKEY_RSA)
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = EVP_PKEY_CTX_get_rsa_padding(c->mdctx->pctx, &pad);
	if (ret <= 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	switch (pad) {
	case RSA_X931_PADDING:
		padding = YACA_PADDING_X931;
		break;
	case RSA_PKCS1_PADDING:
		padding = YACA_PADDING_PKCS1;
		break;
	case RSA_PKCS1_PSS_PADDING:
		padding = YACA_PADDING_PKCS1_PSS;
		break;
	default:
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(YACA_ERROR_INTERNAL);
		return ret;
	}

	*value = yaca_malloc(sizeof(yaca_padding_e));
	if (*value == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	memcpy(*value, &padding, sizeof(yaca_padding_e));
	*value_len = sizeof(yaca_padding_e);

	return YACA_ERROR_NONE;
}

API int yaca_sign_init(yaca_ctx_h *ctx,
                       yaca_digest_algo_e algo,
                       const yaca_key_h key)
{
	struct yaca_sign_ctx_s *nc = NULL;
	const EVP_MD *md = NULL;
	int ret;
	const struct yaca_key_evp_s *evp_key = key_get_evp(key);

	if (ctx == NULL || evp_key == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	switch (key->type) {
	case YACA_KEY_TYPE_RSA_PRIV:
	case YACA_KEY_TYPE_DSA_PRIV:
		break;
//	case YACA_KEY_TYPE_EC_PRIV:
//		TODO NOT_IMPLEMENTED
	default:
		return YACA_ERROR_INVALID_ARGUMENT;
	}

	nc = yaca_zalloc(sizeof(struct yaca_sign_ctx_s));
	if (nc == NULL)
		return  YACA_ERROR_OUT_OF_MEMORY;

	nc->op_type = OP_SIGN;
	nc->ctx.type = YACA_CTX_SIGN;
	nc->ctx.ctx_destroy = destroy_sign_context;
	nc->ctx.get_output_length = get_sign_output_length;
	nc->ctx.set_param = set_sign_param;
	nc->ctx.get_param = get_sign_param;

	ret = digest_get_algorithm(algo, &md);
	if (ret != YACA_ERROR_NONE)
		goto free_ctx;

	nc->mdctx = EVP_MD_CTX_create();
	if (nc->mdctx == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto free_ctx;
	}

	ret = EVP_DigestSignInit(nc->mdctx, NULL, md, NULL, evp_key->evp);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto free_ctx;
	}

	*ctx = (yaca_ctx_h)nc;

	return YACA_ERROR_NONE;

free_ctx:
	yaca_ctx_free((yaca_ctx_h)nc);

	return ret;
}

API int yaca_sign_hmac_init(yaca_ctx_h *ctx,
                            yaca_digest_algo_e algo,
                            const yaca_key_h key)
{
	struct yaca_sign_ctx_s *nc = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *md;
	int ret;
	const struct yaca_key_simple_s *simple_key = key_get_simple(key);

	if (ctx == NULL || simple_key == NULL ||
	    (key->type != YACA_KEY_TYPE_SYMMETRIC && key->type != YACA_KEY_TYPE_DES))
		return YACA_ERROR_INVALID_ARGUMENT;

	nc = yaca_zalloc(sizeof(struct yaca_sign_ctx_s));
	if (nc == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	nc->op_type = OP_SIGN;
	nc->ctx.type = YACA_CTX_SIGN;
	nc->ctx.ctx_destroy = destroy_sign_context;
	nc->ctx.get_output_length = get_sign_output_length;

	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC,
	                            NULL,
	                            (unsigned char *)simple_key->d,
	                            simple_key->bits / 8);
	if (pkey == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto free_ctx;
	}

	ret = digest_get_algorithm(algo, &md);
	if (ret != YACA_ERROR_NONE)
		goto free_pkey;

	nc->mdctx = EVP_MD_CTX_create();
	if (nc->mdctx == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto free_pkey;
	}

	ret = EVP_DigestSignInit(nc->mdctx, NULL, md, NULL, pkey);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto free_pkey;
	}

	*ctx = (yaca_ctx_h)nc;
	return YACA_ERROR_NONE;

free_pkey:
	EVP_PKEY_free(pkey);
free_ctx:
	yaca_ctx_free((yaca_ctx_h)nc);

	return ret;
}

API int yaca_sign_cmac_init(yaca_ctx_h *ctx,
                            yaca_enc_algo_e algo,
                            const yaca_key_h key)
{
	struct yaca_sign_ctx_s *nc = NULL;
	CMAC_CTX* cmac_ctx = NULL;
	const EVP_CIPHER* cipher = NULL;
	EVP_PKEY *pkey = NULL;
	int ret;
	const struct yaca_key_simple_s *simple_key = key_get_simple(key);

	if (ctx == NULL || simple_key == NULL ||
	    (key->type != YACA_KEY_TYPE_SYMMETRIC && key->type != YACA_KEY_TYPE_DES))
		return YACA_ERROR_INVALID_ARGUMENT;

	nc = yaca_zalloc(sizeof(struct yaca_sign_ctx_s));
	if (nc == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	nc->op_type = OP_SIGN;
	nc->ctx.type = YACA_CTX_SIGN;
	nc->ctx.ctx_destroy = destroy_sign_context;
	nc->ctx.get_output_length = get_sign_output_length;

	ret = encrypt_get_algorithm(algo, YACA_BCM_CBC, simple_key->bits, &cipher);
	if (ret != YACA_ERROR_NONE)
		goto free_ctx;

	// create and initialize low level CMAC context
	cmac_ctx = CMAC_CTX_new();
	if (cmac_ctx == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto free_ctx;
	}

	if (CMAC_Init(cmac_ctx, simple_key->d, simple_key->bits/8, cipher, NULL) != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		// TODO refactor error handling: use single cleanup label
		goto free_cmac_ctx;
	}

	// create key and assign CMAC context to it
	pkey = EVP_PKEY_new();
	if (!pkey) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto free_cmac_ctx;
	}

	if (EVP_PKEY_assign(pkey, EVP_PKEY_CMAC, cmac_ctx) != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto free_pkey;
	}
	// TODO refactor error handling: set cmac_ctx to NULL

	nc->mdctx = EVP_MD_CTX_create();
	if (nc->mdctx == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto free_pkey;
	}

	if (EVP_DigestSignInit(nc->mdctx, NULL, NULL, NULL, pkey) != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto free_pkey;
	}
	// TODO refactor error handling: set mdctx to NULL, set pkey to NULL

	*ctx = (yaca_ctx_h)nc;
	return YACA_ERROR_NONE;

free_pkey:
	EVP_PKEY_free(pkey);
free_cmac_ctx:
	CMAC_CTX_free(cmac_ctx);
free_ctx:
	yaca_ctx_free((yaca_ctx_h)nc);

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
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return YACA_ERROR_NONE;
}

API int yaca_sign_final(yaca_ctx_h ctx,
                        char *signature,
                        size_t *signature_len)
{
	struct yaca_sign_ctx_s *c = get_sign_ctx(ctx);
	int ret;

	if (c == NULL ||  c->op_type != OP_SIGN ||
	    signature == NULL || signature_len == NULL || *signature_len == 0)
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = EVP_DigestSignFinal(c->mdctx, (unsigned char *)signature, signature_len);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return YACA_ERROR_NONE;
}

API int yaca_verify_init(yaca_ctx_h *ctx,
                         yaca_digest_algo_e algo,
                         const yaca_key_h key)
{
	struct yaca_sign_ctx_s *nc = NULL;
	const EVP_MD *md = NULL;
	int ret;
	const struct yaca_key_evp_s *evp_key = key_get_evp(key);

	if (ctx == NULL || evp_key == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	switch (key->type) {
	case YACA_KEY_TYPE_RSA_PUB:
	case YACA_KEY_TYPE_DSA_PUB:
		break;
//	case YACA_KEY_TYPE_EC_PUB:
//		TODO NOT_IMPLEMENTED
	default:
		return YACA_ERROR_INVALID_ARGUMENT;
	}

	nc = yaca_zalloc(sizeof(struct yaca_sign_ctx_s));
	if (nc == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	nc->op_type = OP_VERIFY;
	nc->ctx.type = YACA_CTX_SIGN;
	nc->ctx.ctx_destroy = destroy_sign_context;
	nc->ctx.get_output_length = NULL;
	nc->ctx.set_param = set_sign_param;
	nc->ctx.get_param = get_sign_param;

	ret = digest_get_algorithm(algo, &md);
	if (ret != YACA_ERROR_NONE)
		goto free_ctx;

	nc->mdctx = EVP_MD_CTX_create();
	if (nc->mdctx == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto free_ctx;
	}

	ret = EVP_DigestVerifyInit(nc->mdctx, NULL, md, NULL, evp_key->evp);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto free_ctx;
	}

	*ctx = (yaca_ctx_h)nc;

	return YACA_ERROR_NONE;

free_ctx:
	yaca_ctx_free((yaca_ctx_h)nc);

	return ret;
}

API int yaca_verify_update(yaca_ctx_h ctx,
                           const char *data,
                           size_t data_len)
{
	struct yaca_sign_ctx_s *c = get_sign_ctx(ctx);
	int ret;

	if (c == NULL || data == NULL || data_len == 0 || c->op_type != OP_VERIFY)
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = EVP_DigestVerifyUpdate(c->mdctx, data, data_len);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return YACA_ERROR_NONE;
}

API int yaca_verify_final(yaca_ctx_h ctx,
                          const char *signature,
                          size_t signature_len)
{
	struct yaca_sign_ctx_s *c = get_sign_ctx(ctx);
	int ret;

	if (c == NULL || signature == NULL || signature_len == 0 || c->op_type != OP_VERIFY)
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = EVP_DigestVerifyFinal(c->mdctx,
	                            (unsigned char *)signature,
	                            signature_len);

	if (ret == 1)
		return YACA_ERROR_NONE;

	if (ret == YACA_ERROR_NONE) {
		ERROR_CLEAR();
		return YACA_ERROR_DATA_MISMATCH;
	}

	ret = YACA_ERROR_INTERNAL;
	ERROR_DUMP(ret);
	return ret;
}
