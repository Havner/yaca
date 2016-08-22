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

struct yaca_sign_context_s {
	struct yaca_context_s ctx;

	EVP_MD_CTX *md_ctx;
	enum sign_op_type op_type;
};

static struct yaca_sign_context_s *get_sign_context(const yaca_context_h ctx)
{
	if (ctx == YACA_CONTEXT_NULL)
		return NULL;

	switch (ctx->type) {
	case YACA_CONTEXT_SIGN:
		return (struct yaca_sign_context_s *)ctx;
	default:
		return NULL;
	}
}

static int get_sign_output_length(const yaca_context_h ctx,
                                  size_t input_len,
                                  size_t *output_len)
{
	assert(output_len != NULL);

	struct yaca_sign_context_s *c = get_sign_context(ctx);

	if (c == NULL || input_len != 0)
		return YACA_ERROR_INVALID_PARAMETER;

	assert(c->md_ctx != NULL);

	if (c->md_ctx->pctx == NULL)
		return YACA_ERROR_INTERNAL;

	EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(c->md_ctx->pctx);
	if (pkey == NULL) {
		ERROR_DUMP(YACA_ERROR_INTERNAL);
		return YACA_ERROR_INTERNAL;
	}

	int len = EVP_PKEY_size(pkey);
	if (len <= 0) {
		ERROR_DUMP(YACA_ERROR_INTERNAL);
		return YACA_ERROR_INTERNAL;
	}

	*output_len = len;
	return YACA_ERROR_NONE;
}

static void destroy_sign_context(yaca_context_h ctx)
{
	struct yaca_sign_context_s *c = get_sign_context(ctx);

	if (c == NULL)
		return;

	EVP_MD_CTX_destroy(c->md_ctx);
	c->md_ctx = NULL;
}

int set_sign_property(yaca_context_h ctx,
                      yaca_property_e property,
                      const void *value,
                      size_t value_len)
{
	int ret;
	struct yaca_sign_context_s *c = get_sign_context(ctx);
	yaca_padding_e padding;
	int pad;
	EVP_PKEY *pkey;

	if (c == NULL || value == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	assert(c->md_ctx != NULL);

	if (c->md_ctx->pctx == NULL)
		return YACA_ERROR_INTERNAL;

	/* this function only supports padding */
	if (property != YACA_PROPERTY_PADDING || value_len != sizeof(yaca_padding_e))
		return YACA_ERROR_INVALID_PARAMETER;

	padding = *(yaca_padding_e *)(value);

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
		return YACA_ERROR_INVALID_PARAMETER;
	}

	pkey = EVP_PKEY_CTX_get0_pkey(c->md_ctx->pctx);
	if (pkey == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	/* padding only works for RSA */
	if (pkey->type != EVP_PKEY_RSA)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = EVP_PKEY_CTX_set_rsa_padding(c->md_ctx->pctx, pad);
	if (ret <= 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return YACA_ERROR_NONE;
}

int get_sign_property(const yaca_context_h ctx,
                      yaca_property_e property,
                      void **value,
                      size_t *value_len)
{
	int ret;
	struct yaca_sign_context_s *c = get_sign_context(ctx);
	EVP_PKEY *pkey;
	int pad;
	yaca_padding_e padding;

	if (c == NULL || value == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	assert(c->md_ctx != NULL);

	if (c->md_ctx->pctx == NULL)
		return YACA_ERROR_INTERNAL;

	/* this function only supports padding */
	if (property != YACA_PROPERTY_PADDING)
		return YACA_ERROR_INVALID_PARAMETER;

	pkey = EVP_PKEY_CTX_get0_pkey(c->md_ctx->pctx);
	if (pkey == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	/* padding only works for RSA */
	if (pkey->type != EVP_PKEY_RSA)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = EVP_PKEY_CTX_get_rsa_padding(c->md_ctx->pctx, &pad);
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

	ret = yaca_malloc(sizeof(yaca_padding_e), value);
	if (ret != YACA_ERROR_NONE)
		return ret;

	memcpy(*value, &padding, sizeof(yaca_padding_e));
	if (value_len != NULL)
		*value_len = sizeof(yaca_padding_e);

	return YACA_ERROR_NONE;
}

API int yaca_sign_initialize(yaca_context_h *ctx,
                             yaca_digest_algorithm_e algo,
                             const yaca_key_h prv_key)
{
	struct yaca_sign_context_s *nc = NULL;
	const EVP_MD *md = NULL;
	int ret;
	const struct yaca_key_evp_s *evp_key = key_get_evp(prv_key);

	if (ctx == NULL || evp_key == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	switch (prv_key->type) {
	case YACA_KEY_TYPE_RSA_PRIV:
	case YACA_KEY_TYPE_DSA_PRIV:
	case YACA_KEY_TYPE_EC_PRIV:
		break;
	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}

	ret = yaca_zalloc(sizeof(struct yaca_sign_context_s), (void**)&nc);
	if (ret != YACA_ERROR_NONE)
		return ret;

	nc->op_type = OP_SIGN;
	nc->ctx.type = YACA_CONTEXT_SIGN;
	nc->ctx.context_destroy = destroy_sign_context;
	nc->ctx.get_output_length = get_sign_output_length;
	nc->ctx.set_property = set_sign_property;
	nc->ctx.get_property = get_sign_property;

	ret = digest_get_algorithm(algo, &md);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	nc->md_ctx = EVP_MD_CTX_create();
	if (nc->md_ctx == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = EVP_DigestSignInit(nc->md_ctx, NULL, md, NULL, evp_key->evp);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	*ctx = (yaca_context_h)nc;
	nc = NULL;
	ret = YACA_ERROR_NONE;

exit:
	yaca_context_destroy((yaca_context_h)nc);

	return ret;
}

API int yaca_sign_initialize_hmac(yaca_context_h *ctx,
                                  yaca_digest_algorithm_e algo,
                                  const yaca_key_h sym_key)
{
	struct yaca_sign_context_s *nc = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *md;
	int ret;
	const struct yaca_key_simple_s *simple_key = key_get_simple(sym_key);

	if (ctx == NULL || simple_key == NULL ||
	    (sym_key->type != YACA_KEY_TYPE_SYMMETRIC && sym_key->type != YACA_KEY_TYPE_DES))
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_zalloc(sizeof(struct yaca_sign_context_s), (void**)&nc);
	if (ret != YACA_ERROR_NONE)
		return ret;

	nc->op_type = OP_SIGN;
	nc->ctx.type = YACA_CONTEXT_SIGN;
	nc->ctx.context_destroy = destroy_sign_context;
	nc->ctx.get_output_length = get_sign_output_length;

	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC,
	                            NULL,
	                            (unsigned char *)simple_key->d,
	                            simple_key->bit_len / 8);
	if (pkey == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = digest_get_algorithm(algo, &md);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	nc->md_ctx = EVP_MD_CTX_create();
	if (nc->md_ctx == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = EVP_DigestSignInit(nc->md_ctx, NULL, md, NULL, pkey);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	pkey = NULL;

	*ctx = (yaca_context_h)nc;
	nc = NULL;
	ret = YACA_ERROR_NONE;

exit:
	EVP_PKEY_free(pkey);
	yaca_context_destroy((yaca_context_h)nc);

	return ret;
}

API int yaca_sign_initialize_cmac(yaca_context_h *ctx,
                                  yaca_encrypt_algorithm_e algo,
                                  const yaca_key_h sym_key)
{
	struct yaca_sign_context_s *nc = NULL;
	CMAC_CTX* cmac_ctx = NULL;
	const EVP_CIPHER* cipher = NULL;
	EVP_PKEY *pkey = NULL;
	int ret;
	const struct yaca_key_simple_s *simple_key = key_get_simple(sym_key);

	if (ctx == NULL || simple_key == NULL ||
	    (sym_key->type != YACA_KEY_TYPE_SYMMETRIC && sym_key->type != YACA_KEY_TYPE_DES))
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_zalloc(sizeof(struct yaca_sign_context_s), (void**)&nc);
	if (ret != YACA_ERROR_NONE)
		return ret;

	nc->op_type = OP_SIGN;
	nc->ctx.type = YACA_CONTEXT_SIGN;
	nc->ctx.context_destroy = destroy_sign_context;
	nc->ctx.get_output_length = get_sign_output_length;

	ret = encrypt_get_algorithm(algo, YACA_BCM_CBC, simple_key->bit_len, &cipher);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* create and initialize low level CMAC context */
	cmac_ctx = CMAC_CTX_new();
	if (cmac_ctx == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	if (CMAC_Init(cmac_ctx, simple_key->d, simple_key->bit_len / 8, cipher, NULL) != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	/* create key and assign CMAC context to it */
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	if (EVP_PKEY_assign(pkey, EVP_PKEY_CMAC, cmac_ctx) != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	cmac_ctx = NULL;

	nc->md_ctx = EVP_MD_CTX_create();
	if (nc->md_ctx == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	if (EVP_DigestSignInit(nc->md_ctx, NULL, NULL, NULL, pkey) != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	pkey = NULL;

	*ctx = (yaca_context_h)nc;
	nc = NULL;
	ret = YACA_ERROR_NONE;

exit:
	EVP_PKEY_free(pkey);
	CMAC_CTX_free(cmac_ctx);
	yaca_context_destroy((yaca_context_h)nc);

	return ret;
}

API int yaca_sign_update(yaca_context_h ctx,
                         const char *data,
                         size_t data_len)
{
	struct yaca_sign_context_s *c = get_sign_context(ctx);
	int ret;

	if (c == NULL || c->op_type != OP_SIGN ||
	    data == NULL || data_len == 0)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = EVP_DigestSignUpdate(c->md_ctx, data, data_len);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return YACA_ERROR_NONE;
}

API int yaca_sign_finalize(yaca_context_h ctx,
                           char *signature,
                           size_t *signature_len)
{
	struct yaca_sign_context_s *c = get_sign_context(ctx);
	int ret;

	if (c == NULL ||  c->op_type != OP_SIGN ||
	    signature == NULL || signature_len == NULL || *signature_len == 0)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = EVP_DigestSignFinal(c->md_ctx, (unsigned char *)signature, signature_len);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return YACA_ERROR_NONE;
}

API int yaca_verify_initialize(yaca_context_h *ctx,
                               yaca_digest_algorithm_e algo,
                               const yaca_key_h pub_key)
{
	struct yaca_sign_context_s *nc = NULL;
	const EVP_MD *md = NULL;
	int ret;
	const struct yaca_key_evp_s *evp_key = key_get_evp(pub_key);

	if (ctx == NULL || evp_key == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	switch (pub_key->type) {
	case YACA_KEY_TYPE_RSA_PUB:
	case YACA_KEY_TYPE_DSA_PUB:
	case YACA_KEY_TYPE_EC_PUB:
		break;
	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}

	ret = yaca_zalloc(sizeof(struct yaca_sign_context_s), (void**)&nc);
	if (ret != YACA_ERROR_NONE)
		return ret;

	nc->op_type = OP_VERIFY;
	nc->ctx.type = YACA_CONTEXT_SIGN;
	nc->ctx.context_destroy = destroy_sign_context;
	nc->ctx.get_output_length = NULL;
	nc->ctx.set_property = set_sign_property;
	nc->ctx.get_property = get_sign_property;

	ret = digest_get_algorithm(algo, &md);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	nc->md_ctx = EVP_MD_CTX_create();
	if (nc->md_ctx == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = EVP_DigestVerifyInit(nc->md_ctx, NULL, md, NULL, evp_key->evp);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	*ctx = (yaca_context_h)nc;
	nc = NULL;
	ret = YACA_ERROR_NONE;

exit:
	yaca_context_destroy((yaca_context_h)nc);

	return ret;
}

API int yaca_verify_update(yaca_context_h ctx,
                           const char *data,
                           size_t data_len)
{
	struct yaca_sign_context_s *c = get_sign_context(ctx);
	int ret;

	if (c == NULL || data == NULL || data_len == 0 || c->op_type != OP_VERIFY)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = EVP_DigestVerifyUpdate(c->md_ctx, data, data_len);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return YACA_ERROR_NONE;
}

API int yaca_verify_finalize(yaca_context_h ctx,
                             const char *signature,
                             size_t signature_len)
{
	struct yaca_sign_context_s *c = get_sign_context(ctx);
	int ret;

	if (c == NULL || signature == NULL || signature_len == 0 || c->op_type != OP_VERIFY)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = EVP_DigestVerifyFinal(c->md_ctx,
	                            (unsigned char *)signature,
	                            signature_len);

	if (ret == 1)
		return YACA_ERROR_NONE;

	if (ret == 0) {
		ERROR_CLEAR();
		return YACA_ERROR_DATA_MISMATCH;
	}

	ret = YACA_ERROR_INTERNAL;
	ERROR_DUMP(ret);
	return ret;
}
