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
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <yaca/crypto.h>
#include <yaca/error.h>
#include <yaca/types.h>

#include "internal.h"

struct yaca_digest_ctx_s
{
	struct yaca_ctx_s ctx;

	const EVP_MD *md;
	EVP_MD_CTX *mdctx;
};

static struct yaca_digest_ctx_s *get_digest_ctx(const yaca_ctx_h ctx)
{
	if (ctx == YACA_CTX_NULL)
		return NULL;

	switch (ctx->type)
	{
	case YACA_CTX_DIGEST:
		return (struct yaca_digest_ctx_s *)ctx;
	default:
		return NULL;
	}
}

static int get_digest_output_length(const yaca_ctx_h ctx, size_t input_len)
{
	struct yaca_digest_ctx_s *c = get_digest_ctx(ctx);

	if (c == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	return EVP_MD_size(c->md);
}

static void destroy_digest_context(yaca_ctx_h ctx)
{
	struct yaca_digest_ctx_s *c = get_digest_ctx(ctx);

	if (c == NULL)
		return;

	EVP_MD_CTX_destroy(c->mdctx);
}

int digest_get_algorithm(yaca_digest_algo_e algo, const EVP_MD **md)
{
	int ret = 0;

	if (!md)
		return YACA_ERROR_INVALID_ARGUMENT;

	*md = NULL;

	switch (algo)
	{
	case YACA_DIGEST_MD5:
		*md = EVP_md5();
		break;
	case YACA_DIGEST_SHA1:
		*md = EVP_sha1();
		break;
	case YACA_DIGEST_SHA224:
		*md = EVP_sha224();
		break;
	case YACA_DIGEST_SHA256:
		*md = EVP_sha256();
		break;
	case YACA_DIGEST_SHA384:
		*md = EVP_sha384();
		break;
	case YACA_DIGEST_SHA512:
		*md = EVP_sha512();
		break;
	case YACA_DIGEST_CMAC:
		ret = YACA_ERROR_NOT_IMPLEMENTED;
		break;
	default:
		ret = YACA_ERROR_INVALID_ARGUMENT;
		break;
	}

	if (ret == 0 && *md == NULL)
		ret = YACA_ERROR_OPENSSL_FAILURE;

	return ret;
}

API int yaca_digest_init(yaca_ctx_h *ctx, yaca_digest_algo_e algo)
{
	int ret;
	struct yaca_digest_ctx_s *nc = NULL;

	if (ctx == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	nc = yaca_malloc(sizeof(struct yaca_digest_ctx_s));
	if (nc == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	nc->ctx.type = YACA_CTX_DIGEST;
	nc->ctx.ctx_destroy = destroy_digest_context;
	nc->ctx.get_output_length = get_digest_output_length;

	ret = digest_get_algorithm(algo, &nc->md);
	if (ret < 0)
		goto free;

	nc->mdctx = EVP_MD_CTX_create();
	if (nc->mdctx == NULL) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		goto free;
	}

	ret = EVP_DigestInit(nc->mdctx, nc->md);
	if (ret != 1) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		goto ctx;
	}

	*ctx = (yaca_ctx_h)nc;

	ret = 0;

ctx:
	if (ret != 0)
		EVP_MD_CTX_destroy(nc->mdctx);
free:
	if (ret != 0)
		yaca_free(nc);

	return ret;
}

API int yaca_digest_update(yaca_ctx_h ctx, const char *data, size_t data_len)
{
	struct yaca_digest_ctx_s *c = get_digest_ctx(ctx);
	int ret;

	if (c == NULL || data == NULL || data_len == 0)
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = EVP_DigestUpdate(c->mdctx, data, data_len);
	if (ret != 1)
		return YACA_ERROR_OPENSSL_FAILURE;

	return 0;
}

API int yaca_digest_final(yaca_ctx_h ctx, char *digest, size_t *digest_len)
{
	struct yaca_digest_ctx_s *c = get_digest_ctx(ctx);
	int ret;
	unsigned len = 0;

	if (c == NULL || digest == NULL || digest_len == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	if (*digest_len == 0 || *digest_len > UINT_MAX) // DigestFinal accepts uint
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = EVP_DigestFinal_ex(c->mdctx, (unsigned char*)digest, &len);
	if (ret != 1)
		return YACA_ERROR_OPENSSL_FAILURE;

	*digest_len = len;

	return 0;
}
