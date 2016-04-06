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
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <yaca/crypto.h>
#include <yaca/error.h>
#include <yaca/types.h>

#include "ctx_p.h"

struct yaca_digest_ctx_s
{
	struct yaca_ctx_s ctx;

	const EVP_MD *md;
	EVP_MD_CTX *mdctx;
};

static struct yaca_digest_ctx_s *get_ctx(yaca_ctx_h ctx)
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
	struct yaca_digest_ctx_s *c = get_ctx(ctx);

	if (c == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	return EVP_MD_size(c->md);
}

API int yaca_digest_init(yaca_ctx_h *ctx, yaca_digest_algo_e algo)
{
	struct yaca_digest_ctx_s *nc;
	int ret = YACA_ERROR_OPENSSL_FAILURE;

	if (ctx == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	nc = yaca_malloc(sizeof(struct yaca_digest_ctx_s));
	if (nc == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	nc->ctx.type = YACA_CTX_DIGEST;
	nc->ctx.get_output_length = get_digest_output_length;

	switch (algo)
	{
	case YACA_DIGEST_MD5:
		nc->md = EVP_md5();
		break;
	case YACA_DIGEST_SHA1:
		nc->md = EVP_sha1();
		break;
	case YACA_DIGEST_SHA224:
		nc->md = EVP_sha224();
		break;
	case YACA_DIGEST_SHA256:
		nc->md = EVP_sha256();
		break;
	case YACA_DIGEST_SHA384:
		nc->md = EVP_sha384();
		break;
	case YACA_DIGEST_SHA512:
		nc->md = EVP_sha512();
		break;
	default:
		ret = YACA_ERROR_INVALID_ARGUMENT;
		goto err;
	}

	if (nc->md == NULL)
		goto err;

	nc->mdctx = EVP_MD_CTX_create();
	if (nc->mdctx == NULL)
		goto err;

	ret = EVP_DigestInit(nc->mdctx, nc->md);
	if (ret == 1) {
		*ctx = (yaca_ctx_h)nc;
		return 0;
	}
	ret = YACA_ERROR_OPENSSL_FAILURE; // TODO: yaca_get_error_code_from_openssl(ret);

	EVP_MD_CTX_destroy(nc->mdctx);
err:
	yaca_free(nc);
	return ret;
}

API int yaca_digest_update(yaca_ctx_h ctx, const char *data, size_t data_len)
{
	struct yaca_digest_ctx_s *c = get_ctx(ctx);
	int ret;

	if (c == NULL || data == NULL || data_len == 0)
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = EVP_DigestUpdate(c->mdctx, data, data_len);
	if (ret == 1)
		return 0;

	return YACA_ERROR_OPENSSL_FAILURE; // TODO: yaca_get_error_code_from_openssl(ret);
}

API int yaca_digest_final(yaca_ctx_h ctx, char *digest, size_t *digest_len)
{
	struct yaca_digest_ctx_s *c = get_ctx(ctx);
	int ret;
	unsigned len = 0;

	if (c == NULL || digest == NULL || digest_len == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	if (*digest_len == 0 || *digest_len > UINT_MAX) // DigestFinal accepts uint
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = EVP_DigestFinal_ex(c->mdctx, (unsigned char*)digest, &len);
	*digest_len = len;
	if (ret == 1)
		return 0;

	return YACA_ERROR_OPENSSL_FAILURE; // TODO: yaca_get_error_code_from_openssl(ret);
}
