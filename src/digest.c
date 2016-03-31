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

#include <crypto/crypto.h>
#include <crypto/error.h>

#include "ctx_p.h"

typedef struct __owl_digest_ctx {
	struct __owl_ctx_s ctx;

	const EVP_MD *md;
	EVP_MD_CTX *mdctx;
} owl_digest_ctx;

static owl_digest_ctx *get_ctx(owl_ctx_h ctx)
{
	if (!ctx)
		return NULL;
	if (ctx->type != OWL_CTX_DIGEST)
		return NULL;
	return (owl_digest_ctx *)ctx;
}

static int get_digest_output_length(const owl_ctx_h ctx, size_t input_len)
{
	owl_digest_ctx *c = get_ctx(ctx);

	if (!c)
		return OWL_ERROR_INVALID_ARGUMENT;

	return EVP_MD_size(c->md);
}

int owl_digest_init(owl_ctx_h *ctx, owl_digest_algo_e algo)
{
	owl_digest_ctx *nc;
	int ret;

	if (!ctx)
		return OWL_ERROR_INVALID_ARGUMENT;

	nc = owl_alloc(sizeof(struct __owl_digest_ctx));
	if (!nc)
		return OWL_ERROR_OUT_OF_MEMORY;

	nc->ctx.type = OWL_CTX_DIGEST;
	nc->ctx.get_output_length = get_digest_output_length;

	switch (algo)
	{
	case OWL_DIGEST_MD5:
		nc->md = EVP_md5();
		break;
	case OWL_DIGEST_SHA1:
		nc->md = EVP_sha1();
		break;
	case OWL_DIGEST_SHA224:
		nc->md = EVP_sha224();
		break;
	case OWL_DIGEST_SHA256:
		nc->md = EVP_sha256();
		break;
	case OWL_DIGEST_SHA384:
		nc->md = EVP_sha384();
		break;
	case OWL_DIGEST_SHA512:
		nc->md = EVP_sha512();
		break;
	default:
		owl_free(nc);
		return OWL_ERROR_INVALID_ARGUMENT;
	}

	if (!nc->md) {
		owl_free(nc);
		return OWL_ERROR_OPENSSL_FAILURE;
	}

	nc->mdctx = EVP_MD_CTX_create();
	if (!nc->mdctx) {
		owl_free(nc);
		return OWL_ERROR_OPENSSL_FAILURE;
	}

	ret = EVP_DigestInit(nc->mdctx, nc->md);
	if (ret == 1) {
		*ctx = &nc->ctx; //TODO: how to do it "better" ?
		return 0;
	}

	EVP_MD_CTX_destroy(nc->mdctx);
	owl_free(nc);

	return OWL_ERROR_OPENSSL_FAILURE;
}

int owl_digest_update(owl_ctx_h ctx, const char *data, size_t data_len)
{
	owl_digest_ctx *c = get_ctx(ctx);
	int ret;

	if (!c || !data || !data_len)
		return OWL_ERROR_INVALID_ARGUMENT;

	ret = EVP_DigestUpdate(c->mdctx, data, data_len);

	if (ret == 1)
		return 0;

	return OWL_ERROR_OPENSSL_FAILURE;
}

int owl_digest_final(owl_ctx_h ctx, char *digest, size_t *digest_len)
{
	owl_digest_ctx *c = get_ctx(ctx);
	int ret;
	unsigned len = 0;

	if (!c || !digest || !digest_len)
		return OWL_ERROR_INVALID_ARGUMENT;

	if (*digest_len == 0 || *digest_len > UINT_MAX) // DigestFinal accepts uint
		return OWL_ERROR_INVALID_ARGUMENT;

	ret = EVP_DigestFinal_ex(c->mdctx, (unsigned char*)digest, &len);
	*digest_len = len;
	if (ret == 1)
		return 0;

	return OWL_ERROR_OPENSSL_FAILURE;
}
