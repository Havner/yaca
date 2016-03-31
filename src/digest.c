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

typedef struct __crypto_digest_ctx {
	struct __crypto_ctx_s ctx;

	const EVP_MD *md;
	EVP_MD_CTX *mdctx;
} crypto_digest_ctx;

static crypto_digest_ctx *get_ctx(crypto_ctx_h ctx)
{
	if (!ctx)
		return NULL;
	if (ctx->type != CRYPTO_CTX_DIGEST)
		return NULL;
	return (crypto_digest_ctx *)ctx;
}

static int get_digest_output_length(const crypto_ctx_h ctx, size_t input_len)
{
	crypto_digest_ctx *c = get_ctx(ctx);

	if (!c)
		return CRYPTO_ERROR_INVALID_ARGUMENT;

	return EVP_MD_size(c->md);
}


int crypto_digest_init(crypto_ctx_h *ctx, crypto_digest_algo_e algo)
{
	crypto_digest_ctx *nc;
	int ret;

	if (!ctx)
		return CRYPTO_ERROR_INVALID_ARGUMENT;

	nc = crypto_alloc(sizeof(struct __crypto_digest_ctx));
	if (!nc)
		return CRYPTO_ERROR_OUT_OF_MEMORY;

	nc->ctx.type = CRYPTO_CTX_DIGEST;
	nc->ctx.get_output_length = get_digest_output_length;

	switch (algo)
	{
	case CRYPTO_DIGEST_MD5:
		nc->md = EVP_md5();
		break;
	case CRYPTO_DIGEST_SHA1:
		nc->md = EVP_sha1();
		break;
	case CRYPTO_DIGEST_SHA224:
		nc->md = EVP_sha224();
		break;
	case CRYPTO_DIGEST_SHA256:
		nc->md = EVP_sha256();
		break;
	case CRYPTO_DIGEST_SHA384:
		nc->md = EVP_sha384();
		break;
	case CRYPTO_DIGEST_SHA512:
		nc->md = EVP_sha512();
		break;
	default:
		crypto_free(nc);
		return CRYPTO_ERROR_INVALID_ARGUMENT;
	}

	if (!nc->md) {
		crypto_free(nc);
		return CRYPTO_ERROR_OPENSSL_FAILURE;
	}

	nc->mdctx = EVP_MD_CTX_create();
	if (!nc->mdctx) {
		crypto_free(nc);
		return CRYPTO_ERROR_OPENSSL_FAILURE;
	}

	ret = EVP_DigestInit(nc->mdctx, nc->md);
	if (ret == 1) {
		*ctx = &nc->ctx; //TODO: how to do it "better" ?
		return 0;
	}

	EVP_MD_CTX_destroy(nc->mdctx);
	crypto_free(nc);

	return CRYPTO_ERROR_OPENSSL_FAILURE;
}

int crypto_digest_update(crypto_ctx_h ctx, const char *data, size_t data_len)
{
	crypto_digest_ctx *c = get_ctx(ctx);
	int ret;

	if (!c || !data || !data_len)
		return CRYPTO_ERROR_INVALID_ARGUMENT;

	ret = EVP_DigestUpdate(c->mdctx, data, data_len);

	if (ret == 1)
		return 0;

	return CRYPTO_ERROR_OPENSSL_FAILURE;
}

int crypto_digest_final(crypto_ctx_h ctx, char *digest, size_t *digest_len)
{
	crypto_digest_ctx *c = get_ctx(ctx);
	int ret;
	unsigned len = 0;

	if (!c || !digest || !digest_len)
		return CRYPTO_ERROR_INVALID_ARGUMENT;

	if (*digest_len == 0 || *digest_len > UINT_MAX) // DigestFinal accepts uint
		return CRYPTO_ERROR_INVALID_ARGUMENT;

	ret = EVP_DigestFinal_ex(c->mdctx, (unsigned char*)digest, &len);
	*digest_len = len;
	if (ret == 1)
		return 0;

	return CRYPTO_ERROR_OPENSSL_FAILURE;
}
