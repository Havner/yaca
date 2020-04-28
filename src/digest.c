/*
 *  Copyright (c) 2016-2020 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file digest.c
 * @brief
 */

#include <assert.h>

#include <openssl/evp.h>

#include <yaca_crypto.h>
#include <yaca_digest.h>
#include <yaca_error.h>

#include "internal.h"

static const struct {
	yaca_digest_algorithm_e algo;
	const EVP_MD *(*digest)(void);
} MESSAGE_DIGESTS[] = {
	{YACA_DIGEST_MD5,    EVP_md5},
	{YACA_DIGEST_SHA1,   EVP_sha1},
	{YACA_DIGEST_SHA224, EVP_sha224},
	{YACA_DIGEST_SHA256, EVP_sha256},
	{YACA_DIGEST_SHA384, EVP_sha384},
	{YACA_DIGEST_SHA512, EVP_sha512},
};

static const size_t MESSAGE_DIGESTS_SIZE = sizeof(MESSAGE_DIGESTS) / sizeof(MESSAGE_DIGESTS[0]);

struct yaca_digest_context_s {
	struct yaca_context_s ctx;

	EVP_MD_CTX *md_ctx;
	enum context_state_e state;
};

static bool CTX_DEFAULT_STATES[CTX_COUNT][CTX_COUNT] = {
/* from \ to  INIT, MSG, FIN */
/* INIT */  { 0,    1,    1 },
/* MSG  */  { 0,    1,    1 },
/* FIN  */  { 0,    0,    0 },
};

static bool verify_state_change(struct yaca_digest_context_s *c, enum context_state_e to)
{
	int from = c->state;

	return CTX_DEFAULT_STATES[from][to];
}

static struct yaca_digest_context_s *get_digest_context(const yaca_context_h ctx)
{
	if (ctx == YACA_CONTEXT_NULL)
		return NULL;

	switch (ctx->type) {
	case YACA_CONTEXT_DIGEST:
		return (struct yaca_digest_context_s *)ctx;
	default:
		return NULL;
	}
}

static int get_digest_output_length(const yaca_context_h ctx,
                                    size_t input_len,
                                    size_t *output_len)
{
	assert(output_len != NULL);

	struct yaca_digest_context_s *c = get_digest_context(ctx);
	assert(c != NULL);
	assert(c->md_ctx != NULL);

	if (input_len != 0)
		return YACA_ERROR_INVALID_PARAMETER;

	int md_size = EVP_MD_CTX_size(c->md_ctx);
	if (md_size <= 0) {
		const int ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	*output_len = md_size;

	return YACA_ERROR_NONE;
}

static void destroy_digest_context(yaca_context_h ctx)
{
	struct yaca_digest_context_s *c = get_digest_context(ctx);
	assert(c != NULL);

	EVP_MD_CTX_destroy(c->md_ctx);
	c->md_ctx = NULL;
}

int digest_get_algorithm(yaca_digest_algorithm_e algo, const EVP_MD **md)
{
	int ret;
	size_t i;

	assert(md != NULL);

	*md = NULL;
	ret = YACA_ERROR_INVALID_PARAMETER;

	for (i = 0; i < MESSAGE_DIGESTS_SIZE; ++i)
		if (MESSAGE_DIGESTS[i].algo == algo) {
			*md = MESSAGE_DIGESTS[i].digest();
			ret = YACA_ERROR_NONE;
			break;
		}

	if (ret == YACA_ERROR_NONE && *md == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return ret;
}

API int yaca_digest_initialize(yaca_context_h *ctx, yaca_digest_algorithm_e algo)
{
	int ret;
	struct yaca_digest_context_s *nc = NULL;
	const EVP_MD *md;

	if (ctx == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_zalloc(sizeof(struct yaca_digest_context_s), (void**)&nc);
	if (ret != YACA_ERROR_NONE)
		return ret;

	nc->ctx.type = YACA_CONTEXT_DIGEST;
	nc->ctx.context_destroy = destroy_digest_context;
	nc->ctx.get_output_length = get_digest_output_length;
	nc->ctx.set_property = NULL;
	nc->ctx.get_property = NULL;

	ret = digest_get_algorithm(algo, &md);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	nc->md_ctx = EVP_MD_CTX_create();
	if (nc->md_ctx == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = EVP_DigestInit(nc->md_ctx, md);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	nc->state = CTX_INITIALIZED;
	*ctx = (yaca_context_h)nc;
	nc = NULL;
	ret = YACA_ERROR_NONE;

exit:
	yaca_context_destroy((yaca_context_h)nc);

	return ret;
}

API int yaca_digest_update(yaca_context_h ctx, const char *message, size_t message_len)
{
	struct yaca_digest_context_s *c = get_digest_context(ctx);
	int ret;

	if (c == NULL || message == NULL || message_len == 0)
		return YACA_ERROR_INVALID_PARAMETER;

	if (!verify_state_change(c, CTX_MSG_UPDATED))
		return YACA_ERROR_INVALID_PARAMETER;

	ret = EVP_DigestUpdate(c->md_ctx, message, message_len);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	c->state = CTX_MSG_UPDATED;
	return YACA_ERROR_NONE;
}

API int yaca_digest_finalize(yaca_context_h ctx, char *digest, size_t *digest_len)
{
	struct yaca_digest_context_s *c = get_digest_context(ctx);
	int ret;
	unsigned len = 0;

	if (c == NULL || digest == NULL || digest_len == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	if (!verify_state_change(c, CTX_FINALIZED))
		return YACA_ERROR_INVALID_PARAMETER;

	ret = EVP_DigestFinal_ex(c->md_ctx, (unsigned char*)digest, &len);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	c->state = CTX_FINALIZED;
	*digest_len = len;

	return YACA_ERROR_NONE;
}
