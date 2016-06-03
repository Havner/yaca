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
 * @file seal.c
 * @brief
 */

#include <assert.h>
#include <stdint.h>

#include <openssl/evp.h>

#include <yaca_crypto.h>
#include <yaca_seal.h>
#include <yaca_error.h>
#include <yaca_key.h>

#include "internal.h"

enum seal_op_type {
	OP_SEAL = 0,
	OP_OPEN = 1
};

struct yaca_seal_ctx_s {
	struct yaca_ctx_s ctx;

	EVP_CIPHER_CTX *cipher_ctx;
	enum seal_op_type op_type; /* Operation context was created for */
};

static struct yaca_seal_ctx_s *get_seal_ctx(const yaca_ctx_h ctx)
{
	if (ctx == YACA_CTX_NULL)
		return NULL;

	switch (ctx->type) {
	case YACA_CTX_SEAL:
		return (struct yaca_seal_ctx_s *)ctx;
	default:
		return NULL;
	}
}

static void destroy_seal_ctx(const yaca_ctx_h ctx)
{
	struct yaca_seal_ctx_s *nc = get_seal_ctx(ctx);

	if (nc == NULL)
		return;

	EVP_CIPHER_CTX_free(nc->cipher_ctx);
	nc->cipher_ctx = NULL;
}

static int get_seal_output_length(const yaca_ctx_h ctx, size_t input_len, size_t *output_len)
{
	struct yaca_seal_ctx_s *nc = get_seal_ctx(ctx);
	int block_size;

	if (nc == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;
	assert(nc->cipher_ctx);

	block_size = EVP_CIPHER_CTX_block_size(nc->cipher_ctx);
	if (block_size <= 0) {
		ERROR_DUMP(YACA_ERROR_INTERNAL);
		return YACA_ERROR_INTERNAL;
	}

	if (input_len > 0) {
		if ((size_t)block_size > SIZE_MAX - input_len + 1)
			return YACA_ERROR_INVALID_ARGUMENT;

		*output_len = block_size + input_len - 1;
	} else {
		*output_len = block_size;
	}

	return YACA_ERROR_NONE;
}

static int seal_init(yaca_ctx_h *ctx,
                     const yaca_key_h pub_key,
                     yaca_enc_algo_e algo,
                     yaca_block_cipher_mode_e bcm,
                     yaca_key_bits_e sym_key_bits,
                     yaca_key_h *sym_key,
                     yaca_key_h *iv)
{
	struct yaca_key_evp_s *lpub;
	struct yaca_key_simple_s *lkey = NULL;
	struct yaca_key_simple_s *liv = NULL;
	struct yaca_seal_ctx_s *nc;
	const EVP_CIPHER *cipher;
	int pub_key_length;
	unsigned char *key_data = NULL;
	int key_data_length;
	unsigned char *iv_data = NULL;
	int iv_length;
	int ret;

	if (ctx == NULL || pub_key == YACA_KEY_NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	if (pub_key->type != YACA_KEY_TYPE_RSA_PUB)
		return YACA_ERROR_INVALID_ARGUMENT;
	lpub = key_get_evp(pub_key);
	assert(lpub);

	ret = yaca_zalloc(sizeof(struct yaca_seal_ctx_s), (void**)&nc);
	if (ret != YACA_ERROR_NONE)
		return ret;

	nc->ctx.type = YACA_CTX_SEAL;
	nc->ctx.ctx_destroy = destroy_seal_ctx;
	nc->ctx.get_output_length = get_seal_output_length;
	nc->op_type = OP_SEAL;

	nc->cipher_ctx = EVP_CIPHER_CTX_new();
	if (nc->cipher_ctx == NULL) {
		ret =  YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = EVP_PKEY_size(lpub->evp);
	if (ret <= 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	pub_key_length = ret;
	ret = yaca_zalloc(sizeof(struct yaca_key_simple_s) + pub_key_length, (void**)&lkey);
	if (ret != YACA_ERROR_NONE)
		goto exit;
	key_data = (unsigned char*)lkey->d;

	ret = encrypt_get_algorithm(algo, bcm, sym_key_bits, &cipher);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = EVP_CIPHER_iv_length(cipher);
	if (ret < 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	iv_length = ret;
	if (iv_length > 0) {
		ret = yaca_zalloc(sizeof(struct yaca_key_simple_s) + iv_length, (void**)&liv);
		if (ret != YACA_ERROR_NONE)
			goto exit;
		iv_data = (unsigned char*)liv->d;
	}

	ret = EVP_SealInit(nc->cipher_ctx,
	                   cipher,
	                   &key_data,
	                   &key_data_length,
	                   iv_data,
	                   &lpub->evp,
	                   1);

	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	lkey->bits = key_data_length * 8;
	lkey->key.type = YACA_KEY_TYPE_SYMMETRIC;
	*sym_key = (yaca_key_h)lkey;
	lkey = NULL;

	if (iv_length > 0) {
		liv->bits = iv_length * 8;
		liv->key.type = YACA_KEY_TYPE_IV;
		*iv = (yaca_key_h)liv;
		liv = NULL;
	} else {
		*iv = NULL;
	}
	*ctx = (yaca_ctx_h)nc;
	nc = NULL;
	ret = YACA_ERROR_NONE;

exit:
	yaca_free(liv);
	yaca_free(lkey);
	yaca_ctx_free((yaca_ctx_h)nc);

	return ret;
}

static int open_init(yaca_ctx_h *ctx,
                     const yaca_key_h prv_key,
                     yaca_enc_algo_e algo,
                     yaca_block_cipher_mode_e bcm,
                     yaca_key_bits_e sym_key_bits,
                     const yaca_key_h sym_key,
                     const yaca_key_h iv)
{
	const struct yaca_key_evp_s *lprv;
	const struct yaca_key_simple_s *lkey;
	const struct yaca_key_simple_s *liv;
	struct yaca_seal_ctx_s *nc;
	const EVP_CIPHER *cipher;
	unsigned char *iv_data = NULL;
	size_t iv_bits;
	size_t iv_bits_check;
	int ret;

	if (ctx == NULL || prv_key == YACA_KEY_NULL || sym_key == YACA_KEY_NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	if (prv_key->type != YACA_KEY_TYPE_RSA_PRIV)
		return YACA_ERROR_INVALID_ARGUMENT;
	lprv = key_get_evp(prv_key);
	assert(lprv);

	lkey = key_get_simple(sym_key);
	if (lkey == NULL || lkey->key.type != YACA_KEY_TYPE_SYMMETRIC)
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = yaca_zalloc(sizeof(struct yaca_seal_ctx_s), (void**)&nc);
	if (ret != YACA_ERROR_NONE)
		return ret;

	nc->ctx.type = YACA_CTX_SEAL;
	nc->ctx.ctx_destroy = destroy_seal_ctx;
	nc->ctx.get_output_length = get_seal_output_length;
	nc->op_type = OP_OPEN;

	ret = encrypt_get_algorithm(algo, bcm, sym_key_bits, &cipher);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = EVP_CIPHER_iv_length(cipher);
	if (ret < 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	iv_bits = ret * 8;
	if (iv_bits == 0 && iv != NULL) { /* 0 -> cipher doesn't use iv, but it was provided */
		ret = YACA_ERROR_INVALID_ARGUMENT;
		goto exit;
	}

	if (iv_bits > 0) { /* cipher requires iv*/
		liv = key_get_simple(iv);
		if (liv == NULL || liv->key.type != YACA_KEY_TYPE_IV) { /* iv was not provided */
			ret = YACA_ERROR_INVALID_ARGUMENT;
			goto exit;
		}
		ret = yaca_key_get_bits(iv, &iv_bits_check);
		if (ret != YACA_ERROR_NONE) {
			ret = YACA_ERROR_INVALID_ARGUMENT;
			goto exit;
		}
		/* IV length doesn't match cipher */
		if (iv_bits != iv_bits_check) {
			ret = YACA_ERROR_INVALID_ARGUMENT;
			goto exit;
		}
		iv_data = (unsigned char*)liv->d;
	}

	nc->cipher_ctx = EVP_CIPHER_CTX_new();
	if (nc->cipher_ctx == NULL) {
		ret =  YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = EVP_OpenInit(nc->cipher_ctx, cipher,
	                   (unsigned char*)lkey->d,
	                   EVP_PKEY_size(lprv->evp),
	                   iv_data,
	                   lprv->evp);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	*ctx = (yaca_ctx_h)nc;
	nc = NULL;
	ret = YACA_ERROR_NONE;

exit:
	yaca_ctx_free((yaca_ctx_h)nc);

	return ret;
}

static int seal_update(yaca_ctx_h ctx,
                       const unsigned char *input,
                       size_t input_len,
                       unsigned char *output,
                       size_t *output_len,
                       enum seal_op_type op_type)
{
	struct yaca_seal_ctx_s *c = get_seal_ctx(ctx);
	int ret;

	if (c == NULL || input == NULL || input_len == 0 ||
	    output == NULL || output_len == NULL || op_type != c->op_type)
		return YACA_ERROR_INVALID_ARGUMENT;

	switch (op_type) {
	case OP_SEAL:
		ret = EVP_SealUpdate(c->cipher_ctx, output, (int*)output_len, input, input_len);
		break;
	case OP_OPEN:
		ret = EVP_OpenUpdate(c->cipher_ctx, output, (int*)output_len, input, input_len);
		break;
	default:
		return YACA_ERROR_INVALID_ARGUMENT;
	}

	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return YACA_ERROR_NONE;
}

static int seal_final(yaca_ctx_h ctx,
                      unsigned char *output,
                      size_t *output_len,
                      enum seal_op_type op_type)
{
	struct yaca_seal_ctx_s *c = get_seal_ctx(ctx);
	int ret;

	if (c == NULL || output == NULL || output_len == NULL || op_type != c->op_type)
		return YACA_ERROR_INVALID_ARGUMENT;

	switch (op_type) {
	case OP_SEAL:
		ret = EVP_SealFinal(c->cipher_ctx, output, (int*)output_len);
		break;
	case OP_OPEN:
		ret = EVP_OpenFinal(c->cipher_ctx, output, (int*)output_len);
		break;
	default:
		return YACA_ERROR_INVALID_ARGUMENT;
	}

	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return YACA_ERROR_NONE;
}

API int yaca_seal_init(yaca_ctx_h *ctx,
                       const yaca_key_h pub_key,
                       yaca_enc_algo_e algo,
                       yaca_block_cipher_mode_e bcm,
                       yaca_key_bits_e sym_key_bits,
                       yaca_key_h *sym_key,
                       yaca_key_h *iv)
{
	return seal_init(ctx, pub_key, algo, bcm, sym_key_bits, sym_key, iv);
}

API int yaca_seal_update(yaca_ctx_h ctx,
                         const char *plain,
                         size_t plain_len,
                         char *cipher,
                         size_t *cipher_len)
{
	return seal_update(ctx,
	                   (const unsigned char*)plain,
	                   plain_len,
	                   (unsigned char*)cipher,
	                   cipher_len,
	                   OP_SEAL);
}

API int yaca_seal_final(yaca_ctx_h ctx,
                        char *cipher,
                        size_t *cipher_len)
{
	return seal_final(ctx,
	                  (unsigned char*)cipher,
	                  cipher_len,
	                  OP_SEAL);
}

API int yaca_open_init(yaca_ctx_h *ctx,
                       const yaca_key_h prv_key,
                       yaca_enc_algo_e algo,
                       yaca_block_cipher_mode_e bcm,
                       yaca_key_bits_e sym_key_bits,
                       const yaca_key_h sym_key,
                       const yaca_key_h iv)
{
	return open_init(ctx, prv_key, algo, bcm, sym_key_bits, sym_key, iv);
}

API int yaca_open_update(yaca_ctx_h ctx,
                         const char *cipher,
                         size_t cipher_len,
                         char *plain,
                         size_t *plain_len)
{
	return seal_update(ctx,
	                   (const unsigned char*)cipher,
	                   cipher_len,
	                   (unsigned char*)plain,
	                   plain_len,
	                   OP_OPEN);
}

API int yaca_open_final(yaca_ctx_h ctx,
                        char *plain,
                        size_t *plain_len)
{
	return seal_final(ctx, (unsigned char*)plain, plain_len, OP_OPEN);
}
