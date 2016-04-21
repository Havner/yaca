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
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include <yaca/crypto.h>
#include <yaca/seal.h>
#include <yaca/error.h>
#include <yaca/key.h>

#include "internal.h"

enum seal_op_type {
	OP_SEAL = 0,
	OP_OPEN = 1
};

struct yaca_seal_ctx_s
{
	struct yaca_ctx_s ctx;

	EVP_CIPHER_CTX *cipher_ctx;
	enum seal_op_type op_type; /* Operation context was created for */
};

static struct yaca_seal_ctx_s *get_seal_ctx(const yaca_ctx_h ctx)
{
	if (ctx == YACA_CTX_NULL)
		return NULL;

	switch (ctx->type)
	{
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

static int get_seal_output_length(const yaca_ctx_h ctx, size_t input_len)
{
	struct yaca_seal_ctx_s *nc = get_seal_ctx(ctx);
	int block_size;

	if (nc == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;
	assert(nc->cipher_ctx);

	block_size = EVP_CIPHER_CTX_block_size(nc->cipher_ctx);
	if (block_size <= 0) {
		ERROR_DUMP(YACA_ERROR_OPENSSL_FAILURE);
		return YACA_ERROR_OPENSSL_FAILURE;
	}

	if (input_len > 0)
		return block_size + input_len - 1;
	return block_size;
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
	struct yaca_key_simple_s *lkey;
	struct yaca_key_simple_s *liv;
	struct yaca_seal_ctx_s *nc;
	const EVP_CIPHER *cipher;
	int pub_key_length;
	int iv_length;
	int ret;

	if (ctx == NULL || pub_key == YACA_KEY_NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	if (pub_key->type != YACA_KEY_TYPE_RSA_PUB)
		return YACA_ERROR_INVALID_ARGUMENT;
	lpub = key_get_evp(pub_key);
	assert(lpub);

	nc = yaca_zalloc(sizeof(struct yaca_seal_ctx_s));
	if (nc == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	nc->ctx.type = YACA_CTX_SEAL;
	nc->ctx.ctx_destroy = destroy_seal_ctx;
	nc->ctx.get_output_length = get_seal_output_length;
	nc->op_type = OP_SEAL;

	nc->cipher_ctx = EVP_CIPHER_CTX_new();
	if (nc->cipher_ctx == NULL) {
		ret =  YACA_ERROR_OPENSSL_FAILURE;
		ERROR_DUMP(ret);
		goto err_free;
	}

	ret = EVP_PKEY_size(lpub->evp);
	if (ret <= 0) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		ERROR_DUMP(ret);
		goto err_ctx;
	}

	pub_key_length = ret;
	lkey = yaca_zalloc(sizeof(struct yaca_key_simple_s) + pub_key_length);
	if (lkey == NULL) {
		ret = YACA_ERROR_OUT_OF_MEMORY;
		goto err_ctx;
	}

	ret = encrypt_get_algorithm(algo, bcm, sym_key_bits, &cipher);
	if (ret != 0)
		goto err_key;

	ret = EVP_CIPHER_iv_length(cipher);
	if (ret < 0) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		ERROR_DUMP(ret);
		goto err_key;
	}

	iv_length = ret;
	liv = yaca_zalloc(sizeof(struct yaca_key_simple_s) + iv_length);
	if (liv == NULL) {
		ret = YACA_ERROR_OUT_OF_MEMORY;
		goto err_key;
	}

	unsigned char *key_data = (unsigned char*)lkey->d;
	int key_data_length;

	ret = EVP_SealInit(nc->cipher_ctx,
	                   cipher,
	                   &key_data,
	                   &key_data_length,
	                   (unsigned char*)liv->d,
	                   &lpub->evp,
	                   1);

	if (ret != 1) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		ERROR_DUMP(ret);
		goto err_iv;
	}

	lkey->bits = key_data_length * 8;
	lkey->key.type = YACA_KEY_TYPE_SYMMETRIC;
	*sym_key = (yaca_key_h)lkey;

	liv->bits = iv_length * 8;
	liv->key.type = YACA_KEY_TYPE_IV;
	*iv = (yaca_key_h)liv;

	*ctx = (yaca_ctx_h)nc;

	return 0;

err_iv:
	yaca_free(liv);
err_key:
	yaca_free(lkey);
err_ctx:
	EVP_CIPHER_CTX_free(nc->cipher_ctx);
err_free:
	yaca_free(nc);
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
	int iv_bits;
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

	nc = yaca_zalloc(sizeof(struct yaca_seal_ctx_s));
	if (nc == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	nc->ctx.type = YACA_CTX_SEAL;
	nc->ctx.ctx_destroy = destroy_seal_ctx;
	nc->ctx.get_output_length = get_seal_output_length;
	nc->op_type = OP_OPEN;

	ret = encrypt_get_algorithm(algo, bcm, sym_key_bits, &cipher);
	if (ret != 0)
		goto err_free;

	ret = EVP_CIPHER_iv_length(cipher);
	if (ret < 0) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		ERROR_DUMP(ret);
		goto err_free;
	}

	iv_bits = ret * 8;
	if (iv_bits == 0 && iv != NULL) { /* 0 -> cipher doesn't use iv, but it was provided */
		ret = YACA_ERROR_INVALID_ARGUMENT;
		goto err_free;
	}

	liv = key_get_simple(iv);
	/* cipher requires iv, but none was provided, or provided wrong iv */
	if (iv_bits != 0 && (liv == NULL || liv->key.type != YACA_KEY_TYPE_IV)) {
		ret = YACA_ERROR_INVALID_ARGUMENT;
		goto err_free;
	}

	// TODO: handling of algorithms with variable IV length
	if (iv_bits != yaca_key_get_bits(iv)) { /* IV length doesn't match cipher */
		ret = YACA_ERROR_INVALID_ARGUMENT;
		goto err_free;
	}

	nc->cipher_ctx = EVP_CIPHER_CTX_new();
	if (nc->cipher_ctx == NULL) {
		ret =  YACA_ERROR_OPENSSL_FAILURE;
		ERROR_DUMP(ret);
		goto err_free;
	}

	ret = EVP_OpenInit(nc->cipher_ctx, cipher,
	                   (unsigned char*)lkey->d,
	                   EVP_PKEY_size(lprv->evp),
	                   (unsigned char*)liv->d,
	                   lprv->evp);
	if (ret != 1) {
		ret = YACA_ERROR_OPENSSL_FAILURE;
		ERROR_DUMP(ret);
		goto err_ctx;
	}

	*ctx = (yaca_ctx_h)nc;
	return 0;

err_ctx:
	EVP_CIPHER_CTX_free(nc->cipher_ctx);
err_free:
	yaca_free(nc);
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
		ret = YACA_ERROR_OPENSSL_FAILURE;
		ERROR_DUMP(ret);
		return ret;
	}

	return 0;
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
		ret = YACA_ERROR_OPENSSL_FAILURE;
		ERROR_DUMP(ret);
		return ret;
	}

	return 0;
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
