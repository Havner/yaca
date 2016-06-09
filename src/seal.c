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

API int yaca_seal_initialize(yaca_context_h *ctx,
                             const yaca_key_h pub_key,
                             yaca_encrypt_algorithm_e algo,
                             yaca_block_cipher_mode_e bcm,
                             size_t sym_key_bit_len,
                             yaca_key_h *sym_key,
                             yaca_key_h *iv)
{
	struct yaca_key_evp_s *lpub;
	struct yaca_key_simple_s *lkey = NULL;
	struct yaca_key_simple_s *liv = NULL;
	struct yaca_encrypt_context_s *nc;
	const EVP_CIPHER *cipher;
	int pub_key_length;
	unsigned char *key_data = NULL;
	int key_data_length;
	unsigned char *iv_data = NULL;
	int iv_length;
	int ret;

	if (ctx == NULL || pub_key == YACA_KEY_NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	if (pub_key->type != YACA_KEY_TYPE_RSA_PUB)
		return YACA_ERROR_INVALID_PARAMETER;
	lpub = key_get_evp(pub_key);
	assert(lpub);

	ret = yaca_zalloc(sizeof(struct yaca_encrypt_context_s), (void**)&nc);
	if (ret != YACA_ERROR_NONE)
		return ret;

	nc->ctx.type = YACA_CTX_ENCRYPT;
	nc->ctx.ctx_destroy = destroy_encrypt_context;
	nc->ctx.get_output_length = get_encrypt_output_length;
	nc->ctx.set_param = set_encrypt_property;
	nc->ctx.get_param = get_encrypt_property;
	nc->op_type = OP_SEAL;
	nc->tag_len = 0;

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

	ret = encrypt_get_algorithm(algo, bcm, sym_key_bit_len, &cipher);
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
	*ctx = (yaca_context_h)nc;
	nc = NULL;
	ret = YACA_ERROR_NONE;

exit:
	yaca_free(liv);
	yaca_free(lkey);
	yaca_context_destroy((yaca_context_h)nc);

	return ret;
}

API int yaca_seal_update(yaca_context_h ctx,
                         const char *plaintext,
                         size_t plaintext_len,
                         char *ciphertext,
                         size_t *ciphertext_len)
{
	return encrypt_update(ctx, (const unsigned char*)plaintext,  plaintext_len,
	                      (unsigned char*)ciphertext, ciphertext_len, OP_SEAL);
}

API int yaca_seal_finalize(yaca_context_h ctx,
                           char *ciphertext,
                           size_t *ciphertext_len)
{
	return encrypt_finalize(ctx, (unsigned char*)ciphertext, ciphertext_len, OP_SEAL);
}

API int yaca_open_initialize(yaca_context_h *ctx,
                             const yaca_key_h prv_key,
                             yaca_encrypt_algorithm_e algo,
                             yaca_block_cipher_mode_e bcm,
                             size_t sym_key_bit_len,
                             const yaca_key_h sym_key,
                             const yaca_key_h iv)
{
	const struct yaca_key_evp_s *lprv;
	const struct yaca_key_simple_s *lkey;
	const struct yaca_key_simple_s *liv;
	struct yaca_encrypt_context_s *nc;
	const EVP_CIPHER *cipher;
	unsigned char *iv_data = NULL;
	size_t iv_bits;
	size_t iv_bits_check;
	int ret;

	if (ctx == NULL || prv_key == YACA_KEY_NULL || sym_key == YACA_KEY_NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	if (prv_key->type != YACA_KEY_TYPE_RSA_PRIV)
		return YACA_ERROR_INVALID_PARAMETER;
	lprv = key_get_evp(prv_key);
	assert(lprv);

	lkey = key_get_simple(sym_key);
	if (lkey == NULL || lkey->key.type != YACA_KEY_TYPE_SYMMETRIC)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_zalloc(sizeof(struct yaca_encrypt_context_s), (void**)&nc);
	if (ret != YACA_ERROR_NONE)
		return ret;

	nc->ctx.type = YACA_CTX_ENCRYPT;
	nc->ctx.ctx_destroy = destroy_encrypt_context;
	nc->ctx.get_output_length = get_encrypt_output_length;
	nc->ctx.set_param = set_encrypt_property;
	nc->ctx.get_param = get_encrypt_property;
	nc->op_type = OP_OPEN;
	nc->tag_len = 0;

	ret = encrypt_get_algorithm(algo, bcm, sym_key_bit_len, &cipher);
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
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	if (iv_bits > 0) { /* cipher requires iv*/
		liv = key_get_simple(iv);
		if (liv == NULL || liv->key.type != YACA_KEY_TYPE_IV) { /* iv was not provided */
			ret = YACA_ERROR_INVALID_PARAMETER;
			goto exit;
		}
		ret = yaca_key_get_bit_length(iv, &iv_bits_check);
		if (ret != YACA_ERROR_NONE) {
			ret = YACA_ERROR_INVALID_PARAMETER;
			goto exit;
		}
		/* IV length doesn't match cipher */
		if (iv_bits != iv_bits_check) {
			ret = YACA_ERROR_INVALID_PARAMETER;
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

	*ctx = (yaca_context_h)nc;
	nc = NULL;
	ret = YACA_ERROR_NONE;

exit:
	yaca_context_destroy((yaca_context_h)nc);

	return ret;
}

API int yaca_open_update(yaca_context_h ctx,
                         const char *ciphertext,
                         size_t ciphertext_len,
                         char *plaintext,
                         size_t *plaintext_len)
{
	return encrypt_update(ctx, (const unsigned char*)ciphertext, ciphertext_len,
	                      (unsigned char*)plaintext, plaintext_len, OP_OPEN);
}

API int yaca_open_finalize(yaca_context_h ctx,
                           char *plaintext,
                           size_t *plaintext_len)
{
	return encrypt_finalize(ctx, (unsigned char*)plaintext, plaintext_len, OP_OPEN);
}
