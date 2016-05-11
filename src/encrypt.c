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
#include <yaca/encrypt.h>
#include <yaca/error.h>
#include <yaca/key.h>

#include "internal.h"

enum encrypt_op_type {
	OP_ENCRYPT = 0,
	OP_DECRYPT = 1
};

struct yaca_encrypt_ctx_s
{
	struct yaca_ctx_s ctx;

	EVP_CIPHER_CTX *cipher_ctx;
	enum encrypt_op_type op_type; /* Operation context was created for */
};

static struct yaca_encrypt_ctx_s *get_encrypt_ctx(const yaca_ctx_h ctx)
{
	if (ctx == YACA_CTX_NULL)
		return NULL;

	switch (ctx->type)
	{
	case YACA_CTX_ENCRYPT:
		return (struct yaca_encrypt_ctx_s *)ctx;
	default:
		return NULL;
	}
}

static void destroy_encrypt_ctx(const yaca_ctx_h ctx)
{
	struct yaca_encrypt_ctx_s *nc = get_encrypt_ctx(ctx);

	if (nc == NULL)
		return;

	EVP_CIPHER_CTX_free(nc->cipher_ctx);
	nc->cipher_ctx = NULL;
}

static int get_encrypt_output_length(const yaca_ctx_h ctx, size_t input_len)
{
	struct yaca_encrypt_ctx_s *nc = get_encrypt_ctx(ctx);
	int block_size;

	if (nc == NULL || nc->cipher_ctx == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	block_size = EVP_CIPHER_CTX_block_size(nc->cipher_ctx);
	if (block_size == 0) {
		ERROR_DUMP(YACA_ERROR_INTERNAL);
		return YACA_ERROR_INTERNAL;
	}

	if (input_len > 0)
		return block_size + input_len - 1;
	return block_size;
}

static const char *encrypt_algo_to_str(yaca_enc_algo_e algo)
{
	switch(algo)
	{
	case YACA_ENC_AES:
		return "aes";
	case YACA_ENC_UNSAFE_DES:
		return "des";
	case YACA_ENC_UNSAFE_3DES_2TDEA:
		return "des-ede";
	case YACA_ENC_3DES_3TDEA:
		return "des-ede3";
	case YACA_ENC_UNSAFE_RC2:
		return "rc2";
	case YACA_ENC_UNSAFE_RC4:
		return "rc4";
	case YACA_ENC_CAST5:
		return "cast5";

	case YACA_ENC_UNSAFE_SKIPJACK:  // TODO: add skipjack implementation
	default:
		return NULL;
	}
}

static const char *bcm_to_str(yaca_block_cipher_mode_e bcm)
{
	switch (bcm) {
	case YACA_BCM_NONE:
		return "none";
	case YACA_BCM_ECB:
		return "ecb";
	case YACA_BCM_CBC:
		return "cbc";
	case YACA_BCM_CTR:
		return "ctr";
	case YACA_BCM_GCM:
		return "gcm";
	case YACA_BCM_CFB:
		return "cfb";
	case YACA_BCM_OFB:
		return "ofb";
	case YACA_BCM_OCB:
		return "ocb";
	case YACA_BCM_CCM:
		return "ccm";
	default:
		return NULL;
	}
}

int encrypt_get_algorithm(yaca_enc_algo_e algo,
			  yaca_block_cipher_mode_e bcm,
			  size_t key_bits,
			  const EVP_CIPHER **cipher)
{
	char cipher_name[32];
	const char *algo_name = encrypt_algo_to_str(algo);
	const char *bcm_name = bcm_to_str(bcm);
	const EVP_CIPHER *lcipher;
	int ret;

	if (algo_name == NULL || bcm_name == NULL || key_bits == 0 ||
	    cipher == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	switch(algo)
	{
	case YACA_ENC_AES:
		ret = snprintf(cipher_name, sizeof(cipher_name), "%s-%zu-%s",
		               algo_name, key_bits, bcm_name);
		break;
	case YACA_ENC_UNSAFE_DES:
	case YACA_ENC_UNSAFE_RC2:
	case YACA_ENC_CAST5:
		ret = snprintf(cipher_name, sizeof(cipher_name), "%s-%s",
		               algo_name, bcm_name);
		break;
	case YACA_ENC_UNSAFE_3DES_2TDEA:
	case YACA_ENC_3DES_3TDEA:
		if (bcm == YACA_BCM_ECB)
			ret = snprintf(cipher_name, sizeof(cipher_name), "%s", algo_name);
		else
			ret = snprintf(cipher_name, sizeof(cipher_name), "%s-%s",
			               algo_name, bcm_name);
		break;
	case YACA_ENC_UNSAFE_RC4:
		ret = snprintf(cipher_name, sizeof(cipher_name), "%s", algo_name);
		break;
	case YACA_ENC_UNSAFE_SKIPJACK:
	default:
		return YACA_ERROR_NOT_IMPLEMENTED;
	}

	if (ret < 0)
		return YACA_ERROR_INVALID_ARGUMENT;
	if ((unsigned)ret >= sizeof(cipher_name)) // output was truncated
		return YACA_ERROR_INVALID_ARGUMENT;

	lcipher = EVP_get_cipherbyname(cipher_name);
	if (lcipher == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	*cipher = lcipher;
	return 0;
}

static int encrypt_init(yaca_ctx_h *ctx,
			yaca_enc_algo_e algo,
			yaca_block_cipher_mode_e bcm,
			const yaca_key_h sym_key,
			const yaca_key_h iv,
			enum encrypt_op_type op_type)
{
	const struct yaca_key_simple_s *lkey;
	const struct yaca_key_simple_s *liv;
	struct yaca_encrypt_ctx_s *nc;
	const EVP_CIPHER *cipher;
	int key_bits;
	unsigned char *iv_data = NULL;
	int iv_bits;
	int ret;

	if (ctx == NULL || sym_key == YACA_KEY_NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	lkey = key_get_simple(sym_key);
	if (lkey == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	nc = yaca_zalloc(sizeof(struct yaca_encrypt_ctx_s));
	if (nc == NULL)
		return YACA_ERROR_OUT_OF_MEMORY;

	nc->ctx.type = YACA_CTX_ENCRYPT;
	nc->ctx.ctx_destroy = destroy_encrypt_ctx;
	nc->ctx.get_output_length = get_encrypt_output_length;
	nc->op_type = op_type;

	ret = yaca_key_get_bits(sym_key);
	if (ret < 0)
		goto err_free;
	key_bits = ret;

	ret = encrypt_get_algorithm(algo, bcm, key_bits, &cipher);
	if (ret != 0)
		goto err_free;

	ret = EVP_CIPHER_iv_length(cipher);
	if (ret < 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto err_free;
	}

	iv_bits = ret * 8;
	if (iv_bits == 0 && iv != NULL) { /* 0 -> cipher doesn't use iv, but it was provided */
		ret = YACA_ERROR_INVALID_ARGUMENT;
		goto err_free;
	}

	if (iv_bits != 0) { /* cipher requires iv*/
		liv = key_get_simple(iv);
		if (liv == NULL) { /* iv was not provided */
			ret = YACA_ERROR_INVALID_ARGUMENT;
			goto err_free;
		}
		if (iv_bits != yaca_key_get_bits(iv)) { /* IV length doesn't match cipher */
			ret = YACA_ERROR_INVALID_ARGUMENT;
			goto err_free;
		}
		iv_data = (unsigned char*)liv->d;
	}

	nc->cipher_ctx = EVP_CIPHER_CTX_new();
	if (nc->cipher_ctx == NULL) {
		ret =  YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto err_free;
	}

	switch (op_type) {
	case OP_ENCRYPT:
		ret = EVP_EncryptInit_ex(nc->cipher_ctx, cipher, NULL, NULL, NULL);
		if (ret != 1)
			break;

		/* Handling of algorithms with variable key length */
		ret = EVP_CIPHER_CTX_set_key_length(nc->cipher_ctx, key_bits / 8);
		if (ret != 1) {
			ret = YACA_ERROR_INVALID_ARGUMENT;
			ERROR_DUMP(ret);
			goto err_ctx;
		}

		ret = EVP_EncryptInit_ex(nc->cipher_ctx, NULL, NULL,
		                         (unsigned char*)lkey->d,
		                         iv_data);

		break;
	case OP_DECRYPT:
		ret = EVP_DecryptInit_ex(nc->cipher_ctx, cipher, NULL, NULL, NULL);
		if (ret != 1)
			break;

		/* Handling of algorithms with variable key length */
		ret = EVP_CIPHER_CTX_set_key_length(nc->cipher_ctx, key_bits / 8);
		if (ret != 1) {
			ret = YACA_ERROR_INVALID_ARGUMENT;
			ERROR_DUMP(ret);
			goto err_ctx;
		}

		ret = EVP_DecryptInit_ex(nc->cipher_ctx, NULL, NULL,
		                         (unsigned char*)lkey->d,
		                         iv_data);

		break;
	default:
		ret = YACA_ERROR_INVALID_ARGUMENT;
		goto err_ctx;
	}

	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
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

static int encrypt_update(yaca_ctx_h ctx,
			  const unsigned char *input,
			  size_t input_len,
			  unsigned char *output,
			  size_t *output_len,
			  enum encrypt_op_type op_type)
{
	struct yaca_encrypt_ctx_s *c = get_encrypt_ctx(ctx);
	int ret;
	int loutput_len;

	if (c == NULL || input == NULL || input_len == 0 ||
	    output == NULL || output_len == NULL || op_type != c->op_type)
		return YACA_ERROR_INVALID_ARGUMENT;

	loutput_len = *output_len;

	switch (op_type) {
	case OP_ENCRYPT:
		ret = EVP_EncryptUpdate(c->cipher_ctx, output, &loutput_len,
					input, input_len);
		break;
	case OP_DECRYPT:
		ret = EVP_DecryptUpdate(c->cipher_ctx, output, &loutput_len,
					input, input_len);
		break;
	default:
		return YACA_ERROR_INVALID_ARGUMENT;
	}

	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	*output_len = loutput_len;
	return 0;
}

static int encrypt_final(yaca_ctx_h ctx,
			 unsigned char *output,
			 size_t *output_len,
			 enum encrypt_op_type op_type)
{
	struct yaca_encrypt_ctx_s *c = get_encrypt_ctx(ctx);
	int ret;
	int loutput_len;

	if (c == NULL || output == NULL || output_len == NULL ||
	    op_type != c->op_type)
		return YACA_ERROR_INVALID_ARGUMENT;

	loutput_len = *output_len;

	switch (op_type) {
	case OP_ENCRYPT:
		ret = EVP_EncryptFinal(c->cipher_ctx, output, &loutput_len);
		break;
	case OP_DECRYPT:
		ret = EVP_DecryptFinal(c->cipher_ctx, output, &loutput_len);
		break;
	default:
		return YACA_ERROR_INVALID_ARGUMENT;
	}

	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	*output_len = loutput_len;
	return 0;
}

API int yaca_get_iv_bits(yaca_enc_algo_e algo,
			 yaca_block_cipher_mode_e bcm,
			 size_t key_bits)
{
	const EVP_CIPHER *cipher;
	int ret;

	ret = encrypt_get_algorithm(algo, bcm, key_bits, &cipher);
	if (ret < 0)
		return ret;

	return EVP_CIPHER_iv_length(cipher) * 8;
}

API int yaca_encrypt_init(yaca_ctx_h *ctx,
			  yaca_enc_algo_e algo,
			  yaca_block_cipher_mode_e bcm,
			  const yaca_key_h sym_key,
			  const yaca_key_h iv)
{
	return encrypt_init(ctx, algo, bcm, sym_key, iv, OP_ENCRYPT);
}

API int yaca_encrypt_update(yaca_ctx_h ctx,
			    const char *plain,
			    size_t plain_len,
			    char *cipher,
			    size_t *cipher_len)
{
	return encrypt_update(ctx, (const unsigned char*)plain, plain_len,
			      (unsigned char*)cipher, cipher_len, OP_ENCRYPT);
}

API int yaca_encrypt_final(yaca_ctx_h ctx,
			   char *cipher,
			   size_t *cipher_len)
{
	return encrypt_final(ctx, (unsigned char*)cipher,
			     cipher_len, OP_ENCRYPT);
}

API int yaca_decrypt_init(yaca_ctx_h *ctx,
			  yaca_enc_algo_e algo,
			  yaca_block_cipher_mode_e bcm,
			  const yaca_key_h sym_key,
			  const yaca_key_h iv)
{
	return encrypt_init(ctx, algo, bcm, sym_key, iv, OP_DECRYPT);
}

API int yaca_decrypt_update(yaca_ctx_h ctx,
			    const char *cipher,
			    size_t cipher_len,
			    char *plain,
			    size_t *plain_len)
{
	return encrypt_update(ctx, (const unsigned char*)cipher, cipher_len,
			      (unsigned char*)plain, plain_len, OP_DECRYPT);
}

API int yaca_decrypt_final(yaca_ctx_h ctx,
			   char *plain,
			   size_t *plain_len)
{
	return encrypt_final(ctx,(unsigned char*)plain, plain_len,
			     OP_DECRYPT);
}
