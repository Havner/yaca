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
 * @file encrypt.c
 * @brief
 */

#include <assert.h>
#include <stdint.h>

#include <openssl/evp.h>

#include <yaca_crypto.h>
#include <yaca_encrypt.h>
#include <yaca_error.h>
#include <yaca_key.h>

#include "internal.h"

struct yaca_encrypt_context_s *get_encrypt_context(const yaca_context_h ctx)
{
	if (ctx == YACA_CONTEXT_NULL)
		return NULL;

	switch (ctx->type) {
	case YACA_CONTEXT_ENCRYPT:
		return (struct yaca_encrypt_context_s *)ctx;
	default:
		return NULL;
	}
}

void destroy_encrypt_context(const yaca_context_h ctx)
{
	struct yaca_encrypt_context_s *nc = get_encrypt_context(ctx);

	if (nc == NULL)
		return;

	EVP_CIPHER_CTX_free(nc->cipher_ctx);
	nc->cipher_ctx = NULL;
}

int get_encrypt_output_length(const yaca_context_h ctx, size_t input_len, size_t *output_len)
{
	assert(output_len != NULL);

	struct yaca_encrypt_context_s *nc = get_encrypt_context(ctx);
	int block_size;

	if (nc == NULL)
		return YACA_ERROR_INVALID_PARAMETER;
	assert(nc->cipher_ctx != NULL);

	block_size = EVP_CIPHER_CTX_block_size(nc->cipher_ctx);
	if (block_size <= 0) {
		ERROR_DUMP(YACA_ERROR_INTERNAL);
		return YACA_ERROR_INTERNAL;
	}

	if (input_len > 0) {
		if ((size_t)block_size > SIZE_MAX - input_len + 1)
			return YACA_ERROR_INVALID_PARAMETER;

		*output_len = block_size + input_len - 1;
	} else {
		*output_len = block_size;
	}
	if (*output_len == 0)
		return YACA_ERROR_INTERNAL;

	return YACA_ERROR_NONE;
}

int set_encrypt_property(yaca_context_h ctx, yaca_property_e property,
                         const void *value, size_t value_len)
{
	struct yaca_encrypt_context_s *c = get_encrypt_context(ctx);
	int len;

	if (c == NULL || value == NULL)
		return YACA_ERROR_INVALID_PARAMETER;
	assert(c->cipher_ctx != NULL);

	switch (property) {
	case YACA_PROPERTY_GCM_AAD:
	case YACA_PROPERTY_CCM_AAD:
		if (c->op_type == OP_ENCRYPT) {
			if (EVP_EncryptUpdate(c->cipher_ctx, NULL, &len, value, value_len) != 1) {
				ERROR_DUMP(YACA_ERROR_INTERNAL);
				return YACA_ERROR_INTERNAL;
			}
		}
		if (c->op_type == OP_DECRYPT) {
			if (EVP_DecryptUpdate(c->cipher_ctx, NULL, &len, value, value_len) != 1) {
				ERROR_DUMP(YACA_ERROR_INTERNAL);
				return YACA_ERROR_INTERNAL;
			}
		}
		if (c->op_type == OP_SEAL) {
			if (EVP_SealUpdate(c->cipher_ctx, NULL, &len, value, value_len) != 1) {
				ERROR_DUMP(YACA_ERROR_INTERNAL);
				return YACA_ERROR_INTERNAL;
			}
		}
		if (c->op_type == OP_OPEN) {
			if (EVP_OpenUpdate(c->cipher_ctx, NULL, &len, value, value_len) != 1) {
				ERROR_DUMP(YACA_ERROR_INTERNAL);
				return YACA_ERROR_INTERNAL;
			}
		}
		break;
	case YACA_PROPERTY_GCM_TAG:
		if (EVP_CIPHER_CTX_ctrl(c->cipher_ctx,
		                        EVP_CTRL_GCM_SET_TAG,
		                        value_len, (void*)value) != 1) {
			ERROR_DUMP(YACA_ERROR_INTERNAL);
			return YACA_ERROR_INTERNAL;
		}
		break;
	case YACA_PROPERTY_GCM_TAG_LEN:
		c->tag_len = *(int*)value;
		break;
	case YACA_PROPERTY_CCM_TAG:
		// TODO Rebuild context
		if (EVP_CIPHER_CTX_ctrl(c->cipher_ctx,
		                        EVP_CTRL_CCM_SET_TAG,
		                        value_len, (void*)value) != 1) {
			ERROR_DUMP(YACA_ERROR_INTERNAL);
			return YACA_ERROR_INTERNAL;
		}
		break;
	case YACA_PROPERTY_CCM_TAG_LEN:
		//TODO Rebuild context
		if (EVP_CIPHER_CTX_ctrl(c->cipher_ctx,
		                        EVP_CTRL_CCM_SET_TAG,
		                        value_len, NULL) != 1) {
			ERROR_DUMP(YACA_ERROR_INTERNAL);
			return YACA_ERROR_INTERNAL;
		}
		c->tag_len = *(int*)value;
		break;
	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}

	return YACA_ERROR_NONE;
}

int get_encrypt_property(const yaca_context_h ctx, yaca_property_e property,
                         void **value, size_t *value_len)
{
	struct yaca_encrypt_context_s *c = get_encrypt_context(ctx);

	if (c == NULL || value == NULL)
		return YACA_ERROR_INVALID_PARAMETER;
	assert(c->cipher_ctx != NULL);

	switch (property) {
	case YACA_PROPERTY_GCM_TAG:
		if (c->tag_len == 0 || value_len == 0)
			return YACA_ERROR_INVALID_PARAMETER;

		if (EVP_CIPHER_CTX_ctrl(c->cipher_ctx,
		                        EVP_CTRL_GCM_GET_TAG,
		                        c->tag_len, value) != 1) {
			ERROR_DUMP(YACA_ERROR_INTERNAL);
			return YACA_ERROR_INTERNAL;
		}
		*value_len = c->tag_len;
		break;
	case YACA_PROPERTY_CCM_TAG:
		if (c->tag_len == 0 || value_len == 0)
			return YACA_ERROR_INVALID_PARAMETER;

		if (EVP_CIPHER_CTX_ctrl(c->cipher_ctx,
		                        EVP_CTRL_CCM_GET_TAG,
		                        c->tag_len, value) != 1) {
			ERROR_DUMP(YACA_ERROR_INTERNAL);
			return YACA_ERROR_INTERNAL;
		}
		*value_len = c->tag_len;
		break;
	default:
		return YACA_ERROR_INVALID_PARAMETER;
		break;
	}

	return YACA_ERROR_NONE;
}

static const char *encrypt_algo_to_str(yaca_encrypt_algorithm_e algo)
{
	switch (algo) {
	case YACA_ENCRYPT_AES:
		return "aes";
	case YACA_ENCRYPT_UNSAFE_DES:
		return "des";
	case YACA_ENCRYPT_UNSAFE_3DES_2TDEA:
		return "des-ede";
	case YACA_ENCRYPT_3DES_3TDEA:
		return "des-ede3";
	case YACA_ENCRYPT_UNSAFE_RC2:
		return "rc2";
	case YACA_ENCRYPT_UNSAFE_RC4:
		return "rc4";
	case YACA_ENCRYPT_CAST5:
		return "cast5";
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
	case YACA_BCM_CFB1:
		return "cfb1";
	case YACA_BCM_CFB8:
		return "cfb8";
	case YACA_BCM_OFB:
		return "ofb";
	case YACA_BCM_CCM:
		return "ccm";
	default:
		return NULL;
	}
}

int encrypt_get_algorithm(yaca_encrypt_algorithm_e algo,
                          yaca_block_cipher_mode_e bcm,
                          size_t key_bit_len,
                          const EVP_CIPHER **cipher)
{
	char cipher_name[32];
	const char *algo_name = encrypt_algo_to_str(algo);
	const char *bcm_name = bcm_to_str(bcm);
	const EVP_CIPHER *lcipher;
	int ret;

	if (algo_name == NULL || bcm_name == NULL || key_bit_len == 0 || cipher == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	switch (algo) {
	case YACA_ENCRYPT_AES:
		ret = snprintf(cipher_name, sizeof(cipher_name), "%s-%zu-%s",
		               algo_name, key_bit_len, bcm_name);
		break;
	case YACA_ENCRYPT_UNSAFE_DES:
	case YACA_ENCRYPT_UNSAFE_RC2:
	case YACA_ENCRYPT_CAST5:
		ret = snprintf(cipher_name, sizeof(cipher_name), "%s-%s",
		               algo_name, bcm_name);
		break;
	case YACA_ENCRYPT_UNSAFE_3DES_2TDEA:
	case YACA_ENCRYPT_3DES_3TDEA:
		if (bcm == YACA_BCM_ECB)
			ret = snprintf(cipher_name, sizeof(cipher_name), "%s", algo_name);
		else
			ret = snprintf(cipher_name, sizeof(cipher_name), "%s-%s",
			               algo_name, bcm_name);
		break;
	case YACA_ENCRYPT_UNSAFE_RC4:
		if (bcm != YACA_BCM_NONE)
			ret = YACA_ERROR_INVALID_PARAMETER;
		else
			ret = snprintf(cipher_name, sizeof(cipher_name), "%s", algo_name);
		break;
	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}

	if (ret < 0)
		return YACA_ERROR_INVALID_PARAMETER;
	if ((unsigned)ret >= sizeof(cipher_name)) /* output was truncated */
		return YACA_ERROR_INVALID_PARAMETER;

	lcipher = EVP_get_cipherbyname(cipher_name);
	if (lcipher == NULL) {
		ret = YACA_ERROR_INVALID_PARAMETER;
		ERROR_CLEAR();
		return ret;
	}

	*cipher = lcipher;
	return YACA_ERROR_NONE;
}

static int encrypt_initialize(yaca_context_h *ctx,
                              yaca_encrypt_algorithm_e algo,
                              yaca_block_cipher_mode_e bcm,
                              const yaca_key_h sym_key,
                              const yaca_key_h iv,
                              enum encrypt_op_type_e op_type)
{
	const struct yaca_key_simple_s *lkey;
	const struct yaca_key_simple_s *liv;
	struct yaca_encrypt_context_s *nc;
	const EVP_CIPHER *cipher;
	size_t key_bit_len;
	unsigned char *iv_data = NULL;
	size_t iv_bit_len;
	size_t iv_bit_len_check;
	int ret;

	if (ctx == NULL || sym_key == YACA_KEY_NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	lkey = key_get_simple(sym_key);
	if (lkey == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_zalloc(sizeof(struct yaca_encrypt_context_s), (void**)&nc);
	if (ret != YACA_ERROR_NONE)
		return ret;

	nc->ctx.type = YACA_CONTEXT_ENCRYPT;
	nc->ctx.context_destroy = destroy_encrypt_context;
	nc->ctx.get_output_length = get_encrypt_output_length;
	nc->ctx.set_property = set_encrypt_property;
	nc->ctx.get_property = get_encrypt_property;
	nc->op_type = op_type;
	nc->tag_len = 0;

	ret = yaca_key_get_bit_length(sym_key, &key_bit_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = encrypt_get_algorithm(algo, bcm, key_bit_len, &cipher);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = EVP_CIPHER_iv_length(cipher);
	if (ret < 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	iv_bit_len = ret * 8;
	if (iv_bit_len == 0 && iv != NULL) { /* 0 -> cipher doesn't use iv, but it was provided */
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	if (iv_bit_len != 0) { /* cipher requires iv*/
		liv = key_get_simple(iv);
		if (liv == NULL) { /* iv was not provided */
			ret = YACA_ERROR_INVALID_PARAMETER;
			goto exit;
		}
		ret = yaca_key_get_bit_length(iv, &iv_bit_len_check);
		if (ret != YACA_ERROR_NONE) {
			ret = YACA_ERROR_INVALID_PARAMETER;
			goto exit;
		}
		/* IV length doesn't match cipher (GCM & CCM supports variable IV length) */
		if (iv_bit_len != iv_bit_len_check &&
		    bcm != YACA_BCM_GCM &&
		    bcm != YACA_BCM_CCM) {
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

	switch (op_type) {
	case OP_ENCRYPT:
		ret = EVP_EncryptInit_ex(nc->cipher_ctx, cipher, NULL, NULL, NULL);
		break;
	case OP_DECRYPT:
		ret = EVP_DecryptInit_ex(nc->cipher_ctx, cipher, NULL, NULL, NULL);
		break;
	default:
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	/* Handling of algorithms with variable key length */
	ret = EVP_CIPHER_CTX_set_key_length(nc->cipher_ctx, key_bit_len / 8);
	if (ret != 1) {
		ret = YACA_ERROR_INVALID_PARAMETER;
		ERROR_DUMP(ret);
		goto exit;
	}

	/* Handling of algorithms with variable IV length */
	if (iv_bit_len != iv_bit_len_check) {
		if (bcm == YACA_BCM_GCM)
			ret = EVP_CIPHER_CTX_ctrl(nc->cipher_ctx, EVP_CTRL_GCM_SET_IVLEN,
			                          iv_bit_len_check / 8, NULL);

		if (bcm == YACA_BCM_CCM)
			ret = EVP_CIPHER_CTX_ctrl(nc->cipher_ctx, EVP_CTRL_CCM_SET_IVLEN,
			                          iv_bit_len_check / 8, NULL);

		if (ret != 1) {
			ret = YACA_ERROR_INVALID_PARAMETER;
			ERROR_DUMP(ret);
			goto exit;
		}
	}

	switch (op_type) {
	case OP_ENCRYPT:
		ret = EVP_EncryptInit_ex(nc->cipher_ctx, NULL, NULL,
		                         (unsigned char*)lkey->d,
		                         iv_data);
		break;
	case OP_DECRYPT:
		ret = EVP_DecryptInit_ex(nc->cipher_ctx, NULL, NULL,
		                         (unsigned char*)lkey->d,
		                         iv_data);
		break;
	default:
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

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

int encrypt_update(yaca_context_h ctx,
                   const unsigned char *input, size_t input_len,
                   unsigned char *output, size_t *output_len,
                   enum encrypt_op_type_e op_type)
{
	struct yaca_encrypt_context_s *c = get_encrypt_context(ctx);
	int ret;
	int loutput_len;

	if (c == NULL || input_len == 0 || output_len == NULL || op_type != c->op_type)
		return YACA_ERROR_INVALID_PARAMETER;

	if (EVP_CIPHER_CTX_mode(c->cipher_ctx) != EVP_CIPH_CCM_MODE)
		if (input == NULL || output == NULL)
			return YACA_ERROR_INVALID_PARAMETER;

	switch (op_type) {
	case OP_ENCRYPT:
		ret = EVP_EncryptUpdate(c->cipher_ctx, output, &loutput_len, input, input_len);
		break;
	case OP_SEAL:
		ret = EVP_SealUpdate(c->cipher_ctx, output, &loutput_len, input, input_len);
		break;
	case OP_DECRYPT:
		ret = EVP_DecryptUpdate(c->cipher_ctx, output, &loutput_len, input, input_len);
		break;
	case OP_OPEN:
		ret = EVP_OpenUpdate(c->cipher_ctx, output, &loutput_len, input, input_len);
		break;
	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}

	if (ret != 1 || loutput_len < 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	*output_len = loutput_len;
	return YACA_ERROR_NONE;
}

int encrypt_finalize(yaca_context_h ctx,
                     unsigned char *output, size_t *output_len,
                     enum encrypt_op_type_e op_type)
{
	struct yaca_encrypt_context_s *c = get_encrypt_context(ctx);
	int ret;
	int loutput_len;

	if (c == NULL || output == NULL || output_len == NULL || op_type != c->op_type)
		return YACA_ERROR_INVALID_PARAMETER;

	switch (op_type) {
	case OP_ENCRYPT:
		ret = EVP_EncryptFinal(c->cipher_ctx, output, &loutput_len);
		break;
	case OP_DECRYPT:
		ret = EVP_DecryptFinal(c->cipher_ctx, output, &loutput_len);
		break;
	case OP_SEAL:
		ret = EVP_SealFinal(c->cipher_ctx, output, &loutput_len);
		break;
	case OP_OPEN:
		ret = EVP_OpenFinal(c->cipher_ctx, output, &loutput_len);
		break;
	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}

	if (ret != 1 || loutput_len < 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	*output_len = loutput_len;
	return YACA_ERROR_NONE;
}

API int yaca_encrypt_get_iv_bit_length(yaca_encrypt_algorithm_e algo,
                                       yaca_block_cipher_mode_e bcm,
                                       size_t key_bit_len,
                                       size_t *iv_bit_len)
{
	const EVP_CIPHER *cipher;
	int ret;

	if(iv_bit_len == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = encrypt_get_algorithm(algo, bcm, key_bit_len, &cipher);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = EVP_CIPHER_iv_length(cipher);
	if (ret < 0) {
		ERROR_DUMP(YACA_ERROR_INTERNAL);
		return YACA_ERROR_INTERNAL;
	}

	*iv_bit_len = ret * 8;
	return YACA_ERROR_NONE;
}

API int yaca_encrypt_initialize(yaca_context_h *ctx,
                                yaca_encrypt_algorithm_e algo,
                                yaca_block_cipher_mode_e bcm,
                                const yaca_key_h sym_key,
                                const yaca_key_h iv)
{
	return encrypt_initialize(ctx, algo, bcm, sym_key, iv, OP_ENCRYPT);
}

API int yaca_encrypt_update(yaca_context_h ctx,
                            const char *plaintext,
                            size_t plaintext_len,
                            char *ciphertext,
                            size_t *ciphertext_len)
{
	return encrypt_update(ctx, (const unsigned char*)plaintext, plaintext_len,
	                      (unsigned char*)ciphertext, ciphertext_len, OP_ENCRYPT);
}

API int yaca_encrypt_finalize(yaca_context_h ctx,
                              char *ciphertext,
                              size_t *ciphertext_len)
{
	return encrypt_finalize(ctx, (unsigned char*)ciphertext, ciphertext_len, OP_ENCRYPT);
}

API int yaca_decrypt_initialize(yaca_context_h *ctx,
                                yaca_encrypt_algorithm_e algo,
                                yaca_block_cipher_mode_e bcm,
                                const yaca_key_h sym_key,
                                const yaca_key_h iv)
{
	return encrypt_initialize(ctx, algo, bcm, sym_key, iv, OP_DECRYPT);
}

API int yaca_decrypt_update(yaca_context_h ctx,
                            const char *ciphertext,
                            size_t ciphertext_len,
                            char *plaintext,
                            size_t *plaintext_len)
{
	return encrypt_update(ctx, (const unsigned char*)ciphertext, ciphertext_len,
	                      (unsigned char*)plaintext, plaintext_len, OP_DECRYPT);
}

API int yaca_decrypt_finalize(yaca_context_h ctx,
                              char *plaintext,
                              size_t *plaintext_len)
{
	return encrypt_finalize(ctx, (unsigned char*)plaintext, plaintext_len, OP_DECRYPT);
}
