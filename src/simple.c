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
 * @file simple.c
 * @brief
 */

#include <assert.h>
#include <stdint.h>

#include <yaca_crypto.h>
#include <yaca_error.h>
#include <yaca_encrypt.h>
#include <yaca_digest.h>
#include <yaca_key.h>
#include <yaca_sign.h>

#include "internal.h"

API int yaca_simple_calculate_digest(yaca_digest_algorithm_e algo,
                                     const char *data,
                                     size_t data_len,
                                     char **digest,
                                     size_t *digest_len)
{
	yaca_context_h ctx;
	int ret;
	char *ldigest = NULL;
	size_t ldigest_len;

	if ((data == NULL && data_len > 0) || (data != NULL && data_len == 0) ||
	    digest == NULL || digest_len == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_digest_initialize(&ctx, algo);
	if (ret != YACA_ERROR_NONE)
		return ret;

	if (data_len > 0) {
		ret = yaca_digest_update(ctx, data, data_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;
	}

	ret = yaca_context_get_output_length(ctx, 0, &ldigest_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	assert(ldigest_len > 0);

	ret = yaca_malloc(ldigest_len, (void**)&ldigest);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_digest_finalize(ctx, ldigest, &ldigest_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	*digest_len = ldigest_len;
	*digest = ldigest;
	ldigest = NULL;

exit:
	yaca_free(ldigest);
	yaca_context_destroy(ctx);

	return ret;
}

API int yaca_simple_encrypt(yaca_encrypt_algorithm_e algo,
                            yaca_block_cipher_mode_e bcm,
                            const yaca_key_h sym_key,
                            const yaca_key_h iv,
                            const char *plaintext,
                            size_t plaintext_len,
                            char **ciphertext,
                            size_t *ciphertext_len)
{
	yaca_context_h ctx;
	int ret;
	char *lciphertext = NULL;
	size_t out_len, lciphertext_len, written;

	if (plaintext == NULL || plaintext_len == 0 ||
	    ciphertext == NULL || ciphertext_len == NULL ||
	    sym_key == YACA_KEY_NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_encrypt_initialize(&ctx, algo, bcm, sym_key, iv);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = yaca_context_get_output_length(ctx, plaintext_len, &out_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_context_get_output_length(ctx, 0, &lciphertext_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	if (out_len > SIZE_MAX - lciphertext_len) {
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	lciphertext_len += out_len;

	assert(lciphertext_len > 0);

	ret = yaca_malloc(lciphertext_len, (void**)&lciphertext);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	out_len = lciphertext_len;
	ret = yaca_encrypt_update(ctx, plaintext, plaintext_len, lciphertext, &out_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	assert(out_len <= lciphertext_len);

	written = out_len;
	out_len = lciphertext_len - written;
	ret = yaca_encrypt_finalize(ctx, lciphertext + written, &out_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	written += out_len;
	assert(written <= lciphertext_len && written > 0);

	ret = yaca_realloc(written, (void**)&lciphertext);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	*ciphertext = lciphertext;
	*ciphertext_len = written;
	lciphertext = NULL;
	ret = YACA_ERROR_NONE;

exit:
	yaca_free(lciphertext);
	yaca_context_destroy(ctx);

	return ret;
}

API int yaca_simple_decrypt(yaca_encrypt_algorithm_e algo,
                            yaca_block_cipher_mode_e bcm,
                            const yaca_key_h sym_key,
                            const yaca_key_h iv,
                            const char *ciphertext,
                            size_t ciphertext_len,
                            char **plaintext,
                            size_t *plaintext_len)
{
	yaca_context_h ctx;
	int ret;
	char *lplaintext = NULL;
	size_t out_len, lplaintext_len, written;

	if (ciphertext == NULL || ciphertext_len == 0 ||
	    plaintext == NULL || plaintext_len == NULL ||
	    sym_key == YACA_KEY_NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_decrypt_initialize(&ctx, algo, bcm, sym_key, iv);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = yaca_context_get_output_length(ctx, ciphertext_len, &out_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_context_get_output_length(ctx, 0, &lplaintext_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	if (out_len > SIZE_MAX - lplaintext_len) {
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	lplaintext_len += out_len;
	assert(lplaintext_len > 0);

	ret = yaca_malloc(lplaintext_len, (void**)&lplaintext);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	out_len = lplaintext_len;
	ret = yaca_decrypt_update(ctx, ciphertext, ciphertext_len, lplaintext, &out_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	assert(out_len <= lplaintext_len);

	written = out_len;
	out_len = lplaintext_len - written;
	ret = yaca_decrypt_finalize(ctx, lplaintext + written, &out_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	written += out_len;
	assert(written <= lplaintext_len && written > 0);

	ret = yaca_realloc(written, (void**)&lplaintext);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	*plaintext = lplaintext;
	*plaintext_len = written;
	lplaintext = NULL;
	ret = YACA_ERROR_NONE;

exit:
	yaca_free(lplaintext);
	yaca_context_destroy(ctx);

	return ret;
}

static int sign(const yaca_context_h ctx, const char *data, size_t data_len,
                char **signature, size_t *signature_len)
{
	int ret;

	assert(signature != NULL);
	assert(signature_len != NULL);

	if (data_len > 0) {
		ret = yaca_sign_update(ctx, data, data_len);
		if (ret != YACA_ERROR_NONE)
			return ret;
	}

	ret = yaca_context_get_output_length(ctx, 0, signature_len);
	if (ret != YACA_ERROR_NONE)
		return ret;

	assert(*signature_len > 0);

	ret = yaca_malloc(*signature_len, (void**)signature);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = yaca_sign_finalize(ctx, *signature, signature_len);
	if (ret != YACA_ERROR_NONE) {
		yaca_free(*signature);
		*signature = NULL;
	}

	return ret;
}

API int yaca_simple_calculate_signature(yaca_digest_algorithm_e algo,
                                        const yaca_key_h key,
                                        const char *data,
                                        size_t data_len,
                                        char **signature,
                                        size_t *signature_len)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;

	if ((data == NULL && data_len > 0) || (data != NULL && data_len == 0) ||
	    signature == NULL || signature_len == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_sign_initialize(&ctx, algo, key);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = sign(ctx, data, data_len, signature, signature_len);

	yaca_context_destroy(ctx);

	return ret;
}

API int yaca_simple_verify_signature(yaca_digest_algorithm_e algo,
                                     const yaca_key_h key,
                                     const char *data,
                                     size_t data_len,
                                     const char *signature,
                                     size_t signature_len)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;

	if ((data == NULL && data_len > 0) || (data != NULL && data_len == 0) ||
	    signature == NULL || signature_len == 0)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_verify_initialize(&ctx, algo, key);
	if (ret != YACA_ERROR_NONE)
		return ret;

	if (data_len > 0) {
		ret = yaca_verify_update(ctx, data, data_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;
	}

	ret = yaca_verify_finalize(ctx, signature, signature_len);

exit:
	yaca_context_destroy(ctx);

	return ret;
}

API int yaca_simple_calculate_hmac(yaca_digest_algorithm_e algo,
                                   const yaca_key_h key,
                                   const char *data,
                                   size_t data_len,
                                   char **mac,
                                   size_t *mac_len)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;

	if ((data == NULL && data_len > 0) || (data != NULL && data_len == 0) ||
	    mac == NULL || mac_len == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_sign_initialize_hmac(&ctx, algo, key);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = sign(ctx, data, data_len, mac, mac_len);

	yaca_context_destroy(ctx);

	return ret;
}

API int yaca_simple_calculate_cmac(yaca_encrypt_algorithm_e algo,
                                   const yaca_key_h key,
                                   const char *data,
                                   size_t data_len,
                                   char **mac,
                                   size_t *mac_len)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;

	if ((data == NULL && data_len > 0) || (data != NULL && data_len == 0) ||
	    mac == NULL || mac_len == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_sign_initialize_cmac(&ctx, algo, key);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = sign(ctx, data, data_len, mac, mac_len);

	yaca_context_destroy(ctx);

	return ret;
}
