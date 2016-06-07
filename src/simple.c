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

	if (data == NULL || data_len == 0 || digest == NULL || digest_len == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_digest_initialize(&ctx, algo);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = yaca_digest_update(ctx, data, data_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

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
                            const char *plain,
                            size_t plain_len,
                            char **cipher,
                            size_t *cipher_len)
{
	yaca_context_h ctx;
	int ret;
	char *lcipher = NULL;
	size_t out_len, lcipher_len, written;

	if (plain == NULL || plain_len == 0 || cipher == NULL || cipher_len == NULL ||
	    sym_key == YACA_KEY_NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_encrypt_initialize(&ctx, algo, bcm, sym_key, iv);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = yaca_context_get_output_length(ctx, plain_len, &out_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_context_get_output_length(ctx, 0, &lcipher_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	if (out_len > SIZE_MAX - lcipher_len) {
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	lcipher_len += out_len;

	assert(lcipher_len > 0);

	ret = yaca_malloc(lcipher_len, (void**)&lcipher);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	out_len = lcipher_len;
	ret = yaca_encrypt_update(ctx, plain, plain_len, lcipher, &out_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	assert(out_len <= lcipher_len);

	written = out_len;
	out_len = lcipher_len - written;
	ret = yaca_encrypt_finalize(ctx, lcipher + written, &out_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	written += out_len;
	assert(written <= lcipher_len && written > 0);

	ret = yaca_realloc(written, (void**)&lcipher);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	*cipher = lcipher;
	*cipher_len = written;
	lcipher = NULL;
	ret = YACA_ERROR_NONE;

exit:
	yaca_free(lcipher);
	yaca_context_destroy(ctx);

	return ret;
}

API int yaca_simple_decrypt(yaca_encrypt_algorithm_e algo,
                            yaca_block_cipher_mode_e bcm,
                            const yaca_key_h sym_key,
                            const yaca_key_h iv,
                            const char *cipher,
                            size_t cipher_len,
                            char **plain,
                            size_t *plain_len)
{
	yaca_context_h ctx;
	int ret;
	char *lplain = NULL;
	size_t out_len, lplain_len, written;

	if (cipher == NULL || cipher_len == 0 || plain == NULL || plain_len == NULL ||
	    sym_key == YACA_KEY_NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_decrypt_initialize(&ctx, algo, bcm, sym_key, iv);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = yaca_context_get_output_length(ctx, cipher_len, &out_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_context_get_output_length(ctx, 0, &lplain_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	if (out_len > SIZE_MAX - lplain_len) {
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	lplain_len += out_len;
	assert(lplain_len > 0);

	ret = yaca_malloc(lplain_len, (void**)&lplain);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	out_len = lplain_len;
	ret = yaca_decrypt_update(ctx, cipher, cipher_len, lplain, &out_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	assert(out_len <= lplain_len);

	written = out_len;
	out_len = lplain_len - written;
	ret = yaca_decrypt_finalize(ctx, lplain + written, &out_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	written += out_len;
	assert(written <= lplain_len && written > 0);

	ret = yaca_realloc(written, (void**)&lplain);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	*plain = lplain;
	*plain_len = written;
	lplain = NULL;
	ret = YACA_ERROR_NONE;

exit:
	yaca_free(lplain);
	yaca_context_destroy(ctx);

	return ret;
}

static int sign(const yaca_context_h ctx, const char *data, size_t data_len,
                char **signature, size_t *signature_len)
{
	int ret;

	assert(signature != NULL);
	assert(signature_len != NULL);

	ret = yaca_sign_update(ctx, data, data_len);
	if (ret != YACA_ERROR_NONE)
		return ret;

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

	ret = yaca_verify_initialize(&ctx, algo, key);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = yaca_verify_update(ctx, data, data_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

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

	ret = yaca_sign_initialize_cmac(&ctx, algo, key);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = sign(ctx, data, data_len, mac, mac_len);

	yaca_context_destroy(ctx);

	return ret;
}
