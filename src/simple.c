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

#include "config.h"

#include <assert.h>
#include <limits.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <crypto/crypto.h>
#include <crypto/error.h>
#include <crypto/encrypt.h>
#include <crypto/digest.h>
#include <crypto/key.h>

API int owl_digest_calc(owl_digest_algo_e algo,
		    const char *data,
		    size_t data_len,
		    char **digest,
		    size_t *digest_len)
{
	owl_ctx_h ctx;
	int ret;
	char *ldigest;
	size_t ldigest_len;

	if (data == NULL || data_len == 0 || digest == NULL || digest_len == NULL)
		return OWL_ERROR_INVALID_ARGUMENT;

	ret = owl_digest_init(&ctx, algo);
	if (ret < 0)
		return ret;

	ret = owl_digest_update(ctx, data, data_len);
	if (ret < 0)
		goto err;

	ret = owl_get_digest_length(ctx);
	if (ret < 0)
		goto err;

	ldigest_len = ret;
	ldigest = owl_malloc(ldigest_len);
	if (!ldigest)
		goto err;

	ret = owl_digest_final(ctx, ldigest, &ldigest_len);
	if (ret < 0)
		goto err_free;

	owl_ctx_free(ctx);

	*digest_len = ldigest_len;
	*digest = ldigest;
	return 0;

err_free:
	owl_free(ldigest);
err:
	owl_ctx_free(ctx);
	return ret;
}

API int owl_encrypt(owl_enc_algo_e algo,
		owl_block_cipher_mode_e bcm,
		const owl_key_h sym_key,
		const owl_key_h iv,
		const char *plain,
		size_t plain_len,
		char **cipher,
		size_t *cipher_len)
{
	owl_ctx_h ctx;
	int ret;
	char *lcipher;
	size_t out_len, lcipher_len, written;

	if (plain == NULL || plain_len == 0 || cipher == NULL || cipher_len == NULL ||
	    sym_key == OWL_KEY_NULL || iv == OWL_KEY_NULL)
		return OWL_ERROR_INVALID_ARGUMENT;

	if (plain_len > INT_MAX) /* TODO: this is because get_output_length returns signed int - perhaps we should change that */
		return OWL_ERROR_TOO_BIG_ARGUMENT;

	ret = owl_encrypt_init(&ctx, algo, bcm, sym_key, iv);
	if (ret < 0)
		return ret;

	ret = owl_get_output_length(ctx, plain_len);
	if (ret < 0)
		goto err;

	lcipher_len = ret;
	lcipher = owl_malloc(lcipher_len);
	if (lcipher == NULL)
		goto err;

	out_len = lcipher_len;
	ret = owl_encrypt_update(ctx, plain, plain_len, lcipher, &out_len);
	if (ret < 0)
		goto err_free;

	assert (out_len <= lcipher_len);

	written = out_len;
	out_len = lcipher_len - written;
	ret = owl_encrypt_final(ctx, lcipher + written, &out_len);
	if (ret < 0)
		goto err_free;

	assert (out_len + written == lcipher_len);

	owl_ctx_free(ctx);

	*cipher = lcipher;
	*cipher_len = lcipher_len;
	return 0;

err_free:
	owl_free(lcipher);
err:
	owl_ctx_free(ctx);
	return ret;
}

API int owl_decrypt(owl_enc_algo_e algo,
		owl_block_cipher_mode_e bcm,
		const owl_key_h sym_key,
		const owl_key_h iv,
		const char *cipher,
		size_t cipher_len,
		char **plain,
		size_t *plain_len)
{
	owl_ctx_h ctx;
	int ret;
	char *lplain;
	size_t out_len, lplain_len, written;

	if (cipher == NULL || cipher_len == 0 || plain == NULL || plain_len == NULL ||
	    sym_key == OWL_KEY_NULL || iv == OWL_KEY_NULL)
		return OWL_ERROR_INVALID_ARGUMENT;

	if (cipher_len > INT_MAX) /* TODO: this is because get_output_length returns signed int - perhaps we should change that */
		return OWL_ERROR_TOO_BIG_ARGUMENT;

	ret = owl_decrypt_init(&ctx, algo, bcm, sym_key, iv);
	if (ret < 0)
		return ret;

	ret = owl_get_output_length(ctx, cipher_len);
	if (ret < 0)
		goto err;

	lplain_len = ret;
	lplain = owl_malloc(lplain_len);
	if (!lplain)
		goto err;

	out_len = lplain_len;
	ret = owl_decrypt_update(ctx, cipher, cipher_len, lplain, &out_len);
	if (ret < 0)
		goto err_free;

	assert(out_len <= lplain_len);

	written = out_len;
	out_len = lplain_len - written;
	ret = owl_decrypt_final(ctx, lplain + written, &out_len);
	if (ret < 0)
		goto err_free;

	assert(out_len + written == lplain_len);

	owl_ctx_free(ctx);

	*plain = lplain;
	*plain_len = lplain_len;
	return 0;

err_free:
	owl_free(lplain);
err:
	owl_ctx_free(ctx);
	return ret;
}
