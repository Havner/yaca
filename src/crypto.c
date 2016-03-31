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

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <crypto/crypto.h>
#include <crypto/error.h>

#include "ctx_p.h"

int crypto_init(void)
{
	OPENSSL_init();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();
	return 0;
}

void crypto_exit(void)
{
}

void *crypto_alloc(size_t size)
{
	return OPENSSL_malloc(size);
}

void crypto_free(void *ptr)
{
	OPENSSL_free(ptr);
}

int crypto_rand_bytes(char *data, size_t data_len)
{
	int ret;

	if (!data || data_len == 0)
		return CRYPTO_ERROR_INVALID_ARGUMENT;

	ret = RAND_bytes((unsigned char *)data, data_len);
	if (ret == -1)
		return CRYPTO_ERROR_NOT_SUPPORTED;
	if (ret == 1)
		return 0;

	return CRYPTO_ERROR_OPENSSL_FAILURE;
}

int crypto_ctx_set_param(crypto_ctx_h ctx, crypto_ex_param_e param,
			 const void *value, size_t value_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_ctx_get_param(const crypto_ctx_h ctx, crypto_ex_param_e param,
			 void **value, size_t *value_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

void crypto_ctx_free(crypto_ctx_h ctx)
{
	crypto_free(ctx);
}

int crypto_get_output_length(const crypto_ctx_h ctx, size_t input_len)
{
	if (!ctx)
		return CRYPTO_ERROR_INVALID_ARGUMENT;
	return ctx->get_output_length(ctx, input_len);
}

int crypto_get_iv_length(crypto_enc_algo_e algo,
			 crypto_block_cipher_mode_e bcm,
			 size_t key_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}
