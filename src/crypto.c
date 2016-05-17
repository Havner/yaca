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
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <yaca/crypto.h>
#include <yaca/error.h>

#include "internal.h"

API int yaca_init(void)
{

	OPENSSL_init();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();
	/*
	  TODO:
		We should prepare for multithreading. Either we or the user should setup static locks.
		We should also decide on Openssl config.
		Here's a good tutorial for initalization and cleanup: https://wiki.openssl.org/index.php/Library_Initialization
		We should also initialize the entropy for random number generator: https://wiki.openssl.org/index.php/Random_Numbers#Initialization
	*/
	return 0;
}

API void yaca_exit(void)
{
	ERR_free_strings();
	ERR_remove_thread_state(NULL);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

API void *yaca_malloc(size_t size)
{
	return OPENSSL_malloc(size);
}

API void *yaca_zalloc(size_t size)
{
	void *blob = OPENSSL_malloc(size);
	if (blob != NULL)
		memset(blob, 0, size);
	return blob;
}

API void *yaca_realloc(void *addr, size_t size)
{
	return OPENSSL_realloc(addr, size);
}

API void yaca_free(void *ptr)
{
	OPENSSL_free(ptr);
}

API int yaca_rand_bytes(char *data, size_t data_len)
{
	int ret;

	if (data == NULL || data_len == 0)
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = RAND_bytes((unsigned char *)data, data_len);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return 0;
}

API int yaca_ctx_set_param(yaca_ctx_h ctx, yaca_ex_param_e param,
			   const void *value, size_t value_len)
{
	if (ctx == YACA_CTX_NULL || ctx->set_param == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	return ctx->set_param(ctx, param, value, value_len);
}

API int yaca_ctx_get_param(const yaca_ctx_h ctx, yaca_ex_param_e param,
			   void **value, size_t *value_len)
{
	if (ctx == YACA_CTX_NULL || ctx->get_param == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	return ctx->get_param(ctx, param, value, value_len);
}

API void yaca_ctx_free(yaca_ctx_h ctx)
{
	if (ctx != YACA_CTX_NULL) {
		assert(ctx->ctx_destroy != NULL);
		ctx->ctx_destroy(ctx);
		yaca_free(ctx);
	}
}

API int yaca_get_output_length(const yaca_ctx_h ctx, size_t input_len, size_t *output_len)
{
	if (ctx == YACA_CTX_NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	return ctx->get_output_length(ctx, input_len, output_len);
}

API int yaca_memcmp(const void *first, const void *second, size_t len)
{
	if (CRYPTO_memcmp(first, second, len) == 0)
		return 0;

	return YACA_ERROR_DATA_MISMATCH;
}
