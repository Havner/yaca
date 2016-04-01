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

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <crypto/crypto.h>
#include <crypto/error.h>

#include "ctx_p.h"

API int owl_init(void)
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

API void owl_exit(void)
{
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

API void *owl_malloc(size_t size)
{
	return OPENSSL_malloc(size);
}

API void *owl_realloc(void *addr, size_t size)
{
	return OPENSSL_realloc(addr, size);
}

API void owl_free(void *ptr)
{
	OPENSSL_free(ptr);
}

API int owl_rand_bytes(char *data, size_t data_len)
{
	int ret;

	if (data == NULL || data_len == 0)
		return OWL_ERROR_INVALID_ARGUMENT;

	ret = RAND_bytes((unsigned char *)data, data_len);
	if (ret == -1)
		return OWL_ERROR_NOT_SUPPORTED;
	if (ret == 1)
		return 0;

	return OWL_ERROR_OPENSSL_FAILURE;
}

API int owl_ctx_set_param(owl_ctx_h ctx, owl_ex_param_e param,
		      const void *value, size_t value_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

API int owl_ctx_get_param(const owl_ctx_h ctx, owl_ex_param_e param,
		      void **value, size_t *value_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

API void owl_ctx_free(owl_ctx_h ctx)
{
	owl_free(ctx);
	/* TODO: What about digest context? This should free specific contexts as well. */
}

API int owl_get_output_length(const owl_ctx_h ctx, size_t input_len)
{
	if (ctx == OWL_CTX_NULL)
		return OWL_ERROR_INVALID_ARGUMENT;

	return ctx->get_output_length(ctx, input_len);
}

API int owl_get_iv_length(owl_enc_algo_e algo,
		      owl_block_cipher_mode_e bcm,
		      size_t key_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}
