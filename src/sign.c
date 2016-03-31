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
#include <openssl/rand.h>

#include <crypto/crypto.h>
#include <crypto/error.h>

int crypto_sign_init(crypto_ctx_h *ctx,
		     crypto_digest_algo_e algo,
		     const crypto_key_h key)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_sign_update(crypto_ctx_h ctx,
		       const char *data,
		       size_t data_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_sign_final(crypto_ctx_h ctx,
		      char *mac,
		      size_t *mac_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_verify_init(crypto_ctx_h *ctx,
		       crypto_digest_algo_e algo,
		       const crypto_key_h key)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_verify_update(crypto_ctx_h ctx,
			 const char *data,
			 size_t data_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_verify_final(crypto_ctx_h ctx,
			const char *mac,
			size_t mac_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}
