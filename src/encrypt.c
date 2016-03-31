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

int crypto_encrypt_init(crypto_ctx_h *ctx,
			crypto_enc_algo_e algo,
			crypto_block_cipher_mode_e bcm,
			const crypto_key_h sym_key,
			const crypto_key_h iv)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_encrypt_update(crypto_ctx_h ctx,
			  const char *plain,
			  size_t plain_len,
			  char *cipher,
			  size_t *cipher_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_encrypt_final(crypto_ctx_h ctx,
			 char *cipher,
			 size_t *cipher_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_decrypt_init(crypto_ctx_h *ctx,
			crypto_enc_algo_e algo,
			crypto_block_cipher_mode_e bcm,
			const crypto_key_h sym_key,
			const crypto_key_h iv)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_decrypt_update(crypto_ctx_h ctx,
			  const char *cipher,
			  size_t cipher_len,
			  char *plain,
			  size_t *plain_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_decrypt_final(crypto_ctx_h ctx,
			 char *plain,
			 size_t *plain_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_seal_init(crypto_ctx_h *ctx,
		     const crypto_key_h pub_key,
		     crypto_enc_algo_e algo,
		     crypto_block_cipher_mode_e bcm,
		     crypto_key_h *sym_key,
		     crypto_key_h *iv)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_seal_update(crypto_ctx_h ctx,
		       const char *plain,
		       size_t plain_len,
		       char *cipher,
		       size_t *cipher_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_seal_final(crypto_ctx_h ctx,
		      char *cipher,
		      size_t *cipher_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_open_init(crypto_ctx_h *ctx,
		     const crypto_key_h prv_key,
		     crypto_enc_algo_e algo,
		     crypto_block_cipher_mode_e bcm,
		     const crypto_key_h sym_key,
		     const crypto_key_h iv)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_open_update(crypto_ctx_h ctx,
		       const char *cipher,
		       size_t cipher_len,
		       char *plain,
		       size_t *plain_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}

int crypto_open_final(crypto_ctx_h ctx,
		      char *plain,
		      size_t *plain_len)
{
	return CRYPTO_ERROR_NOT_IMPLEMENTED;
}
