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

int owl_encrypt_init(owl_ctx_h *ctx,
		     owl_enc_algo_e algo,
		     owl_block_cipher_mode_e bcm,
		     const owl_key_h sym_key,
		     const owl_key_h iv)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

int owl_encrypt_update(owl_ctx_h ctx,
		       const char *plain,
		       size_t plain_len,
		       char *cipher,
		       size_t *cipher_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

int owl_encrypt_final(owl_ctx_h ctx,
		      char *cipher,
		      size_t *cipher_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

int owl_decrypt_init(owl_ctx_h *ctx,
		     owl_enc_algo_e algo,
		     owl_block_cipher_mode_e bcm,
		     const owl_key_h sym_key,
		     const owl_key_h iv)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

int owl_decrypt_update(owl_ctx_h ctx,
		       const char *cipher,
		       size_t cipher_len,
		       char *plain,
		       size_t *plain_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

int owl_decrypt_final(owl_ctx_h ctx,
		      char *plain,
		      size_t *plain_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

int owl_seal_init(owl_ctx_h *ctx,
		  const owl_key_h pub_key,
		  owl_enc_algo_e algo,
		  owl_block_cipher_mode_e bcm,
		  owl_key_h *sym_key,
		  owl_key_h *iv)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

int owl_seal_update(owl_ctx_h ctx,
		    const char *plain,
		    size_t plain_len,
		    char *cipher,
		    size_t *cipher_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

int owl_seal_final(owl_ctx_h ctx,
		   char *cipher,
		   size_t *cipher_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

int owl_open_init(owl_ctx_h *ctx,
		  const owl_key_h prv_key,
		  owl_enc_algo_e algo,
		  owl_block_cipher_mode_e bcm,
		  const owl_key_h sym_key,
		  const owl_key_h iv)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

int owl_open_update(owl_ctx_h ctx,
		    const char *cipher,
		    size_t cipher_len,
		    char *plain,
		    size_t *plain_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

int owl_open_final(owl_ctx_h ctx,
		   char *plain,
		   size_t *plain_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}
