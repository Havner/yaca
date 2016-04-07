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

#include <yaca/crypto.h>
#include <yaca/error.h>

#include "internal.h"

API int yaca_encrypt_init(yaca_ctx_h *ctx,
			  yaca_enc_algo_e algo,
			  yaca_block_cipher_mode_e bcm,
			  const yaca_key_h sym_key,
			  const yaca_key_h iv)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_encrypt_update(yaca_ctx_h ctx,
			    const char *plain,
			    size_t plain_len,
			    char *cipher,
			    size_t *cipher_len)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_encrypt_final(yaca_ctx_h ctx,
			   char *cipher,
			   size_t *cipher_len)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_decrypt_init(yaca_ctx_h *ctx,
			  yaca_enc_algo_e algo,
			  yaca_block_cipher_mode_e bcm,
			  const yaca_key_h sym_key,
			  const yaca_key_h iv)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_decrypt_update(yaca_ctx_h ctx,
			    const char *cipher,
			    size_t cipher_len,
			    char *plain,
			    size_t *plain_len)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_decrypt_final(yaca_ctx_h ctx,
			   char *plain,
			   size_t *plain_len)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_seal_init(yaca_ctx_h *ctx,
		       const yaca_key_h pub_key,
		       yaca_enc_algo_e algo,
		       yaca_block_cipher_mode_e bcm,
		       yaca_key_h *sym_key,
		       yaca_key_h *iv)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_seal_update(yaca_ctx_h ctx,
			 const char *plain,
			 size_t plain_len,
			 char *cipher,
			 size_t *cipher_len)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_seal_final(yaca_ctx_h ctx,
			char *cipher,
			size_t *cipher_len)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_open_init(yaca_ctx_h *ctx,
		       const yaca_key_h prv_key,
		       yaca_enc_algo_e algo,
		       yaca_block_cipher_mode_e bcm,
		       const yaca_key_h sym_key,
		       const yaca_key_h iv)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_open_update(yaca_ctx_h ctx,
			 const char *cipher,
			 size_t cipher_len,
			 char *plain,
			 size_t *plain_len)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_open_final(yaca_ctx_h ctx,
			char *plain,
			size_t *plain_len)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}
