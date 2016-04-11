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
#include <openssl/evp.h>

#include <yaca/crypto.h>
#include <yaca/error.h>

#include "internal.h"

static const char *symmetric_algo_to_str(yaca_enc_algo_e algo)
{
	switch(algo)
	{
	case YACA_ENC_AES:
		return "aes";
	case YACA_ENC_UNSAFE_DES:
		return "des";
	case YACA_ENC_UNSAFE_RC2:
		return "rc2";
	case YACA_ENC_UNSAFE_RC4:
		return "rc4";
	case YACA_ENC_CAST5:
		return "cast5";

	case YACA_ENC_UNSAFE_3DES_2TDEA: // TODO: add 3des/2tdea support
	case YACA_ENC_3DES_3TDEA:  // TODO: add 3des/3tdea support
	case YACA_ENC_UNSAFE_SKIPJACK:  // TODO: add skipjack implementation
	default:
		return NULL;
	}
}

static const char *bcm_to_str(yaca_block_cipher_mode_e bcm)
{
	switch (bcm) {
	case YACA_BCM_ECB:
		return "ecb";
	case YACA_BCM_CBC:
		return "cbc";
	case YACA_BCM_CTR:
		return "ctr";
	case YACA_BCM_GCM:
		return "gcm";
	case YACA_BCM_CFB:
		return "cfb";
	case YACA_BCM_OFB:
		return "ofb";
	case YACA_BCM_OCB:
		return "ocb";
	case YACA_BCM_CCM:
		return "ccm";
	default:
		return NULL;
	}
}

int get_symmetric_algorithm(yaca_enc_algo_e algo,
			    yaca_block_cipher_mode_e bcm,
			    unsigned key_bits,
			    const EVP_CIPHER **cipher)
{
	char cipher_name[32];
	const char *algo_name = symmetric_algo_to_str(algo);
	const char *bcm_name = bcm_to_str(bcm);
	const EVP_CIPHER *lcipher;
	int ret;

	if (algo_name == NULL || bcm_name == NULL || key_bits == 0 ||
	    cipher == NULL)
		return YACA_ERROR_INVALID_ARGUMENT;

	ret = snprintf(cipher_name, sizeof(cipher_name), "%s-%d-%s", algo_name,
		       key_bits, bcm_name);
	if (ret < 0)
		return YACA_ERROR_INVALID_ARGUMENT;
	if ((unsigned)ret >= sizeof(cipher_name)) // output was truncated
		return YACA_ERROR_INVALID_ARGUMENT;

	lcipher = EVP_get_cipherbyname(cipher_name);
	if (lcipher == NULL)
		return YACA_ERROR_OPENSSL_FAILURE; // TODO: yaca_get_error_code_from_openssl(ret);

	*cipher = lcipher;
	return 0;
}

API int yaca_get_iv_bits(yaca_enc_algo_e algo,
			 yaca_block_cipher_mode_e bcm,
			 size_t key_bits)
{
	const EVP_CIPHER *cipher;
	int ret;

	ret = get_symmetric_algorithm(algo, bcm, key_bits, &cipher);
	if (ret < 0)
		return ret;

	return EVP_CIPHER_iv_length(cipher) * 8;
}

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
