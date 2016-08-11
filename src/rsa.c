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
 * @file   rsa.c
 * @brief  Advanced API for low-level RSA operations
 */

#include <assert.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <yaca_rsa.h>
#include <yaca_error.h>
#include <yaca_types.h>
#include <yaca_crypto.h>
#include <yaca_key.h>

#include "internal.h"

int rsa_padding2openssl(yaca_padding_e padding)
{
	switch (padding) {
	case YACA_PADDING_NONE:
		return RSA_NO_PADDING;
	case YACA_PADDING_X931:
		return RSA_X931_PADDING;
	case YACA_PADDING_PKCS1:
		return RSA_PKCS1_PADDING;
	case YACA_PADDING_PKCS1_PSS:
		return RSA_PKCS1_PSS_PADDING;
	case YACA_PADDING_PKCS1_OAEP:
		return RSA_PKCS1_OAEP_PADDING;
	case YACA_PADDING_PKCS1_SSLV23:
		return RSA_SSLV23_PADDING;
	default:
		return -1;
	}
}

typedef int (*encrypt_decrypt_fn)(int, const unsigned char*, unsigned char*, RSA*, int);

static int encrypt_decrypt(yaca_padding_e padding,
                           const yaca_key_h key,
                           const char *input,
                           size_t input_len,
                           char **output,
                           size_t *output_len,
                           encrypt_decrypt_fn fn)
{
	int ret;
	size_t max_len;
	char *loutput = NULL;
	struct yaca_key_evp_s *lasym_key;
	int lpadding;

	if ((input == NULL && input_len > 0) || (input != NULL && input_len == 0) ||
	    output == NULL || output_len == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	lpadding = rsa_padding2openssl(padding);
	assert(lpadding != -1);

	lasym_key = key_get_evp(key);
	assert(lasym_key != NULL);

	ret = EVP_PKEY_size(lasym_key->evp);
	if (ret <= 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	max_len = ret;

	ret = yaca_zalloc(max_len, (void**)&loutput);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = fn(input_len,
	         (const unsigned char*)input,
	         (unsigned char*)loutput,
	         lasym_key->evp->pkey.rsa,
	         lpadding);

	if (ret < 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	if (ret == 0) {
		yaca_free(loutput);
		loutput = NULL;
	}

	*output_len = ret;
	*output = loutput;
	loutput = NULL;
	ret = YACA_ERROR_NONE;

exit:
	yaca_free(loutput);
	return ret;
}


API int yaca_rsa_public_encrypt(yaca_padding_e padding,
                                const yaca_key_h pub_key,
                                const char *plaintext,
                                size_t plaintext_len,
                                char **ciphertext,
                                size_t *ciphertext_len)
{
	if (pub_key == YACA_KEY_NULL || pub_key->type != YACA_KEY_TYPE_RSA_PUB)
		return YACA_ERROR_INVALID_PARAMETER;

	switch(padding) {
	case YACA_PADDING_NONE:
	case YACA_PADDING_PKCS1:
	case YACA_PADDING_PKCS1_OAEP:
	case YACA_PADDING_PKCS1_SSLV23:
		break;
	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}

	return encrypt_decrypt(padding,
	                       pub_key,
	                       plaintext,
	                       plaintext_len,
	                       ciphertext,
	                       ciphertext_len,
	                       RSA_public_encrypt);
}

API int yaca_rsa_private_decrypt(yaca_padding_e padding,
                                 const yaca_key_h prv_key,
                                 const char *ciphertext,
                                 size_t ciphertext_len,
                                 char **plaintext,
                                 size_t *plaintext_len)
{
	if (prv_key == YACA_KEY_NULL || prv_key->type != YACA_KEY_TYPE_RSA_PRIV)
		return YACA_ERROR_INVALID_PARAMETER;

	switch(padding) {
	case YACA_PADDING_NONE:
	case YACA_PADDING_PKCS1:
	case YACA_PADDING_PKCS1_OAEP:
	case YACA_PADDING_PKCS1_SSLV23:
		break;
	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}

	return encrypt_decrypt(padding,
	                       prv_key,
	                       ciphertext,
	                       ciphertext_len,
	                       plaintext,
	                       plaintext_len,
	                       RSA_private_decrypt);
}

API int yaca_rsa_private_encrypt(yaca_padding_e padding,
                                 const yaca_key_h prv_key,
                                 const char *plaintext,
                                 size_t plaintext_len,
                                 char **ciphertext,
                                 size_t *ciphertext_len)
{
	if (prv_key == YACA_KEY_NULL || prv_key->type != YACA_KEY_TYPE_RSA_PRIV)
		return YACA_ERROR_INVALID_PARAMETER;

	switch(padding) {
	case YACA_PADDING_NONE:
	case YACA_PADDING_PKCS1:
		break;
	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}

	return encrypt_decrypt(padding,
	                       prv_key,
	                       plaintext,
	                       plaintext_len,
	                       ciphertext,
	                       ciphertext_len,
	                       RSA_private_encrypt);
}

API int yaca_rsa_public_decrypt(yaca_padding_e padding,
                                const yaca_key_h pub_key,
                                const char *ciphertext,
                                size_t ciphertext_len,
                                char **plaintext,
                                size_t *plaintext_len)
{
	if (pub_key == YACA_KEY_NULL || pub_key->type != YACA_KEY_TYPE_RSA_PUB)
		return YACA_ERROR_INVALID_PARAMETER;

	switch(padding) {
	case YACA_PADDING_NONE:
	case YACA_PADDING_PKCS1:
		break;
	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}

	return encrypt_decrypt(padding,
	                       pub_key,
	                       ciphertext,
	                       ciphertext_len,
	                       plaintext,
	                       plaintext_len,
	                       RSA_public_decrypt);
}
