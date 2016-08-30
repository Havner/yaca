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
 * @file rsa.c
 * @brief
 */

#include <stdio.h>

#include <yaca_crypto.h>
#include <yaca_rsa.h>
#include <yaca_types.h>
#include <yaca_key.h>
#include <yaca_error.h>

#include "lorem.h"
#include "misc.h"

static int public_encrypt()
{
	yaca_key_h prv_key = YACA_KEY_NULL;
	yaca_key_h pub_key = YACA_KEY_NULL;
	char *ciphertext = NULL;
	size_t ciphertext_len;
	char *plaintext = NULL;
	size_t plaintext_len;
	const size_t key_bit_len = YACA_KEY_LENGTH_1024BIT;
	const size_t input_len = key_bit_len / 8 - 12;
	int ret;

	printf("Plain data (16 of %zu bytes): %.16s\n", input_len, lorem1024);

	/* Key generation */
	ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, key_bit_len, &prv_key);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = yaca_key_extract_public(prv_key, &pub_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* encrypt with PKCS1 padding */
	ret = yaca_rsa_public_encrypt(YACA_PADDING_PKCS1, pub_key,
	                              lorem1024, input_len,
	                              &ciphertext, &ciphertext_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	dump_hex(ciphertext, 16, "Encrypted data (16 of %zu bytes): ", ciphertext_len);

	/*
	 * YACA_PADDING_PKCS1_SSLV23 is compatible with YACA_PADDING_PKCS1. It is used to detect if
	 * both the encrypting and decrypting side used YACA_PADDING_PKCS1_SSLV23, that is, both are
	 * SSL3 capable but use the SSL2 (rollback attack detection).
	 */
	ret = yaca_rsa_private_decrypt(YACA_PADDING_PKCS1_SSLV23, prv_key,
	                               ciphertext, ciphertext_len,
	                               &plaintext, &plaintext_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	printf("Decrypted data (16 of %zu bytes): %.16s\n\n", plaintext_len, plaintext);

exit:
	yaca_free(ciphertext);
	yaca_free(plaintext);
	yaca_key_destroy(prv_key);
	yaca_key_destroy(pub_key);
	return ret;
}

static int private_encrypt()
{
	yaca_key_h prv_key = YACA_KEY_NULL;
	yaca_key_h pub_key = YACA_KEY_NULL;
	char *ciphertext = NULL;
	size_t ciphertext_len;
	char *plaintext = NULL;
	size_t plaintext_len;
	const size_t key_bit_len = YACA_KEY_LENGTH_1024BIT;
	const size_t input_len = key_bit_len / 8 - 12;
	int ret;

	printf("Plain data (16 of %zu bytes): %.16s\n", input_len, lorem1024);

	/* Key generation */
	ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, key_bit_len, &prv_key);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = yaca_key_extract_public(prv_key, &pub_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_rsa_private_encrypt(YACA_PADDING_PKCS1, prv_key,
	                               lorem1024, input_len,
	                               &ciphertext, &ciphertext_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	dump_hex(ciphertext, 16, "Encrypted data (16 of %zu bytes): ", ciphertext_len);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_PKCS1, pub_key,
	                              ciphertext, ciphertext_len,
	                              &plaintext, &plaintext_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	printf("Decrypted data (16 of %zu bytes): %.16s\n\n", plaintext_len, plaintext);

exit:
	yaca_free(ciphertext);
	yaca_free(plaintext);
	yaca_key_destroy(prv_key);
	yaca_key_destroy(pub_key);
	return ret;
}

int main()
{
	int ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = public_encrypt();
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = private_encrypt();

exit:
	yaca_cleanup();
	return ret;
}
