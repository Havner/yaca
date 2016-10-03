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
 * @file rsa_private.c
 * @brief Private RSA Encrypt API example.
 */

//! [Private RSA Encrypt API example]
#include <stdio.h>

#include <yaca_crypto.h>
#include <yaca_rsa.h>
#include <yaca_key.h>
#include <yaca_error.h>

/* include helpers functions and definitions */
#include "misc.h"

int main()
{
	int ret;
	yaca_key_h rsa_priv = YACA_KEY_NULL;
	yaca_key_h rsa_pub = YACA_KEY_NULL;

	char *encrypted = NULL;
	char *decrypted = NULL;
	size_t encrypted_len;
	size_t decrypted_len;

	const size_t key_bit_len = YACA_KEY_LENGTH_1024BIT;
	const size_t input_len = key_bit_len / 8 - 12;

	printf("Plain data (16 of %zu bytes): %.16s\n", input_len, INPUT_DATA);

	ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* Key generation */
	ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, key_bit_len, &rsa_priv);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_extract_public(rsa_priv, &rsa_pub);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* Encryption */
	{
		ret = yaca_rsa_private_encrypt(YACA_PADDING_PKCS1, rsa_priv, INPUT_DATA, input_len,
		                               &encrypted, &encrypted_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* display encrypted data in hexadecimal format */
		dump_hex(encrypted, 16, "Encrypted data (16 of %zu bytes): ", encrypted_len);
	}

	/* Decryption */
	{
		ret = yaca_rsa_public_decrypt(YACA_PADDING_PKCS1, rsa_pub, encrypted, encrypted_len,
		                              &decrypted, &decrypted_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		printf("Decrypted data (16 of %zu bytes): %.16s\n\n", decrypted_len, decrypted);
	}

exit:
	yaca_free(encrypted);
	yaca_free(decrypted);
	yaca_key_destroy(rsa_priv);
	yaca_key_destroy(rsa_pub);

	yaca_cleanup();
	return ret;
}
//! [Private RSA Encrypt API example]
