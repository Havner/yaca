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
 * @file encrypt_simple.c
 * @brief Simple Encrypt API example.
 */

//! [Simple Encrypt API example]
#include <stdio.h>

#include <yaca_crypto.h>
#include <yaca_simple.h>
#include <yaca_encrypt.h>
#include <yaca_key.h>
#include <yaca_error.h>

/* include helpers functions and definitions */
#include "misc.h"

int main()
{
	int ret;
	yaca_key_h key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;
	size_t iv_bit_len;

	char *encrypted = NULL;
	char *decrypted = NULL;
	size_t encrypted_len;
	size_t decrypted_len;

	ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		goto exit;

	printf("Plain data (16 of %zu bytes): %.16s\n", INPUT_DATA_SIZE, INPUT_DATA);

	/* Key generation */
	ret = yaca_key_derive_pbkdf2("foo bar", "123456789", 10, 1000,
	                             YACA_DIGEST_SHA256, YACA_KEY_LENGTH_256BIT, &key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* IV generation */
	ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_AES, YACA_BCM_CTR, YACA_KEY_LENGTH_256BIT,
	                                     &iv_bit_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	if (iv_bit_len > 0) {
		ret = yaca_key_generate(YACA_KEY_TYPE_IV, iv_bit_len, &iv);
		if (ret != YACA_ERROR_NONE)
			goto exit;
	}

	/* Encryption */
	{
		ret = yaca_simple_encrypt(YACA_ENCRYPT_AES, YACA_BCM_CTR, key, iv,
		                          INPUT_DATA, INPUT_DATA_SIZE, &encrypted, &encrypted_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* display encrypted data in hexadecimal format */
		dump_hex(encrypted, 16, "Encrypted data (16 of %zu bytes): ", encrypted_len);
	}

	/* Decryption */
	{
		ret = yaca_simple_decrypt(YACA_ENCRYPT_AES, YACA_BCM_CTR, key, iv,
		                          encrypted, encrypted_len, &decrypted, &decrypted_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		printf("Decrypted data (16 of %zu bytes): %.16s\n\n", decrypted_len, decrypted);
	}

exit:
	yaca_free(encrypted);
	yaca_free(decrypted);
	yaca_key_destroy(iv);
	yaca_key_destroy(key);

	yaca_cleanup();
	return ret;
}
//! [Simple Encrypt API example]
