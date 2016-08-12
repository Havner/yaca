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
 * @file key_wrap.c
 * @brief
 */

#include <stdio.h>
#include <stdlib.h>

#include <yaca_crypto.h>
#include <yaca_simple.h>
#include <yaca_encrypt.h>
#include <yaca_key.h>
#include <yaca_error.h>

#include "misc.h"

void key_wrap_aes(void)
{
	int ret;
	yaca_key_h sym_key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;
	yaca_key_h aes_key = YACA_KEY_NULL;

	size_t iv_bit_len;
	char *key_data = NULL;
	size_t key_data_len;
	char *wrapped_key = NULL;
	size_t wrapped_key_len;

	printf("\n***** AES key wrapping ******\n");

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &aes_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_192BIT, &sym_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_AES,
	                                     YACA_BCM_WRAP,
	                                     YACA_KEY_LENGTH_192BIT,
	                                     &iv_bit_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	if (iv_bit_len > 0) {
		ret = yaca_key_generate(YACA_KEY_TYPE_IV, iv_bit_len, &iv);
		if (ret != YACA_ERROR_NONE)
			goto exit;
	}

	/* Key wrapping */
	{
		ret = yaca_key_export(aes_key, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_RAW, NULL,
		                      &key_data, &key_data_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		ret = yaca_simple_encrypt(YACA_ENCRYPT_AES, YACA_BCM_WRAP, sym_key, iv,
		                          key_data, key_data_len,
		                          &wrapped_key, &wrapped_key_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		dump_hex(key_data, key_data_len, "***** Unwrapped key:*****");
		dump_hex(wrapped_key, wrapped_key_len, "***** Wrapped key:*****");
	}

	yaca_free(key_data);
	key_data = NULL;
	yaca_key_destroy(aes_key);
	aes_key = YACA_KEY_NULL;

	/* Key unwrapping */
	{
		ret = yaca_simple_decrypt(YACA_ENCRYPT_AES, YACA_BCM_WRAP, sym_key, iv,
		                          wrapped_key, wrapped_key_len,
		                          &key_data, &key_data_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		ret = yaca_key_import(YACA_KEY_TYPE_SYMMETRIC, NULL, key_data, key_data_len, &aes_key);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		dump_hex(key_data, key_data_len, "***** Unwrapped key:*****");
	}

exit:
	yaca_key_destroy(aes_key);
	yaca_key_destroy(sym_key);
	yaca_key_destroy(iv);
	yaca_free(key_data);
	yaca_free(wrapped_key);
}

void key_wrap_des(void)
{
	int ret;
	yaca_key_h sym_key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;
	yaca_key_h des_key = YACA_KEY_NULL;

	size_t iv_bit_len;
	char *key_data = NULL;
	size_t key_data_len;
	char *wrapped_key = NULL;
	size_t wrapped_key_len;

	printf("\n***** 3DES key wrapping ******\n");

	ret = yaca_key_generate(YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_192BIT, &des_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_generate(YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_192BIT, &sym_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_3DES_3TDEA,
	                                     YACA_BCM_WRAP,
	                                     YACA_KEY_LENGTH_192BIT,
	                                     &iv_bit_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	if (iv_bit_len > 0) {
		ret = yaca_key_generate(YACA_KEY_TYPE_IV, iv_bit_len, &iv);
		if (ret != YACA_ERROR_NONE)
			goto exit;
	}

	/* Key wrapping */
	{
		ret = yaca_key_export(des_key, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_RAW, NULL,
		                      &key_data, &key_data_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		ret = yaca_simple_encrypt(YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_WRAP, sym_key, iv,
		                          key_data, key_data_len,
		                          &wrapped_key, &wrapped_key_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		dump_hex(key_data, key_data_len, "***** Unwrapped key:*****");
		dump_hex(wrapped_key, wrapped_key_len, "***** Wrapped key:*****");
	}

	yaca_free(key_data);
	key_data = NULL;
	yaca_key_destroy(des_key);
	des_key = YACA_KEY_NULL;

	/* Key unwrapping */
	{
		ret = yaca_simple_decrypt(YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_WRAP, sym_key, iv,
		                          wrapped_key, wrapped_key_len,
		                          &key_data, &key_data_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		ret = yaca_key_import(YACA_KEY_TYPE_DES, NULL, key_data, key_data_len, &des_key);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		dump_hex(key_data, key_data_len, "***** Unwrapped key:*****");
	}

exit:
	yaca_key_destroy(des_key);
	yaca_key_destroy(sym_key);
	yaca_key_destroy(iv);
	yaca_free(key_data);
	yaca_free(wrapped_key);
}

int main()
{
	int ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		return ret;

	key_wrap_aes();
	key_wrap_des();

	yaca_cleanup();
	return ret;
}

