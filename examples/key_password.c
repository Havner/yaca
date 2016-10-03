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
 * @file key_password.c
 * @brief Key import/export with password API example.
 */

//! [Key import/export with password API example]
#include <stdio.h>

#include <yaca_crypto.h>
#include <yaca_key.h>
#include <yaca_error.h>

/* include helpers functions and definitions */
#include  "misc.h"

int main()
{
	int ret;
	yaca_key_h key = YACA_KEY_NULL;
	char *password = NULL;
	char *key_data = NULL;
	size_t key_data_len;

	ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_2048BIT, &key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* Export key */
	{
		ret = read_stdin_line("encryption pass: ", &password);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		ret = yaca_key_export(key, YACA_KEY_FORMAT_PKCS8, YACA_KEY_FILE_FORMAT_PEM, password,
		                      &key_data, &key_data_len);
		if (ret == YACA_ERROR_INVALID_PARAMETER)
			printf("invalid parameter, probably a missing password for PKCS8\n");
		if (ret != YACA_ERROR_NONE)
			goto exit;

		yaca_key_destroy(key);
		key = YACA_KEY_NULL;
		yaca_free(password);
		password = NULL;
	}

	/* Import key */
	{
		ret = read_stdin_line("decryption pass: ", &password);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		ret = yaca_key_import(YACA_KEY_TYPE_RSA_PRIV, password, key_data, key_data_len, &key);
		if (ret == YACA_ERROR_INVALID_PASSWORD)
			printf("invalid password\n");
		if (ret != YACA_ERROR_NONE)
			goto exit;

		yaca_free(key_data);
		key_data = NULL;

		ret = yaca_key_export(key, YACA_KEY_FORMAT_PKCS8, YACA_KEY_FILE_FORMAT_PEM, password,
		                      &key_data, &key_data_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		printf("%.*s", (int)key_data_len, key_data);
	}

exit:
	yaca_free(key_data);
	yaca_free(password);
	yaca_key_destroy(key);

	yaca_cleanup();
	return ret;
}
//! [Key import/export with password API example]
