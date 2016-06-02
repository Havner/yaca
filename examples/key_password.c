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

#include <stdio.h>
#include <string.h>
#include <yaca_crypto.h>
#include <yaca_key.h>
#include <yaca_types.h>
#include <yaca_error.h>
#include "misc.h"
#include "../src/debug.h"

void example_password(const yaca_key_h key, yaca_key_fmt_e key_fmt)
{
	char *k = NULL;
	size_t kl;
	int ret;
	char *password = NULL;
	yaca_key_h lkey = YACA_KEY_NULL;

	ret = read_stdin_line("encryption pass: ", &password);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_export(key, key_fmt, YACA_KEY_FILE_FORMAT_PEM, password, &k, &kl);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	yaca_free(password);
	password = NULL;

	ret = yaca_key_import(YACA_KEY_TYPE_RSA_PRIV, NULL, k, kl, &lkey);
	if (ret == YACA_ERROR_PASSWORD_INVALID) {
		ret = read_stdin_line("decryption pass: ", &password);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		ret = yaca_key_import(YACA_KEY_TYPE_RSA_PRIV, password, k, kl, &lkey);
		if (ret == YACA_ERROR_PASSWORD_INVALID)
			printf("invalid password\n");

		yaca_free(password);
		password = NULL;
	}

	if (ret != YACA_ERROR_NONE)
		goto exit;

	yaca_free(k);
	k = NULL;

	ret = yaca_key_export(lkey, key_fmt, YACA_KEY_FILE_FORMAT_PEM, NULL, &k, &kl);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	printf("%.*s", (int)kl, k);

exit:
	yaca_free(k);
	yaca_free(password);
	yaca_key_free(lkey);
}

int main(int argc, char *argv[])
{
	int ret;
	yaca_key_h key = YACA_KEY_NULL;

	yaca_debug_set_error_cb(debug_func);

	ret = yaca_init();
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_gen(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_1024BIT, &key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	printf("Default format:\n");
	example_password(key, YACA_KEY_FORMAT_DEFAULT);
	printf("\nPKCS8 format:\n");
	example_password(key, YACA_KEY_FORMAT_PKCS8);

exit:
	yaca_key_free(key);
	yaca_exit();

	return 0;
}
