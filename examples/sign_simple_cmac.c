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
 * @file sign_simple_cmac.c
 * @brief Simple CMAC Signature API example.
 */

//! [Simple CMAC Signature API example]
#include <stdio.h>

#include <yaca_crypto.h>
#include <yaca_key.h>
#include <yaca_error.h>
#include <yaca_simple.h>

/* include helpers functions and definitions */
#include "misc.h"

int main()
{
	int ret;
	yaca_key_h sym_key = YACA_KEY_NULL;

	char *signature1 = NULL;
	char *signature2 = NULL;
	size_t signature_len;

	ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* Key generation */
	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &sym_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* Sign */
	{
		ret = yaca_simple_calculate_cmac(YACA_ENCRYPT_AES, sym_key,
		                                 INPUT_DATA, INPUT_DATA_SIZE,
		                                 &signature1, &signature_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* display signature in hexadecimal format */
		dump_hex(signature1, signature_len, "CMAC Signature of INPUT_DATA:");
	}

	/* Verify */
	{
		ret = yaca_simple_calculate_cmac(YACA_ENCRYPT_AES, sym_key,
		                                 INPUT_DATA, INPUT_DATA_SIZE,
		                                 &signature2, &signature_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		ret = yaca_memcmp(signature1, signature2, signature_len);
		if (ret != YACA_ERROR_NONE) {
			printf("Verification failed\n");
			goto exit;
		} else {
			printf("Verification successful\n");
		}
	}

exit:
	yaca_free(signature1);
	yaca_free(signature2);
	yaca_key_destroy(sym_key);

	yaca_cleanup();
	return ret;
}
//! [Simple CMAC Signature API example]
