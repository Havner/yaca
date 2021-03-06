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
 * @file sign.c
 * @brief Signature API example.
 */

//! [Signature API example]
#include <stdio.h>

#include <yaca_crypto.h>
#include <yaca_sign.h>
#include <yaca_key.h>
#include <yaca_error.h>

/* include helpers functions and definitions */
#include "misc.h"

int main()
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h priv_key = YACA_KEY_NULL;
	yaca_key_h pub_key = YACA_KEY_NULL;
	yaca_padding_e padding = YACA_PADDING_PKCS1_PSS;

	char *signature = NULL;
	size_t signature_len;

	ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* Generate key pair */
	ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_2048BIT, &priv_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_extract_public(priv_key, &pub_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* Sign */
	{
		/* Initialize sign context */
		ret = yaca_sign_initialize(&ctx, YACA_DIGEST_SHA256, priv_key);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Set padding method */
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, &padding, sizeof(padding));
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Feeds the message */
		ret = yaca_sign_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Get signature length and allocate memory */
		ret = yaca_context_get_output_length(ctx, 0, &signature_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		ret = yaca_malloc(signature_len, (void**)&signature);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Calculate signature */
		ret = yaca_sign_finalize(ctx, signature, &signature_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* display signature in hexadecimal format */
		dump_hex(signature, signature_len, "Signature of INPUT_DATA:");

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* Verify */
	{
		/* Initialize verify context */
		ret = yaca_verify_initialize(&ctx, YACA_DIGEST_SHA256, pub_key);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Set padding method */
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, &padding, sizeof(padding));
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Feeds the message */
		ret = yaca_verify_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Verify signature */
		ret = yaca_verify_finalize(ctx, signature, signature_len);
		if (ret != YACA_ERROR_NONE) {
			printf("Verification failed\n");
			goto exit;
		} else {
			printf("Verification successful\n");
		}
	}

exit:
	yaca_free(signature);
	yaca_key_destroy(priv_key);
	yaca_key_destroy(pub_key);
	yaca_context_destroy(ctx);

	yaca_cleanup();
	return ret;
}
//! [Signature API example]
