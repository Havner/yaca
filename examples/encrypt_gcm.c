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
 * @file encrypt_gcm.c
 * @brief AES GCM encrypt API example.
 */

//! [AES GCM encrypt API example]
#include <stdio.h>

#include <yaca_crypto.h>
#include <yaca_encrypt.h>
#include <yaca_key.h>
#include <yaca_error.h>

/* include helpers functions and definitions */
#include "misc.h"

int main()
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;

	char *encrypted = NULL;
	char *decrypted = NULL;
	size_t encrypted_len;
	size_t decrypted_len;

	char *aad = NULL;
	char *tag = NULL;
	size_t aad_len = 16;
	size_t tag_len = 16;

	size_t block_len;
	size_t output_len;
	size_t written_len;

	ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		goto exit;

	printf("Plain data (16 of %zu bytes): %.16s\n", INPUT_DATA_SIZE, INPUT_DATA);

	/* Key generation */
	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* IV generation */
	ret = yaca_key_generate(YACA_KEY_TYPE_IV, YACA_KEY_LENGTH_IV_128BIT, &iv);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* Additional Authentication Data generation */
	ret = yaca_zalloc(aad_len, (void**)&aad);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_randomize_bytes(aad, aad_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* Encryption */
	{
		/* Initialize encryption context */
		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, iv);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Get output length for the update */
		ret = yaca_context_get_output_length(ctx, INPUT_DATA_SIZE, &output_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Get output length for the finalize */
		ret = yaca_context_get_output_length(ctx, 0, &block_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Calculate max output length and allocate memory */
		encrypted_len = output_len + block_len;
		ret = yaca_zalloc(encrypted_len, (void**)&encrypted);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Provide Additional Authentication Data */
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Encrypt data */
		ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		encrypted_len = written_len;

		ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		encrypted_len += written_len;

		/* Resize output buffer */
		ret = yaca_realloc(encrypted_len, (void**)&encrypted);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Set the tag length and get the tag */
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG_LEN, &tag_len, sizeof(tag_len));
		if (ret != YACA_ERROR_NONE)
			goto exit;

		ret = yaca_context_get_property(ctx, YACA_PROPERTY_GCM_TAG, (void**)&tag, &tag_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* display encrypted data in hexadecimal format */
		dump_hex(encrypted, 16, "Encrypted data (16 of %zu bytes): ", encrypted_len);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* Decryption */
	{
		/* Initialize decryption context */
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, iv);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Get output length for the update */
		ret = yaca_context_get_output_length(ctx, encrypted_len, &output_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Get output length for the finalize */
		ret = yaca_context_get_output_length(ctx, 0, &block_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Calculate max output length and allocate memory */
		decrypted_len = output_len + block_len;
		ret = yaca_zalloc(decrypted_len, (void**)&decrypted);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Provide Additional Authentication Data */
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		/* Decrypt data */
		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		decrypted_len = written_len;

		/* Set expected tag value before final decryption */
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag, tag_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		decrypted_len += written_len;

		/* Resize output buffer */
		ret = yaca_realloc(decrypted_len, (void**)&decrypted);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		printf("Decrypted data (16 of %zu bytes): %.16s\n\n", decrypted_len, decrypted);
	}

exit:
	yaca_free(decrypted);
	yaca_free(encrypted);
	yaca_free(tag);
	yaca_free(aad);
	yaca_context_destroy(ctx);
	yaca_key_destroy(iv);
	yaca_key_destroy(key);

	yaca_cleanup();
	return ret;
}
//! [AES GCM encrypt API example]
