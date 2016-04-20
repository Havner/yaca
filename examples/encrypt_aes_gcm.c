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
 * @file encrypt_aes_gcm.c
 * @brief
 */

#include <stdio.h>

#include <yaca/crypto.h>
#include <yaca/encrypt.h>
#include <yaca/key.h>
#include <yaca/types.h>
#include <yaca/error.h>

#include "lorem.h"
#include "misc.h"

// Symmetric aes gcm encryption using advanced API
void encrypt_decrypt_aes_gcm(void)
{
	int ret;

	yaca_ctx_h ctx = YACA_CTX_NULL;

	yaca_key_h key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;
	yaca_key_h aad_key = YACA_KEY_NULL; // add YACA_YACA_KEY_TYPE_AAD ?

	char *plaintext = NULL;
	char *ciphertext = NULL;
	char *aad = NULL;
	char *tag = NULL;
	size_t plaintext_len;
	size_t ciphertext_len;
	size_t aad_len;
	size_t tag_len;

	printf("Plain data (16 of %zu bytes): %.16s\n", (size_t)4096, lorem4096);

	/// Key generation

	ret = yaca_key_gen(&key, YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_256BIT); // key_type, key_len, *key ? looks imo much better
	if (ret < 0)
		goto clean;

	// use YACA_KEY_IV_128BIT & YACA_KEY_TYPE_IV or maybe YACA_KEY_128BIT & YACA_KEY_TYPE_SYMMETRIC ?
	ret = yaca_key_gen(&iv, YACA_KEY_TYPE_IV, YACA_KEY_IV_128BIT);
	if (ret < 0)
		goto clean;

	// use YACA_KEY_128BIT & YACA_KEY_TYPE_SYMMETRIC or maybe add YACA_KEY_AAD_128BIT & YACA_KEY_TYPE_AAD ?
	ret = yaca_key_gen(&aad_key, YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_UNSAFE_128BIT);
	if (ret < 0)
		goto clean;

	// generate and export aad?
	ret = yaca_key_export(aad_key, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_RAW, &aad, &aad_len);
	if (ret < 0)
		goto clean;

	/// Encryption
	{
		ret = yaca_encrypt_init(&ctx, YACA_ENC_AES, YACA_BCM_GCM, key, iv);
		if (ret < 0)
			goto clean;

		ret = yaca_ctx_set_param(ctx, YACA_PARAM_GCM_AAD, aad, aad_len);
		if (ret < 0)
			goto clean;

		ret = yaca_encrypt_update(ctx, lorem4096, 4096, NULL, &ciphertext_len);
		if (ret != 42)
			goto clean;// TODO: what error code?

		ret = yaca_get_block_length(ctx);
		if (ret < 0)
			goto clean;

		ciphertext_len += ret ; // Add block size for finalize
		ciphertext = yaca_malloc(ciphertext_len);
		if (ciphertext == NULL)
			goto clean;

		size_t len;
		ret = yaca_encrypt_update(ctx, lorem4096, 4096, ciphertext, &len);
		if (ret < 0)
			goto clean;

		ciphertext_len = len;

		ret = yaca_encrypt_final(ctx, ciphertext + len, &len);
		if (ret < 0)
			goto clean;

		ciphertext_len += len;

		ret = yaca_ctx_get_param(ctx, YACA_PARAM_GCM_TAG, (void*)&tag, &tag_len);
		if (ret < 0)
			goto clean;

		dump_hex(ciphertext, 16, "Encrypted data (16 of %zu bytes): ", ciphertext_len);

		yaca_ctx_free(ctx); // TODO: perhaps it should not return value
	}

	/// Decryption
	{
		size_t len;

		ret = yaca_decrypt_init(&ctx, YACA_ENC_AES, YACA_BCM_GCM, key, iv);
		if (ret < 0)
			goto clean;

		ret = yaca_ctx_set_param(ctx, YACA_PARAM_GCM_AAD, aad, aad_len);
		if (ret < 0)
			goto clean;

		ret = yaca_decrypt_update(ctx, ciphertext, ciphertext_len, NULL, &plaintext_len);
		if (ret != 42)
			goto clean; // TODO: what error code?

		ret = yaca_get_block_length(ctx);
		if (ret < 0)
			goto clean;

		plaintext_len += ret; // Add block size for finalize
		plaintext = yaca_malloc(plaintext_len);
		if (plaintext == NULL)
			goto clean;

		ret = yaca_decrypt_update(ctx, ciphertext, ciphertext_len, plaintext, &len);
		if (ret < 0)
			goto clean;

		plaintext_len = len;

		ret = yaca_ctx_set_param(ctx, YACA_PARAM_GCM_TAG, tag, tag_len);
		if (ret < 0)
			goto clean;

		ret = yaca_encrypt_final(ctx, plaintext + len, &len);
		if (ret < 0)
			goto clean;

		plaintext_len += len;

		printf("Decrypted data (16 of %zu bytes): %.16s\n", plaintext_len, plaintext);

		yaca_ctx_free(ctx);
	}

clean:
	yaca_free(plaintext);
	yaca_free(ciphertext);
	yaca_free(tag);
	yaca_free(aad);
	yaca_ctx_free(ctx);
	yaca_key_free(aad_key);
	yaca_key_free(iv);
	yaca_key_free(key);
}

int main()
{
	yaca_error_set_debug_func(debug_func);

	int ret = yaca_init();
	if (ret < 0)
		return ret;

	encrypt_decrypt_aes_gcm();

	yaca_exit(); // TODO: what about handing of return value from exit??
	return ret;
}
