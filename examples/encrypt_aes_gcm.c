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

#include <crypto/crypto.h>
#include <crypto/encrypt.h>
#include <crypto/key.h>
#include <crypto/types.h>

#include "lorem.h"
#include "misc.h"

// Symmetric aes gcm encryption using advanced API
void encrypt_decrypt_aes_gcm(void)
{
	int ret;

	crypto_ctx_h ctx;

	crypto_key_h key = CRYPTO_KEY_NULL;
	crypto_key_h iv = CRYPTO_KEY_NULL;
	crypto_key_h aad_key = CRYPTO_KEY_NULL; // add CRYPTO_CRYPTO_KEY_TYPE_AAD ?

	char *plaintext = NULL, *ciphertext = NULL, *aad = NULL, *tag = NULL;
	size_t plaintext_len, ciphertext_len, aad_len, tag_len;

	printf("Plain data (16 of %zu bytes): %.16s\n", (size_t)4096, lorem4096);

	/// Key generation

	ret = crypto_key_gen(&key, CRYPTO_KEY_256BIT, CRYPTO_KEY_TYPE_SYMMETRIC); // key_type, key_len, *key ? looks imo much better
	if (ret) goto clean;

	// use CRYPTO_KEY_IV_128BIT & CRYPTO_KEY_TYPE_IV or maybe CRYPTO_KEY_128BIT & CRYPTO_KEY_TYPE_SYMMETRIC ?
	ret = crypto_key_gen(&iv, CRYPTO_KEY_IV_128BIT, CRYPTO_KEY_TYPE_IV);
	if (ret) goto clean;

	// use CRYPTO_KEY_128BIT & CRYPTO_KEY_TYPE_SYMMETRIC or maybe add CRYPTO_KEY_AAD_128BIT & CRYPTO_KEY_TYPE_AAD ?
	ret = crypto_key_gen(&aad_key, CRYPTO_KEY_UNSAFE_128BIT, CRYPTO_KEY_TYPE_SYMMETRIC);
	if (ret) goto clean;

	// generate and export aad?
	ret = crypto_key_export(aad_key, CRYPTO_KEY_FORMAT_RAW, &aad, &aad_len);
	if (ret) goto clean;

	/// Encryption
	{
		ret = crypto_encrypt_init(&ctx, CRYPTO_ENC_AES, CRYPTO_BCM_GCM, key, iv);
		if (ret) goto clean;

		ret = crypto_ctx_set_param(ctx, CRYPTO_PARAM_GCM_AAD, aad, aad_len);
		if (ret) goto clean;

		ret = crypto_encrypt_update(ctx, lorem4096, 4096, NULL, &ciphertext_len);
		if (ret != 42) goto clean;// TODO: what error code?

		ret = crypto_get_block_length(ctx);
		if (ret) goto clean;

		ciphertext_len += ret ; // Add block size for finalize
		ciphertext = crypto_alloc(ciphertext_len);
		if (!ciphertext) goto clean;

		size_t len;
		ret = crypto_encrypt_update(ctx, lorem4096, 4096, ciphertext, &len);
		if (ret) goto clean;

		ciphertext_len = len;

		ret = crypto_encrypt_final(ctx, ciphertext + len, &len);
		if (ret) goto clean;

		ciphertext_len += len;

		ret = crypto_ctx_get_param(ctx, CRYPTO_PARAM_GCM_TAG, (void*)&tag, &tag_len);
		if (ret) goto clean;

		dump_hex(ciphertext, 16, "Encrypted data (16 of %zu bytes): ", ciphertext_len);

		crypto_ctx_free(ctx); // TODO: perhaps it should not return value
	}

	/// Decryption
	{
		ret = crypto_decrypt_init(&ctx, CRYPTO_ENC_AES, CRYPTO_BCM_GCM, key, iv);
		if (ret) goto clean;

		ret = crypto_ctx_set_param(ctx, CRYPTO_PARAM_GCM_AAD, aad, aad_len);
		if (ret) goto clean;

		ret = crypto_decrypt_update(ctx, ciphertext, ciphertext_len, NULL, &plaintext_len);
		if (ret != 42) goto clean; // TODO: what error code?

		ret = crypto_get_block_length(ctx);
		if (ret) goto clean;

		plaintext_len += ret; // Add block size for finalize
		plaintext = crypto_alloc(plaintext_len);
		if (!plaintext) goto clean;

		size_t len;
		ret = crypto_decrypt_update(ctx, ciphertext, ciphertext_len, plaintext, &len);
		if (ret) goto clean;

		plaintext_len = len;

		ret = crypto_ctx_set_param(ctx, CRYPTO_PARAM_GCM_TAG, tag, tag_len);
		if (ret) goto clean;

		ret = crypto_encrypt_final(ctx, plaintext + len, &len);
		if (ret) goto clean;

		plaintext_len += len;

		printf("Decrypted data (16 of %zu bytes): %.16s\n", plaintext_len, plaintext);

		crypto_ctx_free(ctx);
	}

clean:
	crypto_free(plaintext);
	crypto_free(ciphertext);
	crypto_free(tag);
	crypto_free(aad);
	crypto_ctx_free(ctx);
	crypto_key_free(aad_key);
	crypto_key_free(iv);
	crypto_key_free(key);
}

int main()
{
	int ret = 0;
	if ((ret = crypto_init()))
		return ret;

	encrypt_decrypt_aes_gcm();

	crypto_exit(); // TODO: what about handing of return value from exit??
	return ret;
}
