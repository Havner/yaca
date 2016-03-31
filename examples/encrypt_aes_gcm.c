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

	owl_ctx_h ctx;

	owl_key_h key = OWL_KEY_NULL;
	owl_key_h iv = OWL_KEY_NULL;
	owl_key_h aad_key = OWL_KEY_NULL; // add OWL_OWL_KEY_TYPE_AAD ?

	char *plaintext = NULL, *ciphertext = NULL, *aad = NULL, *tag = NULL;
	size_t plaintext_len, ciphertext_len, aad_len, tag_len;

	printf("Plain data (16 of %zu bytes): %.16s\n", (size_t)4096, lorem4096);

	/// Key generation

	ret = owl_key_gen(&key, OWL_KEY_256BIT, OWL_KEY_TYPE_SYMMETRIC); // key_type, key_len, *key ? looks imo much better
	if (ret) goto clean;

	// use OWL_KEY_IV_128BIT & OWL_KEY_TYPE_IV or maybe OWL_KEY_128BIT & OWL_KEY_TYPE_SYMMETRIC ?
	ret = owl_key_gen(&iv, OWL_KEY_IV_128BIT, OWL_KEY_TYPE_IV);
	if (ret) goto clean;

	// use OWL_KEY_128BIT & OWL_KEY_TYPE_SYMMETRIC or maybe add OWL_KEY_AAD_128BIT & OWL_KEY_TYPE_AAD ?
	ret = owl_key_gen(&aad_key, OWL_KEY_UNSAFE_128BIT, OWL_KEY_TYPE_SYMMETRIC);
	if (ret) goto clean;

	// generate and export aad?
	ret = owl_key_export(aad_key, OWL_KEY_FORMAT_RAW, &aad, &aad_len);
	if (ret) goto clean;

	/// Encryption
	{
		ret = owl_encrypt_init(&ctx, OWL_ENC_AES, OWL_BCM_GCM, key, iv);
		if (ret) goto clean;

		ret = owl_ctx_set_param(ctx, OWL_PARAM_GCM_AAD, aad, aad_len);
		if (ret) goto clean;

		ret = owl_encrypt_update(ctx, lorem4096, 4096, NULL, &ciphertext_len);
		if (ret != 42) goto clean;// TODO: what error code?

		ret = owl_get_block_length(ctx);
		if (ret) goto clean;

		ciphertext_len += ret ; // Add block size for finalize
		ciphertext = owl_alloc(ciphertext_len);
		if (!ciphertext) goto clean;

		size_t len;
		ret = owl_encrypt_update(ctx, lorem4096, 4096, ciphertext, &len);
		if (ret) goto clean;

		ciphertext_len = len;

		ret = owl_encrypt_final(ctx, ciphertext + len, &len);
		if (ret) goto clean;

		ciphertext_len += len;

		ret = owl_ctx_get_param(ctx, OWL_PARAM_GCM_TAG, (void*)&tag, &tag_len);
		if (ret) goto clean;

		dump_hex(ciphertext, 16, "Encrypted data (16 of %zu bytes): ", ciphertext_len);

		owl_ctx_free(ctx); // TODO: perhaps it should not return value
	}

	/// Decryption
	{
		ret = owl_decrypt_init(&ctx, OWL_ENC_AES, OWL_BCM_GCM, key, iv);
		if (ret) goto clean;

		ret = owl_ctx_set_param(ctx, OWL_PARAM_GCM_AAD, aad, aad_len);
		if (ret) goto clean;

		ret = owl_decrypt_update(ctx, ciphertext, ciphertext_len, NULL, &plaintext_len);
		if (ret != 42) goto clean; // TODO: what error code?

		ret = owl_get_block_length(ctx);
		if (ret) goto clean;

		plaintext_len += ret; // Add block size for finalize
		plaintext = owl_alloc(plaintext_len);
		if (!plaintext) goto clean;

		size_t len;
		ret = owl_decrypt_update(ctx, ciphertext, ciphertext_len, plaintext, &len);
		if (ret) goto clean;

		plaintext_len = len;

		ret = owl_ctx_set_param(ctx, OWL_PARAM_GCM_TAG, tag, tag_len);
		if (ret) goto clean;

		ret = owl_encrypt_final(ctx, plaintext + len, &len);
		if (ret) goto clean;

		plaintext_len += len;

		printf("Decrypted data (16 of %zu bytes): %.16s\n", plaintext_len, plaintext);

		owl_ctx_free(ctx);
	}

clean:
	owl_free(plaintext);
	owl_free(ciphertext);
	owl_free(tag);
	owl_free(aad);
	owl_ctx_free(ctx);
	owl_key_free(aad_key);
	owl_key_free(iv);
	owl_key_free(key);
}

int main()
{
	int ret = 0;
	if ((ret = owl_init()))
		return ret;

	encrypt_decrypt_aes_gcm();

	owl_exit(); // TODO: what about handing of return value from exit??
	return ret;
}
