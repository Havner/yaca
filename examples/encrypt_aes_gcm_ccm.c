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
 * @file encrypt_aes_gcm_ccm.c
 * @brief
 */

#include <stdio.h>

#include <yaca_crypto.h>
#include <yaca_encrypt.h>
#include <yaca_key.h>
#include <yaca_error.h>

#include "lorem.h"
#include "misc.h"

void encrypt_decrypt_aes_gcm(void)
{
	yaca_encrypt_algorithm_e algo = YACA_ENCRYPT_AES;
	yaca_block_cipher_mode_e bcm = YACA_BCM_GCM;
	yaca_key_type_e key_type = YACA_KEY_TYPE_SYMMETRIC;
	size_t key_bit_len = YACA_KEY_LENGTH_256BIT;
	size_t iv_bit_len = YACA_KEY_LENGTH_IV_128BIT;

	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;

	char *enc = NULL;
	char *dec = NULL;
	size_t enc_len;
	size_t dec_len;

	char *aad = NULL;
	char *tag = NULL;
	size_t aad_len = 16;
	size_t tag_len = 16;

	size_t block_len;
	size_t output_len;
	size_t written_len;

	printf("AES GCM 256bit key encryption/decryption\n");
	printf("Plain data (16 of %zu bytes): %.16s\n", LOREM4096_SIZE, lorem4096);

	/* Key generation */
	if (yaca_key_generate(key_type, key_bit_len, &key) != YACA_ERROR_NONE)
		return;

	/* IV generation */
	if (yaca_key_generate(YACA_KEY_TYPE_IV, iv_bit_len, &iv) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_zalloc(aad_len, (void**)&aad) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_randomize_bytes(aad, aad_len) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_zalloc(tag_len, (void**)&tag) != YACA_ERROR_NONE)
		goto exit;

	/* Encryption */
	{
		if (yaca_encrypt_initialize(&ctx, algo, bcm, key, iv) != YACA_ERROR_NONE)
			goto exit;

		/* Provide any AAD data */
		if (yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len) != YACA_ERROR_NONE)
			goto exit;

		/* For the update */
		if (yaca_context_get_output_length(ctx, LOREM4096_SIZE, &output_len) != YACA_ERROR_NONE)
			goto exit;

		/* For the finalize */
		if (yaca_context_get_output_length(ctx, 0, &block_len) != YACA_ERROR_NONE)
			goto exit;

		/* Calculate max output: size of update + final chunks */
		enc_len = output_len + block_len;
		if (yaca_malloc(enc_len, (void**)&enc) != YACA_ERROR_NONE)
			goto exit;

		if (yaca_encrypt_update(ctx, lorem4096, LOREM4096_SIZE, enc, &written_len) != YACA_ERROR_NONE)
			goto exit;

		enc_len = written_len;

		if (yaca_encrypt_finalize(ctx, enc + written_len, &written_len) != YACA_ERROR_NONE)
			goto exit;

		enc_len += written_len;

		/* Set the tag length and get the tag after final encryption */
		if (yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG_LEN,
		                              (void*)&tag_len, sizeof(tag_len)) != YACA_ERROR_NONE)
			goto exit;

		if (yaca_context_get_property(ctx, YACA_PROPERTY_GCM_TAG, (void**)tag, &tag_len) != YACA_ERROR_NONE)
			goto exit;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_len);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* Decryption */
	{
		if (yaca_decrypt_initialize(&ctx, algo, bcm, key, iv) != YACA_ERROR_NONE)
			goto exit;

		/* Provide any AAD data */
		if (yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len) != YACA_ERROR_NONE)
			goto exit;

		/* For the update */
		if (yaca_context_get_output_length(ctx, enc_len, &output_len) != YACA_ERROR_NONE)
			goto exit;

		/* For the finalize */
		if (yaca_context_get_output_length(ctx, 0, &block_len) != YACA_ERROR_NONE)
			goto exit;

		/* Calculate max output: size of update + final chunks */
		dec_len = output_len + block_len;
		if (yaca_malloc(dec_len, (void**)&dec) != YACA_ERROR_NONE)
			goto exit;

		if (yaca_decrypt_update(ctx, enc, enc_len, dec, &written_len) != YACA_ERROR_NONE)
			goto exit;

		dec_len = written_len;

		/* Set expected tag value before final decryption */
		if (yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag, tag_len) != YACA_ERROR_NONE)
			goto exit;

		if (yaca_decrypt_finalize(ctx, dec + written_len, &written_len) != YACA_ERROR_NONE)
			goto exit;

		dec_len += written_len;

		printf("Decrypted data (16 of %zu bytes): %.16s\n\n", dec_len, dec);
	}

exit:
	yaca_free(enc);
	yaca_free(dec);
	yaca_free(tag);
	yaca_free(aad);
	yaca_context_destroy(ctx);
	yaca_key_destroy(iv);
	yaca_key_destroy(key);
}

void encrypt_decrypt_aes_ccm(void)
{
	yaca_encrypt_algorithm_e algo = YACA_ENCRYPT_AES;
	yaca_block_cipher_mode_e bcm = YACA_BCM_CCM;
	yaca_key_type_e key_type = YACA_KEY_TYPE_SYMMETRIC;
	size_t key_bit_len = YACA_KEY_LENGTH_256BIT;
	size_t iv_bit_len = YACA_KEY_LENGTH_IV_64BIT;

	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;

	char *enc = NULL;
	char *dec = NULL;
	size_t enc_len;
	size_t dec_len;

	char *aad = NULL;
	char *tag = NULL;
	size_t aad_len = 16;
	size_t tag_len = 14;

	size_t block_len;
	size_t output_len;
	size_t written_len;
	size_t len;

	printf("AES CCM 256bit key encryption/decryption\n");
	printf("Plain data (16 of %zu bytes): %.16s\n", LOREM4096_SIZE, lorem4096);

	/* Key generation */
	if (yaca_key_generate(key_type, key_bit_len, &key) != YACA_ERROR_NONE)
		return;

	/* IV generation */
	if (yaca_key_generate(YACA_KEY_TYPE_IV, iv_bit_len, &iv) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_zalloc(aad_len, (void**)&aad) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_randomize_bytes(aad, aad_len) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_zalloc(tag_len, (void**)&tag) != YACA_ERROR_NONE)
		goto exit;

	/* Encryption */
	{
		if (yaca_encrypt_initialize(&ctx, algo, bcm, key, iv) != YACA_ERROR_NONE)
			goto exit;

		/* Set tag length (optionally) */
		if (yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG_LEN,
		                              (void*)&tag_len, sizeof(tag_len)) != YACA_ERROR_NONE)
			goto exit;

		/* The total plain text length must be passed (only needed if AAD is passed) */
		if (yaca_encrypt_update(ctx, NULL, LOREM4096_SIZE , NULL, &len) != YACA_ERROR_NONE)
			goto exit;

		if (yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len) != YACA_ERROR_NONE)
			goto exit;

		/* For the update */
		if (yaca_context_get_output_length(ctx, LOREM4096_SIZE, &output_len) != YACA_ERROR_NONE)
			goto exit;

		/* For the finalize */
		if (yaca_context_get_output_length(ctx, 0, &block_len) != YACA_ERROR_NONE)
			goto exit;

		/* Calculate max output: size of update + final chunks */
		enc_len = output_len + block_len;
		if (yaca_malloc(enc_len, (void**)&enc) != YACA_ERROR_NONE)
			goto exit;

		if (yaca_encrypt_update(ctx, lorem4096, LOREM4096_SIZE, enc, &written_len) != YACA_ERROR_NONE)
			goto exit;

		enc_len = written_len;

		if (yaca_encrypt_finalize(ctx, enc + written_len, &written_len) != YACA_ERROR_NONE)
			goto exit;

		enc_len += written_len;

		/* Get the tag after final encryption */
		if (yaca_context_get_property(ctx, YACA_PROPERTY_CCM_TAG, (void**)tag, &tag_len) != YACA_ERROR_NONE)
			goto exit;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_len);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* Decryption */
	{
		if (yaca_decrypt_initialize(&ctx, algo, bcm, key, iv) != YACA_ERROR_NONE)
			goto exit;

		/* Set expected tag value */
		if (yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len) != YACA_ERROR_NONE)
			goto exit;

		/* The total encrypted text length must be passed (only needed if AAD is passed) */
		if (yaca_decrypt_update(ctx, NULL, enc_len , NULL, &len) != YACA_ERROR_NONE)
			goto exit;

		if (yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len) != YACA_ERROR_NONE)
			goto exit;

		/* For the update */
		if (yaca_context_get_output_length(ctx, enc_len, &output_len) != YACA_ERROR_NONE)
			goto exit;

		/* For the finalize */
		if (yaca_context_get_output_length(ctx, 0, &block_len) != YACA_ERROR_NONE)
			goto exit;

		/* Calculate max output: size of update + final chunks */
		dec_len = output_len + block_len;
		if (yaca_malloc(dec_len, (void**)&dec) != YACA_ERROR_NONE)
			goto exit;

		if (yaca_decrypt_update(ctx, enc, enc_len, dec, &written_len) != YACA_ERROR_NONE)
			goto exit;

		dec_len = written_len;

		if (yaca_decrypt_finalize(ctx, dec + written_len, &written_len) != YACA_ERROR_NONE)
			goto exit;

		dec_len += written_len;

		printf("Decrypted data (16 of %zu bytes): %.16s\n\n", dec_len, dec);
	}

exit:
	yaca_free(enc);
	yaca_free(dec);
	yaca_free(tag);
	yaca_free(aad);
	yaca_context_destroy(ctx);
	yaca_key_destroy(iv);
	yaca_key_destroy(key);
}

int main()
{
	int ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		return ret;

	encrypt_decrypt_aes_gcm();
	encrypt_decrypt_aes_ccm();

	yaca_cleanup();
	return ret;
}
