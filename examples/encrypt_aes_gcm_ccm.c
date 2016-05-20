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

#include <yaca/crypto.h>
#include <yaca/encrypt.h>
#include <yaca/key.h>
#include <yaca/error.h>

#include "lorem.h"
#include "misc.h"
#include "../src/debug.h"

void encrypt_decrypt_aes_gcm(void)
{
	yaca_enc_algo_e algo = YACA_ENC_AES;
	yaca_block_cipher_mode_e bcm = YACA_BCM_GCM;
	yaca_key_type_e key_type = YACA_KEY_TYPE_SYMMETRIC;
	size_t key_bits = YACA_KEY_256BIT;
	size_t iv_bits = YACA_KEY_IV_128BIT;

	yaca_ctx_h ctx = YACA_CTX_NULL;
	yaca_key_h key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;

	char *enc = NULL;
	char *dec = NULL;
	size_t enc_size;
	size_t dec_size;

	char *aad = NULL;
	char *tag = NULL;
	size_t aad_size = 16;
	size_t tag_size = 16;

	size_t block_len;
	size_t output_len;
	size_t out_size;
	size_t rem;

	printf("AES GCM 256bit key encryption/decryption\n");
	printf("Plain data (16 of %zu bytes): %.16s\n", LOREM4096_SIZE, lorem4096);

	/* Key generation */
	if (yaca_key_gen(&key, key_type, key_bits) != 0)
		return;

	/* IV generation */
	if (yaca_key_gen(&iv, YACA_KEY_TYPE_IV, iv_bits) != 0)
		goto clean;

	if ((aad = yaca_zalloc(aad_size)) == NULL)
		goto clean;

	if (yaca_rand_bytes(aad, aad_size) != 0)
		goto clean;

	if ((tag = yaca_zalloc(tag_size)) == NULL)
		goto clean;

	/* Encryption */
	{
		if (yaca_encrypt_init(&ctx, algo, bcm, key, iv) != 0)
			goto clean;

		/* Provide any AAD data */
		if (yaca_ctx_set_param(ctx, YACA_PARAM_GCM_AAD, aad, aad_size) != 0)
			goto clean;

		if (yaca_get_block_length(ctx, &block_len) != 0)
			goto clean;

		if (yaca_get_output_length(ctx, LOREM4096_SIZE, &output_len) != 0)
			goto clean;

		/* Calculate max output: size of update + final chunks */
		enc_size = output_len + block_len;
		if ((enc = yaca_malloc(enc_size)) == NULL)
			goto clean;

		out_size = enc_size;
		if (yaca_encrypt_update(ctx, lorem4096, LOREM4096_SIZE, enc, &out_size) != 0)
			goto clean;

		rem = enc_size - out_size;
		if (yaca_encrypt_final(ctx, enc + out_size, &rem) != 0)
			goto clean;

		enc_size = rem + out_size;

		/* Set the tag length and get the tag after final encryption */
		if (yaca_ctx_set_param(ctx, YACA_PARAM_GCM_TAG_LEN,
		                       (void*)&tag_size, sizeof(tag_size)) != 0)
			goto clean;

		if (yaca_ctx_get_param(ctx, YACA_PARAM_GCM_TAG, (void**)tag, &tag_size) != 0)
			goto clean;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_size);

		yaca_ctx_free(ctx);
		ctx = YACA_CTX_NULL;
	}

	/* Decryption */
	{
		if (yaca_decrypt_init(&ctx, algo, bcm, key, iv) != 0)
			goto clean;

		/* Provide any AAD data */
		if (yaca_ctx_set_param(ctx, YACA_PARAM_GCM_AAD, aad, aad_size) != 0)
			goto clean;

		if (yaca_get_block_length(ctx, &block_len) != 0)
			goto clean;

		if (yaca_get_output_length(ctx, LOREM4096_SIZE, &output_len) != 0)
			goto clean;

		/* Calculate max output: size of update + final chunks */
		dec_size = output_len + block_len;
		if ((dec = yaca_malloc(dec_size)) == NULL)
			goto clean;

		out_size = dec_size;
		if (yaca_decrypt_update(ctx, enc, enc_size, dec, &out_size) != 0)
			goto clean;

		rem = dec_size - out_size;

		/* Set expected tag value before final decryption */
		if (yaca_ctx_set_param(ctx, YACA_PARAM_GCM_TAG, tag, tag_size) != 0)
			goto clean;

		if (yaca_decrypt_final(ctx, dec + out_size, &rem) != 0)
			goto clean;

		dec_size = rem + out_size;

		printf("Decrypted data (16 of %zu bytes): %.16s\n\n", dec_size, dec);
	}

clean:
	yaca_free(enc);
	yaca_free(dec);
	yaca_free(tag);
	yaca_free(aad);
	yaca_ctx_free(ctx);
	yaca_key_free(iv);
	yaca_key_free(key);
}

void encrypt_decrypt_aes_ccm(void)
{
	yaca_enc_algo_e algo = YACA_ENC_AES;
	yaca_block_cipher_mode_e bcm = YACA_BCM_CCM;
	yaca_key_type_e key_type = YACA_KEY_TYPE_SYMMETRIC;
	size_t key_bits = YACA_KEY_256BIT;
	size_t iv_bits = YACA_KEY_IV_64BIT;

	yaca_ctx_h ctx = YACA_CTX_NULL;
	yaca_key_h key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;

	char *enc = NULL;
	char *dec = NULL;
	size_t enc_size;
	size_t dec_size;

	char *aad = NULL;
	char *tag = NULL;
	size_t aad_size = 16;
	size_t tag_size = 12;

	size_t block_len;
	size_t output_len;
	size_t out_size;
	size_t rem;
	size_t len;

	printf("AES CCM 256bit key encryption/decryption\n");
	printf("Plain data (16 of %zu bytes): %.16s\n", LOREM4096_SIZE, lorem4096);

	/* Key generation */
	if (yaca_key_gen(&key, key_type, key_bits) != 0)
		return;

	/* IV generation */
	if (yaca_key_gen(&iv, YACA_KEY_TYPE_IV, iv_bits) != 0)
		goto clean;

	if ((aad = yaca_zalloc(aad_size)) == NULL)
		goto clean;

	if (yaca_rand_bytes(aad, aad_size) != 0)
		goto clean;

	if ((tag = yaca_zalloc(tag_size)) == NULL)
		goto clean;

	/* Encryption */
	{
		if (yaca_encrypt_init(&ctx, algo, bcm, key, iv) != 0)
			goto clean;

		/* Set tag length (optionally) */
		if (yaca_ctx_set_param(ctx, YACA_PARAM_CCM_TAG_LEN,
		                       (void*)&tag_size, sizeof(tag_size)) != 0)
			goto clean;

		/* The total plain text length must be passed (only needed if AAD is passed) */
		if (yaca_encrypt_update(ctx, NULL, LOREM4096_SIZE , NULL, &len) != 0)
			goto clean;

		if (yaca_ctx_set_param(ctx, YACA_PARAM_CCM_AAD, aad, aad_size) != 0)
			goto clean;

		if (yaca_get_block_length(ctx, &block_len) != 0)
			goto clean;

		if (yaca_get_output_length(ctx, LOREM4096_SIZE, &output_len) != 0)
			goto clean;

		/* Calculate max output: size of update + final chunks */
		enc_size = output_len + block_len;
		if ((enc = yaca_malloc(enc_size)) == NULL)
			goto clean;

		out_size = enc_size;
		if (yaca_encrypt_update(ctx, lorem4096, LOREM4096_SIZE, enc, &out_size) != 0)
			goto clean;

		rem = enc_size - out_size;
		if (yaca_encrypt_final(ctx, enc + out_size, &rem) != 0)
			goto clean;

		enc_size = rem + out_size;

		/* Get the tag after final encryption */
		if (yaca_ctx_get_param(ctx, YACA_PARAM_CCM_TAG, (void**)tag, &tag_size) != 0)
			goto clean;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_size);

		yaca_ctx_free(ctx);
		ctx = YACA_CTX_NULL;
	}

	/* Decryption */
	{
		if (yaca_decrypt_init(&ctx, algo, bcm, key, iv) != 0)
			goto clean;

		/* Set expected tag value */
		if (yaca_ctx_set_param(ctx, YACA_PARAM_CCM_TAG, tag, tag_size) != 0)
			goto clean;

		/* The total encrypted text length must be passed (only needed if AAD is passed) */
		if (yaca_decrypt_update(ctx, NULL, enc_size , NULL, &len) != 0)
			goto clean;

		if (yaca_ctx_set_param(ctx, YACA_PARAM_CCM_AAD, aad, aad_size) != 0)
			goto clean;

		if (yaca_get_block_length(ctx, &block_len) != 0)
			goto clean;

		if (yaca_get_output_length(ctx, LOREM4096_SIZE, &output_len) != 0)
			goto clean;

		/* Calculate max output: size of update + final chunks */
		dec_size = output_len + block_len;
		if ((dec = yaca_malloc(dec_size)) == NULL)
			goto clean;

		out_size = dec_size;
		/* The tag verify is performed when you call the final yaca_decrypt_update(),
		 * there is no call to yaca_decrypt_final() */
		if (yaca_decrypt_update(ctx, enc, enc_size, dec, &out_size) != 0)
			goto clean;

		dec_size = out_size;

		printf("Decrypted data (16 of %zu bytes): %.16s\n\n", dec_size, dec);
	}

clean:
	yaca_free(enc);
	yaca_free(dec);
	yaca_free(tag);
	yaca_free(aad);
	yaca_ctx_free(ctx);
	yaca_key_free(iv);
	yaca_key_free(key);
}

int main()
{
	yaca_debug_set_error_cb(debug_func);

	int ret = yaca_init();
	if (ret != 0)
		return ret;

	encrypt_decrypt_aes_gcm();
	encrypt_decrypt_aes_ccm();

	yaca_exit();
	return ret;
}
