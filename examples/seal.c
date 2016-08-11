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
 * @file seal.c
 * @brief
 */

#include <stdio.h>

#include <yaca_crypto.h>
#include <yaca_seal.h>
#include <yaca_key.h>
#include <yaca_error.h>

#include "lorem.h"
#include "misc.h"
#include "../src/debug.h"

void encrypt_seal(const yaca_encrypt_algorithm_e algo,
                  const yaca_block_cipher_mode_e bcm,
                  const size_t key_bit_len)
{
	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key_pub = YACA_KEY_NULL;
	yaca_key_h key_priv = YACA_KEY_NULL;
	yaca_key_h sym_key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;

	char *enc = NULL;
	char *dec = NULL;
	size_t enc_len;
	size_t dec_len;

	size_t block_len;
	size_t output_len;
	size_t written_len;

	printf("Plain data (16 of %zu bytes): %.16s\n", LOREM4096_SIZE, lorem4096);

	/* Generate key pair */
	if (yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_4096BIT, &key_priv) != YACA_ERROR_NONE)
		return;

	if (yaca_key_extract_public(key_priv, &key_pub) != YACA_ERROR_NONE)
		goto exit;

	/* Encrypt a.k.a. seal */
	{
		if (yaca_seal_initialize(&ctx, key_pub, algo, bcm, key_bit_len, &sym_key, &iv) != YACA_ERROR_NONE)
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

		/* Seal and finalize */
		if (yaca_seal_update(ctx, lorem4096, LOREM4096_SIZE, enc, &written_len) != YACA_ERROR_NONE)
			goto exit;

		enc_len = written_len;

		if (yaca_seal_finalize(ctx, enc + written_len, &written_len) != YACA_ERROR_NONE)
			goto exit;

		enc_len += written_len;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_len);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* Decrypt a.k.a. open */
	{
		if (yaca_open_initialize(&ctx, key_priv, algo, bcm, key_bit_len, sym_key, iv) != YACA_ERROR_NONE)
			goto exit;

		/* For the update */
		if (yaca_context_get_output_length(ctx, LOREM4096_SIZE, &output_len) != YACA_ERROR_NONE)
			goto exit;

		/* For the finalize */
		if (yaca_context_get_output_length(ctx, 0, &block_len) != YACA_ERROR_NONE)
			goto exit;

		/* Calculate max output: size of update + final chunks */
		dec_len = output_len + block_len;
		if (yaca_malloc(dec_len, (void**)&dec) != YACA_ERROR_NONE)
			goto exit;

		/* Open and finalize */
		if (yaca_open_update(ctx, enc, enc_len, dec, &written_len) != YACA_ERROR_NONE)
			goto exit;

		dec_len = written_len;

		if (yaca_open_finalize(ctx, dec + written_len, &written_len) != YACA_ERROR_NONE)
			goto exit;

		dec_len += written_len;

		printf("Decrypted data (16 of %zu bytes): %.16s\n\n", dec_len, dec);
	}

exit:
	yaca_free(dec);
	yaca_free(enc);
	yaca_context_destroy(ctx);
	yaca_key_destroy(sym_key);
	yaca_key_destroy(iv);
	yaca_key_destroy(key_pub);
	yaca_key_destroy(key_priv);
}

void encrypt_seal_aes_gcm(void)
{
	yaca_encrypt_algorithm_e algo = YACA_ENCRYPT_AES;
	yaca_block_cipher_mode_e bcm = YACA_BCM_GCM;
	size_t key_bit_len = YACA_KEY_LENGTH_256BIT;

	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key_pub = YACA_KEY_NULL;
	yaca_key_h key_priv = YACA_KEY_NULL;
	yaca_key_h sym_key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;

	char *enc = NULL;
	char *dec = NULL;
	size_t enc_len;
	size_t dec_len;

	char *aad = NULL;
	char *tag = NULL;
	size_t aad_len = 16;
	size_t tag_len = 13;

	size_t block_len;
	size_t output_len;
	size_t written_len;

	printf("Plain data (16 of %zu bytes): %.16s\n", LOREM4096_SIZE, lorem4096);

	/* Generate key pair */
	if (yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_4096BIT, &key_priv) != YACA_ERROR_NONE)
		return;

	if (yaca_key_extract_public(key_priv, &key_pub) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_zalloc(aad_len, (void**)&aad) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_randomize_bytes(aad, aad_len) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_zalloc(tag_len, (void**)&tag) != YACA_ERROR_NONE)
		goto exit;

	/* Encryption */
	{
		if (yaca_seal_initialize(&ctx, key_pub, algo, bcm, key_bit_len, &sym_key, &iv) != YACA_ERROR_NONE)
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

		if (yaca_seal_update(ctx, lorem4096, LOREM4096_SIZE, enc, &written_len) != YACA_ERROR_NONE)
			goto exit;

		enc_len = written_len;

		if (yaca_seal_finalize(ctx, enc + written_len, &written_len) != YACA_ERROR_NONE)
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
		if (yaca_open_initialize(&ctx, key_priv, algo, bcm, key_bit_len, sym_key, iv) != YACA_ERROR_NONE)
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
		dec_len = output_len + block_len;
		if (yaca_malloc(dec_len, (void**)&dec) != YACA_ERROR_NONE)
			goto exit;

		if (yaca_open_update(ctx, enc, enc_len, dec, &written_len) != YACA_ERROR_NONE)
			goto exit;

		/* Set expected tag value before final decryption */
		if (yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag, tag_len) != YACA_ERROR_NONE)
			goto exit;

		dec_len = written_len;

		if (yaca_open_finalize(ctx, dec + written_len, &written_len) != YACA_ERROR_NONE)
			goto exit;

		dec_len += written_len;

		printf("Decrypted data (16 of %zu bytes): %.16s\n\n", dec_len, dec);
	}

exit:
	yaca_free(dec);
	yaca_free(enc);
	yaca_context_destroy(ctx);
	yaca_key_destroy(sym_key);
	yaca_key_destroy(iv);
	yaca_free(aad);
	yaca_free(tag);
	yaca_key_destroy(key_pub);
	yaca_key_destroy(key_priv);
}

void encrypt_seal_aes_ccm(void)
{
	yaca_encrypt_algorithm_e algo = YACA_ENCRYPT_AES;
	yaca_block_cipher_mode_e bcm = YACA_BCM_CCM;
	size_t key_bit_len = YACA_KEY_LENGTH_192BIT;

	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key_pub = YACA_KEY_NULL;
	yaca_key_h key_priv = YACA_KEY_NULL;
	yaca_key_h sym_key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;

	char *enc = NULL;
	char *dec = NULL;
	size_t enc_len;
	size_t dec_len;

	char *aad = NULL;
	char *tag = NULL;
	size_t aad_len = 16;
	size_t tag_len = 8;

	size_t block_len;
	size_t output_len;
	size_t written_len;
	size_t len;

	printf("Plain data (16 of %zu bytes): %.16s\n", LOREM4096_SIZE, lorem4096);

	/* Generate key pair */
	if (yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_3072BIT, &key_priv) != YACA_ERROR_NONE)
		return;

	if (yaca_key_extract_public(key_priv, &key_pub) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_zalloc(aad_len, (void**)&aad) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_randomize_bytes(aad, aad_len) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_zalloc(tag_len, (void**)&tag) != YACA_ERROR_NONE)
		goto exit;

	/* Encryption */
	{
		if (yaca_seal_initialize(&ctx, key_pub, algo, bcm, key_bit_len, &sym_key, &iv) != YACA_ERROR_NONE)
			goto exit;

		/* Set tag length (optionally) */
		if (yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG_LEN,
		                              (void*)&tag_len, sizeof(tag_len)) != YACA_ERROR_NONE)
			goto exit;

		/* The total plain text length must be passed (only needed if AAD is passed) */
		if (yaca_seal_update(ctx, NULL, LOREM4096_SIZE , NULL, &len) != YACA_ERROR_NONE)
			goto exit;

		/* Provide any AAD data */
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

		if (yaca_seal_update(ctx, lorem4096, LOREM4096_SIZE, enc, &written_len) != YACA_ERROR_NONE)
			goto exit;

		enc_len = written_len;

		if (yaca_seal_finalize(ctx, enc + written_len, &written_len) != YACA_ERROR_NONE)
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
		if (yaca_open_initialize(&ctx, key_priv, algo, bcm, key_bit_len, sym_key, iv) != YACA_ERROR_NONE)
			goto exit;

		/* Set expected tag value */
		if (yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len) != YACA_ERROR_NONE)
			goto exit;

		/* The total encrypted text length must be passed (only needed if AAD is passed) */
		if (yaca_open_update(ctx, NULL, enc_len , NULL, &len) != YACA_ERROR_NONE)
			goto exit;

		/* Provide any AAD data */
		if (yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len) != YACA_ERROR_NONE)
			goto exit;

		/* For the update */
		if (yaca_context_get_output_length(ctx, LOREM4096_SIZE, &output_len) != YACA_ERROR_NONE)
			goto exit;

		/* For the finalize */
		if (yaca_context_get_output_length(ctx, 0, &block_len) != YACA_ERROR_NONE)
			goto exit;

		/* Calculate max output: size of update + final chunks */
		dec_len = output_len + block_len;
		if (yaca_malloc(dec_len, (void**)&dec) != YACA_ERROR_NONE)
			goto exit;

		/* The tag verify is performed when you call the final yaca_open_update(),
		 * there is no call to yaca_open_finalize() */
		if (yaca_open_update(ctx, enc, enc_len, dec, &written_len) != YACA_ERROR_NONE)
			goto exit;

		dec_len = written_len;

		printf("Decrypted data (16 of %zu bytes): %.16s\n\n", dec_len, dec);
	}

exit:
	yaca_free(dec);
	yaca_free(enc);
	yaca_context_destroy(ctx);
	yaca_key_destroy(sym_key);
	yaca_key_destroy(iv);
	yaca_free(aad);
	yaca_free(tag);
	yaca_key_destroy(key_pub);
	yaca_key_destroy(key_priv);
}

int main()
{
	yaca_debug_set_error_cb(debug_func);

	int ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		return ret;

	printf("AES CBC 256bit key seal/open\n");
	yaca_encrypt_algorithm_e algo = YACA_ENCRYPT_AES;
	yaca_block_cipher_mode_e bcm = YACA_BCM_CBC;
	size_t key_bit_len = YACA_KEY_LENGTH_256BIT;
	encrypt_seal(algo, bcm, key_bit_len);

	printf("3DES 192bit key seal/open\n");
	algo = YACA_ENCRYPT_3DES_3TDEA;
	bcm = YACA_BCM_CFB;
	key_bit_len = YACA_KEY_LENGTH_192BIT;
	encrypt_seal(algo, bcm, key_bit_len);

	printf("RC2 40bit key seal/open\n");
	algo = YACA_ENCRYPT_UNSAFE_RC2;
	bcm = YACA_BCM_OFB;
	key_bit_len = YACA_KEY_LENGTH_UNSAFE_40BIT;
	encrypt_seal(algo, bcm, key_bit_len);

	printf("AES GCM 256bit key seal/open\n");
	encrypt_seal_aes_gcm();

	printf("AES CCM 192bit key seal/open\n");
	encrypt_seal_aes_ccm();

	yaca_cleanup();
	return ret;
}
