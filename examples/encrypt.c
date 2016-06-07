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
 * @file encrypt.c
 * @brief
 */

#include <stdio.h>

#include <yaca_crypto.h>
#include <yaca_simple.h>
#include <yaca_encrypt.h>
#include <yaca_key.h>
#include <yaca_error.h>

#include "lorem.h"
#include "misc.h"
#include "../src/debug.h"

void encrypt_simple(const yaca_encrypt_algorithm_e algo,
                    const yaca_block_cipher_mode_e bcm,
                    const size_t key_bits)
{
	yaca_key_h key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;

	char *enc = NULL;
	char *dec = NULL;
	size_t enc_size;
	size_t dec_size;
	size_t iv_bits;

	printf("Plain data (16 of %zu bytes): %.16s\n", LOREM4096_SIZE, lorem4096);

	/* Key generation */
	if (yaca_key_derive_pbkdf2("foo bar", "123456789", 10, 1000,
	                           YACA_DIGEST_SHA256, key_bits, &key) != YACA_ERROR_NONE)
		return;

	if (yaca_encrypt_get_iv_bit_length(algo, bcm, key_bits, &iv_bits) != YACA_ERROR_NONE)
		goto exit;

	if (iv_bits > 0 && yaca_key_generate(YACA_KEY_TYPE_IV, iv_bits, &iv) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_simple_encrypt(algo, bcm, key, iv, lorem4096, LOREM4096_SIZE, &enc, &enc_size) != YACA_ERROR_NONE)
		goto exit;

	dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_size);

	if (yaca_simple_decrypt(algo, bcm, key, iv, enc, enc_size, &dec, &dec_size) != YACA_ERROR_NONE)
		goto exit;

	printf("Decrypted data (16 of %zu bytes): %.16s\n\n", dec_size, dec);

exit:
	yaca_free(enc);
	yaca_free(dec);
	yaca_key_destroy(iv);
	yaca_key_destroy(key);
}

void encrypt_advanced(const yaca_encrypt_algorithm_e algo,
                      const yaca_block_cipher_mode_e bcm,
                      const yaca_key_type_e key_type,
                      const size_t key_bits)
{
	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;
	size_t iv_bits;

	char *enc = NULL;
	char *dec = NULL;
	size_t enc_size;
	size_t dec_size;

	size_t block_len;
	size_t output_len;
	size_t out_size;
	size_t rem;

	printf("Plain data (16 of %zu bytes): %.16s\n", LOREM4096_SIZE, lorem4096);

	/* Key generation */
	if (yaca_key_generate(key_type, key_bits, &key) != YACA_ERROR_NONE)
		return;

	if (yaca_encrypt_get_iv_bit_length(algo, bcm, key_bits, &iv_bits) != YACA_ERROR_NONE)
		goto exit;

	if (iv_bits > 0 && yaca_key_generate(YACA_KEY_TYPE_IV, iv_bits, &iv) != YACA_ERROR_NONE)
		goto exit;

	/* Encryption */
	{
		if (yaca_encrypt_initialize(&ctx, algo, bcm, key, iv) != YACA_ERROR_NONE)
			goto exit;

		/* For the update */
		if (yaca_context_get_output_length(ctx, LOREM4096_SIZE, &output_len) != YACA_ERROR_NONE)
			goto exit;

		/* For the finalize */
		if (yaca_context_get_output_length(ctx, 0, &block_len) != YACA_ERROR_NONE)
			goto exit;

		/* Calculate max output: size of update + final chunks */
		enc_size = output_len + block_len;
		if (yaca_malloc(enc_size, (void**)&enc) != YACA_ERROR_NONE)
			goto exit;

		out_size = enc_size;
		if (yaca_encrypt_update(ctx, lorem4096, LOREM4096_SIZE, enc, &out_size) != YACA_ERROR_NONE)
			goto exit;

		rem = enc_size - out_size;
		if (yaca_encrypt_finalize(ctx, enc + out_size, &rem) != YACA_ERROR_NONE)
			goto exit;

		enc_size = rem + out_size;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_size);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* Decryption */
	{
		if (yaca_decrypt_initialize(&ctx, algo, bcm, key, iv) != YACA_ERROR_NONE)
			goto exit;

		/* For the update */
		if (yaca_context_get_output_length(ctx, LOREM4096_SIZE, &output_len) != YACA_ERROR_NONE)
			goto exit;

		/* For the finalize */
		if (yaca_context_get_output_length(ctx, 0, &block_len) != YACA_ERROR_NONE)
			goto exit;

		/* Calculate max output: size of update + final chunks */
		dec_size = output_len + block_len;
		if (yaca_malloc(dec_size, (void**)&dec) != YACA_ERROR_NONE)
			goto exit;

		out_size = dec_size;
		if (yaca_decrypt_update(ctx, enc, enc_size, dec, &out_size) != YACA_ERROR_NONE)
			goto exit;

		rem = dec_size - out_size;
		if (yaca_decrypt_finalize(ctx, dec + out_size, &rem) != YACA_ERROR_NONE)
			goto exit;

		dec_size = rem + out_size;

		printf("Decrypted data (16 of %zu bytes): %.16s\n\n", dec_size, dec);
	}

exit:
	yaca_free(dec);
	yaca_free(enc);
	yaca_context_destroy(ctx);
	yaca_key_destroy(iv);
	yaca_key_destroy(key);
}

int main()
{
	yaca_debug_set_error_cb(debug_func);

	int ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		return ret;

	yaca_encrypt_algorithm_e algo = YACA_ENCRYPT_AES;
	yaca_block_cipher_mode_e bcm = YACA_BCM_ECB;
	yaca_key_type_e key_type = YACA_KEY_TYPE_SYMMETRIC;
	size_t key_bits = YACA_KEY_LENGTH_256BIT;

	encrypt_simple(algo, bcm, key_bits);
	encrypt_advanced(algo, bcm, key_type, key_bits);

	algo = YACA_ENCRYPT_3DES_3TDEA;
	bcm = YACA_BCM_OFB;
	key_type = YACA_KEY_TYPE_DES;
	key_bits = YACA_KEY_LENGTH_192BIT;

	encrypt_advanced(algo, bcm, key_type, key_bits);

	algo = YACA_ENCRYPT_CAST5;
	bcm = YACA_BCM_CFB;
	key_type = YACA_KEY_TYPE_SYMMETRIC;
	key_bits = YACA_KEY_LENGTH_UNSAFE_40BIT;

	encrypt_simple(algo, bcm, key_bits);
	encrypt_advanced(algo, bcm, key_type, key_bits);

	algo = YACA_ENCRYPT_UNSAFE_RC2;
	bcm = YACA_BCM_CBC;
	key_type = YACA_KEY_TYPE_SYMMETRIC;
	key_bits = YACA_KEY_LENGTH_UNSAFE_8BIT;

	encrypt_simple(algo, bcm, key_bits);
	encrypt_advanced(algo, bcm, key_type, key_bits);

	algo = YACA_ENCRYPT_UNSAFE_RC4;
	bcm = YACA_BCM_NONE;
	key_type = YACA_KEY_TYPE_SYMMETRIC;
	key_bits = YACA_KEY_LENGTH_2048BIT;

	encrypt_simple(algo, bcm, key_bits);
	encrypt_advanced(algo, bcm, key_type, key_bits);

	yaca_cleanup();

	return ret;
}
