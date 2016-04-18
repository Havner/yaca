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

#include <yaca/crypto.h>
#include <yaca/encrypt.h>
#include <yaca/simple.h>
#include <yaca/key.h>
#include "lorem.h"
#include "misc.h"

// Symmetric encryption using simple API
void encrypt_simple(void)
{
	const yaca_enc_algo_e algo = YACA_ENC_AES;
	const yaca_block_cipher_mode_e bcm = YACA_BCM_CBC;
	const size_t key_bits = YACA_KEY_256BIT;
	int ret;
	yaca_key_h key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;
	char *enc_data = NULL;
	char *dec_data = NULL;
	size_t enc_len;
	size_t dec_len;
	int iv_bits;

	printf("Simple Encrypt\nPlain data (16 of %zu bytes): %.16s\n",
	       LOREM1024_SIZE, lorem1024);

	ret = yaca_key_derive_pbkdf2("foo bar", "123456789", 10, 1000,
				     YACA_DIGEST_SHA256, key_bits, &key);
	if (ret)
		return;

	iv_bits = yaca_get_iv_bits(algo, bcm, key_bits);
	if (iv_bits < 0)
		return;

	if (iv_bits > 0) {
		ret = yaca_key_gen(&iv, YACA_KEY_TYPE_IV, iv_bits);
		if (ret)
			goto exit;
	}

	ret = yaca_encrypt(algo, bcm, key, iv, lorem1024, LOREM1024_SIZE,
			   &enc_data, &enc_len);
	if (ret)
		goto exit;

	dump_hex(enc_data, 16, "Encrypted data (16 of %zu bytes): ", enc_len);

	ret = yaca_decrypt(algo, bcm, key, iv, enc_data, enc_len, &dec_data,
			   &dec_len);
	if (ret < 0)
		goto exit;

	printf("Decrypted data (16 of %zu bytes): %.16s\n", dec_len, dec_data);
exit:
	if (enc_data)
		yaca_free(enc_data);
	if (dec_data)
		yaca_free(dec_data);
	if (iv != YACA_KEY_NULL)
		yaca_key_free(iv);
	yaca_key_free(key);
}

// Symmetric encryption using advanced API
void encrypt_advanced(void)
{
	const yaca_enc_algo_e algo = YACA_ENC_AES;
	const yaca_block_cipher_mode_e bcm = YACA_BCM_CBC;
	const size_t key_bits = YACA_KEY_256BIT;
	int ret;
	yaca_ctx_h ctx;
	yaca_key_h key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;
	char *enc = NULL;
	char *dec = NULL;
	size_t enc_size;
	size_t dec_size;
	int iv_bits;

	printf("Advanced Encrypt\nPlain data (16 of %zu bytes): %.16s\n",
	       LOREM4096_SIZE, lorem4096);

	/// Key generation

	ret = yaca_key_derive_pbkdf2("foo bar", "123456789", 10, 1000,
				     YACA_DIGEST_SHA256, key_bits, &key);
	if (ret)
		return;

	iv_bits = yaca_get_iv_bits(algo, bcm, key_bits);
	if (iv_bits < 0)
		goto ex_key;

	if (iv_bits > 0) {
		ret = yaca_key_gen(&iv, YACA_KEY_TYPE_IV, iv_bits);
		if (ret)
			goto ex_key;
	}

	/// Encryption
	{
		size_t block_len;
		size_t output_len;
		size_t out_size;
		size_t rem;

		ret = yaca_encrypt_init(&ctx, algo, bcm, key, iv);
		if (ret)
			goto ex_iv;

		ret = yaca_get_block_length(ctx);
		if (ret < 0)
			goto ex_ctx;

		block_len = ret;

		ret = yaca_get_output_length(ctx, LOREM4096_SIZE);
		if (ret < 0)
			goto ex_ctx;

		output_len = ret;

		/* Calculate max output: size of update + final chunks */
		enc_size = output_len + block_len;
		enc = yaca_malloc(enc_size);
		if (enc == NULL)
			goto ex_ctx;

		out_size = enc_size;
		ret = yaca_encrypt_update(ctx, lorem4096, LOREM4096_SIZE, enc,
					  &out_size);
		if (ret < 0)
			goto ex_of;

		rem = enc_size - out_size;
		ret = yaca_encrypt_final(ctx, enc + out_size, &rem);
		if (ret < 0)
			goto ex_of;

		enc_size = rem + out_size;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ",
			 enc_size);

		yaca_ctx_free(ctx); // TODO: perhaps it should not return value
	}

	/// Decryption
	{
		size_t block_len;
		size_t output_len;
		size_t out_size;
		size_t rem;

		ret = yaca_decrypt_init(&ctx, algo, bcm, key, iv);
		if (ret < 0) {
			ctx = YACA_CTX_NULL;
			goto ex_of;
		}

		ret = yaca_get_block_length(ctx);
		if (ret < 0)
			goto ex_of;

		block_len = ret;

		ret = yaca_get_output_length(ctx, LOREM4096_SIZE);
		if (ret < 0)
			goto ex_ctx;

		output_len = ret;

		/* Calculate max output: size of update + final chunks */
		dec_size = output_len + block_len;
		dec = yaca_malloc(dec_size);
		if (dec == NULL)
			goto ex_of;

		out_size = dec_size;
		ret = yaca_decrypt_update(ctx, enc, enc_size, dec, &out_size);
		if (ret < 0)
			goto ex_in;

		rem = dec_size - out_size;
		ret = yaca_encrypt_final(ctx, dec + out_size, &rem);
		if (ret < 0)
			goto ex_in;

		dec_size = rem + out_size;

		printf("Decrypted data (16 of %zu bytes): %.16s\n", dec_size, dec);
	}

ex_in:
	yaca_free(dec);
ex_of:
	yaca_free(enc);
ex_ctx:
	yaca_ctx_free(ctx);
ex_iv:
	yaca_key_free(iv);
ex_key:
	yaca_key_free(key);
}

int main()
{
	int ret = yaca_init();
	if (ret < 0)
		return ret;

	encrypt_simple();

	encrypt_advanced();

	yaca_exit(); // TODO: what about handing of return value from exit??
	return ret;
}
