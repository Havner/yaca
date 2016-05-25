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
#include <yaca/simple.h>
#include <yaca/encrypt.h>
#include <yaca/key.h>
#include <yaca/error.h>

#include "lorem.h"
#include "misc.h"
#include "../src/debug.h"

void encrypt_simple(const yaca_enc_algo_e algo,
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
	                           YACA_DIGEST_SHA256, key_bits, &key) != 0)
		return;

	if (yaca_get_iv_bits(algo, bcm, key_bits, &iv_bits) != 0)
		goto exit;

	if (iv_bits > 0 && yaca_key_gen(&iv, YACA_KEY_TYPE_IV, iv_bits) != 0)
		goto exit;

	if (yaca_encrypt(algo, bcm, key, iv, lorem4096, LOREM4096_SIZE, &enc, &enc_size) != 0)
		goto exit;

	dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_size);

	if (yaca_decrypt(algo, bcm, key, iv, enc, enc_size, &dec, &dec_size) != 0)
		goto exit;

	printf("Decrypted data (16 of %zu bytes): %.16s\n\n", dec_size, dec);

exit:

	yaca_free(enc);
	yaca_free(dec);
	yaca_key_free(iv);
	yaca_key_free(key);
}

void encrypt_advanced(const yaca_enc_algo_e algo,
                      const yaca_block_cipher_mode_e bcm,
                      const yaca_key_type_e key_type,
                      const size_t key_bits)
{
	yaca_ctx_h ctx = YACA_CTX_NULL;
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
	if (yaca_key_gen(&key, key_type, key_bits) != 0)
		return;

	if (yaca_get_iv_bits(algo, bcm, key_bits, &iv_bits) != 0)
		goto ex_key;

	if (iv_bits > 0 && yaca_key_gen(&iv, YACA_KEY_TYPE_IV, iv_bits) != 0)
		goto ex_key;

	/* Encryption */
	{
		if (yaca_encrypt_init(&ctx, algo, bcm, key, iv) != 0)
			goto ex_iv;

		if (yaca_get_block_length(ctx, &block_len) != 0)
			goto ex_ctx;

		if (yaca_get_output_length(ctx, LOREM4096_SIZE, &output_len) != 0)
			goto ex_ctx;

		/* Calculate max output: size of update + final chunks */
		enc_size = output_len + block_len;
		if ((enc = yaca_malloc(enc_size)) == NULL)
			goto ex_ctx;

		out_size = enc_size;
		if (yaca_encrypt_update(ctx, lorem4096, LOREM4096_SIZE, enc, &out_size) != 0)
			goto ex_of;

		rem = enc_size - out_size;
		if (yaca_encrypt_final(ctx, enc + out_size, &rem) != 0)
			goto ex_of;

		enc_size = rem + out_size;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_size);

		yaca_ctx_free(ctx);
		ctx = YACA_CTX_NULL;
	}

	/* Decryption */
	{
		if (yaca_decrypt_init(&ctx, algo, bcm, key, iv) != 0)
			goto ex_of;

		if (yaca_get_block_length(ctx, &block_len) != 0)
			goto ex_of;

		if (yaca_get_output_length(ctx, LOREM4096_SIZE, &output_len) != 0)
			goto ex_of;

		/* Calculate max output: size of update + final chunks */
		dec_size = output_len + block_len;
		if ((dec = yaca_malloc(dec_size)) == NULL)
			goto ex_of;

		out_size = dec_size;
		if (yaca_decrypt_update(ctx, enc, enc_size, dec, &out_size) != 0)
			goto ex_in;

		rem = dec_size - out_size;
		if (yaca_decrypt_final(ctx, dec + out_size, &rem) != 0)
			goto ex_in;

		dec_size = rem + out_size;

		printf("Decrypted data (16 of %zu bytes): %.16s\n\n", dec_size, dec);
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
	yaca_debug_set_error_cb(debug_func);

	int ret = yaca_init();
	if (ret != 0)
		return ret;

	yaca_enc_algo_e algo = YACA_ENC_AES;
	yaca_block_cipher_mode_e bcm = YACA_BCM_ECB;
	yaca_key_type_e key_type = YACA_KEY_TYPE_SYMMETRIC;
	size_t key_bits = YACA_KEY_256BIT;

	encrypt_simple(algo, bcm, key_bits);
	encrypt_advanced(algo, bcm, key_type,key_bits);

	algo = YACA_ENC_3DES_3TDEA;
	bcm = YACA_BCM_OFB;
	key_type = YACA_KEY_TYPE_DES;
	key_bits = YACA_KEY_192BIT;

	encrypt_advanced(algo, bcm, key_type,key_bits);

	algo = YACA_ENC_CAST5;
	bcm = YACA_BCM_CFB;
	key_type = YACA_KEY_TYPE_SYMMETRIC;
	key_bits = YACA_KEY_UNSAFE_40BIT;

	encrypt_simple(algo, bcm, key_bits);
	encrypt_advanced(algo, bcm, key_type,key_bits);

	algo = YACA_ENC_UNSAFE_RC2;
	bcm = YACA_BCM_CBC;
	key_type = YACA_KEY_TYPE_SYMMETRIC;
	key_bits = YACA_KEY_UNSAFE_8BIT;

	encrypt_simple(algo, bcm, key_bits);
	encrypt_advanced(algo, bcm, key_type,key_bits);

	algo = YACA_ENC_UNSAFE_RC4;
	bcm = YACA_BCM_NONE;
	key_type = YACA_KEY_TYPE_SYMMETRIC;
	key_bits = YACA_KEY_2048BIT;

	encrypt_simple(algo, bcm, key_bits);
	encrypt_advanced(algo, bcm, key_type,key_bits);

	yaca_exit();

	return ret;
}
