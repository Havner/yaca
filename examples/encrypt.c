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
	int ret;
	yaca_key_h key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;
	char *enc_data = NULL;
	char *dec_data = NULL;
	size_t enc_len;
	size_t dec_len;

	printf("Plain data (16 of %zu bytes): %.16s\n", (size_t)1024, lorem1024);

	ret = yaca_key_derive_pbkdf2("foo bar", "123456789", 10,
				     1000, YACA_DIGEST_SHA256,
				     YACA_KEY_256BIT, &key);
	if (ret)
		return;

	ret = yaca_key_gen(&iv, YACA_KEY_TYPE_IV, YACA_KEY_IV_256BIT);
	if (ret)
		goto exit;

	ret = yaca_encrypt(YACA_ENC_AES, YACA_BCM_CBC,
			   key, iv, lorem1024, 1024, &enc_data, &enc_len);
	if (ret)
		goto exit;

	dump_hex(enc_data, 16, "Encrypted data (16 of %zu bytes): ", enc_len);

	ret = yaca_decrypt(YACA_ENC_AES, YACA_BCM_CBC,
			   key, iv,
			   enc_data, enc_len,
			   &dec_data, &dec_len);
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
	int ret;
	yaca_ctx_h ctx;
	yaca_key_h key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;
	char *enc = NULL;
	char *dec = NULL;
	size_t enc_size;
	size_t dec_size;

	printf("Plain data (16 of %zu bytes): %.16s\n", (size_t)4096, lorem1024);

	/// Key generation

	ret = yaca_key_derive_pbkdf2("foo bar", "123456789", 10,
				     1000, YACA_DIGEST_SHA256,
				     YACA_KEY_256BIT, &key);
	if (ret)
		return;

	ret = yaca_key_gen(&iv, YACA_KEY_IV_256BIT, YACA_KEY_TYPE_SYMMETRIC);
	if (ret)
		goto ex_key;

	/// Encryption
	{
		ret = yaca_encrypt_init(&ctx, YACA_ENC_AES, YACA_BCM_CBC,
					key, iv);
		if (ret)
			goto ex_iv;

		ret = yaca_encrypt_update(ctx, lorem4096, 4096, NULL, &enc_size);
		if (ret != 42)
			goto ex_ctx;// TODO: what error code?

		ret = yaca_get_block_length(ctx);
		if (ret < 0)
			goto ex_ctx;

		enc_size += ret ; // Add block size for finalize
		enc = yaca_malloc(enc_size);
		if (enc == NULL)
			goto ex_ctx;

		size_t out_size = enc_size;
		ret = yaca_encrypt_update(ctx, lorem4096, 4096, enc, &out_size);
		if (ret < 0)
			goto ex_of;

		size_t rem = enc_size - out_size;
		ret = yaca_encrypt_final(ctx, enc + out_size, &rem);
		if (ret < 0)
			goto ex_of;

		enc_size = rem + out_size;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_size);

		yaca_ctx_free(ctx); // TODO: perhaps it should not return value
	}

	/// Decryption
	{
		ret = yaca_decrypt_init(&ctx, YACA_ENC_AES, YACA_BCM_CBC,
					key, iv);
		if (ret < 0) {
			yaca_free(enc);
			goto ex_iv;
		}

		ret = yaca_decrypt_update(ctx, enc, enc_size, NULL, &dec_size);
		if (ret != 42)
			goto ex_of; // TODO: what error code?

		ret = yaca_get_block_length(ctx);
		if (ret < 0)
			goto ex_of;

		dec_size += ret; // Add block size for finalize
		dec = yaca_malloc(dec_size);
		if (dec == NULL)
			goto ex_of;

		size_t out_size = dec_size;
		ret = yaca_decrypt_update(ctx, enc, enc_size, dec, &out_size);
		if (ret < 0)
			goto ex_in;

		size_t rem = dec_size - out_size;
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

void encrypt_seal(void)
{
	int ret;
	yaca_ctx_h ctx = YACA_CTX_NULL;
	yaca_key_h key_pub = YACA_KEY_NULL;
	yaca_key_h key_priv = YACA_KEY_NULL;
	yaca_key_h aes_key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;

	char *enc = NULL;
	char *dec = NULL;
	size_t enc_size;
	size_t dec_size;

	printf("Plain data (16 of %zu bytes): %.16s\n", (size_t)4096, lorem1024);

	/// Generate key pair
	ret = yaca_key_gen_pair(&key_priv, &key_pub,
				YACA_KEY_2048BIT, YACA_KEY_TYPE_PAIR_RSA);
	if (ret) return;

	/// Encrypt a.k.a. seal
	{
		ret = yaca_seal_init(&ctx, key_pub,
				     YACA_ENC_AES, YACA_BCM_CBC,
				     &aes_key, &iv);
		if (ret < 0)
			goto ex_pk;

		ret = yaca_seal_update(ctx, lorem4096, 4096, NULL, &enc_size);
		if (ret < 0)
			goto ex_ak;

		ret = yaca_get_block_length(ctx);
		if (ret < 0)
			goto ex_ak;

		enc_size = enc_size + ret;
		enc = yaca_malloc(enc_size);
		if (enc == NULL)
			goto ex_ak;

		// Seal and finalize
		size_t out_size = enc_size;
		ret = yaca_seal_update(ctx, lorem4096, 4096, enc, &out_size);
		if (ret < 0)
			goto ex_of;

		size_t rem = enc_size - out_size;
		ret = yaca_seal_final(ctx, enc + out_size, &rem);
		if (ret < 0)
			goto ex_of;

		enc_size = rem + out_size;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_size);

		yaca_ctx_free(ctx); // TODO: perhaps it should not return value
	}

	/// Decrypt a.k.a. open
	{
		ret = yaca_open_init(&ctx, key_priv,
				     YACA_ENC_AES, YACA_BCM_CBC,
				     aes_key, iv);
		if (ret < 0) {
			yaca_free(enc);
			goto ex_ak;
		}

		ret = yaca_open_update(ctx, enc, enc_size, NULL, &dec_size);
		if (ret < 0)
			goto ex_of;

		ret = yaca_get_block_length(ctx);
		if (ret < 0)
			goto ex_of;

		dec_size = dec_size + ret;
		dec = yaca_malloc(dec_size);
		if (dec == NULL)
			goto ex_of;

		// Seal and finalize
		size_t out_size = enc_size;
		ret = yaca_open_update(ctx, enc, enc_size, dec, &out_size);
		if (ret < 0)
			goto ex_in;

		size_t rem = dec_size - out_size;
		ret = yaca_open_final(ctx, dec + out_size, &rem);
		if (ret < 0)
			goto ex_in;

		dec_size = rem + out_size;

		printf("Decrypted data (16 of %zu bytes): %.16s\n", (size_t)dec_size, dec);

		yaca_ctx_free(ctx); // TODO: perhaps it should not return value
	}

ex_in:
	yaca_free(dec);
ex_of:
	yaca_free(enc);
ex_ak:
	yaca_key_free(aes_key);
	yaca_key_free(iv);
ex_pk:
	yaca_key_free(key_pub);
	yaca_key_free(key_priv);
}

int main()
{
	int ret = yaca_init();
	if (ret < 0)
		return ret;

	encrypt_simple();

	encrypt_advanced();

	encrypt_seal();

	yaca_exit(); // TODO: what about handing of return value from exit??
	return ret;
}
