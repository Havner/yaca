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

#include <crypto/crypto.h>
#include <crypto/encrypt.h>
#include <crypto/simple.h>
#include <crypto/key.h>
#include "lorem.h"
#include "misc.h"

// Symmetric encryption using simple API
void encrypt_simple(void)
{
	int ret;
	crypto_key_h key = CRYPTO_KEY_NULL, iv = CRYPTO_KEY_NULL;
	char *enc_data = NULL, *dec_data = NULL;
	size_t enc_len, dec_len;

	printf("Plain data (16 of %zu bytes): %.16s\n", (size_t)1024, lorem1024);

	ret = crypto_key_derive_pbkdf2("foo bar", "123456789", 10,
				       1000, CRYPTO_DIGEST_SHA256,
				       CRYPTO_KEY_256BIT, &key);
	if (ret) return;

	ret = crypto_key_gen(&iv, CRYPTO_KEY_TYPE_IV, CRYPTO_KEY_IV_256BIT);
	if (ret) goto exit;

	ret = crypto_encrypt(CRYPTO_ENC_AES, CRYPTO_BCM_CBC,
			     key, iv, lorem1024, 1024, &enc_data, &enc_len);
	if (ret) goto exit;

	dump_hex(enc_data, 16, "Encrypted data (16 of %zu bytes): ", enc_len);

	ret = crypto_decrypt(CRYPTO_ENC_AES, CRYPTO_BCM_CBC,
			     key, iv,
			     enc_data, enc_len,
			     &dec_data, &dec_len);
	if (ret < 0) goto exit;

	printf("Decrypted data (16 of %zu bytes): %.16s\n", dec_len, dec_data);
exit:
	if (enc_data)
		crypto_free(enc_data);
	if (dec_data)
		crypto_free(dec_data);
	if (iv != CRYPTO_KEY_NULL)
		crypto_key_free(iv);
	crypto_key_free(key);
}

// Symmetric encryption using advanced API
void encrypt_advanced(void)
{
	int ret;
	crypto_ctx_h ctx;
	crypto_key_h key = CRYPTO_KEY_NULL, iv = CRYPTO_KEY_NULL;
	char *enc = NULL, *dec = NULL;
	size_t enc_size, dec_size;

	printf("Plain data (16 of %zu bytes): %.16s\n", (size_t)4096, lorem1024);

	/// Key generation

	ret = crypto_key_derive_pbkdf2("foo bar", "123456789", 10,
				       1000, CRYPTO_DIGEST_SHA256,
				       CRYPTO_KEY_256BIT, &key);
	if (ret) return;

	ret = crypto_key_gen(&iv, CRYPTO_KEY_IV_256BIT, CRYPTO_KEY_TYPE_SYMMETRIC);
	if (ret) goto ex_key;

	/// Encryption
	{
		ret = crypto_encrypt_init(&ctx, CRYPTO_ENC_AES, CRYPTO_BCM_CBC,
					  key, iv);
		if (ret) goto ex_iv;

		ret = crypto_encrypt_update(ctx, lorem4096, 4096, NULL, &enc_size);
		if (ret != 42) goto ex_ctx;// TODO: what error code?

		ret = crypto_get_block_length(ctx);
		if (ret < 0) goto ex_ctx;

		enc_size += ret ; // Add block size for finalize
		enc = crypto_alloc(enc_size);
		if (!enc) goto ex_ctx;

		size_t out_size = enc_size;
		ret = crypto_encrypt_update(ctx, lorem4096, 4096, enc, &out_size);
		if (ret < 0) goto ex_of;

		size_t rem = enc_size - out_size;
		ret = crypto_encrypt_final(ctx, enc + out_size, &rem);
		if (ret < 0) goto ex_of;

		enc_size = rem + out_size;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_size);

		crypto_ctx_free(ctx); // TODO: perhaps it should not return value
	}

	/// Decryption
	{
		ret = crypto_decrypt_init(&ctx, CRYPTO_ENC_AES, CRYPTO_BCM_CBC,
					  key, iv);
		if (ret < 0) {
			crypto_free(enc);
			goto ex_iv;
		}

		ret = crypto_decrypt_update(ctx, enc, enc_size, NULL, &dec_size);
		if (ret != 42) goto ex_of; // TODO: what error code?

		ret = crypto_get_block_length(ctx);
		if (ret < 0) goto ex_of;

		dec_size += ret; // Add block size for finalize
		dec = crypto_alloc(dec_size);
		if (!dec) goto ex_of;

		size_t out_size = dec_size;
		ret = crypto_decrypt_update(ctx, enc, enc_size, dec, &out_size);
		if (ret < 0) goto ex_in;

		size_t rem = dec_size - out_size;
		ret = crypto_encrypt_final(ctx, dec + out_size, &rem);
		if (ret < 0) goto ex_in;

		dec_size = rem + out_size;

		printf("Decrypted data (16 of %zu bytes): %.16s\n", dec_size, dec);
	}

ex_in:
	crypto_free(dec);
ex_of:
	crypto_free(enc);
ex_ctx:
	crypto_ctx_free(ctx);
ex_iv:
	crypto_key_free(iv);
ex_key:
	crypto_key_free(key);
}

void encrypt_seal(void)
{
	int ret;
	crypto_ctx_h ctx;
	crypto_key_h key_pub = CRYPTO_KEY_NULL, key_priv = CRYPTO_KEY_NULL;
	crypto_key_h aes_key, iv = CRYPTO_KEY_NULL;

	char *enc = NULL, *dec = NULL;
	size_t enc_size, dec_size;

	printf("Plain data (16 of %zu bytes): %.16s\n", (size_t)4096, lorem1024);

	/// Generate key pair
	ret = crypto_key_gen_pair(&key_priv, &key_pub,
				  CRYPTO_KEY_2048BIT, CRYPTO_KEY_TYPE_PAIR_RSA);
	if (ret) return;

	/// Encrypt a.k.a. seal
	{
		ret = crypto_seal_init(&ctx, key_pub,
				       CRYPTO_ENC_AES, CRYPTO_BCM_CBC,
				       &aes_key, &iv);
		if (ret) goto ex_pk;

		ret = crypto_seal_update(ctx, lorem4096, 4096, NULL, &enc_size);
		if (ret) goto ex_ak;

		ret = crypto_get_block_length(ctx);
		if (ret < 0) goto ex_ak;

		enc_size = enc_size + ret;
		enc = crypto_alloc(enc_size);
		if (!enc) goto ex_ak;

		// Seal and finalize
		size_t out_size = enc_size;
		ret = crypto_seal_update(ctx, lorem4096, 4096, enc, &out_size);
		if (ret < 0) goto ex_of;

		size_t rem = enc_size - out_size;
		ret = crypto_seal_final(ctx, enc + out_size, &rem);
		if (ret < 0) goto ex_of;

		enc_size = rem + out_size;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_size);

		crypto_ctx_free(ctx); // TODO: perhaps it should not return value
	}

	/// Decrypt a.k.a. open
	{
		ret = crypto_open_init(&ctx, key_priv,
				       CRYPTO_ENC_AES, CRYPTO_BCM_CBC,
				       aes_key, iv);
		if (ret) {
			crypto_free(enc);
			goto ex_ak;
		}

		ret = crypto_open_update(ctx, enc, enc_size, NULL, &dec_size);
		if (ret) goto ex_of;

		ret = crypto_get_block_length(ctx);
		if (ret < 0) goto ex_of;

		dec_size = dec_size + ret;
		dec = crypto_alloc(dec_size);
		if (!dec) goto ex_of;

		// Seal and finalize
		size_t out_size = enc_size;
		ret = crypto_open_update(ctx, enc, enc_size, dec, &out_size);
		if (ret < 0) goto ex_in;

		size_t rem = dec_size - out_size;
		ret = crypto_open_final(ctx, dec + out_size, &rem);
		if (ret < 0) goto ex_in;

		dec_size = rem + out_size;

		printf("Decrypted data (16 of %zu bytes): %.16s\n", (size_t)dec_size, dec);

		crypto_ctx_free(ctx); // TODO: perhaps it should not return value
	}

ex_in:
	crypto_free(dec);
ex_of:
	crypto_free(enc);
ex_ak:
	crypto_key_free(aes_key);
	crypto_key_free(iv);
ex_pk:
	crypto_key_free(key_pub);
	crypto_key_free(key_priv);
}

int main()
{
	int ret = 0;
	if ((ret = crypto_init()))
		return ret;

	encrypt_simple();

	encrypt_advanced();

	encrypt_seal();

	crypto_exit(); // TODO: what about handing of return value from exit??
	return ret;
}
