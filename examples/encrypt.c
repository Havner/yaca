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

#include <owl/crypto.h>
#include <owl/encrypt.h>
#include <owl/simple.h>
#include <owl/key.h>
#include "lorem.h"
#include "misc.h"

// Symmetric encryption using simple API
void encrypt_simple(void)
{
	int ret;
	owl_key_h key = OWL_KEY_NULL;
	owl_key_h iv = OWL_KEY_NULL;
	char *enc_data = NULL;
	char *dec_data = NULL;
	size_t enc_len;
	size_t dec_len;

	printf("Plain data (16 of %zu bytes): %.16s\n", (size_t)1024, lorem1024);

	ret = owl_key_derive_pbkdf2("foo bar", "123456789", 10,
				    1000, OWL_DIGEST_SHA256,
				    OWL_KEY_256BIT, &key);
	if (ret)
		return;

	ret = owl_key_gen(&iv, OWL_KEY_TYPE_IV, OWL_KEY_IV_256BIT);
	if (ret)
		goto exit;

	ret = owl_encrypt(OWL_ENC_AES, OWL_BCM_CBC,
			  key, iv, lorem1024, 1024, &enc_data, &enc_len);
	if (ret)
		goto exit;

	dump_hex(enc_data, 16, "Encrypted data (16 of %zu bytes): ", enc_len);

	ret = owl_decrypt(OWL_ENC_AES, OWL_BCM_CBC,
			  key, iv,
			  enc_data, enc_len,
			  &dec_data, &dec_len);
	if (ret < 0)
		goto exit;

	printf("Decrypted data (16 of %zu bytes): %.16s\n", dec_len, dec_data);
exit:
	if (enc_data)
		owl_free(enc_data);
	if (dec_data)
		owl_free(dec_data);
	if (iv != OWL_KEY_NULL)
		owl_key_free(iv);
	owl_key_free(key);
}

// Symmetric encryption using advanced API
void encrypt_advanced(void)
{
	int ret;
	owl_ctx_h ctx;
	owl_key_h key = OWL_KEY_NULL;
	owl_key_h iv = OWL_KEY_NULL;
	char *enc = NULL;
	char *dec = NULL;
	size_t enc_size;
	size_t dec_size;

	printf("Plain data (16 of %zu bytes): %.16s\n", (size_t)4096, lorem1024);

	/// Key generation

	ret = owl_key_derive_pbkdf2("foo bar", "123456789", 10,
				    1000, OWL_DIGEST_SHA256,
				    OWL_KEY_256BIT, &key);
	if (ret)
		return;

	ret = owl_key_gen(&iv, OWL_KEY_IV_256BIT, OWL_KEY_TYPE_SYMMETRIC);
	if (ret)
		goto ex_key;

	/// Encryption
	{
		ret = owl_encrypt_init(&ctx, OWL_ENC_AES, OWL_BCM_CBC,
					  key, iv);
		if (ret)
			goto ex_iv;

		ret = owl_encrypt_update(ctx, lorem4096, 4096, NULL, &enc_size);
		if (ret != 42)
			goto ex_ctx;// TODO: what error code?

		ret = owl_get_block_length(ctx);
		if (ret < 0)
			goto ex_ctx;

		enc_size += ret ; // Add block size for finalize
		enc = owl_malloc(enc_size);
		if (enc == NULL)
			goto ex_ctx;

		size_t out_size = enc_size;
		ret = owl_encrypt_update(ctx, lorem4096, 4096, enc, &out_size);
		if (ret < 0)
			goto ex_of;

		size_t rem = enc_size - out_size;
		ret = owl_encrypt_final(ctx, enc + out_size, &rem);
		if (ret < 0)
			goto ex_of;

		enc_size = rem + out_size;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_size);

		owl_ctx_free(ctx); // TODO: perhaps it should not return value
	}

	/// Decryption
	{
		ret = owl_decrypt_init(&ctx, OWL_ENC_AES, OWL_BCM_CBC,
					  key, iv);
		if (ret < 0) {
			owl_free(enc);
			goto ex_iv;
		}

		ret = owl_decrypt_update(ctx, enc, enc_size, NULL, &dec_size);
		if (ret != 42)
			goto ex_of; // TODO: what error code?

		ret = owl_get_block_length(ctx);
		if (ret < 0)
			goto ex_of;

		dec_size += ret; // Add block size for finalize
		dec = owl_malloc(dec_size);
		if (dec == NULL)
			goto ex_of;

		size_t out_size = dec_size;
		ret = owl_decrypt_update(ctx, enc, enc_size, dec, &out_size);
		if (ret < 0)
			goto ex_in;

		size_t rem = dec_size - out_size;
		ret = owl_encrypt_final(ctx, dec + out_size, &rem);
		if (ret < 0)
			goto ex_in;

		dec_size = rem + out_size;

		printf("Decrypted data (16 of %zu bytes): %.16s\n", dec_size, dec);
	}

ex_in:
	owl_free(dec);
ex_of:
	owl_free(enc);
ex_ctx:
	owl_ctx_free(ctx);
ex_iv:
	owl_key_free(iv);
ex_key:
	owl_key_free(key);
}

void encrypt_seal(void)
{
	int ret;
	owl_ctx_h ctx = OWL_CTX_NULL;
	owl_key_h key_pub = OWL_KEY_NULL;
	owl_key_h key_priv = OWL_KEY_NULL;
	owl_key_h aes_key = OWL_KEY_NULL;
	owl_key_h iv = OWL_KEY_NULL;

	char *enc = NULL;
	char *dec = NULL;
	size_t enc_size;
	size_t dec_size;

	printf("Plain data (16 of %zu bytes): %.16s\n", (size_t)4096, lorem1024);

	/// Generate key pair
	ret = owl_key_gen_pair(&key_priv, &key_pub,
				  OWL_KEY_2048BIT, OWL_KEY_TYPE_PAIR_RSA);
	if (ret) return;

	/// Encrypt a.k.a. seal
	{
		ret = owl_seal_init(&ctx, key_pub,
				       OWL_ENC_AES, OWL_BCM_CBC,
				       &aes_key, &iv);
		if (ret < 0)
			goto ex_pk;

		ret = owl_seal_update(ctx, lorem4096, 4096, NULL, &enc_size);
		if (ret < 0)
			goto ex_ak;

		ret = owl_get_block_length(ctx);
		if (ret < 0)
			goto ex_ak;

		enc_size = enc_size + ret;
		enc = owl_malloc(enc_size);
		if (enc == NULL)
			goto ex_ak;

		// Seal and finalize
		size_t out_size = enc_size;
		ret = owl_seal_update(ctx, lorem4096, 4096, enc, &out_size);
		if (ret < 0)
			goto ex_of;

		size_t rem = enc_size - out_size;
		ret = owl_seal_final(ctx, enc + out_size, &rem);
		if (ret < 0)
			goto ex_of;

		enc_size = rem + out_size;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_size);

		owl_ctx_free(ctx); // TODO: perhaps it should not return value
	}

	/// Decrypt a.k.a. open
	{
		ret = owl_open_init(&ctx, key_priv,
				    OWL_ENC_AES, OWL_BCM_CBC,
				    aes_key, iv);
		if (ret < 0) {
			owl_free(enc);
			goto ex_ak;
		}

		ret = owl_open_update(ctx, enc, enc_size, NULL, &dec_size);
		if (ret < 0)
			goto ex_of;

		ret = owl_get_block_length(ctx);
		if (ret < 0)
			goto ex_of;

		dec_size = dec_size + ret;
		dec = owl_malloc(dec_size);
		if (dec == NULL)
			goto ex_of;

		// Seal and finalize
		size_t out_size = enc_size;
		ret = owl_open_update(ctx, enc, enc_size, dec, &out_size);
		if (ret < 0)
			goto ex_in;

		size_t rem = dec_size - out_size;
		ret = owl_open_final(ctx, dec + out_size, &rem);
		if (ret < 0)
			goto ex_in;

		dec_size = rem + out_size;

		printf("Decrypted data (16 of %zu bytes): %.16s\n", (size_t)dec_size, dec);

		owl_ctx_free(ctx); // TODO: perhaps it should not return value
	}

ex_in:
	owl_free(dec);
ex_of:
	owl_free(enc);
ex_ak:
	owl_key_free(aes_key);
	owl_key_free(iv);
ex_pk:
	owl_key_free(key_pub);
	owl_key_free(key_priv);
}

int main()
{
	int ret = owl_init();
	if (ret < 0)
		return ret;

	encrypt_simple();

	encrypt_advanced();

	encrypt_seal();

	owl_exit(); // TODO: what about handing of return value from exit??
	return ret;
}
