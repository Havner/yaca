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

#include <yaca/crypto.h>
#include <yaca/seal.h>
#include <yaca/key.h>
#include <yaca/error.h>
#include "lorem.h"
#include "misc.h"

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
				YACA_KEY_TYPE_PAIR_RSA,
				YACA_KEY_2048BIT);
	if (ret) return;

	/// Encrypt a.k.a. seal
	{
		size_t out_size;
		size_t rem;

		ret = yaca_seal_init(&ctx, key_pub,
				     YACA_ENC_AES, YACA_BCM_CBC, YACA_KEY_192BIT,
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
		out_size = enc_size;
		ret = yaca_seal_update(ctx, lorem4096, 4096, enc, &out_size);
		if (ret < 0)
			goto ex_of;

		rem = enc_size - out_size;
		ret = yaca_seal_final(ctx, enc + out_size, &rem);
		if (ret < 0)
			goto ex_of;

		enc_size = rem + out_size;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_size);

		yaca_ctx_free(ctx); // TODO: perhaps it should not return value
	}

	/// Decrypt a.k.a. open
	{
		size_t out_size;
		size_t rem;

		ret = yaca_open_init(&ctx, key_priv,
				     YACA_ENC_AES, YACA_BCM_CBC, YACA_KEY_192BIT,
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
		out_size = enc_size;
		ret = yaca_open_update(ctx, enc, enc_size, dec, &out_size);
		if (ret < 0)
			goto ex_in;

		rem = dec_size - out_size;
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
	yaca_error_set_debug_func(debug_func);

	int ret = yaca_init();
	if (ret < 0)
		return ret;

	encrypt_seal();

	yaca_exit(); // TODO: what about handing of return value from exit??
	return ret;
}
