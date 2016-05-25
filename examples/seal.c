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
#include "../src/debug.h"

void encrypt_seal(void)
{
	const yaca_enc_algo_e algo = YACA_ENC_AES;
	const yaca_block_cipher_mode_e bcm = YACA_BCM_CBC;
	const size_t key_bits = YACA_KEY_256BIT;
	yaca_ctx_h ctx = YACA_CTX_NULL;
	yaca_key_h key_pub = YACA_KEY_NULL;
	yaca_key_h key_priv = YACA_KEY_NULL;
	yaca_key_h aes_key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;

	char *enc = NULL;
	char *dec = NULL;
	size_t enc_size;
	size_t dec_size;

	size_t block_len;
	size_t output_len;
	size_t out_size;
	size_t rem;

	printf("Plain data (16 of %zu bytes): %.16s\n", LOREM4096_SIZE, lorem4096);

	/* Generate key pair */
	if (yaca_key_gen(&key_priv, YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_4096BIT) != 0)
		return;

	if (yaca_key_extract_public(key_priv, &key_pub) != 0)
		goto ex_prvk;

	/* Encrypt a.k.a. seal */
	{
		if (yaca_seal_init(&ctx, key_pub, algo, bcm, key_bits, &aes_key, &iv) != 0)
			goto ex_pubk;

		if (yaca_get_block_length(ctx, &block_len) != 0)
			goto ex_ak;

		if (yaca_get_output_length(ctx, LOREM4096_SIZE, &output_len) != 0)
			goto ex_ak;

		/* Calculate max output: size of update + final chunks */
		enc_size = output_len + block_len;
		if ((enc = yaca_malloc(enc_size)) == NULL)
			goto ex_ak;

		/* Seal and finalize */
		out_size = enc_size;
		if (yaca_seal_update(ctx, lorem4096, LOREM4096_SIZE, enc, &out_size) != 0)
			goto ex_of;

		rem = enc_size - out_size;
		if (yaca_seal_final(ctx, enc + out_size, &rem) != 0)
			goto ex_of;

		enc_size = rem + out_size;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_size);

		yaca_ctx_free(ctx);
		ctx = YACA_CTX_NULL;
	}

	/* Decrypt a.k.a. open */
	{
		if (yaca_open_init(&ctx, key_priv, algo, bcm, key_bits, aes_key, iv) != 0)
			goto ex_of;

		if (yaca_get_block_length(ctx, &block_len) != 0)
			goto ex_of;

		if (yaca_get_output_length(ctx, LOREM4096_SIZE, &output_len) != 0)
			goto ex_of;

		/* Calculate max output: size of update + final chunks */
		dec_size = output_len + block_len;
		if ((dec = yaca_malloc(dec_size)) == NULL)
			goto ex_of;

		/* Open and finalize */
		out_size = dec_size;
		if (yaca_open_update(ctx, enc, enc_size, dec, &out_size) != 0)
			goto ex_in;

		rem = dec_size - out_size;
		if (yaca_open_final(ctx, dec + out_size, &rem) != 0)
			goto ex_in;

		dec_size = rem + out_size;

		printf("Decrypted data (16 of %zu bytes): %.16s\n", dec_size, dec);
	}

ex_in:
	yaca_free(dec);
ex_of:
	yaca_free(enc);
ex_ak:
	yaca_ctx_free(ctx);
	yaca_key_free(aes_key);
	yaca_key_free(iv);
ex_pubk:
	yaca_key_free(key_pub);
ex_prvk:
	yaca_key_free(key_priv);
}

int main()
{
	yaca_debug_set_error_cb(debug_func);

	int ret = yaca_init();
	if (ret != 0)
		return ret;

	encrypt_seal();

	yaca_exit();
	return ret;
}
