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

void encrypt_seal(void)
{
	const yaca_encrypt_algorithm_e algo = YACA_ENCRYPT_AES;
	const yaca_block_cipher_mode_e bcm = YACA_BCM_CBC;
	const size_t key_bits = YACA_KEY_LENGTH_256BIT;
	yaca_context_h ctx = YACA_CONTEXT_NULL;
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
	if (yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_4096BIT, &key_priv) != YACA_ERROR_NONE)
		return;

	if (yaca_key_extract_public(key_priv, &key_pub) != YACA_ERROR_NONE)
		goto exit;

	/* Encrypt a.k.a. seal */
	{
		if (yaca_seal_initialize(&ctx, key_pub, algo, bcm, key_bits, &aes_key, &iv) != YACA_ERROR_NONE)
			goto exit;

		if (yaca_get_block_length(ctx, &block_len) != YACA_ERROR_NONE)
			goto exit;

		if (yaca_get_output_length(ctx, LOREM4096_SIZE, &output_len) != YACA_ERROR_NONE)
			goto exit;

		/* Calculate max output: size of update + final chunks */
		enc_size = output_len + block_len;
		if (yaca_malloc(enc_size, (void**)&enc) != YACA_ERROR_NONE)
			goto exit;

		/* Seal and finalize */
		out_size = enc_size;
		if (yaca_seal_update(ctx, lorem4096, LOREM4096_SIZE, enc, &out_size) != YACA_ERROR_NONE)
			goto exit;

		rem = enc_size - out_size;
		if (yaca_seal_finalize(ctx, enc + out_size, &rem) != YACA_ERROR_NONE)
			goto exit;

		enc_size = rem + out_size;

		dump_hex(enc, 16, "Encrypted data (16 of %zu bytes): ", enc_size);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* Decrypt a.k.a. open */
	{
		if (yaca_open_initialize(&ctx, key_priv, algo, bcm, key_bits, aes_key, iv) != YACA_ERROR_NONE)
			goto exit;

		if (yaca_get_block_length(ctx, &block_len) != YACA_ERROR_NONE)
			goto exit;

		if (yaca_get_output_length(ctx, LOREM4096_SIZE, &output_len) != YACA_ERROR_NONE)
			goto exit;

		/* Calculate max output: size of update + final chunks */
		dec_size = output_len + block_len;
		if (yaca_malloc(dec_size, (void**)&dec) != YACA_ERROR_NONE)
			goto exit;

		/* Open and finalize */
		out_size = dec_size;
		if (yaca_open_update(ctx, enc, enc_size, dec, &out_size) != YACA_ERROR_NONE)
			goto exit;

		rem = dec_size - out_size;
		if (yaca_open_finalize(ctx, dec + out_size, &rem) != YACA_ERROR_NONE)
			goto exit;

		dec_size = rem + out_size;

		printf("Decrypted data (16 of %zu bytes): %.16s\n", dec_size, dec);
	}

exit:
	yaca_free(dec);
	yaca_free(enc);
	yaca_context_destroy(ctx);
	yaca_key_destroy(aes_key);
	yaca_key_destroy(iv);
	yaca_key_destroy(key_pub);
	yaca_key_destroy(key_priv);
}

int main()
{
	yaca_debug_set_error_cb(debug_func);

	int ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		return ret;

	encrypt_seal();

	yaca_cleanup();
	return ret;
}
