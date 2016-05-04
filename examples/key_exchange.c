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
 * @file key_exchange.c
 * @brief
 */

#include <stdio.h>
#include <yaca/crypto.h>
#include <yaca/encrypt.h>
#include <yaca/key.h>
#include <yaca/types.h>
#include <yaca/error.h>
#include "misc.h"

void key_exchange_dh(void)
{
	int ret;

	yaca_key_h private_key = YACA_KEY_NULL;
	yaca_key_h public_key = YACA_KEY_NULL;
	yaca_key_h peer_key = YACA_KEY_NULL;
	yaca_key_h secret = YACA_KEY_NULL;

	FILE *fp = NULL;
	char *buffer = NULL;
	long size;

	// generate  private, public key
	ret = yaca_key_gen(&private_key, YACA_KEY_TYPE_DH_PRIV, YACA_KEY_2048BIT);
	if (ret < 0)
		goto clean;

	ret = yaca_key_extract_public(private_key, &public_key);
	if (ret < 0)
		goto clean;

	// get peer public key from file
	// add helper to read key from file to buffer?
	fp = fopen("key.pub", "r");
	if (!fp) goto clean;

	fseek(fp ,0L ,SEEK_END);
	size = ftell(fp);
	rewind(fp);

	/* allocate memory for entire content */
	buffer = yaca_malloc(size+1);
	if (buffer == NULL)
		goto clean;

	/* copy the file into the buffer */
	if (1 != fread(buffer, size, 1, fp))
		goto clean;

	ret = yaca_key_import(&peer_key, YACA_KEY_TYPE_DH_PUB,
			      buffer, size);
	if (ret < 0)
		goto clean;

	// derive secret
	ret = yaca_key_derive_dh(private_key, peer_key, &secret);
	if (ret < 0)
		goto clean;

clean:
	yaca_key_free(private_key);
	yaca_key_free(public_key);
	yaca_key_free(peer_key);
	yaca_key_free(secret);
	if (fp != NULL)
		fclose(fp);
	yaca_free(buffer);
}

void key_exchange_ecdh(void)
{
	int ret;

	yaca_key_h private_key = YACA_KEY_NULL;
	yaca_key_h public_key = YACA_KEY_NULL;
	yaca_key_h peer_key = YACA_KEY_NULL;
	yaca_key_h secret = YACA_KEY_NULL;

	FILE *fp = NULL;
	char *buffer = NULL;
	long size;

	// generate  private, public key
	ret = yaca_key_gen(&private_key, YACA_KEY_TYPE_ECDH_PRIV, YACA_KEY_CURVE_P256);
	if (ret < 0)
		goto clean;

	ret = yaca_key_extract_public(private_key, &public_key);
	if (ret < 0)
		goto clean;

	// get peer public key from file
	fp = fopen("key.pub", "r");
	if (fp == NULL)
		goto clean;

	fseek(fp ,0L ,SEEK_END);
	size = ftell(fp);
	rewind(fp);

	/* allocate memory for entire content */
	buffer = yaca_malloc(size+1);
	if (buffer == NULL)
		goto clean;

	/* copy the file into the buffer */
	if (1 != fread(buffer, size, 1, fp))
		goto clean;

	ret = yaca_key_import(&peer_key, YACA_KEY_TYPE_ECDH_PUB, buffer, size);
	if (ret < 0)
		goto clean;

	// derive secret
	ret = yaca_key_derive_dh(private_key, peer_key, &secret);
	if (ret < 0)
		goto clean;

clean:
	yaca_key_free(private_key);
	yaca_key_free(public_key);
	yaca_key_free(peer_key);
	yaca_key_free(secret);
	if (fp != NULL)
		fclose(fp);
	yaca_free(buffer);
}

int main()
{
	yaca_error_set_debug_func(debug_func);

	int ret = yaca_init();
	if (ret < 0)
		return ret;

	key_exchange_dh();
	key_exchange_ecdh();

	yaca_exit();
	return ret;
}
