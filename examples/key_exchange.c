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

#include <yaca_crypto.h>
#include <yaca_key.h>
#include <yaca_error.h>

#include "misc.h"
#include "../src/debug.h"

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

	/* generate  private, public key */
	ret = yaca_key_generate(YACA_KEY_TYPE_DH_PRIV, YACA_KEY_LENGTH_2048BIT, &private_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_extract_public(private_key, &public_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* get peer public key */
	// TODO: read key from file to buffer can be replaced with read_file() from misc.h
	fp = fopen("key.pub", "r");
	if (!fp) goto exit;

	fseek(fp, 0L, SEEK_END);
	size = ftell(fp);
	rewind(fp);

	/* allocate memory for entire content */
	if (yaca_malloc(size + 1, (void**)&buffer) != YACA_ERROR_NONE)
		goto exit;

	/* copy the file into the buffer */
	if (1 != fread(buffer, size, 1, fp))
		goto exit;

	ret = yaca_key_import(YACA_KEY_TYPE_DH_PUB, NULL,
	                      buffer, size, &peer_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* derive secret */
	ret = yaca_key_derive_dh(private_key, peer_key, &secret);
	if (ret != YACA_ERROR_NONE)
		goto exit;

exit:
	yaca_key_destroy(private_key);
	yaca_key_destroy(public_key);
	yaca_key_destroy(peer_key);
	yaca_key_destroy(secret);
	if (fp != NULL)
		fclose(fp);
	yaca_free(buffer);
}

// TODO ECDH is not supported yet
#if 0
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

	/* generate  private, public key */
	ret = yaca_key_generate(YACA_KEY_TYPE_EC_PRIV, YACA_KEY_CURVE_P256, &private_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_extract_public(private_key, &public_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* get peer public key */
	// TODO: read key from file to buffer can be replaced with read_file() from misc.h
	fp = fopen("key.pub", "r");
	if (fp == NULL)
		goto exit;

	fseek(fp, 0L, SEEK_END);
	size = ftell(fp);
	rewind(fp);

	/* allocate memory for entire content */
	if (yaca_malloc(size + 1, (void**)&buffer) != YACA_ERROR_NONE)
		goto exit;

	/* copy the file into the buffer */
	if (1 != fread(buffer, size, 1, fp))
		goto exit;

	ret = yaca_key_import(YACA_KEY_TYPE_EC_PUB, NULL, buffer, size, &peer_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* derive secret */
	ret = yaca_key_derive_dh(private_key, peer_key, &secret);
	if (ret != YACA_ERROR_NONE)
		goto exit;

exit:
	yaca_key_destroy(private_key);
	yaca_key_destroy(public_key);
	yaca_key_destroy(peer_key);
	yaca_key_destroy(secret);
	if (fp != NULL)
		fclose(fp);
	yaca_free(buffer);
}
#endif

int main()
{
	yaca_debug_set_error_cb(debug_func);

	int ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		return ret;

	key_exchange_dh();
	//key_exchange_ecdh();

	yaca_cleanup();
	return ret;
}
