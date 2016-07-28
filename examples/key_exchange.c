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

/* send own public key and get peer public key */
static yaca_key_h exchange_keys(const yaca_key_h pkey)
{
	int ret;
	char *secret = NULL;
	size_t secret_len;
	char *key_material = NULL;

	yaca_key_h private_key = YACA_KEY_NULL;
	yaca_key_h public_key = YACA_KEY_NULL;
	yaca_key_h params = YACA_KEY_NULL;
	yaca_key_h aes_key = YACA_KEY_NULL;

	ret = yaca_key_extract_parameters(pkey, &params);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_generate_from_parameters(params, &private_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_extract_public(private_key, &public_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* derive secret */
	ret = yaca_key_derive_dh(private_key, pkey, &secret, &secret_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_derive_kdf(YACA_KDF_X962, YACA_DIGEST_SHA512, secret, secret_len,
	                          NULL, 0, YACA_KEY_LENGTH_192BIT, &key_material);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_import(YACA_KEY_TYPE_SYMMETRIC, NULL, key_material, YACA_KEY_LENGTH_192BIT,
	                      &aes_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	dump_hex(secret, secret_len, "\n***** Peer Secret: *****");
	dump_hex(key_material, YACA_KEY_LENGTH_192BIT, "\n***** Peer AES key: *****");

exit:
	yaca_key_destroy(private_key);
	yaca_key_destroy(params);
	yaca_key_destroy(aes_key);
	yaca_free(secret);
	yaca_free(key_material);

	return public_key;
}

void key_exchange_dh_standard_parameters(void)
{
	int ret;
	char *secret = NULL;
	size_t secret_len;
	char *key_material = NULL;

	yaca_key_h private_key = YACA_KEY_NULL;
	yaca_key_h public_key = YACA_KEY_NULL;
	yaca_key_h peer_key = YACA_KEY_NULL;
	yaca_key_h aes_key = YACA_KEY_NULL;

	printf("\n***** Diffie Hellman key exchange with standard DH parameters *****");

	/* generate private, public key */
	ret = yaca_key_generate(YACA_KEY_TYPE_DH_PRIV, YACA_KEY_LENGTH_DH_RFC_2048_256, &private_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_extract_public(private_key, &public_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* get peer public key */
	peer_key = exchange_keys(public_key);
	if (peer_key == YACA_KEY_NULL)
		goto exit;

	/* derive secret */
	ret = yaca_key_derive_dh(private_key, peer_key, &secret, &secret_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_derive_kdf(YACA_KDF_X962, YACA_DIGEST_SHA512, secret, secret_len,
	                          NULL, 0, YACA_KEY_LENGTH_192BIT, &key_material);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_import(YACA_KEY_TYPE_SYMMETRIC, NULL, key_material, YACA_KEY_LENGTH_192BIT,
	                      &aes_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	dump_hex(secret, secret_len, "\n***** My Secret: *****");
	dump_hex(key_material, YACA_KEY_LENGTH_192BIT, "\n***** My AES key: *****");

exit:
	yaca_key_destroy(private_key);
	yaca_key_destroy(public_key);
	yaca_key_destroy(peer_key);
	yaca_key_destroy(aes_key);
	yaca_free(secret);
	yaca_free(key_material);
}

void key_exchange_dh_generated_parameters(void)
{
	int ret;
	char *secret = NULL;
	size_t secret_len;
	char *key_material = NULL;

	yaca_key_h params = YACA_KEY_NULL;
	yaca_key_h private_key = YACA_KEY_NULL;
	yaca_key_h public_key = YACA_KEY_NULL;
	yaca_key_h peer_key = YACA_KEY_NULL;
	yaca_key_h aes_key = YACA_KEY_NULL;

	printf("\n***** Diffie Hellman key exchange with parameters generation *****");

	/* generate parameters */
	ret = yaca_key_generate(YACA_KEY_TYPE_DH_PARAMS,
	                        YACA_KEY_LENGTH_DH_GENERATOR_2 | 1024, &params);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* generate private, public key */
	ret = yaca_key_generate_from_parameters(params, &private_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_extract_public(private_key, &public_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* get peer public key */
	peer_key = exchange_keys(public_key);
	if (peer_key == YACA_KEY_NULL)
		goto exit;

	/* derive secret */
	ret = yaca_key_derive_dh(private_key, peer_key, &secret, &secret_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_derive_kdf(YACA_KDF_X962, YACA_DIGEST_SHA512, secret, secret_len,
	                          NULL, 0, YACA_KEY_LENGTH_192BIT, &key_material);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_import(YACA_KEY_TYPE_SYMMETRIC, NULL, key_material, YACA_KEY_LENGTH_192BIT,
	                      &aes_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	dump_hex(secret, secret_len, "\n***** My Secret: *****");
	dump_hex(key_material, YACA_KEY_LENGTH_192BIT, "\n***** My AES key: *****");

exit:
	yaca_key_destroy(params);
	yaca_key_destroy(private_key);
	yaca_key_destroy(public_key);
	yaca_key_destroy(peer_key);
	yaca_key_destroy(aes_key);
	yaca_free(secret);
	yaca_free(key_material);
}

void key_exchange_ecdh(void)
{
	int ret;
	char *secret = NULL;
	size_t secret_len;
	char *key_material = NULL;

	yaca_key_h private_key = YACA_KEY_NULL;
	yaca_key_h public_key = YACA_KEY_NULL;
	yaca_key_h peer_key = YACA_KEY_NULL;
	yaca_key_h aes_key = YACA_KEY_NULL;

	printf("\n***** Elliptic Curve Diffie Hellman key exchange *****");

	/* generate  private, public key */
	ret = yaca_key_generate(YACA_KEY_TYPE_EC_PRIV, YACA_KEY_LENGTH_EC_PRIME256V1, &private_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_extract_public(private_key, &public_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* get peer public key */
	peer_key = exchange_keys(public_key);
	if (peer_key == YACA_KEY_NULL)
		goto exit;

	/* derive secret */
	ret = yaca_key_derive_dh(private_key, peer_key, &secret, &secret_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_derive_kdf(YACA_KDF_X962, YACA_DIGEST_SHA512, secret, secret_len,
	                          NULL, 0, YACA_KEY_LENGTH_192BIT, &key_material);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_import(YACA_KEY_TYPE_SYMMETRIC, NULL, key_material, YACA_KEY_LENGTH_192BIT,
	                      &aes_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	dump_hex(secret, secret_len, "\n***** My Secret: *****");
	dump_hex(key_material, YACA_KEY_LENGTH_192BIT, "\n***** My AES key: *****");

exit:
	yaca_key_destroy(private_key);
	yaca_key_destroy(public_key);
	yaca_key_destroy(peer_key);
	yaca_key_destroy(aes_key);
	yaca_free(secret);
	yaca_free(key_material);
}

int main()
{
	yaca_debug_set_error_cb(debug_func);

	int ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		return ret;

	key_exchange_dh_standard_parameters();
	key_exchange_dh_generated_parameters();
	key_exchange_ecdh();

	yaca_cleanup();
	return ret;
}
