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
 * @brief Diffie-Helmann key exchange API example.
 */

//! [Diffie-Helmann key exchange API example]
#include <yaca_crypto.h>
#include <yaca_key.h>
#include <yaca_error.h>

/* include helpers functions and definitions */
#include "misc.h"

static yaca_key_h exchange_public_keys(const yaca_key_h peer_key)
{
	int ret;
	yaca_key_h params = YACA_KEY_NULL;
	yaca_key_h priv_key = YACA_KEY_NULL;
	yaca_key_h pub_key = YACA_KEY_NULL;

	ret = yaca_key_extract_parameters(peer_key, &params);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_generate_from_parameters(params, &priv_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_extract_public(priv_key, &pub_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

exit:
	yaca_key_destroy(priv_key);
	yaca_key_destroy(params);

	return pub_key;
}

int main()
{
	int ret;
	yaca_key_h priv_key = YACA_KEY_NULL;
	yaca_key_h pub_key = YACA_KEY_NULL;
	yaca_key_h peer_key = YACA_KEY_NULL;
	yaca_key_h aes_key = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL;

	char *secret = NULL;
	size_t secret_len;
	char *key_material = NULL;
	size_t key_material_len;
	char *iv_material = NULL;
	size_t iv_material_len;
	char *temp_material = NULL;
	size_t temp_material_len;

	ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* Key generation */
	ret = yaca_key_generate(YACA_KEY_TYPE_DH_PRIV, YACA_KEY_LENGTH_DH_RFC_2048_256, &priv_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_extract_public(priv_key, &pub_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* Send own public key and get peer public key */
	peer_key = exchange_public_keys(pub_key);
	if (peer_key == YACA_KEY_NULL)
		goto exit;

	/* Derive shared secret */
	ret = yaca_key_derive_dh(priv_key, peer_key, &secret, &secret_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* Derive AES key and IV */
	key_material_len = YACA_KEY_LENGTH_256BIT / 8;
	iv_material_len = YACA_KEY_LENGTH_IV_128BIT / 8;
	temp_material_len = key_material_len + iv_material_len;
	ret = yaca_key_derive_kdf(YACA_KDF_X942, YACA_DIGEST_SHA512, secret, secret_len,
	                          NULL, 0, temp_material_len, &temp_material);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	key_material = temp_material;
	iv_material = temp_material + key_material_len;

	ret = yaca_key_import(YACA_KEY_TYPE_SYMMETRIC, NULL, key_material, key_material_len, &aes_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_import(YACA_KEY_TYPE_IV, NULL, iv_material, iv_material_len, &iv);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* display key and IV in hexadecimal format */
	dump_hex(key_material, key_material_len, "***** Derived AES key: *****");
	dump_hex(iv_material, iv_material_len, "\n***** Derived IV: *****");

exit:
	yaca_key_destroy(priv_key);
	yaca_key_destroy(pub_key);
	yaca_key_destroy(peer_key);
	yaca_key_destroy(aes_key);
	yaca_key_destroy(iv);
	yaca_free(secret);
	yaca_free(temp_material);

	yaca_cleanup();
	return ret;
}
//! [Diffie-Helmann key exchange API example]
