/*
 *  Copyright (c) 2020 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Lukasz Pawelczyk <l.pawelczyk@samsung.com>
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
 * @file    test_seal.cpp
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   Seal API unit tests.
 */

#include <boost/test/unit_test.hpp>
#include <vector>

#include <yaca_crypto.h>
#include <yaca_seal.h>
#include <yaca_key.h>
#include <yaca_encrypt.h>
#include <yaca_error.h>

#include "common.h"


BOOST_AUTO_TEST_SUITE(TESTS_SEAL)

BOOST_FIXTURE_TEST_CASE(T701__positive__seal_open, InitDebugFixture)
{
	struct seal_args {
		yaca_encrypt_algorithm_e algo;
		yaca_block_cipher_mode_e bcm;
		size_t key_bit_len;
		yaca_padding_e padding;
		size_t split;
	};

	const std::vector<seal_args> sargs = {
		{YACA_ENCRYPT_AES, YACA_BCM_CBC,  128, YACA_INVALID_PADDING, 16},
		{YACA_ENCRYPT_AES, YACA_BCM_CBC,  128, YACA_PADDING_NONE,     8},
		{YACA_ENCRYPT_AES, YACA_BCM_CBC,  128, YACA_PADDING_PKCS7,   11},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB,  128, YACA_INVALID_PADDING, 24},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB1, 128, YACA_INVALID_PADDING, 13},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB8, 128, YACA_INVALID_PADDING,  4},
		{YACA_ENCRYPT_AES, YACA_BCM_CTR,  128, YACA_INVALID_PADDING, 66},
		{YACA_ENCRYPT_AES, YACA_BCM_ECB,  128, YACA_INVALID_PADDING,  3},
		{YACA_ENCRYPT_AES, YACA_BCM_ECB,  128, YACA_PADDING_NONE,    11},
		{YACA_ENCRYPT_AES, YACA_BCM_ECB,  128, YACA_PADDING_PKCS7,   34},
		{YACA_ENCRYPT_AES, YACA_BCM_OFB,  128, YACA_INVALID_PADDING, 27},

		{YACA_ENCRYPT_AES, YACA_BCM_CBC,  192, YACA_INVALID_PADDING,  9},
		{YACA_ENCRYPT_AES, YACA_BCM_CBC,  192, YACA_PADDING_NONE,    12},
		{YACA_ENCRYPT_AES, YACA_BCM_CBC,  192, YACA_PADDING_PKCS7,   11},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB,  192, YACA_INVALID_PADDING, 31},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB1, 192, YACA_INVALID_PADDING, 17},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB8, 192, YACA_INVALID_PADDING,  2},
		{YACA_ENCRYPT_AES, YACA_BCM_CTR,  192, YACA_INVALID_PADDING,  1},
		{YACA_ENCRYPT_AES, YACA_BCM_ECB,  192, YACA_INVALID_PADDING, 24},
		{YACA_ENCRYPT_AES, YACA_BCM_ECB,  192, YACA_PADDING_NONE,    15},
		{YACA_ENCRYPT_AES, YACA_BCM_ECB,  192, YACA_PADDING_PKCS7,   33},
		{YACA_ENCRYPT_AES, YACA_BCM_OFB,  192, YACA_INVALID_PADDING, 44},

		{YACA_ENCRYPT_AES, YACA_BCM_CBC,  256, YACA_INVALID_PADDING, 10},
		{YACA_ENCRYPT_AES, YACA_BCM_CBC,  256, YACA_PADDING_NONE,    11},
		{YACA_ENCRYPT_AES, YACA_BCM_CBC,  256, YACA_PADDING_PKCS7,   23},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB,  256, YACA_INVALID_PADDING, 17},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB1, 256, YACA_INVALID_PADDING, 23},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB8, 256, YACA_INVALID_PADDING, 29},
		{YACA_ENCRYPT_AES, YACA_BCM_CTR,  256, YACA_INVALID_PADDING, 21},
		{YACA_ENCRYPT_AES, YACA_BCM_ECB,  256, YACA_INVALID_PADDING,  9},
		{YACA_ENCRYPT_AES, YACA_BCM_ECB,  256, YACA_PADDING_NONE,     3},
		{YACA_ENCRYPT_AES, YACA_BCM_ECB,  256, YACA_PADDING_PKCS7,   15},
		{YACA_ENCRYPT_AES, YACA_BCM_OFB,  256, YACA_INVALID_PADDING, 13},

		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_CBC,  64, YACA_INVALID_PADDING, 31},
		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_CBC,  64, YACA_PADDING_NONE,    22},
		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_CBC,  64, YACA_PADDING_PKCS7,   39},
		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_CFB,  64, YACA_INVALID_PADDING, 24},
		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_CFB1, 64, YACA_INVALID_PADDING, 11},
		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_CFB8, 64, YACA_INVALID_PADDING, 22},
		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_ECB,  64, YACA_INVALID_PADDING,  7},
		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_ECB,  64, YACA_PADDING_NONE,    19},
		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_ECB,  64, YACA_PADDING_PKCS7,    9},
		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_OFB,  64, YACA_INVALID_PADDING,  2},

		{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_CBC, 128, YACA_INVALID_PADDING, 16},
		{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_CBC, 128, YACA_PADDING_NONE,    25},
		{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_CBC, 128, YACA_PADDING_PKCS7,   26},
		{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_CFB, 128, YACA_INVALID_PADDING, 23},
		{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_ECB, 128, YACA_INVALID_PADDING, 13},
		{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_ECB, 128, YACA_PADDING_NONE,    10},
		{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_ECB, 128, YACA_PADDING_PKCS7,   29},
		{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_OFB, 128, YACA_INVALID_PADDING, 32},

		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CBC,  192, YACA_INVALID_PADDING, 39},
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CBC,  192, YACA_PADDING_NONE,    29},
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CBC,  192, YACA_PADDING_PKCS7,   19},
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CFB,  192, YACA_INVALID_PADDING,  9},
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CFB1, 192, YACA_INVALID_PADDING, 44},
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CFB8, 192, YACA_INVALID_PADDING, 33},
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_ECB,  192, YACA_INVALID_PADDING, 22},
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_ECB,  192, YACA_PADDING_NONE,    11},
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_ECB,  192, YACA_PADDING_PKCS7,   13},
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_OFB,  192, YACA_INVALID_PADDING,  1},

		{YACA_ENCRYPT_UNSAFE_RC4, YACA_BCM_NONE, 256, YACA_INVALID_PADDING, 17},

		{YACA_ENCRYPT_CAST5, YACA_BCM_CBC, 128, YACA_INVALID_PADDING,  3},
		{YACA_ENCRYPT_CAST5, YACA_BCM_CBC, 128, YACA_PADDING_NONE,    24},
		{YACA_ENCRYPT_CAST5, YACA_BCM_CBC, 128, YACA_PADDING_PKCS7,   21},
		{YACA_ENCRYPT_CAST5, YACA_BCM_CFB, 128, YACA_INVALID_PADDING, 19},
		{YACA_ENCRYPT_CAST5, YACA_BCM_ECB, 128, YACA_INVALID_PADDING,  7},
		{YACA_ENCRYPT_CAST5, YACA_BCM_ECB, 128, YACA_PADDING_NONE,     6},
		{YACA_ENCRYPT_CAST5, YACA_BCM_ECB, 128, YACA_PADDING_PKCS7,   18},
		{YACA_ENCRYPT_CAST5, YACA_BCM_OFB, 128, YACA_INVALID_PADDING,  2},
	};

	for (const auto &sa: sargs) {
		int ret;
		yaca_context_h ctx = YACA_CONTEXT_NULL;
		yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
		yaca_key_h key_sym = YACA_KEY_NULL, iv = YACA_KEY_NULL;

		char *encrypted = NULL, *decrypted = NULL;
		size_t encrypted_len = 0, decrypted_len = 0;

		generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_prv, &key_pub);

		/* SEAL */
		{
			ret = yaca_seal_initialize(&ctx, key_pub, sa.algo, sa.bcm,
			                           sa.key_bit_len, &key_sym, &iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			size_t total = allocate_output(ctx, INPUT_DATA_SIZE, sa.split, encrypted);
			size_t written;

			call_update_loop(ctx, INPUT_DATA, INPUT_DATA_SIZE,
			                 encrypted, encrypted_len, sa.split,
			                 yaca_seal_update);

			if (sa.padding != YACA_INVALID_PADDING) {
				ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, &sa.padding,
				                                sizeof(yaca_padding_e));
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			ret = yaca_seal_finalize(ctx, encrypted + encrypted_len, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			encrypted_len += written;

			BOOST_REQUIRE(encrypted_len <= total);
			ret = yaca_realloc(encrypted_len, (void **)&encrypted);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		/* OPEN */
		{
			ret = yaca_open_initialize(&ctx, key_prv, sa.algo, sa.bcm,
			                           sa.key_bit_len, key_sym, iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			if (sa.padding != YACA_INVALID_PADDING) {
				ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, &sa.padding,
				                                sizeof(yaca_padding_e));
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			size_t total = allocate_output(ctx, encrypted_len, sa.split, decrypted);
			size_t written;

			call_update_loop(ctx, encrypted, encrypted_len,
			                 decrypted, decrypted_len, sa.split,
			                 yaca_open_update);

			ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			decrypted_len += written;

			BOOST_REQUIRE(decrypted_len <= total);
			ret = yaca_realloc(decrypted_len, (void **)&decrypted);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		BOOST_REQUIRE(decrypted_len == INPUT_DATA_SIZE);
		ret = yaca_memcmp(INPUT_DATA, decrypted, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_key_destroy(key_prv);
		yaca_key_destroy(key_pub);
		yaca_key_destroy(key_sym);
		yaca_key_destroy(iv);
		yaca_free(encrypted);
		yaca_free(decrypted);
	}
}

BOOST_FIXTURE_TEST_CASE(T702__negative__seal_open, InitDebugFixture)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL, ctx_encrypt = YACA_CONTEXT_NULL;
	yaca_key_h key_rsa_prv = YACA_KEY_NULL, key_rsa_pub = YACA_KEY_NULL;
	yaca_key_h key_rsa_prv2 = YACA_KEY_NULL, key_rsa_pub2 = YACA_KEY_NULL;
	yaca_key_h key_dsa_prv = YACA_KEY_NULL, key_dsa_pub = YACA_KEY_NULL;
	yaca_key_h key_sym = YACA_KEY_NULL, key_sym2 = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL, iv2 = YACA_KEY_NULL;
	yaca_padding_e pad_pkcs7 = YACA_PADDING_PKCS7;
	yaca_padding_e pad_invalid = YACA_PADDING_X931;
	size_t len = 128;

	char *encrypted = NULL, *decrypted = NULL;
	size_t encrypted_len = 0, decrypted_len = 0;

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key_sym2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_IV, YACA_KEY_LENGTH_IV_128BIT, &iv2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_encrypt_initialize(&ctx_encrypt, YACA_ENCRYPT_AES, YACA_BCM_CBC, key_sym2, iv2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_rsa_prv,  &key_rsa_pub);
	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_rsa_prv2, &key_rsa_pub2);
	generate_asymmetric_keys(YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_dsa_prv,  &key_dsa_pub);

	/* get an encrypted key_sym2 */
	yaca_key_destroy(key_sym2);
	key_sym2 = YACA_KEY_NULL;
	ret = yaca_seal_initialize(&ctx, key_rsa_pub2, YACA_ENCRYPT_AES, YACA_BCM_CBC,
	                           YACA_KEY_LENGTH_256BIT, &key_sym2, &iv);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	yaca_context_destroy(ctx);
	ctx = YACA_CONTEXT_NULL;
	yaca_key_destroy(iv);
	iv = YACA_KEY_NULL;

	/* SEAL */
	{
		ret = yaca_seal_initialize(NULL, key_rsa_pub, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_initialize(&ctx, YACA_KEY_NULL, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_initialize(&ctx, key_rsa_prv, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_initialize(&ctx, key_dsa_pub, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_initialize(&ctx, key_dsa_prv, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_initialize(&ctx, key_sym2, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_initialize(&ctx, key_rsa_pub, YACA_INVALID_ENCRYPT_ALGORITHM, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_initialize(&ctx, key_rsa_pub, YACA_ENCRYPT_AES, YACA_INVALID_BLOCK_CIPHER_MODE,
		                           YACA_KEY_LENGTH_256BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_initialize(&ctx, key_rsa_pub, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           257, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_initialize(&ctx, key_rsa_pub, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, NULL, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_initialize(&ctx, key_rsa_pub, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, &key_sym, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_initialize(&ctx, key_rsa_pub, YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CTR,
		                           YACA_KEY_LENGTH_256BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_initialize(&ctx, key_rsa_pub, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_get_output_length(ctx, INPUT_DATA_SIZE, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		size_t total = allocate_output(ctx, INPUT_DATA_SIZE, 1, encrypted);
		size_t written;

		ret = yaca_seal_update(YACA_CONTEXT_NULL, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_update(ctx_encrypt, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_update(ctx, NULL, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_update(ctx, INPUT_DATA, 0, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len = written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
		                                &len, sizeof(size_t));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad_invalid, sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad_pkcs7, 1);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, &pad_pkcs7,
		                                sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_seal_finalize(YACA_CONTEXT_NULL, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_finalize(ctx_encrypt, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_finalize(ctx, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_finalize(ctx, encrypted + encrypted_len, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_finalize(ctx, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len += written;
		BOOST_REQUIRE(encrypted_len <= total);
		ret = yaca_realloc(encrypted_len, (void **)&encrypted);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, &pad_pkcs7,
		                                sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_finalize(ctx, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* OPEN */
	{
		ret = yaca_open_initialize(NULL, key_rsa_prv, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_initialize(&ctx, key_rsa_pub, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_initialize(&ctx, key_dsa_prv, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_initialize(&ctx, key_dsa_pub, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_initialize(&ctx, key_sym2, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_initialize(&ctx, key_rsa_prv, YACA_INVALID_ENCRYPT_ALGORITHM, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_initialize(&ctx, key_rsa_prv, YACA_ENCRYPT_AES, YACA_INVALID_BLOCK_CIPHER_MODE,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_initialize(&ctx, key_rsa_prv, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_192BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_initialize(&ctx, key_rsa_prv, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, YACA_KEY_NULL, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_initialize(&ctx, key_rsa_prv, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, key_sym2, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_initialize(&ctx, key_rsa_prv, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, key_rsa_prv, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_initialize(&ctx, key_rsa_prv, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, iv, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_initialize(&ctx, key_rsa_prv, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, key_sym, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_initialize(&ctx, key_rsa_prv, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, key_sym, key_sym2);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_initialize(&ctx, key_rsa_prv, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
		                                &len, sizeof(size_t));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad_invalid, 1);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad_pkcs7, sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_get_output_length(ctx, encrypted_len, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_open_update(YACA_CONTEXT_NULL, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_update(ctx_encrypt, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_update(ctx, NULL, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_update(ctx, encrypted, 0, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad_pkcs7, sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_finalize(YACA_CONTEXT_NULL, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_finalize(ctx_encrypt, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_finalize(ctx, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_finalize(ctx, decrypted + decrypted_len, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* OPEN, wrong asym key */
	{
		ret = yaca_open_initialize(&ctx, key_rsa_prv2, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);
	}

	/* OPEN, wrong BCM */
	{
		ret = yaca_open_initialize(&ctx, key_rsa_prv, YACA_ENCRYPT_AES, YACA_BCM_ECB,
		                           YACA_KEY_LENGTH_256BIT, key_sym, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad_pkcs7, sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* OPEN, wrong symmetric key */
	{
		ret = yaca_open_initialize(&ctx, key_rsa_prv, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, key_sym2, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);
	}

	/* OPEN, broken the end of ciphertext */
	{
		encrypted[encrypted_len - 1] = ~encrypted[encrypted_len - 1];
		encrypted[encrypted_len - 2] = ~encrypted[encrypted_len - 2];

		ret = yaca_open_initialize(&ctx, key_rsa_prv, YACA_ENCRYPT_AES, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad_pkcs7, sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	yaca_key_destroy(key_rsa_prv);
	yaca_key_destroy(key_rsa_pub);
	yaca_key_destroy(key_rsa_prv2);
	yaca_key_destroy(key_rsa_pub2);
	yaca_key_destroy(key_dsa_prv);
	yaca_key_destroy(key_dsa_pub);
	yaca_key_destroy(key_sym);
	yaca_key_destroy(key_sym2);
	yaca_key_destroy(iv);
	yaca_free(encrypted);
}

BOOST_FIXTURE_TEST_CASE(T703__positive__seal_open_rc2, InitDebugFixture)
{
	struct seal_args {
		yaca_block_cipher_mode_e bcm;
		size_t key_bit_len;
		size_t effective_key_bits;
		size_t split;
	};

	const std::vector<seal_args> sargs = {
		{YACA_BCM_CBC, 128, IGNORE, 11},
		{YACA_BCM_CBC, 192,     64, 22},
		{YACA_BCM_CBC, 200,    128,  3},
		{YACA_BCM_CBC, 192,    255,  7},
		{YACA_BCM_CBC, 192,    713,  2},
		{YACA_BCM_CBC, 224,      1, 19},
		{YACA_BCM_CBC, 256,   1024, 19},
		{YACA_BCM_CFB, 192, IGNORE, 13},
		{YACA_BCM_CFB, 192,    333, 33},
		{YACA_BCM_ECB, 272, IGNORE,  8},
		{YACA_BCM_ECB, 192,    666, 15},
		{YACA_BCM_OFB, 520, IGNORE, 25},
		{YACA_BCM_OFB, 224,    999, 35},
	};

	for (const auto &sa: sargs) {
		int ret;
		yaca_context_h ctx = YACA_CONTEXT_NULL;
		yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
		yaca_key_h key_sym = YACA_KEY_NULL, iv = YACA_KEY_NULL;

		char *encrypted = NULL, *decrypted = NULL;
		size_t encrypted_len = 0, decrypted_len = 0;

		generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_prv, &key_pub);

		/* SEAL */
		{
			ret = yaca_seal_initialize(&ctx, key_pub, YACA_ENCRYPT_UNSAFE_RC2, sa.bcm,
			                           sa.key_bit_len, &key_sym, &iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			if (sa.effective_key_bits != IGNORE) {
				ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
				                                &sa.effective_key_bits, sizeof(size_t));
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			size_t total = allocate_output(ctx, INPUT_DATA_SIZE, sa.split, encrypted);
			size_t written;

			call_update_loop(ctx, INPUT_DATA, INPUT_DATA_SIZE,
			                 encrypted, encrypted_len, sa.split,
			                 yaca_seal_update);

			ret = yaca_seal_finalize(ctx, encrypted + encrypted_len, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			encrypted_len += written;

			BOOST_REQUIRE(encrypted_len <= total);
			ret = yaca_realloc(encrypted_len, (void **)&encrypted);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		/* OPEN */
		{
			ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_UNSAFE_RC2, sa.bcm,
			                           sa.key_bit_len, key_sym, iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			if (sa.effective_key_bits != IGNORE) {
				ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
				                                &sa.effective_key_bits, sizeof(size_t));
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			size_t total = allocate_output(ctx, encrypted_len, sa.split, decrypted);
			size_t written;

			call_update_loop(ctx, encrypted, encrypted_len,
			                 decrypted, decrypted_len, sa.split,
			                 yaca_open_update);

			ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			decrypted_len += written;

			BOOST_REQUIRE(decrypted_len <= total);
			ret = yaca_realloc(decrypted_len, (void **)&decrypted);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		BOOST_REQUIRE(decrypted_len == INPUT_DATA_SIZE);
		ret = yaca_memcmp(INPUT_DATA, decrypted, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_key_destroy(key_prv);
		yaca_key_destroy(key_pub);
		yaca_key_destroy(key_sym);
		yaca_key_destroy(iv);
		yaca_free(encrypted);
		yaca_free(decrypted);
	}
}

BOOST_FIXTURE_TEST_CASE(T704__negative__encrypt_decrypt_rc2, InitDebugFixture)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
	yaca_key_h key_sym = YACA_KEY_NULL, iv = YACA_KEY_NULL;

	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_prv, &key_pub);

	/* SEAL */
	{
		ret = yaca_seal_initialize(&ctx, key_pub, YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CFB1,
		                           YACA_KEY_LENGTH_192BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_initialize(&ctx, key_pub, YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CTR,
		                           YACA_KEY_LENGTH_192BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_initialize(&ctx, key_pub, YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CBC,
		                           YACA_KEY_LENGTH_192BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* OPEN */
	{
		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CFB1,
		                           YACA_KEY_LENGTH_192BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CTR,
		                           YACA_KEY_LENGTH_192BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);
	}

	yaca_key_destroy(key_prv);
	yaca_key_destroy(key_pub);
	yaca_key_destroy(key_sym);
	yaca_key_destroy(iv);
}

BOOST_FIXTURE_TEST_CASE(T705__positive__open_seal_ccm, InitDebugFixture)
{
	struct seal_args {
		size_t key_bit_len;
		size_t ccm_tag_len;
		size_t aad_len;
	};

	const std::vector<seal_args> sargs = {
		{128, IGNORE, IGNORE},
		{128,      4, IGNORE},
		{128, IGNORE,     13},
		{128,      6,     23},

		{192, IGNORE, IGNORE},
		{192,     10, IGNORE},
		{192, IGNORE,     21},
		{192,      8,     17},

		{256, IGNORE, IGNORE},
		{256,     16, IGNORE},
		{256, IGNORE,     55},
		{256,     12,     33},
	};

	for (const auto &sa: sargs) {
		int ret;
		yaca_context_h ctx = YACA_CONTEXT_NULL;
		yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
		yaca_key_h key_sym = YACA_KEY_NULL, iv = YACA_KEY_NULL;

		char *tag = NULL, *aad = NULL;
		size_t tag_len;

		char *encrypted = NULL, *decrypted = NULL;
		size_t encrypted_len, decrypted_len;

		generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_prv, &key_pub);

		/* SEAL */
		{
			ret = yaca_seal_initialize(&ctx, key_pub, YACA_ENCRYPT_AES, YACA_BCM_CCM,
			                           sa.key_bit_len, &key_sym, &iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			size_t total = allocate_output(ctx, INPUT_DATA_SIZE, 1, encrypted);
			size_t written;

			if (sa.ccm_tag_len != IGNORE) {
				tag_len = sa.ccm_tag_len;

				ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG_LEN,
				                                &tag_len, sizeof(tag_len));
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			if (sa.aad_len != IGNORE) {
				ret = yaca_malloc(sa.aad_len, (void**)&aad);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);

				ret = yaca_randomize_bytes(aad, sa.aad_len);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);

				ret = yaca_seal_update(ctx, NULL, INPUT_DATA_SIZE,
				                       NULL, &written);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);

				ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD,
				                                aad, sa.aad_len);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			encrypted_len = written;

			ret = yaca_seal_finalize(ctx, encrypted + encrypted_len, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			encrypted_len += written;

			BOOST_REQUIRE(encrypted_len <= total);
			ret = yaca_realloc(encrypted_len, (void **)&encrypted);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			ret = yaca_context_get_property(ctx, YACA_PROPERTY_CCM_TAG, (void**)&tag, &tag_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		/* OPEN */
		{
			ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_CCM,
			                           sa.key_bit_len, key_sym, iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			size_t total = allocate_output(ctx, encrypted_len, 1, decrypted);

			ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			size_t written;

			if (sa.aad_len != IGNORE) {
				ret = yaca_open_update(ctx, NULL, encrypted_len,
				                       NULL, &written);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);

				ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD,
				                                aad, sa.aad_len);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			decrypted_len = written;

			ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			decrypted_len += written;

			BOOST_REQUIRE(decrypted_len <= total);
			ret = yaca_realloc(decrypted_len, (void **)&decrypted);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		BOOST_REQUIRE(decrypted_len == INPUT_DATA_SIZE);
		ret = yaca_memcmp(INPUT_DATA, decrypted, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_key_destroy(key_prv);
		yaca_key_destroy(key_pub);
		yaca_key_destroy(key_sym);
		yaca_key_destroy(iv);
		yaca_free(encrypted);
		yaca_free(decrypted);
		yaca_free(tag);
		yaca_free(aad);
	}
}

BOOST_FIXTURE_TEST_CASE(T706__negative__open_seal_ccm, InitDebugFixture)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
	yaca_key_h key_sym = YACA_KEY_NULL, iv = YACA_KEY_NULL;

	char *tag = NULL, *aad = NULL;
	size_t tag_len = 0, tag_len_invalid = 17, aad_len = 55;

	char *encrypted = NULL, *decrypted = NULL;
	size_t encrypted_len, decrypted_len;

	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_prv, &key_pub);

	ret = yaca_malloc(aad_len, (void**)&aad);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_randomize_bytes(aad, aad_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	/* SEAL, AAD without pre-update */
	{
		ret = yaca_seal_initialize(&ctx, key_pub, YACA_ENCRYPT_AES, YACA_BCM_CCM,
		                           YACA_KEY_LENGTH_256BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_key_destroy(key_sym);
		key_sym = YACA_KEY_NULL;
		yaca_key_destroy(iv);
		iv = YACA_KEY_NULL;
	}

	/* SEAL, pre-update without AAD */
	{
		ret = yaca_seal_initialize(&ctx, key_pub, YACA_ENCRYPT_AES, YACA_BCM_CCM,
		                           YACA_KEY_LENGTH_256BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, INPUT_DATA_SIZE, 1, encrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG_LEN,
		                                &tag_len_invalid, sizeof(tag_len_invalid));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_update(ctx, NULL, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_key_destroy(key_sym);
		key_sym = YACA_KEY_NULL;
		yaca_key_destroy(iv);
		iv = YACA_KEY_NULL;
	}

	/* SEAL */
	{
		ret = yaca_seal_initialize(&ctx, key_pub, YACA_ENCRYPT_AES, YACA_BCM_CCM,
		                           YACA_KEY_LENGTH_256BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		size_t total = allocate_output(ctx, INPUT_DATA_SIZE, 1, encrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG_LEN,
		                                &tag_len_invalid, sizeof(tag_len_invalid));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_update(ctx, NULL, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_get_property(ctx, YACA_PROPERTY_CCM_TAG, (void**)&tag, &tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_update(ctx, NULL, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_seal_update(ctx, NULL, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len = written;

		ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_finalize(ctx, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len += written;
		BOOST_REQUIRE(encrypted_len <= total);
		ret = yaca_realloc(encrypted_len, (void **)&encrypted);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_finalize(ctx, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_get_property(ctx, YACA_PROPERTY_CCM_TAG, (void**)&tag, &tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* OPEN, no TAG */
	{
		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_CCM,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_open_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* OPEN, AAD without pre-update */
	{
		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_CCM,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* OPEN, pre-update without AAD */
	{
		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_CCM,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* OPEN, no AAD */
	{
		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_CCM,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* OPEN */
	{
		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_CCM,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, NULL, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* OPEN, broken TAG */
	{
		char *tag2 = NULL;
		ret = yaca_malloc(tag_len, (void**)&tag2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		memcpy((void*)tag2, (void*)tag, tag_len);
		tag2[0] = ~tag2[0];
		tag2[1] = ~tag2[1];

		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_CCM,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag2, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
		yaca_free(tag2);
	}

	/* OPEN, broken AAD */
	{
		char *aad2 = NULL;
		ret = yaca_malloc(aad_len, (void**)&aad2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		memcpy((void*)aad2, (void*)aad, aad_len);
		aad2[0] = ~aad2[0];
		aad2[1] = ~aad2[1];

		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_CCM,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad2, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
		yaca_free(aad2);
	}

	/* OPEN, broken ciphertext */
	{
		encrypted[0] = ~encrypted[0];
		encrypted[1] = ~encrypted[1];

		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_CCM,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	yaca_key_destroy(key_prv);
	yaca_key_destroy(key_pub);
	yaca_key_destroy(key_sym);
	yaca_key_destroy(iv);
	yaca_free(encrypted);
	yaca_free(tag);
	yaca_free(aad);
}

BOOST_FIXTURE_TEST_CASE(T707__positive__seal_open_gcm, InitDebugFixture)
{
	struct seal_args {
		size_t key_bit_len;
		size_t gcm_tag_len;
		size_t aad_len;
		size_t split;
	};

	const std::vector<seal_args> sargs = {
		{128, IGNORE, IGNORE, 11},
		{128,      4, IGNORE, 12},
		{128, IGNORE,     21, 13},
		{128,     13,     22, 14},

		{192, IGNORE, IGNORE, 22},
		{192,      8, IGNORE, 23},
		{192, IGNORE,     32, 24},
		{192,     15,     33, 25},

		{256, IGNORE, IGNORE, 33},
		{256,     14, IGNORE, 34},
		{256, IGNORE,     17, 35},
		{256,     16,     44, 36},
	};

	for (const auto &sa: sargs) {
		int ret;
		yaca_context_h ctx = YACA_CONTEXT_NULL;
		yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
		yaca_key_h key_sym = YACA_KEY_NULL, iv = YACA_KEY_NULL;

		char *encrypted = NULL, *decrypted = NULL;
		size_t encrypted_len = 0, decrypted_len = 0;

		char *tag = NULL, *aad = NULL;
		size_t tag_len;

		generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_prv, &key_pub);

		/* SEAL */
		{
			ret = yaca_seal_initialize(&ctx, key_pub, YACA_ENCRYPT_AES, YACA_BCM_GCM,
			                           sa.key_bit_len, &key_sym, &iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			size_t total = allocate_output(ctx, INPUT_DATA_SIZE, sa.split, encrypted);
			size_t written;

			if (sa.aad_len != IGNORE) {
				ret = yaca_malloc(sa.aad_len, (void**)&aad);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);

				ret = yaca_randomize_bytes(aad, sa.aad_len);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);

				ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD,
				                                aad, sa.aad_len);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			call_update_loop(ctx, INPUT_DATA, INPUT_DATA_SIZE,
			                 encrypted, encrypted_len, sa.split,
			                 yaca_seal_update);

			ret = yaca_seal_finalize(ctx, encrypted + encrypted_len, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			encrypted_len += written;

			BOOST_REQUIRE(encrypted_len <= total);
			ret = yaca_realloc(encrypted_len, (void **)&encrypted);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			if (sa.gcm_tag_len != IGNORE) {
				tag_len = sa.gcm_tag_len;

				ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG_LEN,
				                                &tag_len, sizeof(tag_len));
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			}

			ret = yaca_context_get_property(ctx, YACA_PROPERTY_GCM_TAG,
			                                (void**)&tag, &tag_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		/* OPEN */
		{
			ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_GCM,
			                           sa.key_bit_len, key_sym, iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			size_t total = allocate_output(ctx, encrypted_len, sa.split, decrypted);
			size_t written;

			if (sa.aad_len != IGNORE) {
				ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD,
				                                aad, sa.aad_len);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			call_update_loop(ctx, encrypted, encrypted_len,
			                 decrypted, decrypted_len, sa.split,
			                 yaca_open_update);

			ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG,
			                                tag, tag_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			decrypted_len += written;

			BOOST_REQUIRE(decrypted_len <= total);
			ret = yaca_realloc(decrypted_len, (void **)&decrypted);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		BOOST_REQUIRE(decrypted_len == INPUT_DATA_SIZE);
		ret = yaca_memcmp(INPUT_DATA, decrypted, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_key_destroy(key_prv);
		yaca_key_destroy(key_pub);
		yaca_key_destroy(key_sym);
		yaca_key_destroy(iv);
		yaca_free(encrypted);
		yaca_free(decrypted);
		yaca_free(tag);
		yaca_free(aad);
	}
}

BOOST_FIXTURE_TEST_CASE(T708__negative__seal_open_gcm, InitDebugFixture)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
	yaca_key_h key_sym = YACA_KEY_NULL, iv = YACA_KEY_NULL;

	char *encrypted = NULL, *decrypted = NULL;
	size_t encrypted_len = 0, decrypted_len = 0;

	char *tag = NULL, *aad = NULL;
	size_t tag_len = 0, tag_len_invalid = 17, aad_len = 55;

	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_prv, &key_pub);

	ret = yaca_malloc(aad_len, (void**)&aad);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_randomize_bytes(aad, aad_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	/* SEAL */
	{
		ret = yaca_seal_initialize(&ctx, key_pub, YACA_ENCRYPT_AES, YACA_BCM_GCM,
		                           YACA_KEY_LENGTH_256BIT, &key_sym, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		size_t total = allocate_output(ctx, INPUT_DATA_SIZE, 1, encrypted);
		size_t written;

		ret = yaca_seal_update(ctx, NULL, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_seal_update(ctx, NULL, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len = written;

		ret = yaca_seal_finalize(ctx, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len += written;
		BOOST_REQUIRE(encrypted_len <= total);
		ret = yaca_realloc(encrypted_len, (void **)&encrypted);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_seal_finalize(ctx, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG_LEN,
		                                &tag_len_invalid, sizeof(tag_len_invalid));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_get_property(ctx, YACA_PROPERTY_GCM_TAG,
		                                (void**)&tag, &tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* OPEN, no TAG */
	{
		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_GCM,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* OPEN, no AAD */
	{
		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_GCM,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* OPEN */
	{
		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_GCM,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_open_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* OPEN, broken TAG */
	{
		char *tag2 = NULL;
		ret = yaca_malloc(tag_len, (void**)&tag2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		memcpy((void*)tag2, (void*)tag, tag_len);
		tag2[0] = ~tag2[0];
		tag2[1] = ~tag2[1];

		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_GCM,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag2, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
		yaca_free(tag2);
	}

	/* OPEN, broken AAD */
	{
		char *aad2 = NULL;
		ret = yaca_malloc(aad_len, (void**)&aad2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		memcpy((void*)aad2, (void*)aad, aad_len);
		aad2[0] = ~aad2[0];
		aad2[1] = ~aad2[1];

		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_GCM,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad2, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
		yaca_free(aad2);
	}

	/* OPEN, broken ciphertext */
	{
		encrypted[0] = ~encrypted[0];
		encrypted[1] = ~encrypted[1];

		ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_GCM,
		                           YACA_KEY_LENGTH_256BIT, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	yaca_key_destroy(key_prv);
	yaca_key_destroy(key_pub);
	yaca_key_destroy(key_sym);
	yaca_key_destroy(iv);
	yaca_free(encrypted);
	yaca_free(tag);
	yaca_free(aad);
}

BOOST_AUTO_TEST_SUITE_END()
