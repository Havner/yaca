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
 * @file    test_encrypt.cpp
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   Encrypt API unit tests.
 */

#include <boost/test/unit_test.hpp>
#include <vector>
#include <cstring>
#include <iostream>

#include <yaca_crypto.h>
#include <yaca_encrypt.h>
#include <yaca_key.h>
#include <yaca_digest.h>
#include <yaca_error.h>

#include "common.h"


namespace {

yaca_key_h generate_iv(yaca_encrypt_algorithm_e algo, yaca_block_cipher_mode_e bcm,
					   size_t key_bit_len, size_t iv_bit_len = IGNORE)
{
	int ret;
	yaca_key_h iv = YACA_KEY_NULL;

	if (iv_bit_len == IGNORE) {
		ret = yaca_encrypt_get_iv_bit_length(algo, bcm, key_bit_len, &iv_bit_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	}

	if (iv_bit_len > 0) {
		ret = yaca_key_generate(YACA_KEY_TYPE_IV, iv_bit_len, &iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	}

	return iv;
}

} // namespace


BOOST_AUTO_TEST_SUITE(TESTS_ENCRYPT)

BOOST_FIXTURE_TEST_CASE(T601__positive__get_iv_bit_length, InitDebugFixture)
{
	struct iv_args {
		yaca_encrypt_algorithm_e algo;
		yaca_block_cipher_mode_e bcm;
		size_t key_bit_len;
		size_t expected_iv_bit_len;
	};

	const std::vector<iv_args> iargs = {
		{YACA_ENCRYPT_AES, YACA_BCM_CBC,  128, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_CCM,  128,  96},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB,  128, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB1, 128, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB8, 128, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_CTR,  128, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_ECB,  128,   0},
		{YACA_ENCRYPT_AES, YACA_BCM_GCM,  128,  96},
		{YACA_ENCRYPT_AES, YACA_BCM_OFB,  128, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_WRAP, 128,  64},

		{YACA_ENCRYPT_AES, YACA_BCM_CBC,  192, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_CCM,  192,  96},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB,  192, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB1, 192, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB8, 192, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_CTR,  192, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_ECB,  192,   0},
		{YACA_ENCRYPT_AES, YACA_BCM_GCM,  192,  96},
		{YACA_ENCRYPT_AES, YACA_BCM_OFB,  192, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_WRAP, 192,  64},

		{YACA_ENCRYPT_AES, YACA_BCM_CBC,  256, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_CCM,  256,  96},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB,  256, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB1, 256, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_CFB8, 256, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_CTR,  256, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_ECB,  256,   0},
		{YACA_ENCRYPT_AES, YACA_BCM_GCM,  256,  96},
		{YACA_ENCRYPT_AES, YACA_BCM_OFB,  256, 128},
		{YACA_ENCRYPT_AES, YACA_BCM_WRAP, 256,  64},

		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_CBC,  64, 64},
		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_CFB,  64, 64},
		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_CFB1, 64, 64},
		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_CFB8, 64, 64},
		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_ECB,  64,  0},
		{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_OFB,  64, 64},

		{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_CBC, 128, 64},
		{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_CFB, 128, 64},
		{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_ECB, 128,  0},
		{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_OFB, 128, 64},

		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CBC,  192, 64},
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CFB,  192, 64},
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CFB1, 192, 64},
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CFB8, 192, 64},
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_ECB,  192,  0},
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_OFB,  192, 64},
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_WRAP, 192,  0},

		{YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CBC, 192, 64},
		{YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CFB, 192, 64},
		{YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_ECB, 192,  0},
		{YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_OFB, 192, 64},

		{YACA_ENCRYPT_UNSAFE_RC4, YACA_BCM_NONE, 256, 0},

		{YACA_ENCRYPT_CAST5, YACA_BCM_CBC, 128, 64},
		{YACA_ENCRYPT_CAST5, YACA_BCM_CFB, 128, 64},
		{YACA_ENCRYPT_CAST5, YACA_BCM_ECB, 128,  0},
		{YACA_ENCRYPT_CAST5, YACA_BCM_OFB, 128, 64},
	};

	for (const auto &ia: iargs) {
		int ret;
		size_t iv_bit_len;

		ret = yaca_encrypt_get_iv_bit_length(ia.algo, ia.bcm, ia.key_bit_len, &iv_bit_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(iv_bit_len == ia.expected_iv_bit_len);
	}
}

BOOST_FIXTURE_TEST_CASE(T602__negative__get_iv_bit_length, InitDebugFixture)
{
	int ret;
	size_t iv_bit_len;

	ret = yaca_encrypt_get_iv_bit_length(YACA_INVALID_ENCRYPT_ALGORITHM, YACA_BCM_CBC,
										 YACA_KEY_LENGTH_256BIT, &iv_bit_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_AES, YACA_INVALID_BLOCK_CIPHER_MODE,
										 YACA_KEY_LENGTH_256BIT, &iv_bit_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_AES, YACA_BCM_CBC,
										 0, &iv_bit_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_AES, YACA_BCM_CBC,
										 1, &iv_bit_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_AES, YACA_BCM_CBC,
										 8, &iv_bit_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_AES, YACA_BCM_CBC,
										 YACA_KEY_LENGTH_256BIT, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_AES, YACA_BCM_CBC,
										 YACA_KEY_LENGTH_UNSAFE_64BIT, &iv_bit_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_CBC,
										 YACA_KEY_LENGTH_192BIT, &iv_bit_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_CBC,
										 YACA_KEY_LENGTH_192BIT, &iv_bit_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CBC,
										 YACA_KEY_LENGTH_2048BIT, &iv_bit_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_UNSAFE_RC4, YACA_BCM_NONE,
										 YACA_KEY_LENGTH_4096BIT, &iv_bit_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_CAST5, YACA_BCM_CBC,
										 YACA_KEY_LENGTH_UNSAFE_8BIT, &iv_bit_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);
}

BOOST_FIXTURE_TEST_CASE(T603__positive__encrypt_decrypt, InitDebugFixture)
{
	struct encrypt_args {
		yaca_encrypt_algorithm_e algo;
		yaca_block_cipher_mode_e bcm;
		size_t key_bit_len;
		yaca_padding_e padding;
		size_t split;
	};

	const std::vector<encrypt_args> eargs = {
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

	for (const auto &ea: eargs) {
		int ret;
		yaca_context_h ctx = YACA_CONTEXT_NULL;
		yaca_key_h key = YACA_KEY_NULL, iv = YACA_KEY_NULL;

		char *encrypted = NULL, *decrypted = NULL;
		size_t encrypted_len = 0, decrypted_len = 0;

		ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, ea.key_bit_len, &key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		iv = generate_iv(ea.algo, ea.bcm, ea.key_bit_len);

		/* ENCRYPT */
		{
			ret = yaca_encrypt_initialize(&ctx, ea.algo, ea.bcm, key, iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			size_t total = allocate_output(ctx, INPUT_DATA_SIZE, ea.split, encrypted);
			size_t written;

			call_update_loop(ctx, INPUT_DATA, INPUT_DATA_SIZE,
							 encrypted, encrypted_len, ea.split,
							 &yaca_encrypt_update);

			if (ea.padding != YACA_INVALID_PADDING) {
				ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, &ea.padding,
												sizeof(yaca_padding_e));
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			encrypted_len += written;

			BOOST_REQUIRE(encrypted_len <= total);
			ret = yaca_realloc(encrypted_len, (void **)&encrypted);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		/* DECRYPT */
		{
			ret = yaca_decrypt_initialize(&ctx, ea.algo, ea.bcm, key, iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			if (ea.padding != YACA_INVALID_PADDING) {
				ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, &ea.padding,
												sizeof(yaca_padding_e));
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			size_t total = allocate_output(ctx, encrypted_len, ea.split, decrypted);
			size_t written;

			call_update_loop(ctx, encrypted, encrypted_len,
							 decrypted, decrypted_len, ea.split,
							 &yaca_decrypt_update);

			ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
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

		yaca_key_destroy(key);
		yaca_key_destroy(iv);
		yaca_free(encrypted);
		yaca_free(decrypted);
	}
}

BOOST_FIXTURE_TEST_CASE(T604__negative__encrypt_decrypt, InitDebugFixture)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL, ctx_digest = YACA_CONTEXT_NULL;
	yaca_key_h key = YACA_KEY_NULL, iv = YACA_KEY_NULL;
	yaca_key_h key2 = YACA_KEY_NULL, iv2 = YACA_KEY_NULL;
	yaca_key_h key_rsa = YACA_KEY_NULL, iv_invalid = YACA_KEY_NULL;
	yaca_padding_e pad_pkcs7 = YACA_PADDING_PKCS7;
	yaca_padding_e pad_invalid = YACA_PADDING_X931;
	yaca_padding_e *pad_get;
	size_t key_bits_len = 128, pad_get_len;

	char *encrypted = NULL, *decrypted = NULL;
	size_t encrypted_len = 0, decrypted_len = 0;

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_IV, YACA_KEY_LENGTH_IV_128BIT, &iv);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_IV, YACA_KEY_LENGTH_IV_128BIT, &iv2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_IV, 32, &iv_invalid);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_rsa);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_digest_initialize(&ctx_digest, YACA_DIGEST_MD5);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	/* ENCRYPT */
	{
		ret = yaca_encrypt_initialize(NULL, YACA_ENCRYPT_AES, YACA_BCM_CBC, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_INVALID_ENCRYPT_ALGORITHM, YACA_BCM_CBC, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_INVALID_BLOCK_CIPHER_MODE, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CBC, YACA_KEY_NULL, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CBC, iv2, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CBC, key_rsa, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CBC, key, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CBC, key, iv_invalid);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CBC, key, key_rsa);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_ECB, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC4, YACA_BCM_CFB, key, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC4, YACA_BCM_NONE, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CBC, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CBC, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_get_output_length(ctx, INPUT_DATA_SIZE, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		size_t total = allocate_output(ctx, INPUT_DATA_SIZE, 1, encrypted);
		size_t written;

		ret = yaca_encrypt_update(YACA_CONTEXT_NULL, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx_digest, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, NULL, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, INPUT_DATA, 0, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len = written;

		ret = yaca_context_set_property(ctx, YACA_INVALID_PROPERTY,
										&pad_pkcs7, sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
										&pad_pkcs7, 0);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
										&pad_pkcs7, 1);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
										&key_bits_len, sizeof(size_t));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
										&pad_invalid, sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
										&pad_pkcs7, sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_get_property(ctx, YACA_INVALID_PROPERTY,
										(void**)&pad_get, &pad_get_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_get_property(ctx, YACA_PROPERTY_PADDING,
										NULL, &pad_get_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_get_property(ctx, YACA_PROPERTY_PADDING,
										(void**)&pad_get, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_get_property(ctx, YACA_PROPERTY_PADDING,
										(void**)&pad_get, &pad_get_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_finalize(YACA_CONTEXT_NULL, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_finalize(ctx_digest, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_finalize(ctx, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len += written;
		BOOST_REQUIRE(encrypted_len <= total);
		ret = yaca_realloc(encrypted_len, (void **)&encrypted);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
										&pad_pkcs7, sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_finalize(ctx, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* DECRYPT */
	{
		ret = yaca_decrypt_initialize(NULL, YACA_ENCRYPT_AES, YACA_BCM_CBC, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_INVALID_ENCRYPT_ALGORITHM, YACA_BCM_CBC, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_INVALID_BLOCK_CIPHER_MODE, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CBC, YACA_KEY_NULL, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CBC, iv2, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CBC, key, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CBC, key, iv_invalid);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CBC, key, key_rsa);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_ECB, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC4, YACA_BCM_CFB, key, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC4, YACA_BCM_NONE, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CBC, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CBC, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_INVALID_PROPERTY,
										&pad_pkcs7, sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
										&pad_pkcs7, 0);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
										&pad_pkcs7, 1);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
										&key_bits_len, sizeof(size_t));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
										&pad_invalid, sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
										&pad_pkcs7, sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_get_property(ctx, YACA_INVALID_PROPERTY,
										(void**)&pad_get, &pad_get_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_get_property(ctx, YACA_PROPERTY_PADDING,
										NULL, &pad_get_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_get_property(ctx, YACA_PROPERTY_PADDING,
										(void**)&pad_get, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_get_property(ctx, YACA_PROPERTY_PADDING,
										(void**)&pad_get, &pad_get_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_get_output_length(ctx, encrypted_len, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

 		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_decrypt_update(YACA_CONTEXT_NULL, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_update(ctx_digest, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_update(ctx, NULL, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_update(ctx, encrypted, 0, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
										&pad_pkcs7, sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_finalize(YACA_CONTEXT_NULL, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_finalize(ctx_digest, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_finalize(ctx, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len += written;

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_finalize(ctx, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* DECRYPT, wrong BCM */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_ECB, key, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, &pad_pkcs7,
										sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* DECRYPT, wrong key */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CBC, key2, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, &pad_pkcs7,
										sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* DECRYPT, broken the end of ciphertext */
	{
		encrypted[encrypted_len - 1] = ~encrypted[encrypted_len - 1];
		encrypted[encrypted_len - 2] = ~encrypted[encrypted_len - 2];

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CBC, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, &pad_pkcs7,
										sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	yaca_context_destroy(ctx_digest);
	yaca_key_destroy(key);
	yaca_key_destroy(key2);
	yaca_key_destroy(iv);
	yaca_key_destroy(iv2);
	yaca_key_destroy(key_rsa);
	yaca_free(encrypted);
}

BOOST_FIXTURE_TEST_CASE(T605__positive__encrypt_decrypt_wrap, InitDebugFixture)
{
	struct encrypt_args {
		yaca_encrypt_algorithm_e algo;
		size_t key_bit_len;
		size_t key_material_len;
	};

	const std::vector<encrypt_args> eargs = {
		{YACA_ENCRYPT_AES,        128, 192 / 8},
		{YACA_ENCRYPT_AES,        192, 256 / 8},
		{YACA_ENCRYPT_AES,        256, 128 / 8},
		{YACA_ENCRYPT_3DES_3TDEA, 192, 128 / 8},
		{YACA_ENCRYPT_3DES_3TDEA, 192, 192 / 8},
	};

	for (const auto &ea: eargs) {
		int ret;
		yaca_context_h ctx = YACA_CONTEXT_NULL;
		yaca_key_h key = YACA_KEY_NULL, iv = YACA_KEY_NULL;
		char *key_material = NULL;

		char *encrypted = NULL, *decrypted = NULL;
		size_t encrypted_len, decrypted_len;

		ret = yaca_zalloc(ea.key_material_len, (void**)&key_material);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_randomize_bytes(key_material, ea.key_material_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, ea.key_bit_len, &key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		iv = generate_iv(ea.algo, YACA_BCM_WRAP, ea.key_bit_len);

		/* ENCRYPT */
		{
			ret = yaca_encrypt_initialize(&ctx, ea.algo, YACA_BCM_WRAP, key, iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			size_t total = allocate_output(ctx, ea.key_material_len, 1, encrypted);
			size_t written;

			ret = yaca_encrypt_update(ctx, key_material, ea.key_material_len,
									  encrypted, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			encrypted_len = written;

			ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			encrypted_len += written;

			BOOST_REQUIRE(encrypted_len <= total);
			ret = yaca_realloc(encrypted_len, (void **)&encrypted);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		/* DECRYPT */
		{
			ret = yaca_decrypt_initialize(&ctx, ea.algo, YACA_BCM_WRAP, key, iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			size_t total = allocate_output(ctx, encrypted_len, 1, decrypted);
			size_t written;

			ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			decrypted_len = written;

			ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			decrypted_len += written;

			BOOST_REQUIRE(decrypted_len <= total);
			ret = yaca_realloc(decrypted_len, (void **)&decrypted);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		BOOST_REQUIRE(decrypted_len == ea.key_material_len);
		ret = yaca_memcmp(key_material, decrypted, decrypted_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_key_destroy(key);
		yaca_key_destroy(iv);
		yaca_free(key_material);
		yaca_free(encrypted);
		yaca_free(decrypted);
	}
}

BOOST_FIXTURE_TEST_CASE(T606__negative__encrypt_decrypt_wrap, InitDebugFixture)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key_sym = YACA_KEY_NULL, iv = YACA_KEY_NULL;
	yaca_key_h key_des1 = YACA_KEY_NULL, key_des2 = YACA_KEY_NULL;
	char *key_material_64 = NULL, *key_material_192 = NULL, *key_material_256 = NULL;

	size_t len64 = 64 / 8, len192 = 192 / 8, len256 = 256 / 8;

	char *encrypted = NULL, *decrypted = NULL;
	size_t encrypted_len, decrypted_len;

	ret = yaca_zalloc(len64, (void**)&key_material_64);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_randomize_bytes(key_material_64, len64);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_zalloc(len192, (void**)&key_material_192);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_randomize_bytes(key_material_192, len192);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_zalloc(len256, (void**)&key_material_256);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_randomize_bytes(key_material_256, len256);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_UNSAFE_128BIT, &key_sym);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_UNSAFE_64BIT, &key_des1);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_192BIT, &key_des2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_generate(YACA_KEY_TYPE_IV, YACA_KEY_LENGTH_IV_64BIT, &iv);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	/* ENCRYPT AES */
	{
		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_DES,
									  YACA_BCM_WRAP, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_CAST5,
									  YACA_BCM_WRAP, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES,
									  YACA_BCM_WRAP, key_des1, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES,
									  YACA_BCM_WRAP, key_sym, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES,
									  YACA_BCM_WRAP, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		size_t total = allocate_output(ctx, len192, 1, encrypted);
		size_t written;

		ret = yaca_encrypt_update(ctx, key_material_64, len64,
								  encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, key_material_192, len192,
								  encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len = written;

		ret = yaca_encrypt_update(ctx, key_material_192, len192,
								  encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len += written;
		BOOST_REQUIRE(encrypted_len <= total);
		ret = yaca_realloc(encrypted_len, (void **)&encrypted);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_encrypt_update(ctx, key_material_192, len192,
								  encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* DECRYPT AES */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_DES,
									  YACA_BCM_WRAP, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_CAST5,
									  YACA_BCM_WRAP, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES,
									  YACA_BCM_WRAP, key_des1, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES,
									  YACA_BCM_WRAP, key_sym, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_WRAP, key_sym, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len - 1, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len += written;

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* ENCRYPT 3DES */
	{
		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_3DES_3TDEA,
									  YACA_BCM_WRAP, key_sym, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_3DES_3TDEA,
									  YACA_BCM_WRAP, key_des1, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_3DES_3TDEA,
									  YACA_BCM_WRAP, key_des2, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_3DES_3TDEA,
									  YACA_BCM_WRAP, key_des2, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		size_t total = allocate_output(ctx, len192, 1, encrypted);
		size_t written;

		ret = yaca_encrypt_update(ctx, key_material_64, len64,
								  encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, key_material_256, len256,
								  encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, key_material_192, len192,
								  encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len = written;

		ret = yaca_encrypt_update(ctx, key_material_192, len192,
								  encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len += written;
		BOOST_REQUIRE(encrypted_len <= total);
		ret = yaca_realloc(encrypted_len, (void **)&encrypted);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_encrypt_update(ctx, key_material_192, len192,
								  encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* DECRYPT 3DES */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_3DES_3TDEA,
									  YACA_BCM_WRAP, key_sym, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_3DES_3TDEA,
									  YACA_BCM_WRAP, key_des1, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_3DES_3TDEA,
									  YACA_BCM_WRAP, key_des2, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_3DES_3TDEA,
									  YACA_BCM_WRAP, key_des2, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len - 1, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len += written;

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	yaca_key_destroy(key_sym);
	yaca_key_destroy(key_des1);
	yaca_key_destroy(key_des2);
	yaca_key_destroy(iv);
	yaca_free(key_material_64);
	yaca_free(key_material_192);
	yaca_free(key_material_256);
	yaca_free(encrypted);
}

BOOST_FIXTURE_TEST_CASE(T607__positive__encrypt_decrypt_rc2, InitDebugFixture)
{
	struct encrypt_args {
		yaca_block_cipher_mode_e bcm;
		size_t key_bit_len;
		yaca_padding_e padding;
		size_t effective_key_bits;
		size_t split;
	};

	const std::vector<encrypt_args> eargs = {
		{YACA_BCM_CBC, 128, YACA_INVALID_PADDING, IGNORE, 11},
		{YACA_BCM_CBC, 192, YACA_PADDING_NONE,        64, 22},
		{YACA_BCM_CBC, 200, YACA_PADDING_PKCS7,      128,  3},
		{YACA_BCM_CBC, 192, YACA_INVALID_PADDING,    255,  7},
		{YACA_BCM_CBC, 192, YACA_INVALID_PADDING,    713,  2},
		{YACA_BCM_CBC, 224, YACA_INVALID_PADDING,      1, 19},
		{YACA_BCM_CBC, 256, YACA_INVALID_PADDING,   1024, 19},
		{YACA_BCM_CFB, 192, YACA_INVALID_PADDING, IGNORE, 13},
		{YACA_BCM_CFB, 192, YACA_INVALID_PADDING,    333, 33},
		{YACA_BCM_ECB, 272, YACA_INVALID_PADDING, IGNORE,  8},
		{YACA_BCM_ECB, 192, YACA_PADDING_NONE,       666, 15},
		{YACA_BCM_ECB, 192, YACA_PADDING_PKCS7,       21, 15},
		{YACA_BCM_OFB, 520, YACA_INVALID_PADDING, IGNORE, 25},
		{YACA_BCM_OFB, 224, YACA_INVALID_PADDING,    999, 35},
	};

	for (const auto &ea: eargs) {
		int ret;
		yaca_context_h ctx = YACA_CONTEXT_NULL;
		yaca_key_h key = YACA_KEY_NULL, iv = YACA_KEY_NULL;

		char *encrypted = NULL, *decrypted = NULL;
		size_t encrypted_len = 0, decrypted_len = 0;

		ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, ea.key_bit_len, &key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		iv = generate_iv(YACA_ENCRYPT_UNSAFE_RC2, ea.bcm, ea.key_bit_len);

		/* ENCRYPT */
		{
			ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC2, ea.bcm, key, iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			if (ea.padding != YACA_INVALID_PADDING) {
				ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
												&ea.padding, sizeof(yaca_padding_e));
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			if (ea.effective_key_bits != IGNORE) {
				ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
												&ea.effective_key_bits, sizeof(size_t));
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			size_t total = allocate_output(ctx, INPUT_DATA_SIZE, ea.split, encrypted);
			size_t written;

			call_update_loop(ctx, INPUT_DATA, INPUT_DATA_SIZE,
							 encrypted, encrypted_len, ea.split,
							 &yaca_encrypt_update);

			ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			encrypted_len += written;

			BOOST_REQUIRE(encrypted_len <= total);
			ret = yaca_realloc(encrypted_len, (void **)&encrypted);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		/* DECRYPT */
		{
			ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC2, ea.bcm, key, iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			if (ea.padding != YACA_INVALID_PADDING) {
				ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
												&ea.padding, sizeof(yaca_padding_e));
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			if (ea.effective_key_bits != IGNORE) {
				ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
												&ea.effective_key_bits, sizeof(size_t));
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			size_t total = allocate_output(ctx, encrypted_len, ea.split, decrypted);
			size_t written;

			call_update_loop(ctx, encrypted, encrypted_len,
							 decrypted, decrypted_len, ea.split,
							 &yaca_decrypt_update);

			ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
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

		yaca_key_destroy(key);
		yaca_key_destroy(iv);
		yaca_free(encrypted);
		yaca_free(decrypted);
	}
}

BOOST_FIXTURE_TEST_CASE(T608__negative__encrypt_decrypt_rc2, InitDebugFixture)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key = YACA_KEY_NULL, iv = YACA_KEY_NULL;
	yaca_padding_e pad_invalid = YACA_PADDING_PKCS1_SSLV23;
	size_t effective_bits_invalid1 = 0, effective_bits_invalid2 = 2048;

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_192BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_IV, YACA_KEY_LENGTH_IV_64BIT, &iv);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	/* ENCRYPT */
	{
		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CFB1, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CTR, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CBC, YACA_KEY_NULL, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CBC, key, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CBC, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
										&pad_invalid, sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
										&effective_bits_invalid1, sizeof(size_t));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
										&effective_bits_invalid2, sizeof(size_t));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* DECRYPT */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CFB1, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CTR, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CBC, YACA_KEY_NULL, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CBC, key, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CBC, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
										&pad_invalid, sizeof(yaca_padding_e));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
										&effective_bits_invalid1, sizeof(size_t));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
										&effective_bits_invalid2, sizeof(size_t));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	yaca_key_destroy(key);
	yaca_key_destroy(iv);
}

BOOST_FIXTURE_TEST_CASE(T609__positive__encrypt_decrypt_ccm, InitDebugFixture)
{
	struct encrypt_args {
		size_t key_bit_len;
		size_t ccm_tag_len;
		size_t aad_len;
		size_t iv_bit_len;
	};

	const std::vector<encrypt_args> eargs = {
		{128, IGNORE, IGNORE, IGNORE},
		{128,      4, IGNORE, IGNORE},
		{128, IGNORE,     13, IGNORE},
		{128,      6,     23, IGNORE},
		{128,     12,     19,     96},
		{128,      8,     43,     64},

		{192, IGNORE, IGNORE, IGNORE},
		{192,     10, IGNORE, IGNORE},
		{192, IGNORE,     21, IGNORE},
		{192,      8,     17, IGNORE},
		{192,     16,     29,     64},
		{192,     10,     34,     96},

		{256, IGNORE, IGNORE, IGNORE},
		{256,     16, IGNORE, IGNORE},
		{256, IGNORE,     55, IGNORE},
		{256,     12,     33, IGNORE},
		{256,      6,     22,     96},
		{256,     10,     44,     64},
	};

	for (const auto &ea: eargs) {
		int ret;
		yaca_context_h ctx = YACA_CONTEXT_NULL;
		yaca_key_h key = YACA_KEY_NULL, iv = YACA_KEY_NULL;

		char *tag = NULL, *aad = NULL;
		size_t tag_len;

		char *encrypted = NULL, *decrypted = NULL;
		size_t encrypted_len, decrypted_len;

		ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, ea.key_bit_len, &key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		iv = generate_iv(YACA_ENCRYPT_AES, YACA_BCM_CCM, ea.key_bit_len, ea.iv_bit_len);

		/* ENCRYPT */
		{
			ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			size_t total = allocate_output(ctx, INPUT_DATA_SIZE, 1, encrypted);
			size_t written;

			if (ea.ccm_tag_len != IGNORE) {
				tag_len = ea.ccm_tag_len;

				ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG_LEN,
												&tag_len, sizeof(tag_len));
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			if (ea.aad_len != IGNORE) {
				ret = yaca_malloc(ea.aad_len, (void**)&aad);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);

				ret = yaca_randomize_bytes(aad, ea.aad_len);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);

				ret = yaca_encrypt_update(ctx, NULL, INPUT_DATA_SIZE,
										  NULL, &written);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);

				ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD,
												aad, ea.aad_len);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			encrypted_len = written;

			ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
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

		/* DECRYPT */
		{
			ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			size_t total = allocate_output(ctx, encrypted_len, 1, decrypted);
			size_t written;

			ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			if (ea.aad_len != IGNORE) {
				ret = yaca_decrypt_update(ctx, NULL, encrypted_len,
										  NULL, &written);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);

				ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD,
												aad, ea.aad_len);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			decrypted_len = written;

			ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
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

		yaca_key_destroy(key);
		yaca_key_destroy(iv);
		yaca_free(encrypted);
		yaca_free(decrypted);
		yaca_free(tag);
		yaca_free(aad);
	}
}

BOOST_FIXTURE_TEST_CASE(T610__negative__encrypt_decrypt_ccm, InitDebugFixture)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key = YACA_KEY_NULL, key2 = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL, iv2 = YACA_KEY_NULL;
	yaca_key_h iv_invalid = YACA_KEY_NULL;

	char *tag = NULL, *aad = NULL;
	size_t tag_len = 0, tag_len_invalid = 17, aad_len = 55;

	char *encrypted = NULL, *decrypted = NULL;
	size_t encrypted_len, decrypted_len;

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_IV, 96, &iv);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_IV, 96, &iv2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_IV, 128, &iv_invalid);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_malloc(aad_len, (void**)&aad);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_randomize_bytes(aad, aad_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	/* ENCRYPT, AAD without pre-update */
	{
		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* ENCRYPT, pre-update without AAD */
	{
		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, INPUT_DATA_SIZE, 1, encrypted);
		size_t written;

		ret = yaca_encrypt_update(ctx, NULL, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(encrypted);
		encrypted = NULL;
	}

	/* ENCRYPT */
	{
		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv_invalid);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		size_t total = allocate_output(ctx, INPUT_DATA_SIZE, 1, encrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG_LEN,
										&tag_len_invalid, sizeof(tag_len_invalid));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, NULL, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_get_property(ctx, YACA_PROPERTY_CCM_TAG, (void**)&tag, &tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, NULL, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_encrypt_update(ctx, NULL, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len = written;

		ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len += written;
		BOOST_REQUIRE(encrypted_len <= total);
		ret = yaca_realloc(encrypted_len, (void **)&encrypted);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_get_property(ctx, YACA_PROPERTY_CCM_TAG, (void**)&tag, &tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* DECRYPT, no TAG */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_decrypt_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_free(decrypted);
		decrypted = NULL;
		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* DECRYPT, AAD without pre-update */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* DECRYPT, pre-update without AAD */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, NULL, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* DECRYPT, no AAD */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* DECRYPT */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv_invalid);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, NULL, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* DECRYPT, wrong key */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key2, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		/* In case of AES/CBC wrong key returned INVALID_PASS
		 * Why this inconsistency?
		 */
		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* DECRYPT, wrong IV */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* DECRYPT, broken TAG */
	{
		char *tag2 = NULL;
		ret = yaca_malloc(tag_len, (void**)&tag2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		memcpy((void*)tag2, (void*)tag, tag_len);
		tag2[0] = ~tag2[0];
		tag2[1] = ~tag2[1];

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag2, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
		yaca_free(tag2);
	}

	/* DECRYPT, broken AAD */
	{
		char *aad2 = NULL;
		ret = yaca_malloc(aad_len, (void**)&aad2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		memcpy((void*)aad2, (void*)aad, aad_len);
		aad2[0] = ~aad2[0];
		aad2[1] = ~aad2[1];

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad2, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
		yaca_free(aad2);
	}

	/* DECRYPT, broken ciphertext */
	{
		encrypted[0] = ~encrypted[0];
		encrypted[1] = ~encrypted[1];

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, NULL, encrypted_len, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	yaca_key_destroy(key);
	yaca_key_destroy(key2);
	yaca_key_destroy(iv);
	yaca_key_destroy(iv2);
	yaca_free(encrypted);
	yaca_free(tag);
	yaca_free(aad);
}

BOOST_FIXTURE_TEST_CASE(T611__positive__encrypt_decrypt_gcm, InitDebugFixture)
{
	struct encrypt_args {
		size_t key_bit_len;
		size_t gcm_tag_len;
		size_t aad_len;
		size_t split;
		size_t iv_bit_len;
	};

	const std::vector<encrypt_args> eargs = {
		{128, IGNORE, IGNORE, 11, IGNORE},
		{128,      4, IGNORE, 12, IGNORE},
		{128, IGNORE,     21, 13, IGNORE},
		{128,     13,     22, 14, IGNORE},
		{128,     14,     80,  4,    128},
		{128,     13,     22, 14,     96},

		{192, IGNORE, IGNORE, 22, IGNORE},
		{192,      8, IGNORE, 23, IGNORE},
		{192, IGNORE,     32, 24, IGNORE},
		{192,     15,     33, 25, IGNORE},
		{192,     13,     30, 74,     64},
		{192,     15,     37, 25,     96},

		{256, IGNORE, IGNORE, 33, IGNORE},
		{256,     14, IGNORE, 34, IGNORE},
		{256, IGNORE,     17, 35, IGNORE},
		{256,     16,     44, 36, IGNORE},
		{256,     14,     12, 15,    128},
		{256,     16,     45, 36,     96},
	};

	for (const auto &ea: eargs) {
		int ret;
		yaca_context_h ctx = YACA_CONTEXT_NULL;
		yaca_key_h key = YACA_KEY_NULL, iv = YACA_KEY_NULL;

		char *encrypted = NULL, *decrypted = NULL;
		size_t encrypted_len = 0, decrypted_len = 0;

		char *tag = NULL, *aad = NULL;
		size_t tag_len;

		ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, ea.key_bit_len, &key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		iv = generate_iv(YACA_ENCRYPT_AES, YACA_BCM_GCM, ea.key_bit_len, ea.iv_bit_len);

		/* ENCRYPT */
		{
			ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			size_t total = allocate_output(ctx, INPUT_DATA_SIZE, ea.split, encrypted);
			size_t written;

			if (ea.aad_len != IGNORE) {
				ret = yaca_malloc(ea.aad_len, (void**)&aad);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);

				ret = yaca_randomize_bytes(aad, ea.aad_len);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);

				ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD,
												aad, ea.aad_len);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			call_update_loop(ctx, INPUT_DATA, INPUT_DATA_SIZE,
							 encrypted, encrypted_len, ea.split,
							 yaca_encrypt_update);

			ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			encrypted_len += written;

			BOOST_REQUIRE(encrypted_len <= total);
			ret = yaca_realloc(encrypted_len, (void **)&encrypted);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			if (ea.gcm_tag_len != IGNORE) {
				tag_len = ea.gcm_tag_len;

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

		/* DECRYPT */
		{
			ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			size_t total = allocate_output(ctx, encrypted_len, ea.split, decrypted);
			size_t written;

			if (ea.aad_len != IGNORE) {
				ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD,
												aad, ea.aad_len);
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			call_update_loop(ctx, encrypted, encrypted_len,
							 decrypted, decrypted_len, ea.split,
							 yaca_decrypt_update);

			ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG,
											tag, tag_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
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

		yaca_key_destroy(key);
		yaca_key_destroy(iv);
		yaca_free(encrypted);
		yaca_free(decrypted);
		yaca_free(tag);
		yaca_free(aad);
	}
}

BOOST_FIXTURE_TEST_CASE(T612__negative__encrypt_decrypt_gcm, InitDebugFixture)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key = YACA_KEY_NULL, key2 = YACA_KEY_NULL;
	yaca_key_h iv = YACA_KEY_NULL, iv2 = YACA_KEY_NULL;

	char *encrypted = NULL, *decrypted = NULL;
	size_t encrypted_len = 0, decrypted_len = 0;

	char *tag = NULL, *aad = NULL;
	size_t tag_len = 0, tag_len_invalid = 17, aad_len = 55;

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_IV, 96, &iv);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_IV, 96, &iv2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_malloc(aad_len, (void**)&aad);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_randomize_bytes(aad, aad_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	/* ENCRYPT */
	{
		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		size_t total = allocate_output(ctx, INPUT_DATA_SIZE, 1, encrypted);
		size_t written;

		ret = yaca_encrypt_update(ctx, NULL, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_encrypt_update(ctx, NULL, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_get_property(ctx, YACA_PROPERTY_GCM_TAG,
										(void**)&tag, &tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len = written;

		ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		encrypted_len += written;
		BOOST_REQUIRE(encrypted_len <= total);
		ret = yaca_realloc(encrypted_len, (void **)&encrypted);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
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

	/* DECRYPT, no TAG */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* DECRYPT, no AAD */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* DECRYPT */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_decrypt_update(ctx, NULL, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, NULL, INPUT_DATA_SIZE, NULL, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* DECRYPT, wrong key */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key2, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* DECRYPT, wrong IV */
	{
		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, iv2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* DECRYPT, broken TAG */
	{
		char *tag2 = NULL;
		ret = yaca_malloc(tag_len, (void**)&tag2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		memcpy((void*)tag2, (void*)tag, tag_len);
		tag2[0] = ~tag2[0];
		tag2[1] = ~tag2[1];

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag2, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* DECRYPT, broken AAD */
	{
		char *aad2 = NULL;
		ret = yaca_malloc(aad_len, (void**)&aad2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		memcpy((void*)aad2, (void*)aad, aad_len);
		aad2[0] = ~aad2[0];
		aad2[1] = ~aad2[1];

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad2, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	/* DECRYPT, broken ciphertext */
	{
		encrypted[0] = ~encrypted[0];
		encrypted[1] = ~encrypted[1];

		ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, iv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		allocate_output(ctx, encrypted_len, 1, decrypted);
		size_t written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD, aad, aad_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		decrypted_len = written;

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG, tag, tag_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(decrypted);
		decrypted = NULL;
	}

	yaca_key_destroy(key);
	yaca_key_destroy(key2);
	yaca_key_destroy(iv);
	yaca_key_destroy(iv2);
	yaca_free(encrypted);
	yaca_free(tag);
	yaca_free(aad);
}

BOOST_AUTO_TEST_SUITE_END()
