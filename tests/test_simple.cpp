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
 * @file    test_simple.cpp
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   Simple API unit tests.
 */

#include <boost/test/unit_test.hpp>
#include <vector>

#include <yaca_crypto.h>
#include <yaca_encrypt.h>
#include <yaca_key.h>
#include <yaca_simple.h>
#include <yaca_error.h>

#include "common.h"


BOOST_AUTO_TEST_SUITE(TESTS_SIMPLE)

BOOST_FIXTURE_TEST_CASE(T301__positive__simple_encrypt_decrypt, InitDebugFixture)
{
	struct encrypt_args {
		yaca_encrypt_algorithm_e algo;
		yaca_block_cipher_mode_e bcm;
		size_t key_bit_len;
	};

	const std::vector<struct encrypt_args> eargs = {
		{yaca_encrypt_algorithm_e::YACA_ENCRYPT_AES,
		 yaca_block_cipher_mode_e::YACA_BCM_CBC,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_256BIT},
		{yaca_encrypt_algorithm_e::YACA_ENCRYPT_AES,
		 yaca_block_cipher_mode_e::YACA_BCM_CFB,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_256BIT},
		{yaca_encrypt_algorithm_e::YACA_ENCRYPT_AES,
		 yaca_block_cipher_mode_e::YACA_BCM_ECB,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_IV_128BIT},
		{yaca_encrypt_algorithm_e::YACA_ENCRYPT_UNSAFE_DES,
		 yaca_block_cipher_mode_e::YACA_BCM_CBC,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_UNSAFE_64BIT},
		{yaca_encrypt_algorithm_e::YACA_ENCRYPT_3DES_3TDEA,
		 yaca_block_cipher_mode_e::YACA_BCM_ECB,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_192BIT},
		{yaca_encrypt_algorithm_e::YACA_ENCRYPT_UNSAFE_RC4,
		 yaca_block_cipher_mode_e::YACA_BCM_NONE,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_192BIT},
		{yaca_encrypt_algorithm_e::YACA_ENCRYPT_CAST5,
		 yaca_block_cipher_mode_e::YACA_BCM_OFB,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_UNSAFE_128BIT}
	};

	for (const auto &ea: eargs) {
		int ret;
		yaca_key_h sym = YACA_KEY_NULL, iv = YACA_KEY_NULL;
		size_t iv_bit_len;
		char *encrypted = NULL, *decrypted = NULL;
		size_t encrypted_len, decrypted_len;

		ret = yaca_encrypt_get_iv_bit_length(ea.algo, ea.bcm, ea.key_bit_len, &iv_bit_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, ea.key_bit_len, &sym);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		if (iv_bit_len > 0) {
			ret = yaca_key_generate(YACA_KEY_TYPE_IV, iv_bit_len, &iv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		}

		ret = yaca_simple_encrypt(ea.algo, ea.bcm, sym, iv, INPUT_DATA, INPUT_DATA_SIZE,
		                          &encrypted, &encrypted_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_simple_decrypt(ea.algo, ea.bcm, sym, iv, encrypted, encrypted_len,
		                          &decrypted, &decrypted_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(decrypted_len == INPUT_DATA_SIZE);
		ret = yaca_memcmp(INPUT_DATA, decrypted, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_key_destroy(sym);
		yaca_key_destroy(iv);
		yaca_free(encrypted);
		yaca_free(decrypted);
	}
}

BOOST_FIXTURE_TEST_CASE(T302__negative__simple_encrypt_decrypt, InitDebugFixture)
{
	int ret;
	yaca_key_h sym = YACA_KEY_NULL, iv = YACA_KEY_NULL;
	yaca_key_h sym2 = YACA_KEY_NULL, iv2 = YACA_KEY_NULL;
	size_t iv_bit_len;
	char *encrypted = NULL, *decrypted = NULL;
	size_t encrypted_len, decrypted_len;

	ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_AES, YACA_BCM_CBC,
	                                     YACA_KEY_LENGTH_256BIT, &iv_bit_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &sym);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_192BIT, &sym2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_IV, iv_bit_len, &iv);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_IV, iv_bit_len * 2, &iv2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_simple_encrypt(YACA_INVALID_ENCRYPT_ALGORITHM, YACA_BCM_CBC, sym, iv,
	                          INPUT_DATA, INPUT_DATA_SIZE,
	                          &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_encrypt(YACA_ENCRYPT_AES, YACA_INVALID_BLOCK_CIPHER_MODE, sym, iv,
	                          INPUT_DATA, INPUT_DATA_SIZE,
	                          &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_encrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, YACA_KEY_NULL, iv,
	                          INPUT_DATA, INPUT_DATA_SIZE,
	                          &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_encrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym, YACA_KEY_NULL,
	                          INPUT_DATA, INPUT_DATA_SIZE,
	                          &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_encrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym, iv,
	                          NULL, INPUT_DATA_SIZE,
	                          &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_encrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym, iv,
	                          INPUT_DATA, 0,
	                          &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_encrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym, iv,
	                          INPUT_DATA, INPUT_DATA_SIZE,
	                          NULL, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_encrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym, iv,
	                          INPUT_DATA, INPUT_DATA_SIZE,
	                          &encrypted, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_encrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym, iv,
	                          INPUT_DATA, INPUT_DATA_SIZE,
	                          &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_simple_decrypt(YACA_INVALID_ENCRYPT_ALGORITHM, YACA_BCM_CBC, sym, iv,
	                          encrypted, encrypted_len,
	                          &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_decrypt(YACA_ENCRYPT_AES, YACA_INVALID_BLOCK_CIPHER_MODE, sym, iv,
	                          encrypted, encrypted_len,
	                          &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_decrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, NULL, iv,
	                          encrypted, encrypted_len,
	                          &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_decrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym, NULL,
	                          encrypted, encrypted_len,
	                          &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_decrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym, iv,
	                          NULL, encrypted_len,
	                          &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_decrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym, iv,
	                          encrypted, 0,
	                          &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_decrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym, iv,
	                          encrypted, encrypted_len,
	                          NULL, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_decrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym, iv,
	                          encrypted, encrypted_len,
	                          &decrypted, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_decrypt(YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CBC, sym, iv,
	                          encrypted, encrypted_len,
	                          &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_decrypt(YACA_ENCRYPT_AES, YACA_BCM_ECB, sym, iv,
	                          encrypted, encrypted_len,
	                          &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_decrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym2, iv,
	                          encrypted, encrypted_len,
	                          &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_decrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym, iv2,
	                          encrypted, encrypted_len,
	                          &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_decrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym, iv,
	                          encrypted, encrypted_len - 1,
	                          &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_decrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym, iv,
	                          encrypted + 1, encrypted_len - 1,
	                          &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	encrypted[encrypted_len - 1] = ~encrypted[encrypted_len - 1];
	encrypted[encrypted_len - 2] = ~encrypted[encrypted_len - 2];
	ret = yaca_simple_decrypt(YACA_ENCRYPT_AES, YACA_BCM_CBC, sym, iv,
	                          encrypted, encrypted_len,
	                          &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	yaca_key_destroy(sym);
	yaca_key_destroy(sym2);
	yaca_key_destroy(iv);
	yaca_key_destroy(iv2);
	yaca_free(encrypted);
	yaca_free(decrypted);
}

BOOST_FIXTURE_TEST_CASE(T303__positive__simple_calculate_digest, InitDebugFixture)
{
	struct digest_args {
		yaca_digest_algorithm_e algo = YACA_DIGEST_SHA256;
		size_t expected;
	};

	const std::vector<struct digest_args> dargs = {
		{yaca_digest_algorithm_e::YACA_DIGEST_MD5, 16},
		{yaca_digest_algorithm_e::YACA_DIGEST_SHA1, 20},
		{yaca_digest_algorithm_e::YACA_DIGEST_SHA224, 28},
		{yaca_digest_algorithm_e::YACA_DIGEST_SHA256, 32},
		{yaca_digest_algorithm_e::YACA_DIGEST_SHA384, 48},
		{yaca_digest_algorithm_e::YACA_DIGEST_SHA512, 64}
	};

	for (const auto &da: dargs) {
		int ret;
		char *digest = NULL;
		size_t digest_len;

		ret = yaca_simple_calculate_digest(da.algo, INPUT_DATA, INPUT_DATA_SIZE,
		                                   &digest, &digest_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(digest_len == da.expected);

		yaca_free(digest);
	}
}

BOOST_FIXTURE_TEST_CASE(T304__negative__simple_calculate_digest, InitDebugFixture)
{
	int ret;
	char *digest = NULL;
	size_t digest_len;

	ret = yaca_simple_calculate_digest(YACA_INVALID_DIGEST_ALGORITHM, INPUT_DATA, INPUT_DATA_SIZE,
	                                   &digest, &digest_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_digest(YACA_DIGEST_SHA256, NULL, INPUT_DATA_SIZE,
	                                   &digest, &digest_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_digest(YACA_DIGEST_SHA256, INPUT_DATA, 0,
	                                   &digest, &digest_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_digest(YACA_DIGEST_SHA256, INPUT_DATA, INPUT_DATA_SIZE,
	                                   NULL, &digest_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_digest(YACA_DIGEST_SHA256, INPUT_DATA, INPUT_DATA_SIZE,
	                                   &digest, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);
}

BOOST_FIXTURE_TEST_CASE(T305__positive__simple_calculate_verify_signature, InitDebugFixture)
{
	struct signature_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
		yaca_digest_algorithm_e algo;
	};

	const std::vector<struct signature_args> sargs = {
		{yaca_key_type_e::YACA_KEY_TYPE_RSA_PRIV,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_1024BIT,
		 yaca_digest_algorithm_e::YACA_DIGEST_MD5},
		{yaca_key_type_e::YACA_KEY_TYPE_RSA_PRIV,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_2048BIT,
		 yaca_digest_algorithm_e::YACA_DIGEST_MD5},
		{yaca_key_type_e::YACA_KEY_TYPE_RSA_PRIV,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_1024BIT,
		 yaca_digest_algorithm_e::YACA_DIGEST_SHA256},
		{yaca_key_type_e::YACA_KEY_TYPE_DSA_PRIV,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_1024BIT,
		 yaca_digest_algorithm_e::YACA_DIGEST_SHA256},
		{yaca_key_type_e::YACA_KEY_TYPE_DSA_PRIV,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_1024BIT,
		 yaca_digest_algorithm_e::YACA_DIGEST_SHA512},
		{yaca_key_type_e::YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)yaca_key_bit_length_ec_e::YACA_KEY_LENGTH_EC_SECP256K1,
		 yaca_digest_algorithm_e::YACA_DIGEST_SHA256}
	};

	for (const auto &sa: sargs) {
		int ret;
		yaca_key_h key_priv = YACA_KEY_NULL;
		yaca_key_h key_pub = YACA_KEY_NULL;

		char *signature = NULL;
		size_t signature_len;

		ret = yaca_key_generate(sa.type, sa.len, &key_priv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_key_extract_public(key_priv, &key_pub);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_simple_calculate_signature(sa.algo, key_priv,
		                                      INPUT_DATA, INPUT_DATA_SIZE,
		                                      &signature, &signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		BOOST_REQUIRE(signature_len > 0);

		ret = yaca_simple_verify_signature(sa.algo, key_pub,
		                                   INPUT_DATA, INPUT_DATA_SIZE,
		                                   signature, signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_key_destroy(key_priv);
		yaca_key_destroy(key_pub);
		yaca_free(signature);
	}
}

BOOST_FIXTURE_TEST_CASE(T306__negative__simple_calculate_verify_signature, InitDebugFixture)
{
	int ret;
	yaca_key_h key_priv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
	yaca_key_h key_ec = YACA_KEY_NULL, key_dsa = YACA_KEY_NULL;

	char *signature = NULL;
	size_t signature_len;

	ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_512BIT, &key_priv);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_extract_public(key_priv, &key_pub);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_512BIT, &key_dsa);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_EC_PRIV, YACA_KEY_LENGTH_EC_PRIME256V1, &key_ec);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_simple_calculate_signature(YACA_INVALID_DIGEST_ALGORITHM, key_priv,
	                                      INPUT_DATA, INPUT_DATA_SIZE,
	                                      &signature, &signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_signature(YACA_DIGEST_SHA384, key_priv,
	                                      INPUT_DATA, INPUT_DATA_SIZE,
	                                      &signature, &signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_signature(YACA_DIGEST_SHA512, key_priv,
	                                      INPUT_DATA, INPUT_DATA_SIZE,
	                                      &signature, &signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_signature(YACA_DIGEST_MD5, YACA_KEY_NULL,
	                                      INPUT_DATA, INPUT_DATA_SIZE,
	                                      &signature, &signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_signature(YACA_DIGEST_MD5, key_priv,
	                                      NULL, INPUT_DATA_SIZE,
	                                      &signature, &signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_signature(YACA_DIGEST_MD5, key_priv,
	                                      INPUT_DATA, 0,
	                                      &signature, &signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_signature(YACA_DIGEST_MD5, key_priv,
	                                      INPUT_DATA, INPUT_DATA_SIZE,
	                                      NULL, &signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_signature(YACA_DIGEST_MD5, key_priv,
	                                      INPUT_DATA, INPUT_DATA_SIZE,
	                                      &signature, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_signature(YACA_DIGEST_MD5, key_dsa,
	                                      INPUT_DATA, INPUT_DATA_SIZE,
	                                      &signature, &signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_signature(YACA_DIGEST_MD5, key_ec,
	                                      INPUT_DATA, INPUT_DATA_SIZE,
	                                      &signature, &signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_signature(YACA_DIGEST_MD5, key_pub,
	                                      INPUT_DATA, INPUT_DATA_SIZE,
	                                      &signature, &signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_signature(YACA_DIGEST_MD5, key_priv,
	                                      INPUT_DATA, INPUT_DATA_SIZE,
	                                      &signature, &signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_simple_verify_signature(YACA_INVALID_DIGEST_ALGORITHM, key_pub,
	                                   INPUT_DATA, INPUT_DATA_SIZE,
	                                   signature, signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_verify_signature(YACA_DIGEST_SHA384, key_pub,
	                                   INPUT_DATA, INPUT_DATA_SIZE,
	                                   signature, signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_verify_signature(YACA_DIGEST_SHA512, key_pub,
	                                   INPUT_DATA, INPUT_DATA_SIZE,
	                                   signature, signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_verify_signature(YACA_DIGEST_MD5, YACA_KEY_NULL,
	                                   INPUT_DATA, INPUT_DATA_SIZE,
	                                   signature, signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_verify_signature(YACA_DIGEST_MD5, key_priv,
	                                   INPUT_DATA, INPUT_DATA_SIZE,
	                                   signature, signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_verify_signature(YACA_DIGEST_MD5, key_ec,
	                                   INPUT_DATA, INPUT_DATA_SIZE,
	                                   signature, signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_verify_signature(YACA_DIGEST_MD5, key_pub,
	                                   NULL, INPUT_DATA_SIZE,
	                                   signature, signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_verify_signature(YACA_DIGEST_MD5, key_pub,
	                                   INPUT_DATA, 0,
	                                   signature, signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_verify_signature(YACA_DIGEST_MD5, key_pub,
	                                   INPUT_DATA, INPUT_DATA_SIZE,
	                                   NULL, signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_verify_signature(YACA_DIGEST_MD5, key_pub,
	                                   INPUT_DATA, INPUT_DATA_SIZE,
	                                   signature, 0);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_verify_signature(YACA_DIGEST_SHA1, key_pub,
	                                   INPUT_DATA, INPUT_DATA_SIZE,
	                                   signature, signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

	ret = yaca_simple_verify_signature(YACA_DIGEST_MD5, key_pub,
	                                   INPUT_DATA, INPUT_DATA_SIZE - 1,
	                                   signature, signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

	ret = yaca_simple_verify_signature(YACA_DIGEST_MD5, key_pub,
	                                   INPUT_DATA + 1, INPUT_DATA_SIZE - 1,
	                                   signature, signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

	ret = yaca_simple_verify_signature(YACA_DIGEST_MD5, key_pub,
	                                   INPUT_DATA, INPUT_DATA_SIZE,
	                                   signature, signature_len - 1);
	BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

	ret = yaca_simple_verify_signature(YACA_DIGEST_MD5, key_pub,
	                                   INPUT_DATA, INPUT_DATA_SIZE,
	                                   signature + 1, signature_len - 1);
	BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

	signature[0] = ~signature[0];
	signature[1] = ~signature[1];
	ret = yaca_simple_verify_signature(YACA_DIGEST_MD5, key_pub,
	                                   INPUT_DATA, INPUT_DATA_SIZE,
	                                   signature, signature_len);
	BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

	yaca_key_destroy(key_priv);
	yaca_key_destroy(key_pub);
	yaca_key_destroy(key_dsa);
	yaca_key_destroy(key_ec);
	yaca_free(signature);
}

BOOST_FIXTURE_TEST_CASE(T307__positive__simple_calculate_hmac, InitDebugFixture)
{
	struct hmac_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
		yaca_digest_algorithm_e algo;
	};

	const std::vector<struct hmac_args> hargs = {
		{yaca_key_type_e::YACA_KEY_TYPE_SYMMETRIC,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_256BIT,
		 yaca_digest_algorithm_e::YACA_DIGEST_MD5},
		{yaca_key_type_e::YACA_KEY_TYPE_SYMMETRIC,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_256BIT,
		 yaca_digest_algorithm_e::YACA_DIGEST_SHA256},
		{yaca_key_type_e::YACA_KEY_TYPE_SYMMETRIC,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_256BIT,
		 yaca_digest_algorithm_e::YACA_DIGEST_SHA512},
		{yaca_key_type_e::YACA_KEY_TYPE_DES,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_UNSAFE_128BIT,
		 yaca_digest_algorithm_e::YACA_DIGEST_SHA1},
		{yaca_key_type_e::YACA_KEY_TYPE_DES,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_192BIT,
		 yaca_digest_algorithm_e::YACA_DIGEST_SHA384}
	};

	for (const auto &ha: hargs) {
		int ret;
		yaca_key_h key = YACA_KEY_NULL;
		char *mac1 = NULL, *mac2 = NULL;
		size_t mac1_len, mac2_len;

		ret = yaca_key_generate(ha.type, ha.len, &key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_simple_calculate_hmac(ha.algo, key,
		                                 INPUT_DATA, INPUT_DATA_SIZE,
		                                 &mac1, &mac1_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_simple_calculate_hmac(ha.algo, key,
		                                 INPUT_DATA, INPUT_DATA_SIZE,
		                                 &mac2, &mac2_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(mac1_len == mac2_len);
		ret = yaca_memcmp(mac1, mac2, mac1_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_key_destroy(key);
		yaca_free(mac1);
		yaca_free(mac2);
	}
}

BOOST_FIXTURE_TEST_CASE(T308__negative__simple_calculate_hmac, InitDebugFixture)
{
	int ret;
	yaca_key_h key = YACA_KEY_NULL, key_prv = YACA_KEY_NULL;
	char *mac = NULL;
	size_t mac_len;

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_512BIT, &key_prv);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_simple_calculate_hmac(YACA_INVALID_DIGEST_ALGORITHM, key,
	                                 INPUT_DATA, INPUT_DATA_SIZE,
	                                 &mac, &mac_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_hmac(YACA_DIGEST_MD5, YACA_KEY_NULL,
	                                 INPUT_DATA, INPUT_DATA_SIZE,
	                                 &mac, &mac_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_hmac(YACA_DIGEST_MD5, key_prv,
	                                 INPUT_DATA, INPUT_DATA_SIZE,
	                                 &mac, &mac_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_hmac(YACA_DIGEST_MD5, key,
	                                 NULL, INPUT_DATA_SIZE,
	                                 &mac, &mac_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_hmac(YACA_DIGEST_MD5, key,
	                                 INPUT_DATA, 0,
	                                 &mac, &mac_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_hmac(YACA_DIGEST_MD5, key,
	                                 INPUT_DATA, INPUT_DATA_SIZE,
	                                 NULL, &mac_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_hmac(YACA_DIGEST_MD5, key,
	                                 INPUT_DATA, INPUT_DATA_SIZE,
	                                 &mac, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	yaca_key_destroy(key);
	yaca_key_destroy(key_prv);
}

BOOST_FIXTURE_TEST_CASE(T309__positive__simple_calculate_cmac, InitDebugFixture)
{
	struct cmac_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
		yaca_encrypt_algorithm_e algo;
	};

	const std::vector<struct cmac_args> cargs = {
		{yaca_key_type_e::YACA_KEY_TYPE_SYMMETRIC,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_256BIT,
		 yaca_encrypt_algorithm_e::YACA_ENCRYPT_AES},
		{yaca_key_type_e::YACA_KEY_TYPE_SYMMETRIC,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_256BIT,
		 yaca_encrypt_algorithm_e::YACA_ENCRYPT_AES},
		{yaca_key_type_e::YACA_KEY_TYPE_SYMMETRIC,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_192BIT,
		 yaca_encrypt_algorithm_e::YACA_ENCRYPT_3DES_3TDEA},
		{yaca_key_type_e::YACA_KEY_TYPE_DES,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_UNSAFE_64BIT,
		 yaca_encrypt_algorithm_e::YACA_ENCRYPT_UNSAFE_DES},
		{yaca_key_type_e::YACA_KEY_TYPE_SYMMETRIC,
		 yaca_key_bit_length_e::YACA_KEY_LENGTH_UNSAFE_128BIT,
		 yaca_encrypt_algorithm_e::YACA_ENCRYPT_CAST5}};

	for (const auto &ha: cargs) {
		int ret;
		yaca_key_h key = YACA_KEY_NULL;
		char *mac1 = NULL, *mac2 = NULL;
		size_t mac1_len, mac2_len;

		ret = yaca_key_generate(ha.type, ha.len, &key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_simple_calculate_cmac(ha.algo, key,
		                                 INPUT_DATA, INPUT_DATA_SIZE,
		                                 &mac1, &mac1_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_simple_calculate_cmac(ha.algo, key,
		                                 INPUT_DATA, INPUT_DATA_SIZE,
		                                 &mac2, &mac2_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(mac1_len == mac2_len);
		ret = yaca_memcmp(mac1, mac2, mac1_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_key_destroy(key);
		yaca_free(mac1);
		yaca_free(mac2);
	}
}

BOOST_FIXTURE_TEST_CASE(T3010__negative__simple_calculate_cmac, InitDebugFixture)
{
	int ret;
	yaca_key_h key = YACA_KEY_NULL, key_prv = YACA_KEY_NULL;
	char *mac = NULL;
	size_t mac_len;

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_512BIT, &key_prv);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_simple_calculate_cmac(YACA_INVALID_ENCRYPT_ALGORITHM, key,
	                                 INPUT_DATA, INPUT_DATA_SIZE,
	                                 &mac, &mac_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_cmac(YACA_ENCRYPT_AES, YACA_KEY_NULL,
	                                 INPUT_DATA, INPUT_DATA_SIZE,
	                                 &mac, &mac_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_cmac(YACA_ENCRYPT_AES, key_prv,
	                                 INPUT_DATA, INPUT_DATA_SIZE,
	                                 &mac, &mac_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_cmac(YACA_ENCRYPT_AES, key,
	                                 NULL, INPUT_DATA_SIZE,
	                                 &mac, &mac_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_cmac(YACA_ENCRYPT_AES, key,
	                                 INPUT_DATA, 0,
	                                 &mac, &mac_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_cmac(YACA_ENCRYPT_AES, key,
	                                 INPUT_DATA, INPUT_DATA_SIZE,
	                                 NULL, &mac_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_simple_calculate_cmac(YACA_ENCRYPT_AES, key,
	                                 INPUT_DATA, INPUT_DATA_SIZE,
	                                 &mac, 0);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	yaca_key_destroy(key);
	yaca_key_destroy(key_prv);
}

BOOST_AUTO_TEST_SUITE_END()
