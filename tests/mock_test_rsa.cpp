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
 * @file    test_rsa.c
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   RSA API unit tests.
 */

#include <boost/test/unit_test.hpp>
#include <vector>

#include <yaca_crypto.h>
#include <yaca_rsa.h>
#include <yaca_key.h>
#include <yaca_error.h>

#include "common.h"


BOOST_AUTO_TEST_SUITE(MOCK_TESTS_RSA)

BOOST_FIXTURE_TEST_CASE(T1401__mock__negative__private_encrypt, InitFixture)
{
	struct rsa_args {
		yaca_padding_e pad;
		yaca_key_bit_length_e bit_len;
		size_t shorter;
	};

	const std::vector<struct rsa_args> rargs = {
		{YACA_PADDING_NONE,         YACA_KEY_LENGTH_512BIT,   0},
		{YACA_PADDING_PKCS1,        YACA_KEY_LENGTH_512BIT,  11},
	};

	for (const auto &ra: rargs) {
		auto test_code = [&ra]()
			{
				int ret;
				yaca_key_h rsa_prv = YACA_KEY_NULL, rsa_pub = YACA_KEY_NULL;
				size_t input_len = ra.bit_len / 8 - ra.shorter;
				char *encrypted = NULL, *decrypted = NULL;
				size_t encrypted_len, decrypted_len;

				ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, ra.bit_len, &rsa_prv);
				if (ret != YACA_ERROR_NONE) goto exit;
				ret = yaca_key_extract_public(rsa_prv, &rsa_pub);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_rsa_private_encrypt(ra.pad, rsa_prv, INPUT_DATA, input_len,
											   &encrypted, &encrypted_len);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_rsa_public_decrypt(ra.pad, rsa_pub, encrypted, encrypted_len,
											  &decrypted, &decrypted_len);
				if (ret != YACA_ERROR_NONE) goto exit;

			exit:
				yaca_key_destroy(rsa_prv);
				yaca_key_destroy(rsa_pub);
				yaca_free(encrypted);
				yaca_free(decrypted);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1402__mock__negative__public_encrypt, InitFixture)
{
	struct rsa_args {
		yaca_padding_e pad;
		yaca_key_bit_length_e bit_len;
		size_t shorter;
	};

	const std::vector<struct rsa_args> rargs = {
		{YACA_PADDING_NONE,         YACA_KEY_LENGTH_512BIT,   0},
		{YACA_PADDING_PKCS1,        YACA_KEY_LENGTH_1024BIT, 11},
		{YACA_PADDING_PKCS1_OAEP,   YACA_KEY_LENGTH_2048BIT, 42},
	};

	for (const auto &ra: rargs) {
		auto test_code = [&ra]()
			{
				int ret;
				yaca_key_h rsa_prv = YACA_KEY_NULL, rsa_pub = YACA_KEY_NULL;
				size_t input_len = ra.bit_len / 8 - ra.shorter;
				char *encrypted = NULL, *decrypted = NULL;
				size_t encrypted_len, decrypted_len;

				ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, ra.bit_len, &rsa_prv);
				if (ret != YACA_ERROR_NONE) goto exit;
				ret = yaca_key_extract_public(rsa_prv, &rsa_pub);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_rsa_public_encrypt(ra.pad, rsa_pub, INPUT_DATA, input_len,
											  &encrypted, &encrypted_len);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_rsa_private_decrypt(ra.pad, rsa_prv, encrypted, encrypted_len,
											   &decrypted, &decrypted_len);
				if (ret != YACA_ERROR_NONE) goto exit;

			exit:
				yaca_key_destroy(rsa_prv);
				yaca_key_destroy(rsa_pub);
				yaca_free(encrypted);
				yaca_free(decrypted);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_AUTO_TEST_SUITE_END()
