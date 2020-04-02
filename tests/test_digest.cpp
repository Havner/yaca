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
 * @file    test_digest.cpp
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   Digest API unit tests.
 */

#include <boost/test/unit_test.hpp>
#include <vector>

#include <yaca_crypto.h>
#include <yaca_digest.h>
#include <yaca_encrypt.h>
#include <yaca_key.h>
#include <yaca_error.h>

#include "common.h"


BOOST_AUTO_TEST_SUITE(TESTS_DIGEST)

BOOST_FIXTURE_TEST_CASE(T501__positive__yaca_digest, InitDebugFixture)
{
	struct digest_args {
		yaca_digest_algorithm_e algo = YACA_DIGEST_SHA256;
		size_t expected;
		size_t split;
	};

	const std::vector<struct digest_args> dargs = {
		{yaca_digest_algorithm_e::YACA_DIGEST_MD5,    16, 5},
		{yaca_digest_algorithm_e::YACA_DIGEST_SHA1,   20, 15},
		{yaca_digest_algorithm_e::YACA_DIGEST_SHA224, 28, 9},
		{yaca_digest_algorithm_e::YACA_DIGEST_SHA256, 32, 7},
		{yaca_digest_algorithm_e::YACA_DIGEST_SHA384, 48, 35},
		{yaca_digest_algorithm_e::YACA_DIGEST_SHA512, 64, 11}
	};

	for (const auto &da: dargs) {
		int ret;
		yaca_context_h ctx = YACA_CONTEXT_NULL;
		char *digest = NULL;
		size_t digest_len;

		ret = yaca_digest_initialize(&ctx, da.algo);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		const char *input = INPUT_DATA;
		size_t left = INPUT_DATA_SIZE;
		size_t todo = INPUT_DATA_SIZE / da.split;
		BOOST_REQUIRE_MESSAGE(todo > 0, "Fix your test");

		for (;;) {
			ret = yaca_digest_update(ctx, input, todo);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			input += todo;
			left -= todo;

			if (left == 0)
				break;

			if (left < todo)
				todo = left;
		}

		ret = yaca_context_get_output_length(ctx, 0, &digest_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_malloc(digest_len, (void**)&digest);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		BOOST_REQUIRE(digest != NULL);

		ret = yaca_digest_finalize(ctx, digest, &digest_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(digest_len == da.expected);

		yaca_context_destroy(ctx);
		yaca_free(digest);
	}
}

BOOST_FIXTURE_TEST_CASE(T502__negative__yaca_digest, InitDebugFixture)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_context_h ctx_encrypt = YACA_CONTEXT_NULL;
	yaca_key_h key_sym = YACA_KEY_NULL;
	char *digest = NULL;
	size_t digest_len;
	yaca_padding_e pad = YACA_PADDING_PKCS1;
	size_t bit_len = 256;

	ret = yaca_digest_initialize(NULL, YACA_DIGEST_MD5);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_digest_initialize(&ctx, YACA_INVALID_DIGEST_ALGORITHM);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_digest_initialize(&ctx, YACA_DIGEST_MD5);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key_sym);
	ret = yaca_encrypt_initialize(&ctx_encrypt, YACA_ENCRYPT_AES,
								  YACA_BCM_ECB, key_sym, YACA_KEY_NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
									&pad, sizeof(yaca_padding_e));
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
									&bit_len, sizeof(size_t));
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_digest_update(NULL, INPUT_DATA, INPUT_DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_digest_update(ctx_encrypt, INPUT_DATA, INPUT_DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_digest_update(ctx, NULL, INPUT_DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_digest_update(ctx, INPUT_DATA, 0);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_digest_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_context_get_output_length(YACA_CONTEXT_NULL, 0, &digest_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_context_get_output_length(ctx, 10, &digest_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_context_get_output_length(ctx, 0, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_context_get_output_length(ctx, 0, &digest_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_malloc(digest_len, (void**)&digest);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_digest_finalize(YACA_CONTEXT_NULL, digest, &digest_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_digest_finalize(ctx_encrypt, digest, &digest_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_digest_finalize(ctx, NULL, &digest_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_digest_finalize(ctx, digest, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_digest_finalize(ctx, digest, &digest_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_digest_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_digest_finalize(ctx, digest, &digest_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	yaca_context_destroy(ctx);
	yaca_context_destroy(ctx_encrypt);
	yaca_key_destroy(key_sym);
	yaca_free(digest);
}

BOOST_AUTO_TEST_SUITE_END()
