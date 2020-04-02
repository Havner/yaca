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
 * @file    test_crypto.cpp
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   Base crypto API unit tests.
 */

#include <boost/test/unit_test.hpp>

#include <openssl/rand.h>

#include <yaca_crypto.h>
#include <yaca_error.h>

#include "common.h"


namespace {

const size_t DATA_SIZE = 10;

bool is_mem_zero(const char* p, size_t size)
{
	for (size_t i = 0; i < size; ++i)
		if (p[i] != '\0')
			return false;
	return true;
}

}

BOOST_AUTO_TEST_SUITE(TESTS_CRYPTO)

BOOST_FIXTURE_TEST_CASE(T101__positive__init, DebugFixture)
{
	int ret;

	ret = yaca_initialize();
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	yaca_cleanup();
}

BOOST_FIXTURE_TEST_CASE(T102__negative__double_init, DebugFixture)
{
	int ret;

	ret = yaca_initialize();
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_initialize();
	BOOST_REQUIRE(ret == YACA_ERROR_INTERNAL);

	yaca_cleanup();
}

BOOST_FIXTURE_TEST_CASE(T103__negative__double_cleanup, DebugFixture)
{
	int ret;

	ret = yaca_initialize();
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	yaca_cleanup();

	yaca_cleanup();
}

BOOST_FIXTURE_TEST_CASE(T104__positivie__malloc, InitDebugFixture)
{
	int ret;
	char *alloc;

	ret = yaca_malloc(DATA_SIZE, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(alloc != NULL);

	yaca_free(alloc);
}

BOOST_FIXTURE_TEST_CASE(T105__negative__malloc, InitDebugFixture)
{
	int ret;
	char *alloc;

	ret = yaca_malloc(0, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_malloc(DATA_SIZE, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_malloc(0, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);
}

BOOST_FIXTURE_TEST_CASE(T106__positive__zalloc, InitDebugFixture)
{
	int ret;
	char *alloc;

	ret = yaca_zalloc(DATA_SIZE, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(alloc != NULL);

	BOOST_REQUIRE(is_mem_zero(alloc, DATA_SIZE));

	yaca_free(alloc);
}

BOOST_FIXTURE_TEST_CASE(T107__negative__zalloc, InitDebugFixture)
{
	int ret;
	char *alloc;

	ret = yaca_zalloc(0, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_zalloc(DATA_SIZE, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_zalloc(0, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);
}

BOOST_FIXTURE_TEST_CASE(T108__positive__realloc, InitDebugFixture)
{
	int ret;
	char *alloc;

	ret = yaca_zalloc(DATA_SIZE, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_realloc(DATA_SIZE * 2, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(alloc != NULL);

	BOOST_REQUIRE(is_mem_zero(alloc, DATA_SIZE));

	ret = yaca_realloc(DATA_SIZE / 2, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(alloc != NULL);

	BOOST_REQUIRE(is_mem_zero(alloc, DATA_SIZE / 2));

	yaca_free(alloc);
	alloc = NULL;

	ret = yaca_realloc(DATA_SIZE, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(alloc != NULL);

	yaca_free(alloc);
}

BOOST_FIXTURE_TEST_CASE(T109__negative__realloc, InitDebugFixture)
{
	int ret;
	char *alloc;

	ret = yaca_zalloc(DATA_SIZE, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_realloc(0, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);
	BOOST_REQUIRE(is_mem_zero(alloc, DATA_SIZE));

	ret = yaca_realloc(DATA_SIZE, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_realloc(0, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	yaca_free(alloc);
}

BOOST_FIXTURE_TEST_CASE(T110__positive__memcmp, InitDebugFixture)
{
	int ret;
	char *alloc1, *alloc2;

	ret = yaca_memcmp(NULL, NULL, 0);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_zalloc(DATA_SIZE, (void**)&alloc1);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_zalloc(DATA_SIZE, (void**)&alloc2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_memcmp(alloc1, alloc2, DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_memcmp(alloc1, alloc2, 0);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_memcmp(NULL, alloc2, 0);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_memcmp(alloc1, NULL, 0);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	alloc1[9] = 'a';

	ret = yaca_memcmp(alloc1, alloc2, DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

	ret = yaca_memcmp(alloc1, alloc2, 9);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	alloc2[0] = 'a';

	ret = yaca_memcmp(alloc1, alloc2, 9);
	BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

	ret = yaca_memcmp(alloc1, alloc1, DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_memcmp(alloc2, alloc2, DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	yaca_free(alloc1);
	yaca_free(alloc2);
}

BOOST_FIXTURE_TEST_CASE(T111__negative__memcmp, InitDebugFixture)
{
	int ret;
	char *alloc;

	ret = yaca_malloc(DATA_SIZE, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_memcmp(alloc, NULL, DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_memcmp(NULL, alloc, DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	yaca_free(alloc);
}

BOOST_FIXTURE_TEST_CASE(T112__positive__yaca_randomize_bytes, InitDebugFixture)
{
	int ret;
	char *alloc1, *alloc2;

	ret = yaca_zalloc(DATA_SIZE, (void**)&alloc1);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_zalloc(DATA_SIZE, (void**)&alloc2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_randomize_bytes(alloc1, DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(!is_mem_zero(alloc1, DATA_SIZE));

	ret = yaca_memcmp(alloc1, alloc2, DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

	ret = yaca_randomize_bytes(alloc2, DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(!is_mem_zero(alloc2, DATA_SIZE));

	ret = yaca_memcmp(alloc1, alloc2, DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

	yaca_free(alloc1);
	yaca_free(alloc2);
}

BOOST_FIXTURE_TEST_CASE(T113__negative__yaca_randomize_bytes, InitDebugFixture)
{
	int ret;
	char *alloc;

	ret = yaca_malloc(DATA_SIZE, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_randomize_bytes(alloc, 0);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_randomize_bytes(NULL, DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

}

BOOST_FIXTURE_TEST_CASE(T114__negative__yaca_context, InitDebugFixture)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_padding_e *get, set = YACA_PADDING_NONE;
	size_t output, input = sizeof(yaca_padding_e);

	ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, (void*)&set, input);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_context_get_property(ctx, YACA_PROPERTY_PADDING, (void**)&get, &output);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_context_get_output_length(ctx, 0, &output);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);
}

BOOST_FIXTURE_TEST_CASE(T115__positive__openssl_rand, InitDebugFixture)
{
	static const size_t LEN = 256;
	int ret;
	unsigned char rand_bytes[LEN] = {};

	ret = RAND_status();
	BOOST_REQUIRE(ret == 1);

	BOOST_REQUIRE(is_mem_zero((const char *)rand_bytes, LEN));
	ret = RAND_bytes(rand_bytes, LEN);
	BOOST_REQUIRE(ret == 1);
	BOOST_REQUIRE(!is_mem_zero((const char *)rand_bytes, LEN));
}

BOOST_AUTO_TEST_SUITE_END()
