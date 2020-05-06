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
 * @file    mock_test_crypto.cpp
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   Base crypto API unit tests using mockup.
 */

#include <boost/test/unit_test.hpp>

#include <openssl/rand.h>
#include <sys/syscall.h>

#include <yaca_crypto.h>
#include <yaca_error.h>

#include "common.h"
#include "openssl_mock_impl.h"


namespace {

const size_t DATA_SIZE = 10;

}

BOOST_AUTO_TEST_SUITE(MOCK_TESTS_CRYPTO)

BOOST_FIXTURE_TEST_CASE(T1101__mock__negative__malloc, InitFixture)
{
	int ret;
	char *alloc;

	MOCK_fail_OPENSSL_malloc = 1;
	ret = yaca_malloc(DATA_SIZE, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_OUT_OF_MEMORY);
}


BOOST_FIXTURE_TEST_CASE(T1102__mock__negative__zalloc, InitFixture)
{
	int ret;
	char *alloc;

	MOCK_fail_OPENSSL_malloc = 1;
	ret = yaca_zalloc(DATA_SIZE, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_OUT_OF_MEMORY);
}


BOOST_FIXTURE_TEST_CASE(T1103__mock__negative__realloc, InitFixture)
{
	int ret;
	char *alloc;

	ret = yaca_zalloc(DATA_SIZE, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	MOCK_fail_OPENSSL_realloc = 1;
	ret = yaca_realloc(DATA_SIZE * 2, (void**)&alloc);
	BOOST_REQUIRE(ret == YACA_ERROR_OUT_OF_MEMORY);

	yaca_free(alloc);
}

BOOST_FIXTURE_TEST_CASE(T1104__mock__negative__randomize_bytes, InitFixture)
{
	int ret;
	char buf[DATA_SIZE] = {};

	MOCK_fail_RAND_bytes = 1;
	ret = yaca_randomize_bytes(buf, DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_INTERNAL);
}

#ifndef SYS_getrandom
BOOST_AUTO_TEST_CASE(T1105__mock__negative__sys_init)
{
	int ret;

	MOCK_fail_open = 1;
	ret = yaca_initialize();
	BOOST_REQUIRE(ret == YACA_ERROR_INTERNAL);
}

BOOST_FIXTURE_TEST_CASE(T1106__mock__negative__sys_randomize_bytes, InitFixture)
{
	int ret;
	char data[DATA_SIZE];

	MOCK_fail_read = 1;
	ret = yaca_randomize_bytes(data, DATA_SIZE);
	BOOST_REQUIRE(ret == YACA_ERROR_INTERNAL);
}
#endif

BOOST_AUTO_TEST_SUITE_END()
