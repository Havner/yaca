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
 * @file    common.cpp
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   Common code for YACA unit tests
 */

#define BOOST_TEST_MODULE YacaUnitTests

#include <boost/test/unit_test.hpp>
#include <boost/test/unit_test_log.hpp>
#include <boost/test/results_reporter.hpp>
#include <iostream>

#include <yaca_crypto.h>
#include <yaca_error.h>
#include <yaca_key.h>
#include <yaca_encrypt.h>
#include "../src/debug.h"

#include "common.h"
#include "colour_log_formatter.h"


namespace {

size_t error_cb_called = 0;

void debug_error_cb(const char *buf)
{
	std::cout << buf;
	++error_cb_called;
}

} // namespace


DebugFixture::DebugFixture()
{
	error_cb_called = 0;
	yaca_debug_set_error_cb(&debug_error_cb);
}

DebugFixture::~DebugFixture()
{
	/* No ERROR_DUMP should've been called. If there is one that is
	 * harmless (that happens) it should be added to error_handle
	 * anyway.
	 */
	BOOST_REQUIRE(error_cb_called == 0);
	yaca_debug_set_error_cb(NULL);
}

InitFixture::InitFixture()
{
	int ret = yaca_initialize();
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
}

InitFixture::~InitFixture()
{
	yaca_cleanup();
}

struct TestConfig {
	TestConfig()
	{
		boost::unit_test::unit_test_log.set_threshold_level(
			boost::unit_test::log_test_units);
		boost::unit_test::results_reporter::set_level(boost::unit_test::SHORT_REPORT);
		boost::unit_test::unit_test_log.set_formatter(new Yaca::colour_log_formatter);
	}
	~TestConfig()
	{
	}
};

BOOST_GLOBAL_FIXTURE(TestConfig);

namespace {

struct key_types {
	yaca_key_type_e pub;
	yaca_key_type_e params;
};

const std::map<yaca_key_type_e, key_types> KEY_TYPES = {
	{YACA_KEY_TYPE_RSA_PRIV, {YACA_KEY_TYPE_RSA_PUB, YACA_INVALID_KEY_TYPE}},
	{YACA_KEY_TYPE_DSA_PRIV, {YACA_KEY_TYPE_DSA_PUB, YACA_KEY_TYPE_DSA_PARAMS}},
	{YACA_KEY_TYPE_DH_PRIV,  {YACA_KEY_TYPE_DH_PUB,  YACA_KEY_TYPE_DH_PARAMS}},
	{YACA_KEY_TYPE_EC_PRIV,  {YACA_KEY_TYPE_EC_PUB,  YACA_KEY_TYPE_EC_PARAMS}},
};

} // namespace

void generate_asymmetric_keys(yaca_key_type_e type_prv, size_t key_bit_len,
                              yaca_key_h *key_prv, yaca_key_h *key_pub, yaca_key_h *key_params)
{
	int ret;
	yaca_key_type_e type_pub, type_params;
	yaca_key_h prv, pub, params;
	type_pub = type_params = YACA_INVALID_KEY_TYPE;
	prv = pub = params = YACA_KEY_NULL;

	BOOST_REQUIRE_NO_THROW(type_pub = KEY_TYPES.at(type_prv).pub);
	BOOST_REQUIRE_NO_THROW(type_params = KEY_TYPES.at(type_prv).params);

	ret = yaca_key_generate(type_prv, key_bit_len, &prv);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	if (key_pub != NULL && type_pub != YACA_INVALID_KEY_TYPE) {
		ret = yaca_key_extract_public(prv, &pub);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	}

	if (key_params != NULL && type_params != YACA_INVALID_KEY_TYPE) {
		ret = yaca_key_extract_parameters(prv, &params);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	}

	if (key_prv != NULL)
		*key_prv = prv;
	else
		yaca_key_destroy(prv);

	if (key_pub != NULL)
		*key_pub = pub;

	if (key_params != NULL)
		*key_params = params;
}

size_t allocate_output(yaca_context_h ctx, size_t input_len, size_t split, char *&output)
{
	BOOST_REQUIRE_MESSAGE(split >= 1, "Fix your test");

	int ret;
	size_t part = input_len / split;
	size_t parts = part * split;
	size_t len1 = 0, len2 = 0, len3 = 0;

	BOOST_REQUIRE_MESSAGE(part >= 1, "Fix your test");

	ret = yaca_context_get_output_length(ctx, part, &len1);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	if (parts < input_len) {
		ret = yaca_context_get_output_length(ctx, input_len - parts, &len2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	}
	ret = yaca_context_get_output_length(ctx, 0, &len3);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	size_t total = len1 * split + len2 + len3;

	ret = yaca_zalloc(total, reinterpret_cast<void**>(&output));
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	return total;
}

void call_update_loop(yaca_context_h ctx, const char *input, size_t input_len,
                      char *output, size_t &output_len, size_t split,
                      update_fun_5_t *fun)
{
	BOOST_REQUIRE_MESSAGE(split >= 1, "Fix your test");

	int ret;
	size_t left = input_len;
	size_t part = input_len / split;
	size_t written;

	BOOST_REQUIRE_MESSAGE(part >= 1, "Fix your test");
	output_len = 0;

	for (;;) {
		ret = fun(ctx, input, part, output, &written);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		output_len += written;
		output += written;
		input += part;
		left -= part;

		if (left == 0)
			break;

		if (left < part)
			part = left;
	}
}
