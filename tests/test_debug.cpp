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
 * @file    test_debug.cpp
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   Debug internal API unit tests.
 */

#include <boost/test/unit_test.hpp>
#include <string>
#include <vector>
#include <iostream>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <openssl/ec.h>

#include <yaca_error.h>
#include "../src/debug.h"
#include "common.h"


namespace {

int error_cb_called = 0;

/* Has to be the same as BUF_SIZE in error_dump */
const size_t BUF_SIZE = 512;
/* Has to be the same as ELLIPSIS in error_dump */
const char ELLIPSIS[] = "...\n";

char last_buf[BUF_SIZE] = {};

void debug_error_cb(const char *buf)
{
	++error_cb_called;

	BOOST_REQUIRE(strlen(buf) < BUF_SIZE);
	memcpy(last_buf, buf, BUF_SIZE);
}

struct CallbackCleanup
{
	CallbackCleanup()
	{
		error_cb_called = 0;
	}
	~CallbackCleanup()
	{
		yaca_debug_set_error_cb(NULL);
	}
};

}

BOOST_AUTO_TEST_SUITE(TESTS_DEBUG)

BOOST_AUTO_TEST_CASE(T001__positive__translate_error)
{
	struct error_args {
		yaca_error_e err;
		std::string msg;
	};

	const std::vector<struct error_args> eargs = {
		{YACA_INVALID_ERROR, "Error not defined"},
		{YACA_ERROR_NONE, "YACA_ERROR_NONE"},
		{YACA_ERROR_INVALID_PARAMETER, "YACA_ERROR_INVALID_PARAMETER"},
		{YACA_ERROR_OUT_OF_MEMORY, "YACA_ERROR_OUT_OF_MEMORY"},
		{YACA_ERROR_INTERNAL, "YACA_ERROR_INTERNAL"},
		{YACA_ERROR_DATA_MISMATCH, "YACA_ERROR_DATA_MISMATCH"},
		{YACA_ERROR_INVALID_PASSWORD, "YACA_ERROR_INVALID_PASSWORD"},
	};

	for (const auto &ea: eargs) {
		std::string ret = yaca_debug_translate_error(ea.err);
		BOOST_REQUIRE(ret == ea.msg);
	}
}

BOOST_FIXTURE_TEST_CASE(T002__positive__debug_set_error_cb, CallbackCleanup)
{
	ERROR_DUMP(YACA_ERROR_INTERNAL);
	BOOST_REQUIRE(error_cb_called == 0);

	yaca_debug_set_error_cb(&debug_error_cb);
	ERROR_DUMP(YACA_ERROR_INTERNAL);
	BOOST_REQUIRE(error_cb_called == 1);

	ERROR_DUMP(YACA_ERROR_INTERNAL);
	BOOST_REQUIRE(error_cb_called == 2);

	yaca_debug_set_error_cb(NULL);
	ERROR_DUMP(YACA_ERROR_INTERNAL);
	ERROR_DUMP(YACA_ERROR_INTERNAL);
	BOOST_REQUIRE(error_cb_called == 2);
}

BOOST_FIXTURE_TEST_CASE(T003__positive__error_dump, CallbackCleanup)
{
	yaca_debug_set_error_cb(&debug_error_cb);

	/* I won't check the string that's been generated. It's too
	 * volatile. Some regexp can be implemented at most. */
	PEMerr(PEM_F_LOAD_IV, PEM_R_READ_KEY);
	ERROR_DUMP(YACA_ERROR_INTERNAL);
	BOOST_REQUIRE(error_cb_called == 1);
	RSAerr(RSA_F_RSA_VERIFY, RSA_R_DATA_TOO_LARGE);
	ERROR_DUMP(-1 * YACA_ERROR_INTERNAL);
	BOOST_REQUIRE(error_cb_called == 2);

	/* The check that makes sense though is ellipsis. Also it'll
	 * trigger the ellipsis code so it's at least a crash check.
	 * No, those errors don't have to make any sense. */
	RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_KEY_SIZE_TOO_SMALL);
	RSAerr(RSA_F_RSA_SIGN, RSA_R_MODULUS_TOO_LARGE);
	DSAerr(DSA_F_PKEY_DSA_KEYGEN, DSA_R_PARAMETER_ENCODING_ERROR);
	DSAerr(DSA_F_DSA_SIGN_SETUP, DSA_R_MODULUS_TOO_LARGE);
	PEMerr(PEM_F_PEM_ASN1_WRITE, PEM_R_BAD_PASSWORD_READ);
	PEMerr(PEM_F_PEM_READ_DHPARAMS, PEM_R_UNSUPPORTED_CIPHER);
	PEMerr(PEM_F_PEM_READ_BIO_EX, PEM_R_ERROR_CONVERTING_PRIVATE_KEY);
	RSAerr(RSA_F_ENCODE_PKCS1, RSA_R_VALUE_MISSING);
	ERROR_DUMP(YACA_ERROR_INTERNAL);
	BOOST_REQUIRE(error_cb_called == 3);

	std::string ret(last_buf);
	std::string ellipsis = ret.substr(ret.size() - strlen(ELLIPSIS));
	BOOST_REQUIRE(ellipsis == ELLIPSIS);
}

BOOST_FIXTURE_TEST_CASE(T004__positive__error_handle, CallbackCleanup)
{
	struct error_args {
		long err1;
		long err2;
		yaca_error_e expected;
		int cb_called;
	};

	const std::vector<struct error_args> eargs = {
		{-1, -1, YACA_ERROR_INTERNAL, 0},
		{ERR_PACK(ERR_LIB_RSA, RSA_F_RSA_OSSL_PRIVATE_DECRYPT, RSA_R_DATA_GREATER_THAN_MOD_LEN),
		 -1, YACA_ERROR_INVALID_PARAMETER, 0},
		{ERR_PACK(ERR_LIB_RSA, RSA_F_PKEY_RSA_CTRL, RSA_R_KEY_SIZE_TOO_SMALL),
		 -1, YACA_ERROR_INVALID_PARAMETER, 0},
		{ERR_PACK(ERR_LIB_ASN1, ASN1_F_ASN1_GET_OBJECT, ASN1_R_TOO_LONG),
		 ERR_PACK(ERR_LIB_RSA, RSA_F_OLD_RSA_PRIV_DECODE, ERR_R_RSA_LIB),
		 YACA_ERROR_INVALID_PASSWORD, 0},
		{ERR_PACK(ERR_LIB_ASN1, ASN1_F_ASN1_GET_OBJECT, ASN1_R_HEADER_TOO_LONG),
		 ERR_PACK(ERR_LIB_RSA, RSA_F_OLD_RSA_PRIV_DECODE, RSA_R_DIGEST_NOT_ALLOWED),
		 YACA_ERROR_INVALID_PARAMETER, 0},
		{ERR_PACK(ERR_LIB_PEM, PEM_F_PEM_READ_BIO_PRIVATEKEY, PEM_R_BAD_PASSWORD_READ),
		 -1, YACA_ERROR_INVALID_PASSWORD, 0},
		{ERR_PACK(ERR_LIB_PEM, PEM_F_PEM_DO_HEADER, PEM_R_BAD_DECRYPT),
		 -1, YACA_ERROR_INVALID_PASSWORD, 0},
		{ERR_PACK(ERR_LIB_RSA, RSA_F_CHECK_PADDING_MD, PEM_R_BAD_DECRYPT),
		 -1, YACA_ERROR_INVALID_PARAMETER, 0},
		{ERR_PACK(ERR_LIB_RSA, RSA_F_RSA_PADDING_ADD_PKCS1_OAEP, PEM_R_BAD_DECRYPT),
		 -1, YACA_ERROR_INVALID_PARAMETER, 0},
		{ERR_PACK(ERR_LIB_EC, EC_F_PKEY_EC_SIGN, ERR_R_MALLOC_FAILURE),
		 -1, YACA_ERROR_OUT_OF_MEMORY, 0},
		{ERR_PACK(ERR_LIB_EC, EC_F_PKEY_EC_SIGN, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED),
		 -1, YACA_ERROR_INVALID_PARAMETER, 0},
		{ERR_PACK(ERR_LIB_EC, EC_F_PKEY_EC_SIGN, ERR_R_PASSED_NULL_PARAMETER),
		 -1, YACA_ERROR_INVALID_PARAMETER, 0},
		{ERR_PACK(ERR_LIB_EC, EC_F_PKEY_EC_SIGN, ERR_R_INTERNAL_ERROR),
		 -1, YACA_ERROR_INTERNAL, 0},
		{ERR_PACK(ERR_LIB_EC, EC_F_PKEY_EC_SIGN, ERR_R_DISABLED),
		 -1, YACA_ERROR_INTERNAL, 0},
		{ERR_PACK(ERR_LIB_RSA, RSA_F_SETUP_TBUF, RSA_R_BAD_SIGNATURE),
		 -1, YACA_ERROR_INTERNAL, 1},
		{ERR_PACK(ERR_LIB_DSA, DSA_F_DSA_NEW_METHOD, DSA_R_BN_ERROR),
		 -1, YACA_ERROR_INTERNAL, 1},
		{ERR_PACK(ERR_LIB_EC, EC_F_BN_TO_FELEM, EC_R_SLOT_FULL),
		 -1, YACA_ERROR_INTERNAL, 1},
	};

	yaca_debug_set_error_cb(&debug_error_cb);

	for (const auto &ea: eargs) {
		error_cb_called = 0;

		if (ea.err1 != -1) {
			ERR_PUT_error(ERR_GET_LIB(ea.err1), ERR_GET_FUNC(ea.err1),
			              ERR_GET_REASON(ea.err1), OPENSSL_FILE, OPENSSL_LINE);
		}
		if (ea.err2 != -1) {
			ERR_PUT_error(ERR_GET_LIB(ea.err2), ERR_GET_FUNC(ea.err2),
			              ERR_GET_REASON(ea.err2), OPENSSL_FILE, OPENSSL_LINE);
		}

		int ret = ERROR_HANDLE();

		BOOST_REQUIRE(ret == ea.expected);
		BOOST_REQUIRE(error_cb_called == ea.cb_called);
	}

}

BOOST_AUTO_TEST_SUITE_END()
