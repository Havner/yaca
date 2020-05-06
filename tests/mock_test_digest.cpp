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


BOOST_AUTO_TEST_SUITE(MOCK_TESTS_DIGEST)

BOOST_FIXTURE_TEST_CASE(T1501__mock__negative__yaca_digest, InitFixture)
{
	struct digest_args {
		yaca_digest_algorithm_e algo = YACA_DIGEST_SHA256;
	};

	const std::vector<struct digest_args> dargs = {
		{yaca_digest_algorithm_e::YACA_DIGEST_MD5},
		{yaca_digest_algorithm_e::YACA_DIGEST_SHA224}
	};

	for (const auto &da: dargs) {
		auto test_code = [&da]() -> int
			{
				int ret;
				yaca_context_h ctx = YACA_CONTEXT_NULL;
				char *digest = NULL;
				size_t digest_len;

				ret = yaca_digest_initialize(&ctx, da.algo);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_digest_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_context_get_output_length(ctx, 0, &digest_len);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_malloc(digest_len, (void**)&digest);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_digest_finalize(ctx, digest, &digest_len);
				if (ret != YACA_ERROR_NONE) goto exit;

			exit:
				yaca_context_destroy(ctx);
				yaca_free(digest);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_AUTO_TEST_SUITE_END()
