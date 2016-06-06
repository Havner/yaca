/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Krzysztof Jackiewicz <k.jackiewicz@samsung.com>
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
 * @file digest.c
 * @brief
 */

#include <yaca_crypto.h>
#include <yaca_digest.h>
#include <yaca_simple.h>
#include <yaca_error.h>

#include "lorem.h"
#include "misc.h"
#include "../src/debug.h"

void digest_simple(void)
{
	int ret = YACA_ERROR_NONE;
	char *digest;
	size_t digest_len;

	ret = yaca_simple_calculate_digest(YACA_DIGEST_SHA256,
	                       lorem1024,
	                       1024, &digest, &digest_len);
	if (ret != YACA_ERROR_NONE)
		return;

	dump_hex(digest, digest_len, "Message digest: ");

	yaca_free(digest);
}

void digest_advanced(void)
{
	int ret = YACA_ERROR_NONE;
	yaca_context_h ctx;

	ret = yaca_digest_initialize(&ctx, YACA_DIGEST_SHA256);
	if (ret != YACA_ERROR_NONE)
		return;

	ret = yaca_digest_update(ctx, lorem1024, 1024);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	size_t digest_len;
	ret = yaca_get_digest_length(ctx, &digest_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	{
		char digest[digest_len];

		ret = yaca_digest_finalize(ctx, digest, &digest_len);
		if (ret != YACA_ERROR_NONE)
			goto exit;

		dump_hex(digest, digest_len, "Message digest: ");
	}

exit:
	yaca_context_destroy(ctx);
}

int main()
{
	yaca_debug_set_error_cb(debug_func);

	int ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		return ret;

	digest_simple();

	digest_advanced();

	yaca_cleanup();
	return ret;
}
