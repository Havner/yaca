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

#include <stdio.h>
#include <yaca/crypto.h>
#include <yaca/digest.h>
#include <yaca/simple.h>
#include "lorem.h"
#include "misc.h"

void digest_simple(void)
{
	int ret = 0;
	char *digest;
	size_t digest_len;

	ret = yaca_digest_calc(YACA_DIGEST_SHA256,
			       lorem1024,
			       1024, &digest, &digest_len);
	if (ret < 0)
		return;

	dump_hex(digest, digest_len, "Message digest: ");

	yaca_free(digest);
}

void digest_advanced(void)
{
	int ret = 0;
	yaca_ctx_h ctx;

	ret = yaca_digest_init(&ctx, YACA_DIGEST_SHA256);
	if (ret < 0)
		return;

	ret = yaca_digest_update(ctx, lorem1024, 1024);
	if (ret < 0)
		goto exit_ctx;

	// TODO: rename to yaca_digest_get_length??
	size_t digest_len;
	digest_len = yaca_get_digest_length(ctx);
	if (digest_len <= 0)
		goto exit_ctx;

	{
		char digest[digest_len];

		ret = yaca_digest_final(ctx, digest, &digest_len);
		if (ret < 0)
			goto exit_ctx;

		dump_hex(digest, digest_len, "Message digest: ");
	}

exit_ctx:
	yaca_ctx_free(ctx);
}

int main()
{
	int ret = yaca_init();
	if (ret < 0)
		return ret;

	digest_simple();

	digest_advanced();

	yaca_exit(); // TODO: what about handing of return value from exit??
	return ret;
}
