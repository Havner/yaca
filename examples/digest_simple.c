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
 * @file digest_simple.c
 * @brief Simple Message Digest API example.
 */

//! [Simple Message Digest API example]
#include <stdio.h>

#include <yaca_crypto.h>
#include <yaca_simple.h>
#include <yaca_error.h>

/* include helpers functions and definitions */
#include "misc.h"

int main()
{
	int ret;
	char *digest = NULL;
	size_t digest_len;

	ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		goto exit;

	printf("Plain data (16 of %zu bytes): %.16s\n", INPUT_DATA_SIZE, INPUT_DATA);

	/* Calculate digest */
	ret = yaca_simple_calculate_digest(YACA_DIGEST_SHA256, INPUT_DATA, INPUT_DATA_SIZE,
	                                   &digest, &digest_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* display digest in hexadecimal format */
	dump_hex(digest, digest_len, "Message digest: ");

exit:
	yaca_free(digest);

	yaca_cleanup();
	return ret;
}
//! [Simple Message Digest API example]
