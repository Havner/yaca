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
 * @file key_import_export_sym.c
 * @brief Symmetric key import/export API example.
 */

//! [Symmetric key import/export API example]
#include <stdio.h>

#include <yaca_crypto.h>
#include <yaca_key.h>
#include <yaca_error.h>

/* include helpers functions and definitions */
#include "misc.h"

int main()
{
	int ret;
	yaca_key_h sym_key = YACA_KEY_NULL;
	yaca_key_h raw_imported = YACA_KEY_NULL;
	yaca_key_h b64_imported = YACA_KEY_NULL;

	char *raw = NULL;
	size_t raw_len;
	char *b64 = NULL;
	size_t b64_len;

	ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &sym_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* BASE64 */
	ret = yaca_key_export(sym_key, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_BASE64, NULL,
	                      &b64, &b64_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_import(YACA_KEY_TYPE_SYMMETRIC, NULL, b64, b64_len, &b64_imported);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	printf("\t***** BASE64 exported key: *****\n%.*s\n", (int)b64_len, b64);
	yaca_free(b64);
	b64 = NULL;

	ret = yaca_key_export(b64_imported, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_BASE64, NULL,
	                      &b64, &b64_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	printf("\t***** BASE64 imported key: *****\n%.*s\n", (int)b64_len, b64);

	/* RAW */
	ret = yaca_key_export(sym_key, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_RAW, NULL,
	                      &raw, &raw_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_import(YACA_KEY_TYPE_SYMMETRIC, NULL, raw, raw_len, &raw_imported);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* display key in hexadecimal format */
	dump_hex(raw, raw_len, "\n\t***** RAW exported key: *****");
	yaca_free(raw);
	raw = NULL;

	ret = yaca_key_export(raw_imported, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_RAW, NULL,
	                      &raw, &raw_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* display key in hexadecimal format */
	dump_hex(raw, raw_len, "\t***** RAW imported key: *****");

exit:
	yaca_key_destroy(sym_key);
	yaca_key_destroy(raw_imported);
	yaca_key_destroy(b64_imported);
	yaca_free(raw);
	yaca_free(b64);

	yaca_cleanup();
	return ret;
}
//! [Symmetric key import/export API example]
