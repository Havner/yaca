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
 * @file debug.c
 * @brief
 */

#include <stdbool.h>
#include <string.h>

#include <openssl/err.h>

#include <yaca_error.h>

#include "internal.h"
#include "debug.h"

// TODO any better idea than to use __thread?
static __thread yaca_error_cb error_cb = NULL;
static bool error_strings_loaded = false;

API void yaca_debug_set_error_cb(yaca_error_cb fn)
{
	error_cb = fn;
}

char *error_translate(yaca_error_e err)
{
	switch (err) {
	case YACA_ERROR_NONE:
		return "YACA_ERROR_NONE";
	case YACA_ERROR_INVALID_ARGUMENT:
		return "YACA_ERROR_INVALID_ARGUMENT";
	case YACA_ERROR_OUT_OF_MEMORY:
		return "YACA_ERROR_OUT_OF_MEMORY";
	case YACA_ERROR_INTERNAL:
		return "YACA_ERROR_INTERNAL";
	case YACA_ERROR_DATA_MISMATCH:
		return "YACA_ERROR_DATA_MISMATCH";
	case YACA_ERROR_PASSWORD_INVALID:
		return "YACA_ERROR_PASSWORD_INVALID";
	default:
		return NULL;
	}
}

// TODO use peeking function to intercept common errors
//unsigned long ERR_peek_error();

void error_dump(const char *file, int line, const char *function, int code)
{
	if (error_cb == NULL) {
		ERR_clear_error();
		return;
	}

	static const size_t BUF_SIZE = 512;
	static const char ELLIPSIS[] = "...\n";
	static const size_t ELLIPSIS_SIZE = sizeof(ELLIPSIS) / sizeof(ELLIPSIS[0]);
	char buf[BUF_SIZE];
	unsigned long err;
	size_t written;
	const char *err_str = error_translate(code);

	written = snprintf(buf, BUF_SIZE, "%s:%d %s() API error: ", file, line, function);
	if (err_str != NULL)
		written += snprintf(buf + written, BUF_SIZE - written, "%s\n", err_str);
	else
		written += snprintf(buf + written, BUF_SIZE - written, "0x%X\n", code);

	while ((err = ERR_get_error()) != 0 && written < BUF_SIZE - 1) {
		if (!error_strings_loaded) {
			/*
			 * This function is thread-safe as long as static locks are
			 * installed according to doc so calling it twice won't break
			 * anything and I don't want to use synchronization mechanisms
			 * here.
			 */
			ERR_load_crypto_strings();
			error_strings_loaded = true;
		}

		ERR_error_string_n(err, buf + written, BUF_SIZE - written);
		written = strlen(buf); /* I trust you, openssl */
		if (written < BUF_SIZE - 1) {
			buf[written] = '\n';
			written++;
		}
	}

	if (written >= BUF_SIZE - 1) {
		strncpy(buf + BUF_SIZE - ELLIPSIS_SIZE, ELLIPSIS, ELLIPSIS_SIZE);
		written = BUF_SIZE - 1;
		ERR_clear_error();
	}
	buf[written] = '\0';

	(*error_cb)(buf);
}

