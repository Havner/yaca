/*
 *  Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
/*
 * @file       error.c
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/err.h>

#include <yaca/error.h>
#include "internal.h"

// TODO any better idea than to use __thread?
static __thread yaca_debug_func debug_fn = NULL;
static bool error_strings_loaded = false;

API void yaca_error_set_debug_func(yaca_debug_func fn)
{
	debug_fn = fn;
}

// TODO use peeking function to intercept common errors
//unsigned long ERR_peek_error();

void error_dump(const char *file, int line, const char *function, int code)
{
	if (debug_fn == NULL)
		return;

	static const size_t BUF_SIZE = 512;
	static const char ELLIPSIS[] = "...\n";
	static const size_t ELLIPSIS_SIZE = sizeof(ELLIPSIS) / sizeof(ELLIPSIS[0]);
	char buf[BUF_SIZE];
	unsigned long err;
	size_t written;

	written = snprintf(buf, BUF_SIZE, "%s:%d %s() API error: %d\n", file, line, function, code);

	while ((err = ERR_get_error()) != 0 && written < BUF_SIZE - 1) {
		if (!error_strings_loaded) {
			/*
			 * Both these functions are thread-safe as long as static locks are
			 * installed according to doc so calling them twice won't break
			 * anything and I don't want to use synchronization mechanisms
			 * here.
			 */
			ERR_load_crypto_strings();
			ERR_clear_error();
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

	(*debug_fn)(buf);
}
