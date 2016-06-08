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
#include <openssl/pem.h>

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
	case YACA_ERROR_INVALID_PARAMETER:
		return "YACA_ERROR_INVALID_PARAMETER";
	case YACA_ERROR_OUT_OF_MEMORY:
		return "YACA_ERROR_OUT_OF_MEMORY";
	case YACA_ERROR_INTERNAL:
		return "YACA_ERROR_INTERNAL";
	case YACA_ERROR_DATA_MISMATCH:
		return "YACA_ERROR_DATA_MISMATCH";
	case YACA_ERROR_INVALID_PASSWORD:
		return "YACA_ERROR_INVALID_PASSWORD";
	default:
		return NULL;
	}
}

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

int error_handle(const char *file, int line, const char *function)
{
	int ret = YACA_ERROR_NONE;
	unsigned long err = ERR_peek_error();

	if (err == 0)
		return YACA_ERROR_INTERNAL;

	/* known errors */
	switch (err) {
	case ERR_PACK(ERR_LIB_RSA, RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_KEYBITS):
	case ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_COMMAND_NOT_SUPPORTED):
		ret = YACA_ERROR_INVALID_PARAMETER;
		break;
	case ERR_PACK(ERR_LIB_PEM, PEM_F_PEM_DO_HEADER, PEM_R_BAD_DECRYPT):
	case ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_BAD_DECRYPT):
		ret = YACA_ERROR_INVALID_PASSWORD;
		break;
	}

	/* fatal errors */
	if (ret == YACA_ERROR_NONE && ERR_FATAL_ERROR(err) > 0) {
		switch (ERR_GET_REASON(err)) {
		case ERR_R_MALLOC_FAILURE:
			ret = YACA_ERROR_OUT_OF_MEMORY;
			break;
		case ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED:
		case ERR_R_PASSED_NULL_PARAMETER:
			ret = YACA_ERROR_INVALID_PARAMETER;
			break;
		case ERR_R_INTERNAL_ERROR:
		case ERR_R_DISABLED:
			ret = YACA_ERROR_INTERNAL;
			break;
		}
	}

	/* neither known nor fatal, unknown */
	if (ret == YACA_ERROR_NONE) {
		error_dump(file, line, function, YACA_ERROR_INTERNAL);
		ret = YACA_ERROR_INTERNAL;
	}

	/* remove all errors from queue */
	ERR_clear_error();
	return ret;
}
