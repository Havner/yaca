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
 * @file misc.c
 * @brief
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <yaca/crypto.h>

#include <openssl/bio.h>
#include "misc.h"

void dump_hex(const char *buf, size_t dump_size, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
	BIO_dump_fp(stdout, buf, dump_size);
}

void debug_func(const char* buf)
{
	puts(buf);
}

int write_file(const char *path, char *data, size_t data_len)
{
	size_t written = 0;
	FILE *f;

	f = fopen(path, "w");
	if (f == NULL)
		return -1;

	while (written != data_len) {
		int ret = fwrite(data + written, 1, data_len - written, f);

		if (ferror(f) != 0) {
			fclose(f);
			return -1;
		}

		written += ret;
	}

	fclose(f);
	return 0;
}

#define BUF_SIZE 512

int read_file(const char *path, char **data, size_t *data_len)
{
	int ret;
	char tmp[BUF_SIZE];
	char *buf = NULL;
	size_t buf_len = 0;
	FILE *f;

	f = fopen(path, "r");
	if (f == NULL)
		return -1;

	for(;;) {
		size_t read = fread(tmp, 1, BUF_SIZE, f);

		if (read > 0) {
			if (buf == NULL) {
				buf = yaca_malloc(read);
				if (buf == NULL) {
					ret = -1;
					break;
				}
			} else {
				char *new_buf = yaca_realloc(buf, buf_len + read);
				if (new_buf == NULL) {
					ret = -1;
					break;
				}
				buf = new_buf;
			}

			memcpy(buf + buf_len, tmp, read);
			buf_len += read;
		}

		if (ferror(f) != 0) {
			ret = -1;
			break;
		}

		if (feof(f)) {
			*data = buf;
			*data_len = buf_len;
			buf = NULL;
			ret = 0;
			break;
		}
	}

	fclose(f);
	free(buf);
	return ret;
}
