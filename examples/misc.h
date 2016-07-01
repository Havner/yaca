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
 * @file misc.h
 * @brief
 */

#ifndef MISC_H
#define MISC_H

#include <stddef.h>

void dump_hex(const char *buf, size_t dump_size, const char *fmt, ...);

void debug_func(const char *buf);

int write_file(const char *path, const char *data, size_t data_len);

int read_file(const char *path, char **data, size_t *data_len);

int read_stdin_line(const char *prompt, char **string);

#endif /* MISC_H */
