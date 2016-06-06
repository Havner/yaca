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
 * @file lorem.h
 * @brief
 */

#ifndef LOREM_H
#define LOREM_H

#include <stddef.h>

/**
 * Test strings, sizes include null-termination
 */
extern const char lorem8[];
extern const char lorem16[];
extern const char lorem1024[];
extern const char lorem4096[];

/**
 * Sizes of test strings
 */
#define LOREM8_SIZE ((size_t)8)
#define LOREM16_SIZE ((size_t)16)
#define LOREM1024_SIZE ((size_t)1024)
#define LOREM4096_SIZE ((size_t)4096)

#endif
