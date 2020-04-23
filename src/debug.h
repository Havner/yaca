/*
 *  Copyright (c) 2016-2020 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file debug.h
 * @brief
 */

#ifndef YACA_DEBUG_H
#define YACA_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif


typedef void (*yaca_error_cb)(const char*);

void yaca_debug_set_error_cb(yaca_error_cb cb);


#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_DEBUG_H */
