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
#define _GNU_SOURCE

#include <openssl/bio.h>

#include <yaca_crypto.h>
#include <yaca_error.h>

#include "misc.h"

void dump_hex(const char *buf, size_t dump_len, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
	BIO_dump_fp(stdout, buf, dump_len);
}

int read_stdin_line(const char *prompt, char **string)
{
	char *buf = NULL;
	size_t size;
	ssize_t read;

	if (prompt != NULL)
		printf("%s", prompt);

	read = getline(&buf, &size, stdin);
	if (read <= 0) {
		free(buf);
		return YACA_ERROR_INVALID_PARAMETER;
	}

	int ret = yaca_realloc(read, (void**)&buf);
	if (ret != YACA_ERROR_NONE) {
		yaca_free(buf);
		return ret;
	}
	buf[read - 1] = '\0';

	*string = buf;
	return YACA_ERROR_NONE;
}

const char INPUT_DATA[INPUT_DATA_SIZE] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus congue semper ipsum, ac convallis magna rhoncus sit amet. Donec pellentesque maximus convallis. Mauris ut egestas sem. Maecenas efficitur suscipit auctor. Nunc malesuada laoreet porttitor. Donec gravida tortor nisi, in mattis lectus porta ut. Integer vehicula eros et tellus placerat, nec fermentum justo aliquet.\
Maecenas metus massa, ultrices et ultricies sed, imperdiet nec dolor. Nam eget massa eros. Proin vitae laoreet metus, at scelerisque massa. Nullam convallis dolor id nisl iaculis, a gravida risus pretium. Proin non nunc eget nibh fermentum dignissim. Nullam tristique, odio eget rutrum sagittis, tortor purus cursus nunc, nec iaculis quam nunc ac metus. Cras ut tortor a eros porta vehicula non at lectus. Aliquam volutpat quis nisi ut mattis. Curabitur semper vehicula ultrices. Aenean cursus laoreet venenatis. Aenean vulputate, nisl id facilisis fringilla, neque velit posuere libero, et viverra tortor felis vitae urna. Sed in congue nunc. Fusce molestie tempor pharetra. Cras sodales pulvinar nunc non sollicitudin.\
Maecenas vehicula metus ac tristique ultricies. Suspendisse potenti. Pellentesque suscipit egestas augue, sed dictum orci. Pellentesque eu lorem ultricies, vestibulum est in, bibendum turpis. Proin placerat tincidunt metus, eget volutpat dolor. Pellentesque varius leo eget velit lobortis, sit amet congue orci bibendum. Aliquam vitae posuere lorem. Donec sed convallis diam. Quisque aliquam interdum purus, eu ornare ex ullamcorper iaculis. In sit amet nisl eu nisl ultricies dapibus. Aenean finibus efficitur elit ut sodales. Nam sit amet auctor sem, eu iaculis nunc. Vivamus mattis arcu a viverra faucibus. In dignissim, nisi sit amet consectetur tempus, lorem dui fringilla augue, sit amet lacinia lectus sapien efficitur odio.\
Nullam et egestas enim. Nam sit amet mi malesuada, dapibus felis quis, viverra mauris. Ut quis enim eu neque porta vehicula. Etiam ullamcorper vitae turpis vehicula blandit. Maecenas blandit tristique semper. Aliquam at sagittis enim. Donec quis molestie urna. Duis ut urna blandit, pellentesque magna ultrices, dignissim mi. Morbi fermentum ex massa, ut facilisis est tincidunt vel. Nam sed erat in lacus molestie mattis quis ut leo. Phasellus tempus elit urna, eget sagittis purus volutpat sed. Suspendisse aliquam, sem vel gravida lobortis, tortor orci ornare nisi, sed mollis ligula sem nec risus. In a ex nibh. Praesent odio est, molestie sed vestibulum id, varius sit amet lectus. Donec vel diam efficitur, tristique ligula a, aliquet felis. Nullam sit amet neque tellus.\
Phasellus aliquet non libero non aliquet. Aliquam efficitur ultrices tortor vitae lobortis. Pellentesque sed dolor quis nisl faucibus eleifend vitae ultrices est. Integer et libero quis nisl sollicitudin volutpat sit amet a quam. Vivamus commodo dolor augue, volutpat dapibus odio dapibus et. Nulla sed congue nisl. Duis nunc sem, condimentum nec neque ac, blandit blandit quam. Integer tincidunt ipsum nec risus viverra mollis. In porta porttitor mattis. Nulla ac eleifend nibh. Vivamus suscipit at nunc ac interdum. In fermentum fringilla odio.\
Sed nec erat eget mauris varius pulvinar. Ut fermentum ante non erat elementum, vitae tempor velit blandit. Curabitur turpis tellus, sodales sit amet mattis nec, volutpat ac magna. Nulla quam orci, rutrum sit amet imperdiet ut, iaculis in nisl. Donec semper vitae tellus nec bibendum. Nam pharetra hendrerit sapien quis rutrum. Morbi tincidunt justo ut sodales ullamcorper. Suspendisse eget pellentesque nulla, non placerat purus. Donec placerat id turpis in interdum. Curabitur lobortis risus et placerat commodo. Morbi pulvinar eros leo, scelerisque rutrum arcu pretium at. Quisque eget diam dui. Quisque bibendum luctus arcu quis semper. Nullam erat lacus, lacinia sit amet neque aliquam, lacinia maximus lorem.\
Nunc ac purus vel sem laoreet interdum quis eget ligula. Aenean id nisl ut quam vehicula pretium sed sit amet urna. Aenean diam lorem, vehicula et sapien nec, pellentesque consectetur libero. Cras fringilla nibh eu libero nullam.";

