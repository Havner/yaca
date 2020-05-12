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
 * @file crypto.c
 * @brief
 */

#define _GNU_SOURCE
#include <assert.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/random.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <yaca_crypto.h>
#include <yaca_error.h>

#include "internal.h"

static __thread bool current_thread_initialized = false;
static size_t threads_cnt = 0;
static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
static const RAND_METHOD *saved_rand_method = NULL;
#ifndef SYS_getrandom
static int urandom_fd = -2;
#endif  /* SYS_getrandom */

static int getrandom_wrapper(unsigned char *buf, int num)
{
	size_t received = 0;
	size_t remaining = num;

#ifndef SYS_getrandom
	assert(urandom_fd != -2);
#endif /* SYS_getrandom */

	while (remaining > 0) {
#ifdef SYS_getrandom
		ssize_t n = TEMP_FAILURE_RETRY(syscall(SYS_getrandom, buf + received, remaining, 0));
#else /* SYS_getrandom */
		ssize_t n = TEMP_FAILURE_RETRY(read(urandom_fd, buf + received, remaining));
#endif /* SYS_getrandom */

		if (n == -1)
			return 0;

		received += n;
		remaining -= n;
	}

	return 1;
}

static int RAND_METHOD_bytes(unsigned char *buf, int num)
{
	return getrandom_wrapper(buf, num);
}

static int RAND_METHOD_status(void)
{
#ifdef SYS_getrandom
	char tmp;
	int n = syscall(SYS_getrandom, &tmp, 1, GRND_NONBLOCK);
	if (n == -1 && errno == EAGAIN)
		return 0;
#endif /* SYS_getrandom */

	return 1;
}

static const RAND_METHOD new_rand_method = {
	NULL,
	RAND_METHOD_bytes,
	NULL,
	NULL,
	NULL,
	RAND_METHOD_status,
};

API int yaca_initialize(void)
{
	int ret = YACA_ERROR_NONE;

	/* no calling yaca_initialize() twice on the same thread */
	if (current_thread_initialized)
		return YACA_ERROR_INTERNAL;

	pthread_mutex_lock(&init_mutex);
	{
		if (threads_cnt == 0) {

#ifndef SYS_getrandom
			if (urandom_fd == -2) {
				int fd;

				do {
					fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
				} while (fd == -1 && errno == EINTR);

				if (fd < 0) {
					ret = YACA_ERROR_INTERNAL;
					goto exit;
				}

				urandom_fd = fd;
			}
#endif /* SYS_getrandom */

			OPENSSL_init();

			/* Use getrandom from urandom pool by default.
			 * As per the following:
			 * http://www.2uo.de/myths-about-urandom/
			 * http://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/
			 *
			 * OpenSSL's PRNG has issues:
			 * https://eprint.iacr.org/2016/367.pdf

			 * Some other things to check/consider for the future:
			 * - entropy on a mobile device (no mouse/keyboard)
			 * - hardware random generator (RdRand on new Intels, Samsung hardware?)
			 */
			saved_rand_method = RAND_get_rand_method();
			RAND_set_rand_method(&new_rand_method);

			OpenSSL_add_all_digests();
			OpenSSL_add_all_ciphers();

			/*
			 * TODO:
			 * - We should also decide on OpenSSL config.
			 * - Here's a good tutorial for initialization and cleanup:
			 *   https://wiki.openssl.org/index.php/Library_Initialization
			 */
		}
		threads_cnt++;
		current_thread_initialized = true;
	}

#if !defined SYS_getrandom
exit:
#endif /* !defined SYS_getrandom */

	pthread_mutex_unlock(&init_mutex);

	return ret;
}

API void yaca_cleanup(void)
{
	/* calling cleanup twice on the same thread is a NOP */
	if (!current_thread_initialized)
		return;

	/* per thread cleanup */
	CRYPTO_cleanup_all_ex_data();

	pthread_mutex_lock(&init_mutex);
	{
		/* last one turns off the light */
		if (threads_cnt == 1) {
			ERR_free_strings();
			EVP_cleanup();
			RAND_cleanup();
			RAND_set_rand_method(saved_rand_method);

#ifndef SYS_getrandom
			close(urandom_fd);
			urandom_fd = -2;
#endif /* SYS_getrandom */

		}

		assert(threads_cnt > 0);

		threads_cnt--;
		current_thread_initialized = false;
	}
	pthread_mutex_unlock(&init_mutex);
}

API int yaca_malloc(size_t size, void **memory)
{
	if (size == 0 || memory == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	*memory = OPENSSL_malloc(size);
	if (*memory == NULL) {
		const int ret = YACA_ERROR_OUT_OF_MEMORY;
		ERROR_DUMP(ret);
		return ret;
	}

	return YACA_ERROR_NONE;
}

API int yaca_zalloc(size_t size, void **memory)
{
	int ret = yaca_malloc(size, memory);
	if (ret != YACA_ERROR_NONE)
		return ret;

	memset(*memory, 0, size);

	return YACA_ERROR_NONE;
}

API int yaca_realloc(size_t size, void **memory)
{
	if (size == 0 || memory == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	void *tmp = OPENSSL_realloc(*memory, size);
	if (tmp == NULL) {
		const int ret = YACA_ERROR_OUT_OF_MEMORY;
		ERROR_DUMP(ret);
		return ret;
	}

	*memory = tmp;

	return YACA_ERROR_NONE;
}

API void yaca_free(void *memory)
{
	OPENSSL_free(memory);
}

API int yaca_randomize_bytes(char *data, size_t data_len)
{
	int ret;

	if (data == NULL || data_len == 0)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = RAND_bytes((unsigned char *)data, data_len);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return YACA_ERROR_NONE;
}

API int yaca_context_set_property(yaca_context_h ctx, yaca_property_e property,
                                  const void *value, size_t value_len)
{
	if (ctx == YACA_CONTEXT_NULL || ctx->set_property == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	return ctx->set_property(ctx, property, value, value_len);
}

API int yaca_context_get_property(const yaca_context_h ctx, yaca_property_e property,
                                  void **value, size_t *value_len)
{
	if (ctx == YACA_CONTEXT_NULL || ctx->get_property == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	return ctx->get_property(ctx, property, value, value_len);
}

API void yaca_context_destroy(yaca_context_h ctx)
{
	if (ctx != YACA_CONTEXT_NULL) {
		assert(ctx->context_destroy != NULL);
		ctx->context_destroy(ctx);
		yaca_free(ctx);
	}
}

API int yaca_context_get_output_length(const yaca_context_h ctx,
                                       size_t input_len, size_t *output_len)
{
	if (ctx == YACA_CONTEXT_NULL || output_len == NULL ||
	    ctx->get_output_length == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	return ctx->get_output_length(ctx, input_len, output_len);
}

API int yaca_memcmp(const void *first, const void *second, size_t len)
{
	if (len > 0 && (first == NULL || second == NULL))
		return YACA_ERROR_INVALID_PARAMETER;

	if (CRYPTO_memcmp(first, second, len) == 0)
		return YACA_ERROR_NONE;

	return YACA_ERROR_DATA_MISMATCH;
}
