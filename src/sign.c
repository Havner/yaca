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

#include "config.h"

#include <assert.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <yaca/crypto.h>
#include <yaca/error.h>

API int yaca_sign_init(yaca_ctx_h *ctx,
		       yaca_digest_algo_e algo,
		       const yaca_key_h key)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_sign_update(yaca_ctx_h ctx,
			 const char *data,
			 size_t data_len)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_sign_final(yaca_ctx_h ctx,
			char *mac,
			size_t *mac_len)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_verify_init(yaca_ctx_h *ctx,
			 yaca_digest_algo_e algo,
			 const yaca_key_h key)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_verify_update(yaca_ctx_h ctx,
			   const char *data,
			   size_t data_len)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}

API int yaca_verify_final(yaca_ctx_h ctx,
			  const char *mac,
			  size_t mac_len)
{
	return YACA_ERROR_NOT_IMPLEMENTED;
}
