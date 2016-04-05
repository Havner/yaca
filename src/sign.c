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

#include <owl/crypto.h>
#include <owl/error.h>

API int owl_sign_init(owl_ctx_h *ctx,
		      owl_digest_algo_e algo,
		      const owl_key_h key)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

API int owl_sign_update(owl_ctx_h ctx,
			const char *data,
			size_t data_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

API int owl_sign_final(owl_ctx_h ctx,
		       char *mac,
		       size_t *mac_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

API int owl_verify_init(owl_ctx_h *ctx,
			owl_digest_algo_e algo,
			const owl_key_h key)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

API int owl_verify_update(owl_ctx_h ctx,
			  const char *data,
			  size_t data_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}

API int owl_verify_final(owl_ctx_h ctx,
			 const char *mac,
			 size_t mac_len)
{
	return OWL_ERROR_NOT_IMPLEMENTED;
}
