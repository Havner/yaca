/*
 * Copyright 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <memory>


namespace keymaster {

template <typename T, typename FreeFuncRet, FreeFuncRet (*FreeFunc)(T*)>
struct OpenSslObjectDeleter {
	void operator()(T* p) { FreeFunc(p); }
};

#define DEFINE_OPENSSL_OBJECT_POINTER(name)	  \
	typedef OpenSslObjectDeleter<name, decltype(name##_free(nullptr)), name##_free> name##_Delete; \
	typedef std::unique_ptr<name, name##_Delete> name##_Ptr;

DEFINE_OPENSSL_OBJECT_POINTER(ASN1_BIT_STRING)
DEFINE_OPENSSL_OBJECT_POINTER(ASN1_INTEGER)
DEFINE_OPENSSL_OBJECT_POINTER(ASN1_OBJECT)
DEFINE_OPENSSL_OBJECT_POINTER(ASN1_OCTET_STRING)
DEFINE_OPENSSL_OBJECT_POINTER(ASN1_TIME)
DEFINE_OPENSSL_OBJECT_POINTER(BN_CTX)
DEFINE_OPENSSL_OBJECT_POINTER(EC_GROUP)
DEFINE_OPENSSL_OBJECT_POINTER(EC_KEY)
DEFINE_OPENSSL_OBJECT_POINTER(EC_POINT)
DEFINE_OPENSSL_OBJECT_POINTER(ENGINE)
DEFINE_OPENSSL_OBJECT_POINTER(EVP_PKEY)
DEFINE_OPENSSL_OBJECT_POINTER(EVP_PKEY_CTX)
DEFINE_OPENSSL_OBJECT_POINTER(PKCS8_PRIV_KEY_INFO)
DEFINE_OPENSSL_OBJECT_POINTER(RSA)
DEFINE_OPENSSL_OBJECT_POINTER(X509)
DEFINE_OPENSSL_OBJECT_POINTER(X509_EXTENSION)
DEFINE_OPENSSL_OBJECT_POINTER(X509_NAME)

typedef OpenSslObjectDeleter<BIGNUM, void, BN_free> BIGNUM_Delete;
typedef std::unique_ptr<BIGNUM, BIGNUM_Delete> BIGNUM_Ptr;

}  // namespace keymaster
