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
 * @file simple.h
 * @brief
 */

#ifndef SIMPLE_H
#define SIMPLE_H

#include <stddef.h>
#include <crypto/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup  Simple-API  Simple API.
 *
 *  This is simple API.
 *  Design constraints:
 *  - All operations are single-shot (no streaming possible)
 *  - Context is not used
 *  - For now only digest and symmetric ciphers are supported
 *  - GCM chaining is not supported
 *  - All outputs are allocated by the library
 *
 * TODO: extended description and examples.
 *
 * @{
 */

/**
 * @brief crypto_digest_calc  Calculate a digest of a buffer.
 *
 * @param[in]  algo        Digest algorithm (select @see CRYPTO_DIGEST_SHA256 if unsure).
 * @param[in]  data        Data from which the digest is to be calculated.
 * @param[in]  data_len    Length of the data.
 * @param[out] digest      Message digest, will be allocated by the library (should be freed with @see crypto_free).
 * @param[out] digest_len  Length of message digest (depends on algorithm).
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int crypto_digest_calc(crypto_digest_algo_e algo,
		       const char *data,
		       size_t data_len,
		       char **digest,
		       size_t *digest_len);

/**
 * @brief crypto_encrypt  Encrypt data using a symmetric cipher.
 *
 * @param[in]  algo        Encryption algorithm (select @see CRYPTO_ENC_AES if unsure).
 * @param[in]  bcm         Chaining mode (select @see CRYPTO_BCM_CBC if unsure).
 * @param[in]  sym_key     Symmetric encryption key (@see key.h for key generation functions).
 * @param[in]  iv          Initialization vector.
 * @param[in]  plain       Plain text to be encrypted.
 * @param[in]  plain_len   Length of the plain text.
 * @param[out] cipher      Encrypted data, will be allocated by the library (should be freed with @see crypto_free).
 * @param[out] cipher_len  Length of the encrypted data (may be larger than decrypted).
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int crypto_encrypt(crypto_enc_algo_e algo,
		   crypto_block_cipher_mode_e bcm,
		   const crypto_key_h sym_key,
		   const crypto_key_h iv,
		   const char *plain,
		   size_t plain_len,
		   char **cipher,
		   size_t *cipher_len);

/**
 * @brief crypto_decrypt  Decrypta data using a symmetric cipher.
 *
 * @param[in] algo        Decryption algorithm that was used to encrypt the data.
 * @param[in] bcm         Chaining mode that was used to encrypt the data.
 * @param[in] sym_key     Symmetric encryption key that was used to encrypt the data.
 * @param[in] iv          Initialization vector that was used to encrypt the data.
 * @param[in] cipher      Cipher text to be decrypted.
 * @param[in] cipher_len  Length of cipher text.
 * @param[out] plain       Decrypted data, will be allocated by the library (should be freed with @see crypto_free).
 * @param[out] plain_len   Length of the decrypted data.
 *
 * @return 0 on success, negative on error (@see error.h).
 */
int crypto_decrypt(crypto_enc_algo_e algo,
		   crypto_block_cipher_mode_e bcm,
		   const crypto_key_h sym_key,
		   const crypto_key_h iv,
		   const char *cipher,
		   size_t cipher_len,
		   char **plain,
		   size_t * plain_len);

// TODO: sign/verify

/**@}*/
#ifdef __cplusplus
} /* extern */
#endif

#endif /* SIMPLE_H */
