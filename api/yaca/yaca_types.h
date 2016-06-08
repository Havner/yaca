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
 * @file yaca_types.h
 * @brief
 */

#ifndef YACA_TYPES_H
#define YACA_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup Crypto-Types Yet Another Crypto API - types.
 *
 * TODO: extended description.
 *
 * @{
 */

/**
 * @brief Context.
 *
 * @since_tizen 3.0
 */
typedef struct yaca_context_s *yaca_context_h;

/**
 * @brief Key.
 *
 * @since_tizen 3.0
 */
typedef struct yaca_key_s *yaca_key_h;

/**
 * @brief Enumeration of YACA key formats.
 *
 * @since_tizen 3.0
 */
typedef enum {
	/** Key is either PKCS#1 for RSA or SSLeay for DSA, also use this option for symmetric */
	YACA_KEY_FORMAT_DEFAULT,
	/** Key is in PKCS#8, can only be used for asymmetric private keys */
	YACA_KEY_FORMAT_PKCS8
} yaca_key_format_e;

/**
 * @brief Enumeration of YACA key file formats.
 *
 * @since_tizen 3.0
 */
typedef enum {
	/** Key file is in raw binary format, used for symmetric keys */
	YACA_KEY_FILE_FORMAT_RAW,
	/** Key file is encoded in ASCII-base64, used for symmetric keys */
	YACA_KEY_FILE_FORMAT_BASE64,
	/** Key file is in PEM file format, used for asymmetric keys */
	YACA_KEY_FILE_FORMAT_PEM,
	/** Key file is in DER file format, used for asymmetric keys */
	YACA_KEY_FILE_FORMAT_DER
} yaca_key_file_format_e;

/**
 * @brief Enumeration of YACA key types, IV is considered as key.
 *
 * @since_tizen 3.0
 */
typedef enum {
	/** Generic symmetric cipher KEY */
	YACA_KEY_TYPE_SYMMETRIC,
	/** DES* key - must be handled differently because of parity bits */
	YACA_KEY_TYPE_DES,
	/** Initialization Vector for symmetric algorithms */
	YACA_KEY_TYPE_IV,

	/** RSA public key */
	YACA_KEY_TYPE_RSA_PUB,
	/** RSA private key */
	YACA_KEY_TYPE_RSA_PRIV,

	/** Digital Signature Algorithm public key */
	YACA_KEY_TYPE_DSA_PUB,
	/** Digital Signature Algorithm private key */
	YACA_KEY_TYPE_DSA_PRIV,
} yaca_key_type_e;

/**
 * @brief Enumeration of YACA key lengths.
 *        It is possible to use arbitrary integer instead,
 *        this enum values are placed here to avoid magic numbers.
 *
 * @since_tizen 3.0
 */
typedef enum {
	YACA_KEY_LENGTH_IV_UNSAFE_24BIT = 24,
	YACA_KEY_LENGTH_IV_64BIT = 64,
	YACA_KEY_LENGTH_IV_128BIT = 128,
	YACA_KEY_LENGTH_IV_256BIT = 256,
	YACA_KEY_LENGTH_UNSAFE_8BIT = 8,
	YACA_KEY_LENGTH_UNSAFE_40BIT = 40,
	YACA_KEY_LENGTH_UNSAFE_64BIT = 64,
	YACA_KEY_LENGTH_UNSAFE_80BIT = 80,
	YACA_KEY_LENGTH_UNSAFE_128BIT = 128,
	YACA_KEY_LENGTH_192BIT = 192,
	YACA_KEY_LENGTH_256BIT = 256,
	YACA_KEY_LENGTH_512BIT = 512,
	YACA_KEY_LENGTH_1024BIT = 1024,
	YACA_KEY_LENGTH_2048BIT = 2048,
	YACA_KEY_LENGTH_3072BIT = 3072,
	YACA_KEY_LENGTH_4096BIT = 4096
} yaca_key_bit_length_e;

/**
 * @brief Enumeration of YACA message digest algorithms.
 *
 * @since_tizen 3.0
 */
typedef enum {
	/** Message digest algorithm MD5 */
	YACA_DIGEST_MD5,
	/** Message digest algorithm SHA1 */
	YACA_DIGEST_SHA1,
	/** Message digest algorithm SHA2, 224bit */
	YACA_DIGEST_SHA224,
	/** Message digest algorithm SHA2, 256bit */
	YACA_DIGEST_SHA256,
	/** Message digest algorithm SHA2, 384bit */
	YACA_DIGEST_SHA384,
	/** Message digest algorithm SHA2, 512bit */
	YACA_DIGEST_SHA512,
} yaca_digest_algorithm_e;

/**
 * @brief Enumeration of YACA symmetric encryption algorithms.
 *
 * @since_tizen 3.0
 */
typedef enum {
	/**
	 * AES encryption.
	 * - Supported key lengths: @c 128, @c 192 and @c 256.
	 * - Supported block cipher modes:
	 * #YACA_BCM_CBC,
	 * #YACA_BCM_OFB,
	 * #YACA_BCM_CFB,
	 * #YACA_BCM_CFB1,
	 * #YACA_BCM_CFB8,
	 * #YACA_BCM_ECB,
	 * #YACA_BCM_GCM,
	 * #YACA_BCM_CCM,
	 * #YACA_BCM_CTR
	 * - see #yaca_block_cipher_mode_e for details on additional parameters (mandatory).
	 */
	YACA_ENCRYPT_AES = 0,

	/**
	 * DES encryption.
	 * - Supported key lengths: @c 64.
	 * - Supported block cipher modes:
	 * #YACA_BCM_CBC,
	 * #YACA_BCM_OFB,
	 * #YACA_BCM_CFB,
	 * #YACA_BCM_CFB1,
	 * #YACA_BCM_CFB8,
	 * #YACA_BCM_ECB
	 * - see #yaca_block_cipher_mode_e for details on additional parameters (mandatory).
	 */
	YACA_ENCRYPT_UNSAFE_DES,

	/**
	 * 3DES 2-key encryption.
	 * - Supported key lengths: @c 128.
	 * - Supported block cipher modes:
	 * #YACA_BCM_CBC,
	 * #YACA_BCM_OFB,
	 * #YACA_BCM_CFB,
	 * #YACA_BCM_ECB
	 * - see #yaca_block_cipher_mode_e for details on additional parameters (mandatory).
	 * - Use double DES keys to perform corresponding 2-key 3DES encryption.

	 */
	YACA_ENCRYPT_UNSAFE_3DES_2TDEA,

	/**
	 * 3DES 3-key encryption.
	 * - Supported key lengths: @c 192.
	 * - Supported block cipher modes:
	 * #YACA_BCM_CBC,
	 * #YACA_BCM_OFB,
	 * #YACA_BCM_CFB,
	 * #YACA_BCM_CFB1,
	 * #YACA_BCM_CFB8,
	 * #YACA_BCM_ECB
	 * - see #yaca_block_cipher_mode_e for details on additional parameters (mandatory).
	 * - Use triple DES keys to perform corresponding 3-key 3DES encryption.
	 */
	YACA_ENCRYPT_3DES_3TDEA,

	/**
	 * RC2 encryption.
	 * This is a variable key length cipher.
	 * - Supported key lengths: 8-1024 bits in steps of 8 bits.
	 * - Effective key bits parameter by default equals to 128.
	 * - Supported block cipher modes:
	 * #YACA_BCM_CBC,
	 * #YACA_BCM_OFB,
	 * #YACA_BCM_CFB,
	 * #YACA_BCM_ECB
	 */
	YACA_ENCRYPT_UNSAFE_RC2,

	/**
	 * RC4 encryption.
	 * This is a variable key length cipher.
	 * - Supported key lengths: 40–2048 bits in steps of 8 bits.
	 * This cipher doesn't support block cipher modes, use #YACA_BCM_NONE instead.
	 */
	YACA_ENCRYPT_UNSAFE_RC4,

	/**
	 * CAST5 encryption.
	 * This is a variable key length cipher.
	 * Supported key lengths: 40-128 bits in steps of 8 bits.
	 * - Supported block cipher modes:
	 * #YACA_BCM_CBC,
	 * #YACA_BCM_OFB,
	 * #YACA_BCM_CFB,
	 * #YACA_BCM_ECB
	 * - see #yaca_block_cipher_mode_e for details on additional parameters (mandatory).
	 */
	YACA_ENCRYPT_CAST5,
} yaca_encrypt_algorithm_e;

/**
 * @brief Enumeration of YACA chaining modes for block ciphers.
 *
 * @since_tizen 3.0
 */
typedef enum {
	/**
	 * Used when algorithm doesn't support block ciphers modes.
	 */
	YACA_BCM_NONE,

	/**
	 * ECB block cipher mode.
	 * Encrypts 64 bit at a time. No IV is used.
	 */
	YACA_BCM_ECB,

	/**
	 * CTR block cipher mode.
	 * 16-byte initialization vector is mandatory.
	 */
	YACA_BCM_CTR,

	/**
	 * CBC block cipher mode.
	 * 16-byte initialization vector is mandatory.
	 */
	YACA_BCM_CBC,

	/**
	 * GCM block cipher mode.
	 * This is a variable IV length mode (recommended 96 bits IV).
	 *
	 * Supported parameters:
	 * - #YACA_PROPERTY_GCM_TAG_LEN = GCM tag length\n
	 *   Supported tag lengths: @c 32, @c 64, @c 96, @c 104, @c 112, @c 120, @c 128,
	 *   (recommended 128 bits tag).\n
	 *   Set after yaca_encrypt_finalize() and before yaca_context_get_property(#YACA_PROPERTY_GCM_TAG)
	 *   in encryption operation.\n\n
	 *
	 * - #YACA_PROPERTY_GCM_TAG = GCM tag\n
	 *   Get after yaca_encrypt_finalize() in encryption operation.\n
	 *   Set before yaca_decrypt_finalize() in decryption operation.\n\n
	 *
	 * - #YACA_PROPERTY_GCM_AAD = additional authentication data (optional)\n
	 *   Set after yaca_encrypt_initialize() and before yaca_encrypt_update()
	 *   in encryption operation.\n
	 *   Set after yaca_decrypt_initialize() and before yaca_decrypt_update()
	 *   in decryption operation.\n\n
	 *
	 *   @see examples/encrypt_aes_gcm_ccm.c
	 */
	YACA_BCM_GCM,

	/**
	 * Default CFB block cipher mode.
	 * 16-byte initialization vector is mandatory.
	 */
	YACA_BCM_CFB,

	/**
	 * 1 bit CFB block cipher mode.
	 * 16-byte initialization vector is mandatory.
	 */
	YACA_BCM_CFB1,

	/**
	 * 8 bits CFB block cipher mode.
	 * 16-byte initialization vector is mandatory.
	 */
	YACA_BCM_CFB8,

	/**
	 * OFB block cipher mode.
	 * 16-byte initialization vector is mandatory.
	 */
	YACA_BCM_OFB,

	/**
	 * CBC-MAC Mode (AES).
	 * This is a variable IV length mode.\n
	 * Supported IV lengths: 56-104 bits in steps of 8 bits (recommended 56 bits IV).\n\n
	 *
	 * Supported parameters:
	 * - #YACA_PROPERTY_CCM_TAG_LEN = CCM tag length\n
	 *   Supported tag lengths: 32-128 bits in step of 16 bits (recommended 96 bits tag).\n
	 *   Set after yaca_encrypt_initialize() and before yaca_encrypt_update()
	 *   in encryption operation.\n\n
	 *
	 * - #YACA_PROPERTY_CCM_TAG = CCM tag\n
	 *   Get after yaca_encrypt_finalize() in encryption operation.\n
	 *   Set after yaca_decrypt_initialize() and before yaca_decrypt_update()
	 *   in decryption operation.\n\n
	 *
	 * - #YACA_PROPERTY_CCM_AAD = additional authentication data (optional)\n
	 *   The total plaintext length must be passed to yaca_encrypt_update()
	 *   if AAD is used.\n
	 *   Set after yaca_encrypt_initialize() and before yaca_encrypt_update()
	 *   in encryption operation.\n
	 *   You can only call yaca_encrypt_update() once for AAD and once for the plaintext.\n\n
	 *
	 *   The total encrypted text length must be passed to yaca_decrypt_update()
	 *   if AAD is used.\n
	 *   Set after yaca_decrypt_initialize() and before yaca_decrypt_update()
	 *   in decryption operation.\n\n
	 *
	 *   @see examples/encrypt_aes_gcm_ccm.c
	 */
	YACA_BCM_CCM

} yaca_block_cipher_mode_e;


/**
 * @brief Enumeration of YACA non-standard properties for algorithms.
 *
 * @since_tizen 3.0
 */
typedef enum {
	/** Padding */
	YACA_PROPERTY_PADDING,

	/** GCM Additional Authentication Data */
	YACA_PROPERTY_GCM_AAD,
	/** GCM Tag bits */
	YACA_PROPERTY_GCM_TAG,
	/** GCM Tag length */
	YACA_PROPERTY_GCM_TAG_LEN,

	/** CCM Additional Authentication Data */
	YACA_PROPERTY_CCM_AAD,
	/** CCM Tag bits */
	YACA_PROPERTY_CCM_TAG,
	/** CCM Tag length */
	YACA_PROPERTY_CCM_TAG_LEN
} yaca_property_e;

/**
 * @brief Enumeration of YACA paddings.
 *
 * @since_tizen 3.0
 */
typedef enum {
	/** The total number of data bytes MUST be a multiple of block size */
	YACA_PADDING_NONE = 0,
	/** RSA X9.31 padding */
	YACA_PADDING_X931,
	/** RSA signature/verify operations */
	YACA_PADDING_PKCS1,
	/** RSA signature/verify operations */
	YACA_PADDING_PKCS1_PSS,
} yaca_padding_e;

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_TYPES_H */
