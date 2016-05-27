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
 * @file types.h
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
 * @brief Context
 *
 * @since_tizen 3.0
 */
typedef struct yaca_ctx_s *yaca_ctx_h;

/**
 * @brief Key
 *
 * @since_tizen 3.0
 */
typedef struct yaca_key_s *yaca_key_h;

/**
 * @brief Key formats
 *
 * @since_tizen 3.0
 */
typedef enum {
	YACA_KEY_FORMAT_DEFAULT,  /**< key is either PKCS#1 for RSA or SSLeay for DSA, also use this option for symmetric */
	YACA_KEY_FORMAT_PKCS8     /**< key is in PKCS#8, can only be used for asymmetric private keys */
} yaca_key_fmt_e;

/**
 * @brief Key file formats
 *
 * @since_tizen 3.0
 */
typedef enum {
	YACA_KEY_FILE_FORMAT_RAW,      /**< key file is in raw binary format, used for symmetric keys */
	YACA_KEY_FILE_FORMAT_BASE64,   /**< key file is encoded in ASCII-base64, used for symmetric keys */
	YACA_KEY_FILE_FORMAT_PEM,      /**< key file is in PEM file format, used for asymmetric keys */
	YACA_KEY_FILE_FORMAT_DER       /**< key file is in DER file format, used for asymmetric keys */
} yaca_key_file_fmt_e;

/**
 * @brief Key types, IV is considered as key
 *
 * @since_tizen 3.0
 */
typedef enum {
	YACA_KEY_TYPE_SYMMETRIC,   /**< Generic symmetric cipher KEY */
	YACA_KEY_TYPE_DES,         /**< DES* key - must be handled differently because of parity bits */
	YACA_KEY_TYPE_IV,          /**< Initialization Vector for symmetric algorithms */

	YACA_KEY_TYPE_RSA_PUB,     /**< RSA public key */
	YACA_KEY_TYPE_RSA_PRIV,    /**< RSA private key */

	YACA_KEY_TYPE_DSA_PUB,     /**< Digital Signature Algorithm public key */
	YACA_KEY_TYPE_DSA_PRIV,    /**< Digital Signature Algorithm private key */

	YACA_KEY_TYPE_DH_PUB,      /**< Diffie-Hellman public key */
	YACA_KEY_TYPE_DH_PRIV,     /**< Diffie-Hellman private key */

	YACA_KEY_TYPE_EC_PUB,      /**< Elliptic Curve public key (for DSA and DH) */
	YACA_KEY_TYPE_EC_PRIV,     /**< Elliptic Curve private key (for DSA and DH) */
} yaca_key_type_e;

/**
 * @brief Key length, It is possible to use arbitrary integer instead, this enums are placed here to avoid magic numbers.
 *
 * @since_tizen 3.0
 */
typedef enum {
	YACA_KEY_IV_UNSAFE_24BIT = 24,    /**< 24-bit IV */
	YACA_KEY_IV_64BIT = 64,           /**< 64-bit IV */
	YACA_KEY_IV_128BIT = 128,         /**< 128-bit IV */
	YACA_KEY_IV_256BIT = 256,         /**< 256-bit IV */
	YACA_KEY_CURVE_P192 = 192,        /**< ECC: P192 curve */
	YACA_KEY_CURVE_P256 = 256,        /**< ECC: P-256 curve */
	YACA_KEY_CURVE_P384 = 384,        /**< ECC: SECP-384 curve */
	YACA_KEY_UNSAFE_8BIT = 8,
	YACA_KEY_UNSAFE_40BIT = 40,
	YACA_KEY_UNSAFE_64BIT = 64,
	YACA_KEY_UNSAFE_80BIT = 80,
	YACA_KEY_UNSAFE_128BIT = 128,
	YACA_KEY_192BIT = 192,
	YACA_KEY_256BIT = 256,
	YACA_KEY_512BIT = 512,
	YACA_KEY_1024BIT = 1024,
	YACA_KEY_2048BIT = 2048,
	YACA_KEY_3072BIT = 3072,
	YACA_KEY_4096BIT = 4096
} yaca_key_bits_e;

/**
 * @brief Message digest algorithms.
 *
 * @since_tizen 3.0
 */
typedef enum {
	YACA_DIGEST_MD5,      /**< Message digest algorithm MD5  */
	YACA_DIGEST_SHA1,     /**< Message digest algorithm SHA1  */
	YACA_DIGEST_SHA224,   /**< Message digest algorithm SHA2, 224bit  */
	YACA_DIGEST_SHA256,   /**< Message digest algorithm SHA2, 256bit  */
	YACA_DIGEST_SHA384,   /**< Message digest algorithm SHA2, 384bit  */
	YACA_DIGEST_SHA512,   /**< Message digest algorithm SHA2, 512bit  */
} yaca_digest_algo_e;

/**
 * @brief Symmetric encryption algorithms
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
	 * #YACA_BCM_CTR,
	 * - see #yaca_block_cipher_mode_e for details on additional parameters (mandatory).
	 */
	YACA_ENC_AES = 0,

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
	YACA_ENC_UNSAFE_DES,

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
	YACA_ENC_UNSAFE_3DES_2TDEA,

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
	YACA_ENC_3DES_3TDEA,

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
	YACA_ENC_UNSAFE_RC2,

	/**
	 * RC4 encryption.
	 * This is a variable key length cipher.
	 * - Supported key lengths: 40–2048 bits in steps of 8 bits.
	 * This cipher doesn't support block cipher modes, use #YACA_BCM_NONE instead.
	 */
	YACA_ENC_UNSAFE_RC4,

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
	YACA_ENC_CAST5,
} yaca_enc_algo_e;

/**
 * @brief Chaining modes for block ciphers
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
	 * - #YACA_PARAM_GCM_TAG_LEN = GCM tag length\n
	 *   Supported tag lengths: @c 32, @c 64, @c 96, @c 104, @c 112, @c 120, @c 128,
	 *   (recommended 128 bits tag).\n
	 *   Set after yaca_encrypt_final() and before yaca_ctx_get_param(#YACA_PARAM_GCM_TAG)
	 *   in encryption operation.\n\n
	 *
	 * - #YACA_PARAM_GCM_TAG = GCM tag\n
	 *   Get after yaca_encrypt_final() in encryption operation.\n
	 *   Set before yaca_decrypt_final() in decryption operation.\n\n
	 *
	 * - #YACA_PARAM_GCM_AAD = additional authentication data (optional)\n
	 *   Set after yaca_encrypt_init() and before yaca_encrypt_update()
	 *   in encryption operation.\n
	 *   Set after yaca_decrypt_init() and before yaca_decrypt_update()
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
	 * - #YACA_PARAM_CCM_TAG_LEN = CCM tag length\n
	 *   Supported tag lengths: 32-128 bits in step of 16 bits (recommended 96 bits tag).\n
	 *   Set after yaca_encrypt_init() and before yaca_encrypt_update()
	 *   in encryption operation.\n\n
	 *
	 * - #YACA_PARAM_CCM_TAG = CCM tag\n
	 *   Get after yaca_encrypt_final() in encryption operation.\n
	 *   Set after yaca_decrypt_init() and before yaca_decrypt_update()
	 *   in decryption operation.\n\n
	 *
	 * - #YACA_PARAM_CCM_AAD = additional authentication data (optional)\n
	 *   The total plain text length must be passed to yaca_encrypt_update()
	 *   if AAD is used.\n
	 *   Set after yaca_encrypt_init() and before yaca_encrypt_update()
	 *   in encryption operation.\n
	 *   You can only call yaca_encrypt_update() once for AAD and once for the plain text.\n\n
	 *
	 *   The total encrypted text length must be passed to yaca_decrypt_update()
	 *   if AAD is used.\n
	 *   Set after yaca_decrypt_init() and before yaca_decrypt_update()
	 *   in decryption operation.\n\n
	 *
	 *   @see examples/encrypt_aes_gcm_ccm.c
	 */
	YACA_BCM_CCM

} yaca_block_cipher_mode_e;


/**
 * @brief Non-standard parameters for algorithms
 *
 * @since_tizen 3.0
 */
typedef enum {
	YACA_PARAM_PADDING,                /**< Padding */

	YACA_PARAM_GCM_AAD,                /**< GCM Additional Authentication Data */
	YACA_PARAM_GCM_TAG,                /**< GCM Tag bits */
	YACA_PARAM_GCM_TAG_LEN,            /**< GCM Tag length */

	YACA_PARAM_CCM_AAD,                /**< CCM Additional Authentication Data */
	YACA_PARAM_CCM_TAG,                /**< CCM Tag bits */
	YACA_PARAM_CCM_TAG_LEN,            /**< CCM Tag length */
} yaca_ex_param_e;

/**
 * @brief Paddings supported by Yet Another Crypto API
 *
 * @since_tizen 3.0
 */
typedef enum {
	YACA_PADDING_NONE = 0,   /**< total number of data MUST multiple of block size, Default */
	YACA_PADDING_X931,       /**< RSA X9.31 padding*/
	YACA_PADDING_PKCS1,      /**< RSA signature/verify operations */
	YACA_PADDING_PKCS1_PSS,  /**< RSA signature/verify operations */
	YACA_PADDING_SSLV23,     /**< RSA SSLv23 */
	YACA_PADDING_PKCS1_OAEP  /**< RSA encrypt/decrypt operations */
} yaca_padding_e;

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_TYPES_H */
