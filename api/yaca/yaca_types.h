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
 * @file   yaca_types.h
 * @brief  Types enums and defines.
 */

#ifndef YACA_TYPES_H
#define YACA_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup CAPI_YACA_ENCRYPTION_MODULE
 * @{
 */

/* The format of the unsigned int used to indicate key_bit_len is as follows:
 *
 *      Bits indicating a type:
 *           bits 31-30 (2 bits) indicate key_length type:
 *                00(0) - regular type for RSA, DSA and DH
 *                01(1) - elliptic curve
 *                remaining combinations reserved
 *
 *      Bits for a regular type:
 *           bits 29-0 (30 bits) indicate length of the key in bits
 *
 *      Bits for an elliptic curve type:
 *           bits 29-26 (4 bits) indicate type of an elliptic curve:
 *                0000(0) - X9.62 Prime
 *                0001(1) - SECP
 *                0010(2) - SECT
 *                0011(3) - Brainpool
 *                remaining combinations reserved (c2pnb, c2tnb, c2onb...)
 *           bits 25-22 (4 bits) indicate a letter:
 *                0000(0) - v
 *                0001(1) - r
 *                0010(2) - k
 *                0011(3) - t
 *                remaining combinations reserved (w...)
 *           bits 21-18 (4 bits) indicate a number:
 *                0000(0) - 1
 *                0001(1) - 2
 *                0010(2) - 3
 *                0011(3) - 4
 *                remaining combinations reserved
 *           bits 17-0 (18 bits) - length of the prime field in bits
 *
 * For now this is mostly used for elliptic curves. For any other keys key_bit_len can be
 * passed just as a number of bits (2 most significant bits set to 00, 30 bits for bit length).
 *
 * For elliptic curves don't use those defines directly, use enums in yaca_key_bit_length_ec_e.
 * Not all combinations are valid and other valid combinations are not guaranteed to be
 * implemented (they most surely aren't).
 */

/** @cond  Don't include those defines in doxygen, they are not to be used directly */
#define YACA_KEY_LEN_TYPE_MASK     (3U << 30)

#define YACA_KEY_LEN_TYPE_REGULAR  (0U << 30)
#define YACA_KEY_LEN_TYPE_EC       (1U << 30)

#define YACA_KEY_LEN_EC_PRIME      (0U << 26)
#define YACA_KEY_LEN_EC_SECP       (1U << 26)
#define YACA_KEY_LEN_EC_SECT       (2U << 26)
#define YACA_KEY_LEN_EC_BRAINPOOL  (3U << 26)

#define YACA_KEY_LEN_EC_V          (0U << 22)
#define YACA_KEY_LEN_EC_R          (1U << 22)
#define YACA_KEY_LEN_EC_K          (2U << 22)
#define YACA_KEY_LEN_EC_T          (3U << 22)

#define YACA_KEY_LEN_EC_1          (0U << 18)
#define YACA_KEY_LEN_EC_2          (1U << 18)
#define YACA_KEY_LEN_EC_3          (2U << 18)
#define YACA_KEY_LEN_EC_4          (3U << 18)
/** @endcond */

/**
 * @brief The context handle.
 *
 * @since_tizen 3.0
 */
typedef struct yaca_context_s *yaca_context_h;

/**
 * @brief The key handle.
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

	/** Diffie-Hellman public key */
	YACA_KEY_TYPE_DH_PUB,
	/** Diffie-Hellman private key */
	YACA_KEY_TYPE_DH_PRIV,

	/** Elliptic Curve public key (for DSA and DH) */
	YACA_KEY_TYPE_EC_PUB,
	/** Elliptic Curve private key (for DSA and DH) */
	YACA_KEY_TYPE_EC_PRIV
} yaca_key_type_e;

/**
 * @brief Enumeration of YACA key lengths.
 *        It is possible to use arbitrary integer instead,
 *        this enum values are placed here to avoid magic numbers.
 *
 * @since_tizen 3.0
 */
typedef enum {
	/** 24 bits */
	YACA_KEY_LENGTH_IV_UNSAFE_24BIT = 24,
	/** 64 bits */
	YACA_KEY_LENGTH_IV_64BIT = 64,
	/** 128 bits */
	YACA_KEY_LENGTH_IV_128BIT = 128,
	/** 256 bits */
	YACA_KEY_LENGTH_IV_256BIT = 256,
	/** 8 bits */
	YACA_KEY_LENGTH_UNSAFE_8BIT = 8,
	/** 40 bits */
	YACA_KEY_LENGTH_UNSAFE_40BIT = 40,
	/** 64 bits */
	YACA_KEY_LENGTH_UNSAFE_64BIT = 64,
	/** 80 bits */
	YACA_KEY_LENGTH_UNSAFE_80BIT = 80,
	/** 128 bits */
	YACA_KEY_LENGTH_UNSAFE_128BIT = 128,
	/** 192 bits */
	YACA_KEY_LENGTH_192BIT = 192,
	/** 256 bits */
	YACA_KEY_LENGTH_256BIT = 256,
	/** 512 bits */
	YACA_KEY_LENGTH_512BIT = 512,
	/** 1024 bits */
	YACA_KEY_LENGTH_1024BIT = 1024,
	/** 2048 bits */
	YACA_KEY_LENGTH_2048BIT = 2048,
	/** 3072 bits */
	YACA_KEY_LENGTH_3072BIT = 3072,
	/** 4096 bits */
	YACA_KEY_LENGTH_4096BIT = 4096
} yaca_key_bit_length_e;

/**
 * @brief Enumeration of YACA elliptic curve types with their bit lengths.
 *        It's meant to be passed or returned as a @a key_bit_len param
 *        in appropriate functions when dealing with elliptic curves.
 *
 * @since_tizen 3.0
 */
typedef enum {
	/** Elliptic curve prime192v1 */
	YACA_KEY_LENGTH_EC_PRIME192V1 = YACA_KEY_LEN_TYPE_EC | YACA_KEY_LEN_EC_PRIME | YACA_KEY_LEN_EC_V | YACA_KEY_LEN_EC_1 | 192U,
	/** Elliptic curve prime256v1 */
	YACA_KEY_LENGTH_EC_PRIME256V1 = YACA_KEY_LEN_TYPE_EC | YACA_KEY_LEN_EC_PRIME | YACA_KEY_LEN_EC_V | YACA_KEY_LEN_EC_1 | 256U,
	/** Elliptic curve secp256k1 */
	YACA_KEY_LENGTH_EC_SECP256K1 = YACA_KEY_LEN_TYPE_EC | YACA_KEY_LEN_EC_SECP | YACA_KEY_LEN_EC_K | YACA_KEY_LEN_EC_1 | 256U,
	/** Elliptic curve secp384r1 */
	YACA_KEY_LENGTH_EC_SECP384R1 = YACA_KEY_LEN_TYPE_EC | YACA_KEY_LEN_EC_SECP | YACA_KEY_LEN_EC_R | YACA_KEY_LEN_EC_1 | 384U,
	/** Elliptic curve secp521r1 */
	YACA_KEY_LENGTH_EC_SECP521R1 = YACA_KEY_LEN_TYPE_EC | YACA_KEY_LEN_EC_SECP | YACA_KEY_LEN_EC_R | YACA_KEY_LEN_EC_1 | 521U
} yaca_key_bit_length_ec_e;

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
	 * - see #yaca_block_cipher_mode_e for details on additional properties (mandatory).
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
	 * - see #yaca_block_cipher_mode_e for details on additional properties (mandatory).
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
	 * - see #yaca_block_cipher_mode_e for details on additional properties (mandatory).
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
	 * - see #yaca_block_cipher_mode_e for details on additional properties (mandatory).
	 * - Use triple DES keys to perform corresponding 3-key 3DES encryption.
	 */
	YACA_ENCRYPT_3DES_3TDEA,

	/**
	 * RC2 encryption.
	 * This is a variable key length cipher.
	 * - Supported key lengths: 8-1024 bits in steps of 8 bits.
	 * - Effective key bits property by default equals to 128.
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
	 * - see #yaca_block_cipher_mode_e for details on additional properties (mandatory).
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
	 * Supported properties:
	 * - #YACA_PROPERTY_GCM_TAG_LEN = GCM tag length\n
	 *   Supported tag lengths: @c 32, @c 64, @c 96, @c 104, @c 112, @c 120, @c 128,
	 *   (recommended 128 bits tag).\n
	 *   Set after yaca_encrypt_finalize() / yaca_seal_finalize() and before
	 *   yaca_context_get_property(#YACA_PROPERTY_GCM_TAG)
	 *   in encryption / seal operation. The @a value should be a size_t variable.\n\n
	 *
	 * - #YACA_PROPERTY_GCM_TAG = GCM tag\n
	 *   Get after yaca_encrypt_finalize() / yaca_seal_finalize() in encryption / seal operation.\n
	 *   Set before yaca_decrypt_finalize() / yaca_open_finalize() in decryption / open operation.\n\n
	 *
	 * - #YACA_PROPERTY_GCM_AAD = additional authentication data (optional)\n
	 *   Set after yaca_encrypt_initialize() / yaca_seal_initialize() and before
	 *   yaca_encrypt_update() / yaca_seal_update() in encryption / seal operation.\n
	 *   Set after yaca_decrypt_initialize() / yaca_open_initialize() and before
	 *   yaca_decrypt_update() / yaca_open_update() in decryption / open operation.\n\n
	 *
	 *   @see yaca_context_set_property()
	 *   @see examples/encrypt_aes_gcm_ccm.c
	 *   @see examples/seal.c
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
	 * Supported properties:
	 * - #YACA_PROPERTY_CCM_TAG_LEN = CCM tag length\n
	 *   Supported tag lengths: 32-128 bits in step of 16 bits (recommended 96 bits tag).\n
	 *   Set after yaca_encrypt_initialize() / yaca_seal_initialize() and before
	 *   yaca_encrypt_update() / yaca_seal_update() in encryption / seal operation.
	 *   The @a value should be a size_t variable. \n\n
	 *
	 * - #YACA_PROPERTY_CCM_TAG = CCM tag\n
	 *   Get after yaca_encrypt_finalize() / yaca_seal_finalize() in encryption / seal operation.\n
	 *   Set after yaca_decrypt_initialize() / yaca_open_initialize() and before
	 *   yaca_decrypt_update() / yaca_open_update() in decryption / open operation.\n\n
	 *
	 * - #YACA_PROPERTY_CCM_AAD = additional authentication data (optional)\n
	 *   The total plaintext length must be passed to yaca_encrypt_update() / yaca_seal_update()
	 *   if AAD is used.\n
	 *   Set after yaca_encrypt_initialize() / yaca_seal_initialize() and before
	 *   yaca_encrypt_update() / yaca_seal_update() in encryption / seal operation.\n
	 *   You can only call yaca_encrypt_update() / yaca_seal_update() once for AAD
	 *   and once for the plaintext.\n\n
	 *
	 *   The total encrypted text length must be passed to yaca_decrypt_update() /
	 *   yaca_open_update() if AAD is used.\n
	 *   Set after yaca_decrypt_initialize() / yaca_open_initialize() and before
	 *   yaca_decrypt_update() / yaca_open_update() in decryption / open operation.\n\n
	 *
	 *   @see examples/encrypt_aes_gcm_ccm.c
	 *   @see examples/seal.c
	 */
	YACA_BCM_CCM

} yaca_block_cipher_mode_e;


/**
 * @brief Enumeration of YACA non-standard properties for algorithms.
 *
 * @since_tizen 3.0
 *
 * @see #yaca_padding_e
 */
typedef enum {
	/**
	 * Padding for the sign/verify operation. Property type is #yaca_padding_e.
	 *
	 * This property can be set at the latest before the *_finalize() call.
	 */
	YACA_PROPERTY_PADDING,

	/** GCM Additional Authentication Data. Property type is a buffer (e.g. char*) */
	YACA_PROPERTY_GCM_AAD,
	/** GCM Tag. Property type is a buffer (e.g. char*) */
	YACA_PROPERTY_GCM_TAG,
	/** GCM Tag length. Property type is size_t. */
	YACA_PROPERTY_GCM_TAG_LEN,

	/** CCM Additional Authentication Data. Property type is a buffer (e.g. char*) */
	YACA_PROPERTY_CCM_AAD,
	/** CCM Tag. Property type is a buffer (e.g. char*) */
	YACA_PROPERTY_CCM_TAG,
	/** CCM Tag length. Property type is size_t. */
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

/**
  * @}
  */

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_TYPES_H */
