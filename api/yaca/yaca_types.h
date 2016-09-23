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
 *           bits 31-28 (4 bits) indicate key_length type:
 *                0000(0) - regular type for RSA, DSA
 *                0001(1) - DH with specified generator
 *                0010(2) - DH with RFC 5114
 *                0011(3) - elliptic curve
 *                remaining combinations reserved
 *
 *      Bits for a regular type:
 *           bits 27-0  (28 bits) indicate length of the key in bits
 *
 *      Bits for a DH with specified generator number:
 *           bits 27-24 (4 bits) indicate DH generator
 *                0000(0) - generator 2
 *                0001(1) - generator 5
 *                remaining combinations reserved
 *           bits 23-16 (8 bits) reserved
 *           bits 15-0 (16 bits) length of the safe prime in bits
 *
 *      Bits for a DH with RFC 5114:
 *           bits 27-24 (4 bits) indicate a bit subgroup:
 *                0000(0) - 160
 *                0001(1) - 224
 *                0010(2) - 256
 *                remaining combinations reserved
 *           bits 23-16 (8 bits) reserved
 *           bits 15-0 (16 bits) length of the safe prime in bits
 *
 *      Bits for an elliptic curve type:
 *           bits 27-24 (4 bits) indicate type of an elliptic curve:
 *                0000(0) - X9.62 Prime
 *                0001(1) - SECP
 *                0010(2) - SECT
 *                0011(3) - Brainpool
 *                remaining combinations reserved (c2pnb, c2tnb, c2onb...)
 *           bits 23-20 (4 bits) indicate a letter:
 *                0000(0) - v
 *                0001(1) - r
 *                0010(2) - k
 *                0011(3) - t
 *                remaining combinations reserved (w...)
 *           bits 19-16 (4 bits) indicate a number:
 *                0000(0) - 1
 *                0001(1) - 2
 *                0010(2) - 3
 *                0011(3) - 4
 *                remaining combinations reserved
 *           bits 15-0 (16 bits) - length of the prime field in bits
 *
 * Those bits are used for DH and EC. For any other keys key_bit_len can be passed just
 * as a number of bits (4 most significant bits set to 0000, 28 bits for bit length).
 *
 * In any case those defines are not be used directly.
 *
 * For DH keys use YACA_KEY_LENGTH_DH_GENERATOR_* or'ed with safe prime length.
 * Alternatively one can use values from yaca_key_bit_length_dh_rfc_e enum to use
 * RFC 5114 parameters.
 *
 * For elliptic curves use values from yaca_key_bit_length_ec_e enum.
 */

/** @cond  Don't include those defines in doxygen, they are not to be used directly */

/* types */
#define YACA_KEYLEN_COMPONENT_TYPE_MASK     (0xF << 28)
#define YACA_KEYLEN_COMPONENT_TYPE_BITS     (0U << 28)
#define YACA_KEYLEN_COMPONENT_TYPE_DH       (1U << 28)
#define YACA_KEYLEN_COMPONENT_TYPE_DH_RFC   (2U << 28)
#define YACA_KEYLEN_COMPONENT_TYPE_EC       (3U << 28)

/* DH type */
#define YACA_KEYLEN_COMPONENT_DH_GEN_MASK   (0xF << 24)
#define YACA_KEYLEN_COMPONENT_DH_GEN_2      (0U << 24)
#define YACA_KEYLEN_COMPONENT_DH_GEN_5      (1U << 24)

#define YACA_KEYLEN_COMPONENT_DH_PRIME_MASK (0xFFFF << 0)

/* DH_RFC type */
#define YACA_KEYLEN_COMPONENT_DH_RFC_MASK   (0xF << 24)
#define YACA_KEYLEN_COMPONENT_DH_RFC_160    (0U << 24)
#define YACA_KEYLEN_COMPONENT_DH_RFC_224    (1U << 24)
#define YACA_KEYLEN_COMPONENT_DH_RFC_256    (2U << 24)

/* EC type */
#define YACA_KEYLEN_COMPONENT_EC_PRIME      (0U << 24)
#define YACA_KEYLEN_COMPONENT_EC_SECP       (1U << 24)
#define YACA_KEYLEN_COMPONENT_EC_SECT       (2U << 24)
#define YACA_KEYLEN_COMPONENT_EC_BRAINPOOL  (3U << 24)

#define YACA_KEYLEN_COMPONENT_EC_V          (0U << 20)
#define YACA_KEYLEN_COMPONENT_EC_R          (1U << 20)
#define YACA_KEYLEN_COMPONENT_EC_K          (2U << 20)
#define YACA_KEYLEN_COMPONENT_EC_T          (3U << 20)

#define YACA_KEYLEN_COMPONENT_EC_1          (0U << 16)
#define YACA_KEYLEN_COMPONENT_EC_2          (1U << 16)
#define YACA_KEYLEN_COMPONENT_EC_3          (2U << 16)
#define YACA_KEYLEN_COMPONENT_EC_4          (3U << 16)
/** @endcond */

/**
 * @brief The context handle.
 *
 * @since_tizen 3.0
 */
typedef struct yaca_context_s *yaca_context_h;

/**
 * @brief The handle of a key, an Initialization Vector or a key generation parameters.
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
 * @brief Enumeration of YACA key types, Initialization Vector is considered as key.
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
	YACA_KEY_TYPE_EC_PRIV,

	/** Digital Signature Algorithm parameters */
	YACA_KEY_TYPE_DSA_PARAMS,
	/** Diffie-Hellman parameters */
	YACA_KEY_TYPE_DH_PARAMS,
	/** Elliptic Curve parameters */
	YACA_KEY_TYPE_EC_PARAMS
} yaca_key_type_e;

/**
 * @brief Enumeration of YACA key lengths.
 *        It is possible to use arbitrary integer instead,
 *        this enum values are placed here to avoid magic numbers.
 *
 * @since_tizen 3.0
 */
typedef enum {
	/** 64 bits */
	YACA_KEY_LENGTH_IV_64BIT = 64,
	/** 128 bits */
	YACA_KEY_LENGTH_IV_128BIT = 128,
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
	YACA_KEY_LENGTH_EC_PRIME192V1 = YACA_KEYLEN_COMPONENT_TYPE_EC | YACA_KEYLEN_COMPONENT_EC_PRIME | YACA_KEYLEN_COMPONENT_EC_V | YACA_KEYLEN_COMPONENT_EC_1 | 192U,
	/** Elliptic curve prime256v1 */
	YACA_KEY_LENGTH_EC_PRIME256V1 = YACA_KEYLEN_COMPONENT_TYPE_EC | YACA_KEYLEN_COMPONENT_EC_PRIME | YACA_KEYLEN_COMPONENT_EC_V | YACA_KEYLEN_COMPONENT_EC_1 | 256U,
	/** Elliptic curve secp256k1 */
	YACA_KEY_LENGTH_EC_SECP256K1 = YACA_KEYLEN_COMPONENT_TYPE_EC | YACA_KEYLEN_COMPONENT_EC_SECP | YACA_KEYLEN_COMPONENT_EC_K | YACA_KEYLEN_COMPONENT_EC_1 | 256U,
	/** Elliptic curve secp384r1 */
	YACA_KEY_LENGTH_EC_SECP384R1 = YACA_KEYLEN_COMPONENT_TYPE_EC | YACA_KEYLEN_COMPONENT_EC_SECP | YACA_KEYLEN_COMPONENT_EC_R | YACA_KEYLEN_COMPONENT_EC_1 | 384U,
	/** Elliptic curve secp521r1 */
	YACA_KEY_LENGTH_EC_SECP521R1 = YACA_KEYLEN_COMPONENT_TYPE_EC | YACA_KEYLEN_COMPONENT_EC_SECP | YACA_KEYLEN_COMPONENT_EC_R | YACA_KEYLEN_COMPONENT_EC_1 | 521U
} yaca_key_bit_length_ec_e;

/**
 * @brief A value indicating generator equal 2 for DH parameters.
 *        To be or'ed with safe prime length in bits. Prime length is recommended
 *        to be 2048 bits or higher.
 */
#define YACA_KEY_LENGTH_DH_GENERATOR_2 (YACA_KEYLEN_COMPONENT_TYPE_DH | YACA_KEYLEN_COMPONENT_DH_GEN_2)
/**
 * @brief A value indicating generator equal 5 for DH parameters.
 *        To be or'ed with safe prime length in bits. Prime length is recommended
 *        to be 2048 bits or higher.
 */
#define YACA_KEY_LENGTH_DH_GENERATOR_5 (YACA_KEYLEN_COMPONENT_TYPE_DH | YACA_KEYLEN_COMPONENT_DH_GEN_5)

/**
 * @brief Enumeration of YACA DH parameters taken from RFC 5114.
 *        It's meant to be passed or returned as a @a key_bit_len param
 *        in appropriate functions when dealing with DH and wanting to
 *        use RFC 5114 values.
 *
 * @since_tizen 3.0
 */
typedef enum {
	/** RFC 5114 DH parameters 1024_160 */
	YACA_KEY_LENGTH_DH_RFC_1024_160 = YACA_KEYLEN_COMPONENT_TYPE_DH_RFC | YACA_KEYLEN_COMPONENT_DH_RFC_160 | 1024U,
	/** RFC 5114 DH parameters 2048_224 */
	YACA_KEY_LENGTH_DH_RFC_2048_224 = YACA_KEYLEN_COMPONENT_TYPE_DH_RFC | YACA_KEYLEN_COMPONENT_DH_RFC_224 | 2048U,
	/** RFC 5114 DH parameters 2048_256 */
	YACA_KEY_LENGTH_DH_RFC_2048_256 = YACA_KEYLEN_COMPONENT_TYPE_DH_RFC | YACA_KEYLEN_COMPONENT_DH_RFC_256 | 2048U
} yaca_key_bit_length_dh_rfc_e;

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
	 * - Supported key lengths: @c 128, @c 192 and @c 256 bits.
	 * - Supported block cipher modes:\n
	 * #YACA_BCM_CBC,\n
	 * #YACA_BCM_OFB,\n
	 * #YACA_BCM_CFB,\n
	 * #YACA_BCM_CFB1,\n
	 * #YACA_BCM_CFB8,\n
	 * #YACA_BCM_ECB,\n
	 * #YACA_BCM_GCM,\n
	 * #YACA_BCM_CCM,\n
	 * #YACA_BCM_CTR,\n
	 * #YACA_BCM_WRAP
	 * - see #yaca_block_cipher_mode_e for details on additional properties (mandatory).
	 */
	YACA_ENCRYPT_AES = 0,

	/**
	 * DES encryption.
	 * - Supported key lengths: @c 64 bits.
	 * - Supported block cipher modes:\n
	 * #YACA_BCM_CBC,\n
	 * #YACA_BCM_OFB,\n
	 * #YACA_BCM_CFB,\n
	 * #YACA_BCM_CFB1,\n
	 * #YACA_BCM_CFB8,\n
	 * #YACA_BCM_ECB
	 * - see #yaca_block_cipher_mode_e for details on additional properties (mandatory).
	 */
	YACA_ENCRYPT_UNSAFE_DES,

	/**
	 * 3DES 2-key encryption.
	 * - Supported key lengths: @c 128 bits.
	 * - Supported block cipher modes:\n
	 * #YACA_BCM_CBC,\n
	 * #YACA_BCM_OFB,\n
	 * #YACA_BCM_CFB,\n
	 * #YACA_BCM_ECB
	 * - see #yaca_block_cipher_mode_e for details on additional properties (mandatory).
	 * - Use double DES keys to perform corresponding 2-key 3DES encryption.
	 */
	YACA_ENCRYPT_UNSAFE_3DES_2TDEA,

	/**
	 * 3DES 3-key encryption.
	 * - Supported key lengths: @c 192 bits.
	 * - Supported block cipher modes:\n
	 * #YACA_BCM_CBC,\n
	 * #YACA_BCM_OFB,\n
	 * #YACA_BCM_CFB,\n
	 * #YACA_BCM_CFB1,\n
	 * #YACA_BCM_CFB8,\n
	 * #YACA_BCM_ECB,\n
	 * #YACA_BCM_WRAP
	 * - see #yaca_block_cipher_mode_e for details on additional properties (mandatory).
	 * - Use triple DES keys to perform corresponding 3-key 3DES encryption.
	 */
	YACA_ENCRYPT_3DES_3TDEA,

	/**
	 * RC2 encryption.
	 * This is a variable key length cipher.
	 * - Supported key lengths: 8-1024 bits in steps of 8 bits.
	 * - Effective key bits property by default equals to 128 bits.\n
	 * Effective key bits can be set using yaca_context_set_property() and
	 * #YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS.\n
	 * It can be set after yaca_encrypt_initialize() / yaca_decrypt_initialize(), and before
	 * yaca_encrypt_update() / yaca_decrypt_update() in encryption / decryption operation.
	 *
	 * - Supported block cipher modes:\n
	 * #YACA_BCM_CBC,\n
	 * #YACA_BCM_OFB,\n
	 * #YACA_BCM_CFB,\n
	 * #YACA_BCM_ECB
	 * - see #yaca_block_cipher_mode_e for details on additional properties (mandatory).
	 */
	YACA_ENCRYPT_UNSAFE_RC2,

	/**
	 * RC4 encryption.
	 * This is a variable key length cipher.
	 * - Supported key lengths: 40–2048 bits in steps of 8 bits.
	 * - Initialization Vector is not used.
	 * - This cipher doesn't support block cipher modes, use #YACA_BCM_NONE instead.
	 */
	YACA_ENCRYPT_UNSAFE_RC4,

	/**
	 * CAST5 encryption.
	 * This is a variable key length cipher.
	 * - Supported key lengths: 40-128 bits in steps of 8 bits.
	 * - Supported block cipher modes:\n
	 * #YACA_BCM_CBC,\n
	 * #YACA_BCM_OFB,\n
	 * #YACA_BCM_CFB,\n
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
	 * Initialization Vector is not used.
	 */
	YACA_BCM_NONE,

	/**
	 * ECB block cipher mode.
	 * Initialization Vector is not used.
	 *
	 * By default the input data is padded using standard block padding (#YACA_PADDING_PKCS7).
	 * Padding can be disabled using yaca_context_set_property() and
	 * #YACA_PROPERTY_PADDING,#YACA_PADDING_NONE,
	 * then the total length of data passed until *_finalize() MUST be a multiple of block size.
	 * #YACA_PROPERTY_PADDING can be set at the latest before the *_finalize() call.
	 */
	YACA_BCM_ECB,

	/**
	 * CTR block cipher mode.
	 * 128-bit Initialization Vector for AES,
	 * 64-bit for other algorithms is mandatory.
	 */
	YACA_BCM_CTR,

	/**
	 * CBC block cipher mode.
	 * 128-bit Initialization Vector for AES,
	 * 64-bit for other algorithms is mandatory.
	 *
	 * By default the input data is padded using standard block padding (#YACA_PADDING_PKCS7).
	 * Padding can be disabled using yaca_context_set_property() and
	 * #YACA_PROPERTY_PADDING, #YACA_PADDING_NONE,
	 * then the total length of data passed until *_finalize() MUST be a multiple of block size.
	 * #YACA_PROPERTY_PADDING can be set at the latest before the *_finalize() call.
	 */
	YACA_BCM_CBC,

	/**
	 * GCM block cipher mode.
	 * This is a variable Initialization Vector length mode (recommended 96-bits).
	 *
	 * Supported properties:
	 * - #YACA_PROPERTY_GCM_TAG_LEN = GCM tag length (optional)\n
	 *   Supported tag lengths: @c 4, @c 8, @c 12, @c 13, @c 14, @c 15, @c 16
	 *   (16 bytes tag by default).\n
	 *   Set after yaca_encrypt_finalize() / yaca_seal_finalize() and before
	 *   yaca_context_get_property(#YACA_PROPERTY_GCM_TAG) in encryption / seal operation.\n
	 *   The @a value should be a size_t variable.\n
	 *   In decryption / open operation tag length is not set.\n\n
	 *
	 * - #YACA_PROPERTY_GCM_TAG = GCM tag\n
	 *   Get after yaca_encrypt_finalize() / yaca_seal_finalize() in encryption / seal operation.\n
	 *   Set after yaca_decrypt_update() / yaca_open_update() and before
	 *   yaca_decrypt_finalize() / yaca_open_finalize() in decryption / open operation.\n\n
	 *
	 * - #YACA_PROPERTY_GCM_AAD = additional authentication data (optional)\n
	 *   Set after yaca_encrypt_initialize() / yaca_seal_initialize() and before
	 *   yaca_encrypt_update() / yaca_seal_update() in encryption / seal operation.\n
	 *   Set after yaca_decrypt_initialize() / yaca_open_initialize() and before
	 *   yaca_decrypt_update() / yaca_open_update() in decryption / open operation.\n\n
	 *
	 *   @see yaca_context_set_property()
	 *   @see yaca_context_get_property()
	 *
	 */
	YACA_BCM_GCM,

	/**
	 * Default CFB block cipher mode.
	 * 128-bit Initialization Vector for AES,
	 * 64-bit for other algorithms is mandatory.
	 */
	YACA_BCM_CFB,

	/**
	 * 1 bit CFB block cipher mode.
	 * 128-bit Initialization Vector for AES,
	 * 64-bit for other algorithms is mandatory.
	 */
	YACA_BCM_CFB1,

	/**
	 * 8 bits CFB block cipher mode.
	 * 128-bit Initialization Vector for AES,
	 * 64-bit for other algorithms is mandatory.
	 */
	YACA_BCM_CFB8,

	/**
	 * OFB block cipher mode.
	 * 128-bit Initialization Vector for AES,
	 * 64-bit for other algorithms is mandatory.
	 */
	YACA_BCM_OFB,

	/**
	 * CBC-MAC Mode (AES).
	 * This is a variable Initialization Vector length mode.\n
	 * Supported Initialization Vector lengths: 56-104 bits in steps of 8 bits
	 * (recommended 56-bits).\n\n
	 *
	 * Supported properties:
	 * - #YACA_PROPERTY_CCM_TAG_LEN = CCM tag length (optional)\n
	 *   Supported tag lengths: 4-16 bytes in steps of 2 bytes (12 bytes tag by default).\n
	 *   Set after yaca_encrypt_initialize() / yaca_seal_initialize() and before
	 *   yaca_encrypt_update() / yaca_seal_update() in encryption / seal operation.\n
	 *   The @a value should be a size_t variable.\n
	 *   In decryption / open operation tag length is not set.\n\n
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
	 *   yaca_decrypt_update() / yaca_open_update() in decryption / open operation.\n
	 *   You can only call yaca_decrypt_update() / yaca_open_update() once for AAD
	 *   and once for the encrypted text.\n\n
	 *
	 *   @see yaca_context_set_property()
	 *   @see yaca_context_get_property()
	 *
	 */
	YACA_BCM_CCM,

	/**
	 * Used with #YACA_ENCRYPT_AES or #YACA_ENCRYPT_3DES_3TDEA to perform a key wrapping
	 * (key material symmetric encryption).
	 *
	 * Only a single yaca_encrypt_update() / yaca_decrypt_update() is allowed.
	 *
	 * Usage in yaca_seal_initialize() / yaca_open_finalize() is forbidden.
	 *
	 * Key used to do the wrapping with #YACA_ENCRYPT_AES can be a 128-bit key, a 192-bit key,
	 * or a 256-bit key.\n
	 * 64-bit Initialization Vector is used.\n
	 * Wrapped key can be a 128-bit key, a 192-bit key, or a 256-bit key.\n
	 * #YACA_ENCRYPT_AES allows wrapping multiple keys together.
	 *
	 * Key used to do the wrapping with #YACA_ENCRYPT_3DES_3TDEA can be a 192-bit DES key only.\n
	 * Initialization Vector is not used.\n
	 * Wrapped key can be a 128-bit DES key (two-key), or a 192-bit DES key (three-key).\n
	 * #YACA_ENCRYPT_3DES_3TDEA allows wrapping only one key.
	 *
	 */
	YACA_BCM_WRAP

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
	 * Padding for the encrypt/decrypt or sign/verify operation. Property type is #yaca_padding_e.
	 *
	 * This property can be set at the latest before the *_finalize() call.
	 */
	YACA_PROPERTY_PADDING,

	/** GCM Additional Authentication Data. Property type is a buffer (e.g. char*) */
	YACA_PROPERTY_GCM_AAD,
	/** GCM Tag. Property type is a buffer (e.g. char*) */
	YACA_PROPERTY_GCM_TAG,
	/** GCM Tag length in bytes. Property type is size_t. */
	YACA_PROPERTY_GCM_TAG_LEN,

	/** CCM Additional Authentication Data. Property type is a buffer (e.g. char*) */
	YACA_PROPERTY_CCM_AAD,
	/** CCM Tag. Property type is a buffer (e.g. char*) */
	YACA_PROPERTY_CCM_TAG,
	/** CCM Tag length in bytes. Property type is size_t. */
	YACA_PROPERTY_CCM_TAG_LEN,

	/** RC2 effective key bits, 1-1024, 1 bit resolution. Property type is size_t. */
	YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
} yaca_property_e;

/**
 * @brief Enumeration of YACA paddings.
 *
 * @since_tizen 3.0
 */
typedef enum {
	/**
	 * No padding at all. This method assumes that the input data already has a proper length for
	 * a given cryptographic operation (e.g. it has been padded by the client). Suitable for
	 * symmetric encrypt/decrypt operations as well as low-level RSA operations.
	 */
	YACA_PADDING_NONE = 0,

	/**
	 * X9.31 padding. Suitable for RSA sign/verify operation. Not supported in low-level
	 * RSA operations.
	 */
	YACA_PADDING_X931,

	/**
	 * PKCS #1 v1.5 padding. Suitable for RSA sign/verify and low-level RSA operations.
	 * For low-level operations the input must be at least 11 bytes shorter than the key length.
	 */
	YACA_PADDING_PKCS1,

	/**
	 * PKCS #1 PSS padding. Suitable for RSA sign/verify operations. Not supported in low-level
	 * RSA operations.
	 */
	YACA_PADDING_PKCS1_PSS,

	/**
	 * EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1 and an empty encoding parameter.
	 * Suitable for low-level RSA public_encrypt/private_decrypt operations. For low-level
	 * operations the input must be at least 42 bytes shorter than the key length.
	 */
	YACA_PADDING_PKCS1_OAEP,

	/**
	 * PKCS #1 v1.5 padding with an SSL-specific modification that denotes that the party
	 * is SSL3 capable. It is used for rollback attack detection in SSLv3. If during decryption it
	 * turns out that both parties are using #YACA_PADDING_PKCS1_SSLV23 (both are communicating
	 * using SSL2 and both are SSL3 capable) it is treated as a rollback attack and an error is
	 * returned. Suitable for low-level RSA public_encrypt/private_decrypt operations. For
	 * low-level operations the input must be at least 11 bytes shorter than the key length.
	 */
	YACA_PADDING_PKCS1_SSLV23,

	/**
	 * PKCS #7 padding. Suitable for symmetric encrypt/decrypt operation.
	 */
	YACA_PADDING_PKCS7
} yaca_padding_e;

/**
 * @brief Enumeration of YACA key derivation functions.
 *
 * @since_tizen 3.0
 */
typedef enum {
	/**
	 * ANSI X9.42 key derivation function,
	 * (shared secret derived using Diffie-Helmann key exchange protocol).
	 */
	YACA_KDF_X942,

	/**
	 * ANSI X9.62 key derivation function,
	 * (shared secret derived using EC Diffie-Helmann key exchange protocol).
	 */
	YACA_KDF_X962,
} yaca_kdf_e;

/**
 * @}
 */

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_TYPES_H */
