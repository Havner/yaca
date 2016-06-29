/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __TIZEN_CORE_YACA_DOC_H__
#define __TIZEN_CORE_YACA_DOC_H__
/**
  * @ingroup CAPI_SECURITY_FRAMEWORK
  * @defgroup CAPI_YACA_MODULE yaca crypto module
  * @brief    The yaca(yet another crypto api) provides a crypto function such as key management, data integrity and data en/decryption.
  *           Key management provides APIs for generating secured key,importing a key trying to match it to the key_type specified and exporting a key to arbitrary format.
  *           Data Integrity provides Advanced/Simpled API for the integrity handling - HMAC, CMAC, message digests and digital signature.
  *           Data en/decryption provides Advanced/Simpled APIs for en/decrypting and sealing/opening a data.
  *
  * @section CAPI_YACA_MODULE_OVERVIEW Overview
  * <table>
  *   <tr><th>API</th><th>Description</th></tr>
  *   <tr>
  *     <td> @ref CAPI_YACA_ENCRYPTION_MODULE</td>
  *     <td> Provides APIs for encryption/decryption operations with symmetric keys and sealing/opening operations with asymmetric keys.</td>
  *   </tr>
  *   <tr>
  *     <td> @ref CAPI_YACA_INTEGRITY_MODULE</td>
  *     <td> Provides APIs for creating/verifying a signature, calculating HMAC/CMAC and calculating a message digest.</td>
  *   </tr>
  *   <tr>
  *     <td> @ref CAPI_YACA_KEY_MODULE</td>
  *     <td> Provides APIs for key handling operations such as generating, importing, and exporting a key and deriving a key from password.</td>
  *   </tr>
  *   <tr>
  *     <td> @ref CAPI_YACA_SIMPLE_MODULE</td>
  *     <td> Provides simple APIs for cryptographic operations.</td>
  *   </tr>
  * </table>
  *
  * The yaca provides a crypto function such as key management, integrity handling and data en/decryption.
  * Key management provides APIs for generating secured key, importing a key trying to match it to the key type specified and exporting a key to arbitrary format.
  * Data Integrity provides Advanced/Simpled API for the integrity handling - HMAC, CMAC, message digest and digital signature.
  * Data en/decryption provides Advanced/Simpled APIs for en/decrypting a data and creating a IV.
  *
  * @image html capi_yaca_overview_diagram.png
  *
  * The yaca provides 3 types of API.
  * - key management APIs : These APIs provides generating key using random number or password, importing a key trying to match it to the key_type specified and exporting a key to arbitrary format.
  * - data en/decryption APIs : These APIs provides Advanced/Simpled API for the data encryption.
  * - integrity APIs : These APIs provides creating a signature using asymmetric private key, verifying a signature using asymmetric public key, calculating a HMAC/CMAC of given message using symmetric key and calculating message digests of given message without key.
  *
  *
  */

#endif /* __TIZEN_CORE_YACA_DOC_H__ */
