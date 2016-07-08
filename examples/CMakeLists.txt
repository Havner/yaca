#
#  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
#
#  Contact: Krzysztof Jackiewicz <k.jackiewicz@samsung.com>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License
#
#
# @file   CMakeLists.txt
# @author Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
#

INCLUDE_DIRECTORIES(${API_FOLDER})

SET(COMMON_SOURCES  ${CMAKE_CURRENT_SOURCE_DIR}/lorem.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/misc.c)

FUNCTION(BUILD_EXAMPLE EXAMPLE_NAME SOURCE_FILE)
	ADD_EXECUTABLE(${EXAMPLE_NAME}
	               ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE}
	               ${COMMON_SOURCES})
	TARGET_LINK_LIBRARIES(${EXAMPLE_NAME} ${PROJECT_NAME})
	INSTALL(TARGETS      ${EXAMPLE_NAME}
	        DESTINATION  ${BIN_INSTALL_DIR}
	        PERMISSIONS  OWNER_READ
	                     OWNER_WRITE
	                     OWNER_EXECUTE
	                     GROUP_READ
	                     GROUP_EXECUTE
	                     WORLD_READ
	                     WORLD_EXECUTE)
	INSTALL(FILES        ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE}
	        DESTINATION  ${EXAMPLES_DIR})
ENDFUNCTION(BUILD_EXAMPLE)

BUILD_EXAMPLE("yaca-example-digest"           digest.c)
BUILD_EXAMPLE("yaca-example-encrypt"          encrypt.c)
BUILD_EXAMPLE("yaca-example-seal"             seal.c)
BUILD_EXAMPLE("yaca-example-encrypt-gcm-ccm"  encrypt_aes_gcm_ccm.c)
BUILD_EXAMPLE("yaca-example-sign"             sign.c)
BUILD_EXAMPLE("yaca-example-key-exchange"     key_exchange.c)
BUILD_EXAMPLE("yaca-example-key-impexp"       key_import_export.c)
BUILD_EXAMPLE("yaca-example-key-password"     key_password.c)

INSTALL(FILES       ${COMMON_SOURCES}
        DESTINATION ${EXAMPLES_DIR})
