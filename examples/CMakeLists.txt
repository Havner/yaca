#
#  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
#
#  Contact:
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
# @version 1.0
# @brief
#

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/api)

SET(COMMON_SOURCES
                ${CMAKE_CURRENT_SOURCE_DIR}/lorem.c
                ${CMAKE_CURRENT_SOURCE_DIR}/misc.c
    )

FUNCTION(BUILD_EXAMPLE EXAMPLE_NAME SOURCE_FILE)
    ADD_EXECUTABLE(${EXAMPLE_NAME}
                    ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE}
                    ${COMMON_SOURCES}
        )
    TARGET_LINK_LIBRARIES(${EXAMPLE_NAME} ${PROJECT_NAME})
    INSTALL(TARGETS ${EXAMPLE_NAME}
        DESTINATION ${BIN_INSTALL_DIR}
        PERMISSIONS OWNER_READ
                    OWNER_WRITE
                    OWNER_EXECUTE
                    GROUP_READ
                    GROUP_EXECUTE
                    WORLD_READ
                    WORLD_EXECUTE
        )
ENDFUNCTION(BUILD_EXAMPLE)

BUILD_EXAMPLE("yaca-example-digest"       digest.c)
BUILD_EXAMPLE("yaca-example-encrypt"      encrypt.c)
BUILD_EXAMPLE("yaca-example-encrypt-gcm"  encrypt_aes_gcm.c)
BUILD_EXAMPLE("yaca-example-sign"         sign.c)
BUILD_EXAMPLE("yaca-example-key-exchange" key_exchange.c)
BUILD_EXAMPLE("yaca-example-test"         test.c)