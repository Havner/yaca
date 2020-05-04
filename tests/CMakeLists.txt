#
#  Copyright (c) 2020 Samsung Electronics Co., Ltd All Rights Reserved
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
# @author Lukasz Pawelczyk (l.pawelczyk@samsung.com)
#

SET(TESTS_NAME yaca-unit-tests)
FILE(GLOB YACA_SOURCES ${SRC_FOLDER}/*.c)
SET(TESTS_SOURCES
	common.cpp
	test_debug.cpp
	test_crypto.cpp
	test_key.cpp
	test_simple.cpp
	test_rsa.cpp
	test_digest.cpp
	test_encrypt.cpp
	test_seal.cpp
	test_sign.cpp
	openssl_mock_impl.c
	)

FIND_PACKAGE(Boost REQUIRED unit_test_framework)
ADD_DEFINITIONS("-DBOOST_TEST_DYN_LINK -DOPENSSL_MOCKUP_TESTS")

INCLUDE_DIRECTORIES(${API_FOLDER} ${SRC_FOLDER})
INCLUDE_DIRECTORIES(SYSTEM ${YACA_DEPS_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS})

ADD_EXECUTABLE(${TESTS_NAME} ${YACA_SOURCES} ${TESTS_SOURCES})
TARGET_LINK_LIBRARIES(${TESTS_NAME}
					  ${YACA_DEPS_LIBRARIES}
					  ${CMAKE_THREAD_LIBS_INIT}
					  ${Boost_LIBRARIES})

INSTALL(TARGETS		 ${TESTS_NAME}
		DESTINATION	 ${BIN_INSTALL_DIR}
		PERMISSIONS	 OWNER_READ
					 OWNER_WRITE
					 OWNER_EXECUTE
					 GROUP_READ
					 GROUP_EXECUTE
					 WORLD_READ
					 WORLD_EXECUTE)
