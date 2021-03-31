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
# @file CMakeLists.txt
# @author Dariusz Michaluk (d.michaluk@samsung.com)
#

PROJECT(yaca)

MESSAGE(STATUS "")
MESSAGE(STATUS "Generating makefile for the yaca...")

FILE(GLOB HEADERS   ${API_FOLDER}/*.h ${API_FOLDER}/*.hpp)
FILE(GLOB SRCS      *.c *.h keymaster/*.cpp keymaster/*.hpp)

SET(_LIB_VERSION_ "${VERSION}")
SET(_LIB_SOVERSION_ "0")
SET(PC_FILE "${PROJECT_NAME}.pc")

## Set the default ELF image symbol visibility to hidden. Using this feature
## can very substantially improve linking and load times of shared object
## libraries, produce more optimized code, provide near-perfect API export
## and prevent symbol clashes
ADD_DEFINITIONS(-fvisibility=hidden)

## Setup target ################################################################
ADD_LIBRARY(${PROJECT_NAME} SHARED ${SRCS} ${HEADERS})
SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES
                      SOVERSION  ${_LIB_SOVERSION_}
                      VERSION    ${_LIB_VERSION_})
ADD_LIBRARY(${PROJECT_NAME}-static STATIC ${SRCS} ${HEADERS})
SET_TARGET_PROPERTIES(${PROJECT_NAME}-static PROPERTIES
                      OUTPUT_NAME ${PROJECT_NAME})

## Link libraries ##############################################################
PKG_CHECK_MODULES(YACA_DEPS REQUIRED openssl>=1.1)

FIND_PACKAGE (Threads)

INCLUDE_DIRECTORIES(${API_FOLDER})
INCLUDE_DIRECTORIES(SYSTEM ${YACA_DEPS_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${PROJECT_NAME}
                      ${YACA_DEPS_LIBRARIES}
                      ${CMAKE_THREAD_LIBS_INIT})

## Generate the pc file ########################################################
CONFIGURE_FILE(${PC_FILE}.in ${CMAKE_CURRENT_BINARY_DIR}/${PC_FILE} @ONLY)

## Install #####################################################################
INSTALL(FILES       ${CMAKE_CURRENT_BINARY_DIR}/${PC_FILE}
        DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)

INSTALL(TARGETS     ${PROJECT_NAME}
        DESTINATION ${LIB_INSTALL_DIR}
        COMPONENT   RuntimeLibraries)
INSTALL(TARGETS     ${PROJECT_NAME}-static
        DESTINATION ${LIB_INSTALL_DIR}
        COMPONENT   DevelopmentLibraries)

INSTALL(FILES       ${HEADERS}
        DESTINATION ${INCLUDE_INSTALL_DIR}/yaca)
