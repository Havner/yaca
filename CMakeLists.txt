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

CMAKE_MINIMUM_REQUIRED (VERSION 2.6.2)

PROJECT(owl)
SET(VERSION "0.0.1")

## pkgconfig ###################################################################
INCLUDE(FindPkgConfig)

## default CMAKE_INSTALL_* variables ###########################################
INCLUDE(GNUInstallDirs)

## Color output if it's possible:
IF (( "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" AND NOT (CMAKE_C_COMPILER_VERSION VERSION_LESS 4.9))
      OR ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" ))

    IF (OWL_BUILD_FORCE_COMPILER_COLORS)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdiagnostics-color=always")
    ENDIF()
ENDIF()

## Compiler flags, depending on the build type #################################
IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE "DEBUG")
ENDIF(NOT CMAKE_BUILD_TYPE)

## Print build information #####################################################
MESSAGE(STATUS "-------------------------------------------------")
MESSAGE(STATUS "Compiler:          " ${CMAKE_C_COMPILER_ID})
MESSAGE(STATUS "Compiler version:  " ${CMAKE_C_COMPILER_VERSION})
MESSAGE(STATUS "Build type:        " ${CMAKE_BUILD_TYPE})
MESSAGE(STATUS "-------------------------------------------------")

SET(CMAKE_C_FLAGS_DEBUG        "-std=c99 -O0 -ggdb -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_C_FLAGS_RELEASE      "-std=c99 -O2 -DNDEBUG")

ADD_DEFINITIONS("-fPIC")   # Position Independent Code
ADD_DEFINITIONS("-Werror") # Make all warnings into errors
ADD_DEFINITIONS("-Wall")   # Generate all warnings
#ADD_DEFINITIONS("-Wextra") # Generate even more extra warnings
#ADD_DEFINITIONS("-pedantic") # Be pedantic
#ADD_DEFINITIONS("-pedantic-errors") # Make pedantic warnings into errors
ADD_DEFINITIONS(-DPROJECT_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

IF("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
    # Warn about documentation problems
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wdocumentation")
    # Enable all diagnostics
    #SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Weverything")
ENDIF()

## Subdirectories ##############################################################
SET(API_FOLDER ${PROJECT_SOURCE_DIR}/api)
SET(EXAMPLES_FOLDER ${PROJECT_SOURCE_DIR}/examples)
SET(SRC_FOLDER ${PROJECT_SOURCE_DIR}/src)
SET(TEST_FOLDER ${PROJECT_SOURCE_DIR}/test)

IF(NOT DEFINED LIB_INSTALL_DIR)
    SET(LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
ENDIF(NOT DEFINED LIB_INSTALL_DIR)

IF(NOT DEFINED INCLUDE_INSTALL_DIR)
    SET(INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}")
ENDIF(NOT DEFINED INCLUDE_INSTALL_DIR)

ADD_SUBDIRECTORY(${SRC_FOLDER})
#ADD_SUBDIRECTORY(${TEST_FOLDER})
ADD_SUBDIRECTORY(${EXAMPLES_FOLDER})
