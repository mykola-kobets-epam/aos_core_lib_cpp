#
# Copyright (C) 2023 Renesas Electronics Corporation.
# Copyright (C) 2023 EPAM Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

set(TARGET aoscommoncpp)

option(WITH_MBEDTLS "build with mbedTLS" ON)

message(STATUS "WITH_MBEDTLS                  = ${WITH_MBEDTLS}")
message(STATUS)

# ######################################################################################################################
# Versioning
# ######################################################################################################################

find_package(Git)

if(NOT GIT_FOUND)
    set(GIT_EXECUTABLE git)
endif()

execute_process(
    OUTPUT_FILE ${CMAKE_CURRENT_BINARY_DIR}/version.hpp
    COMMAND
        ${CMAKE_COMMAND} -D GIT_EXECUTABLE=${GIT_EXECUTABLE} -D
        INPUT_FILE=${CMAKE_SOURCE_DIR}/src/common/version.hpp.in -D OUTPUT_FILE=${CMAKE_CURRENT_BINARY_DIR}/version.hpp
        -D GIT_SOURCE_DIR=${CMAKE_SOURCE_DIR} -P ${CMAKE_MODULE_PATH}/GenerateVersion.cmake
)

# ######################################################################################################################
# Includes
# ######################################################################################################################

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/crypto/mbedtls/drivers)

# ######################################################################################################################
# Target
# ######################################################################################################################

add_library(
    ${TARGET} STATIC
    crypto/mbedtls/cryptoprovider.cpp
    crypto/mbedtls/driverwrapper.cpp
    cryptoutils.cpp
    monitoring/monitoring.cpp
    pkcs11/pkcs11.cpp
    pkcs11/privatekey.cpp
    tools/uuid.cpp
)

target_sources(${TARGET} PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/version.hpp)

if(WITH_MBEDTLS)
    find_package(MbedTLS REQUIRED)
    target_link_libraries(${TARGET} PUBLIC MbedTLS::mbedcrypto MbedTLS::mbedx509 MbedTLS::mbedtls)
endif()

# ######################################################################################################################
# Install
# ######################################################################################################################

install(TARGETS ${TARGET} ARCHIVE DESTINATION lib)

install(
    DIRECTORY ${CMAKE_SOURCE_DIR}/include/aos/common
    DESTINATION include/aos
    FILES_MATCHING
    PATTERN "*.hpp"
    PATTERN "*.h"
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/version.hpp DESTINATION include/aos/common)
