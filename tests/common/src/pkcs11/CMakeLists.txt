#
# Copyright (C) 2024 Renesas Electronics Corporation.
# Copyright (C) 2024 EPAM Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

set(TARGET pkcs11_test)

# ######################################################################################################################
# Setup SoftHSM2
# ######################################################################################################################

find_library(
    SOFTHSM2_LIB
    NAMES softhsm2
    PATH_SUFFIXES softhsm
)

if(NOT SOFTHSM2_LIB)
    message(FATAL_ERROR "softhsm2 library not found")
endif()

set(SOFTHSM_BASE ${CMAKE_CURRENT_BINARY_DIR}/softhsm)

file(MAKE_DIRECTORY ${SOFTHSM_BASE}/tokens/)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/softhsm2.conf ${SOFTHSM_BASE}/softhsm2.conf COPYONLY)
file(APPEND ${SOFTHSM_BASE}/softhsm2.conf "directories.tokendir = ${SOFTHSM_BASE}/tokens/\n")

# ######################################################################################################################
# Create PKCS11 test certificates
# ######################################################################################################################

set(CERTDIR ${CMAKE_CURRENT_BINARY_DIR}/certificates)

file(MAKE_DIRECTORY ${CERTDIR})

message("\nGenerating PKCS11 test certificates...")

message("  Create a Certificate Authority private key...")
execute_process(
    COMMAND openssl req -new -newkey rsa:2048 -nodes -out ${CERTDIR}/ca.csr -keyout ${CERTDIR}/ca.key -nodes -subj
            "/C=XX/ST=StateName/L=CityName/O=Epam/OU=CompanySectionName/CN=Aos Core" COMMAND_ERROR_IS_FATAL ANY
)

message("  Create a CA self-signed certificate:")
execute_process(
    COMMAND openssl x509 -trustout -signkey ${CERTDIR}/ca.key -days 365 -req -in ${CERTDIR}/ca.csr -out
            ${CERTDIR}/ca.pem COMMAND_ERROR_IS_FATAL ANY
)

message(
    "  Issue a client certificate by first generating the key, then request, then sign the certificate using private key of the CA..."
)
execute_process(COMMAND openssl genrsa -out ${CERTDIR}/client.key 2048 COMMAND_ERROR_IS_FATAL ANY)

execute_process(
    COMMAND openssl req -new -key ${CERTDIR}/client.key -out ${CERTDIR}/client.csr -nodes -subj
            "/C=XX/ST=StateName/L=CityName/O=Epam/OU=CompanySectionName/CN=MKobets" COMMAND_ERROR_IS_FATAL ANY
)

execute_process(
    COMMAND openssl x509 -req -days 365 -in ${CERTDIR}/client.csr -CA ${CERTDIR}/ca.pem -CAkey ${CERTDIR}/ca.key
            -set_serial 01 -out ${CERTDIR}/client.cer COMMAND_ERROR_IS_FATAL ANY
)

message("  Convert PEM to DER...")
execute_process(
    COMMAND openssl x509 -outform der -in ${CERTDIR}/ca.pem -out ${CERTDIR}/ca.cer.der COMMAND_ERROR_IS_FATAL ANY
)

execute_process(
    COMMAND openssl x509 -outform der -in ${CERTDIR}/client.cer -out ${CERTDIR}/client.cer.der COMMAND_ERROR_IS_FATAL
            ANY
)

message("Generating PKCS11 test certificates done!\n")

# ######################################################################################################################
# Sources
# ######################################################################################################################

set(SOURCES pkcs11_test.cpp)

# ######################################################################################################################
# Test
# ######################################################################################################################

add_executable(${TARGET} ${SOURCES})
target_link_libraries(${TARGET} aoscommoncpp GTest::gmock_main)

gtest_discover_tests(${TARGET})

# ######################################################################################################################
# Add definitions
# ######################################################################################################################

target_compile_definitions(${TARGET} PRIVATE WORK_DIR="${CMAKE_CURRENT_BINARY_DIR}" SOFTHSM2_LIB="${SOFTHSM2_LIB}")
