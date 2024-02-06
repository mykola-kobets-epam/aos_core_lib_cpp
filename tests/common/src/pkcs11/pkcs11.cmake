#
# Copyright (C) 2024 Renesas Electronics Corporation.
# Copyright (C) 2024 EPAM Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

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

set(SOFTHSM_BASE_DIR ${CMAKE_CURRENT_BINARY_DIR}/softhsm)

file(MAKE_DIRECTORY ${SOFTHSM_BASE_DIR}/tokens/)

configure_file(${CMAKE_CURRENT_LIST_DIR}/softhsm2.conf ${SOFTHSM_BASE_DIR}/softhsm2.conf COPYONLY)
file(APPEND ${SOFTHSM_BASE_DIR}/softhsm2.conf "directories.tokendir = ${SOFTHSM_BASE_DIR}/tokens/\n")

# ######################################################################################################################
# Create PKCS11 test certificates
# ######################################################################################################################

set(CERTIFICATES_DIR ${CMAKE_CURRENT_BINARY_DIR}/certificates)

file(MAKE_DIRECTORY ${CERTIFICATES_DIR})

message("\nGenerating PKCS11 test certificates...")

message("\nCreate a Certificate Authority private key...")
execute_process(
    COMMAND
        openssl req -new -newkey rsa:2048 -nodes -out ${CERTIFICATES_DIR}/ca.csr -keyout ${CERTIFICATES_DIR}/ca.key
        -nodes -subj "/C=XX/ST=StateName/L=CityName/O=Epam/OU=CompanySectionName/CN=Aos Core" COMMAND_ERROR_IS_FATAL
        ANY
)

message("\nCreate a CA self-signed certificate...")
execute_process(
    COMMAND openssl x509 -signkey ${CERTIFICATES_DIR}/ca.key -days 365 -req -in ${CERTIFICATES_DIR}/ca.csr -out
            ${CERTIFICATES_DIR}/ca.pem COMMAND_ERROR_IS_FATAL ANY
)

message("\nIssue a client certificate...")
execute_process(COMMAND openssl genrsa -out ${CERTIFICATES_DIR}/client.key 2048 COMMAND_ERROR_IS_FATAL ANY)

execute_process(
    COMMAND openssl req -new -key ${CERTIFICATES_DIR}/client.key -out ${CERTIFICATES_DIR}/client.csr -nodes -subj
            "/C=XX/ST=StateName/L=CityName/O=Epam/OU=CompanySectionName/CN=MKobets" COMMAND_ERROR_IS_FATAL ANY
)

execute_process(
    COMMAND openssl x509 -req -days 365 -in ${CERTIFICATES_DIR}/client.csr -CA ${CERTIFICATES_DIR}/ca.pem -CAkey
            ${CERTIFICATES_DIR}/ca.key -set_serial 01 -out ${CERTIFICATES_DIR}/client.cer COMMAND_ERROR_IS_FATAL ANY
)

message("\nConvert PEM to DER...")
execute_process(
    COMMAND openssl x509 -outform der -in ${CERTIFICATES_DIR}/ca.pem -out ${CERTIFICATES_DIR}/ca.cer.der
            COMMAND_ERROR_IS_FATAL ANY
)

execute_process(
    COMMAND openssl x509 -outform der -in ${CERTIFICATES_DIR}/client.cer -out ${CERTIFICATES_DIR}/client.cer.der
            COMMAND_ERROR_IS_FATAL ANY
)

message("\nCreate a single certificate chain file...")
file(WRITE ${CERTIFICATES_DIR}/client-ca-chain.pem "")
file(READ ${CERTIFICATES_DIR}/client.cer CONTENT)
file(APPEND ${CERTIFICATES_DIR}/client-ca-chain.pem "${CONTENT}")
file(READ ${CERTIFICATES_DIR}/ca.pem CONTENT)
file(APPEND ${CERTIFICATES_DIR}/client-ca-chain.pem "${CONTENT}")

message("\nGenerating PKCS11 test certificates done!\n")
