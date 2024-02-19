#
# Copyright (C) 2024 Renesas Electronics Corporation.
# Copyright (C) 2024 EPAM Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

set(TARGET testutils)

# ######################################################################################################################
# Setup softhsm environment
# ######################################################################################################################

include(src/softhsm.cmake)

# ######################################################################################################################
# Sources
# ######################################################################################################################

set(SOURCES src/softhsmenv.cpp)

# ######################################################################################################################
# Set SOFTHSM test environment
# ######################################################################################################################

add_library(${TARGET} ${SOURCES})

target_compile_definitions(
    ${TARGET} PUBLIC SOFTHSM_BASE_DIR="${SOFTHSM_BASE_DIR}" CERTIFICATES_DIR="${CERTIFICATES_DIR}"
                     SOFTHSM2_LIB="${SOFTHSM2_LIB}"
)

target_include_directories(${TARGET} PUBLIC include)
