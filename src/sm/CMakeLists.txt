#
# Copyright (C) 2023 Renesas Electronics Corporation.
# Copyright (C) 2023 EPAM Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

set(TARGET aossmcpp)

# ######################################################################################################################
# Sources
# ######################################################################################################################

set(SOURCES launcher/launcher.cpp launcher/instance.cpp launcher/service.cpp resourcemanager/resourcemanager.cpp
            servicemanager/servicemanager.cpp
)

# ######################################################################################################################
# Target
# ######################################################################################################################

add_library(${TARGET} STATIC ${SOURCES})

# ######################################################################################################################
# Install
# ######################################################################################################################

install(TARGETS ${TARGET} ARCHIVE DESTINATION lib)

install(
    DIRECTORY ${CMAKE_SOURCE_DIR}/include/aos/sm
    DESTINATION include/aos
    FILES_MATCHING
    PATTERN "*.hpp"
)
