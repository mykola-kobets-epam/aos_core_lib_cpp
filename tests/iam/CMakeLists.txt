#
# Copyright (C) 2023 Renesas Electronics Corporation.
# Copyright (C) 2023 EPAM Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

set(TARGET aosiamcpp_test)

# ######################################################################################################################
# Sources
# ######################################################################################################################

set(SOURCES certhandler/certhandler_test.cpp)

# ######################################################################################################################
# Target
# ######################################################################################################################

add_executable(${TARGET} ${SOURCES})
target_link_libraries(${TARGET} aosiamcpp GTest::gmock_main)
target_include_directories(${TARGET} PUBLIC ../include)

gtest_discover_tests(${TARGET})
