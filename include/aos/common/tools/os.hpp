/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_OS_HPP_
#define AOS_OS_HPP_

#include "aos/common/tools/string.hpp"

namespace aos {
namespace os {

/**
 * Returns value of specified environment variable.
 *
 * @param envName name of environment variable.
 * @param env result value.
 * @return Error.
 */
Error GetEnv(const String& envName, String& env)
{
    (void)envName;
    (void)env;

    return ErrorEnum::eNone;
}

} // namespace os
} // namespace aos

#endif
