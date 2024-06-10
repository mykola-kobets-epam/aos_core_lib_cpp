/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LOG_HPP_
#define LOG_HPP_

#include "aos/common/tools/log.hpp"

#define LOG_DBG() LOG_MODULE_DBG(LogModuleEnum::eProvisionManager)
#define LOG_INF() LOG_MODULE_INF(LogModuleEnum::eProvisionManager)
#define LOG_WRN() LOG_MODULE_WRN(LogModuleEnum::eProvisionManager)
#define LOG_ERR() LOG_MODULE_ERR(LogModuleEnum::eProvisionManager)

#endif
