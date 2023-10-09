/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_TIME_HPP_
#define AOS_TIME_HPP_

#include "aos/common/tools/array.hpp"
#include "aos/common/tools/string.hpp"

namespace aos {
namespace time {

/**
 * A certain point in time.
 */
struct Time { };

/**
 * An hour time interval.
 */
constexpr uint64_t Hour = 60 * 60 * 1000; // ms.

} // namespace time
} // namespace aos

#endif
