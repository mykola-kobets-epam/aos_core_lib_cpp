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
 * TODO: Add implementation
 */
struct Time {
    bool IsZero() const { return true; }

    Time AddYears(int /*year*/) { return Time(); }

    uint64_t UnixNano() const { return 0ULL; }

    bool operator<(const Time& /*right*/) const { return true; }
    bool operator==(const Time& /*right*/) const { return true; }
    bool operator!=(const Time& time) const { return !operator==(time); }

    static Time Now() { return Time(); }
};

template <class Stream>
Stream& operator<<(Stream& stream, const Time& /*time*/)
{
    return stream;
}

/**
 * An hour time interval.
 */
constexpr uint64_t Hour = 60 * 60 * 1000; // ms.

} // namespace time
} // namespace aos

#endif
