/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_TIME_HPP_
#define AOS_TIME_HPP_

#include "aos/common/tools/array.hpp"
#include "aos/common/tools/log.hpp"
#include "aos/common/tools/string.hpp"

namespace aos {
namespace time {

/**
 * Base type for a time duration. Can also be negative to set a point back in time.
 */
using Duration = int64_t;

/**
 * Returns time duration in years.
 *
 * @param num number of years.
 * @result Duration.
 */
constexpr Duration Years(int num)
{
    (void)num;
    return 0;
}

/**
 * An object specifying a time instant.
 */
class Time {
public:
    /**
     * Checks whether Time object is default initialized.
     *
     * @result bool.
     */
    bool IsZero() const { return true; }

    /**
     * Returns a copy of the current object increased by a specified time duration.
     *
     * @param duration duration to be added to the current time instant.
     * @result Time.
     */
    Time Add(Duration duration) const
    {
        (void)duration;
        return Time();
    }

    /**
     * Returns an integer representing a time in nanoseconds elapsed since January 1, 1970 UTC.
     *
     * @result result time in nanoseconds.
     */
    uint64_t UnixNano() const { return 0ULL; }

    /**
     * Checks whether a current time is less than a specified one.
     *
     * @param obj time object to compare with.
     * @result bool.
     */
    bool operator<(const Time& obj) const
    {
        (void)obj;
        return true;
    }

    /**
     * Checks whether a current time and a specified object represent the same time instant.
     *
     * @param obj time object to compare with.
     * @result bool.
     */
    bool operator==(const Time& obj) const
    {
        (void)obj;
        return true;
    }

    /**
     * Checks whether a current time and a specified object don't represent the same time instant.
     *
     * @param obj time object to compare with.
     * @result bool.
     */
    bool operator!=(const Time& obj) const
    {
        (void)obj;
        return !operator==(obj);
    }

    /**
     * Returns current local time.
     *
     * @result Time.
     */
    static Time Now() { return Time(); }

    /**
     * Prints time into log.
     *
     * @param log log object to print time into.
     * @param obj time object to be printed.
     * @result source stream object.
     */
    friend Log& operator<<(Log& log, const Time& obj)
    {
        (void)obj;
        return log;
    }
};

} // namespace time
} // namespace aos

#endif
