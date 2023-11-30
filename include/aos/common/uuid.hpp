/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_UUID_HPP_
#define AOS_UUID_HPP_

#include "aos/common/tools/string.hpp"

namespace aos {
namespace uuid {

/**
 *  UUID length
 */
constexpr auto cUUIDLen = AOS_CONFIG_UUID_LEN;

/**
 *  Length of UUID string representation
 */
constexpr auto cUUIDStrLen = AOS_CONFIG_UUID_STR_LEN;

/**
 * A UUID is a 128 bit (16 byte) Universal Unique IDentifier as defined in RFC 4122.
 */
using UUID = StaticArray<uint8_t, cUUIDLen>;

/**
 * Provides API to manage UUIDs.
 */
class UUIDManagerItf {
public:
    /**
     * Creates unique UUID.
     *
     * @return RetWithError<UUID>.
     */
    virtual RetWithError<UUID> CreateUUID() = 0;

    /**
     * Returns a new SHA1 UUID based on the supplied name space and data.
     *
     * @param space name space.
     * @param data data.
     * @return RetWithError<UUID>.
     */
    virtual RetWithError<UUID> CreateSHA1(const UUID& space, const Array<uint8_t>& data) = 0;

    /**
     * Converts UUID to string.
     *
     * @param uuid uuid.
     * @return RetWithError<StaticString<cUUIDStrLen>>.
     */
    virtual RetWithError<StaticString<cUUIDStrLen>> UUIDToString(const UUID& uuid) = 0;

    /**
     * Converts string to UUID.
     *
     * @param src input string.
     * @return RetWithError<UUID>.
     */
    virtual RetWithError<UUID> StringToUUID(const String& src) = 0;

    /**
     * Destroys object instance.
     */
    virtual ~UUIDManagerItf() = default;
};

} // namespace uuid
} // namespace aos

#endif
