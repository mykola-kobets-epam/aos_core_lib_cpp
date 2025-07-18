/*
 * Copyright (C) 2025 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CM_LAUNCHER_TESTS_TEST_STREAM_OPERATORS_HPP_
#define AOS_CM_LAUNCHER_TESTS_TEST_STREAM_OPERATORS_HPP_

#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "stubs/instancerunner.hpp"
#include <core/cm/launcher/itf/storage.hpp>
#include <gtest/gtest.h>

namespace aos {

/**
 * @brief
 *
 */
inline std::ostream& operator<<(std::ostream& os, const NetworkParameters& params)
{
    os << "{\"networkID\":\"" << params.mNetworkID.CStr() << "\",\"subnet\":\"" << params.mSubnet.CStr()
       << "\",\"ip\":\"" << params.mIP.CStr() << "\",\"vlanID\":" << params.mVlanID << ",\"dnsServers\":[";

    bool first = true;
    for (const auto& dns : params.mDNSServers) {
        if (!first)
            os << ",";
        os << "\"" << dns.CStr() << "\"";
        first = false;
    }

    os << "],\"firewallRules\":[";
    first = true;
    for (const auto& rule : params.mFirewallRules) {
        if (!first)
            os << ",";
        os << "{\"dstIP\":\"" << rule.mDstIP.CStr() << "\",\"dstPort\":\"" << rule.mDstPort.CStr() << "\",\"proto\":\""
           << rule.mProto.CStr() << "\",\"srcIP\":\"" << rule.mSrcIP.CStr() << "\"}";
        first = false;
    }

    os << "]}";
    return os;
}

/**
 * Stream output operator for InstanceInfo.
 */
inline std::ostream& operator<<(std::ostream& os, const InstanceInfo& info)
{
    os << "{\"instanceIdent\":[\"" << info.mItemID.CStr() << "\",\"" << info.mSubjectID.CStr() << "\","
       << info.mInstance << "],\"imageID\":\"" << info.mImageID.CStr() << "\",\"runtimeID\":\""
       << info.mRuntimeID.CStr() << "\",\"uid\":" << info.mUID << ",\"priority\":" << info.mPriority
       << ",\"storagePath\":\"" << info.mStoragePath.CStr() << "\",\"statePath\":\"" << info.mStatePath.CStr()
       << "\",\"networkParameters\":" << info.mNetworkParameters << "}";
    return os;
}

/**
 * Stream output operator for vector of InstanceInfo.
 */
inline std::ostream& operator<<(std::ostream& os, const std::vector<InstanceInfo>& instances)
{
    os << "[";
    bool first = true;
    for (const auto& instance : instances) {
        if (!first)
            os << ",";
        os << instance;
        first = false;
    }
    os << "]";
    return os;
}

/**
 * Stream output operator for Array of InstanceStatus.
 */
inline std::ostream& operator<<(std::ostream& os, const Array<InstanceStatus>& statuses)
{
    os << "[";
    bool first = true;
    for (const auto& status : statuses) {
        if (!first)
            os << ",";
        os << "{\"instanceIdent\":[\"" << status.mItemID.CStr() << "\",\"" << status.mSubjectID.CStr() << "\","
           << status.mInstance << "],\"version\":\"" << status.mVersion.CStr() << "\",\"nodeID\":\""
           << status.mNodeID.CStr() << "\",\"runtimeID\":\"" << status.mRuntimeID.CStr() << "\",\"stateChecksum\":[";

        bool checksumFirst = true;
        for (const auto& byte : status.mStateChecksum) {
            if (!checksumFirst)
                os << ",";
            os << static_cast<int>(byte);
            checksumFirst = false;
        }

        os << "],\"state\":\"" << status.mState.ToString().CStr() << "\",\"error\":\"" << status.mError.StrValue()
           << "\"}";
        first = false;
    }
    os << "]";
    return os;
}

} // namespace aos

namespace aos::cm::launcher {

/**
 * Stream output operator for launcher::InstanceInfo.
 */
inline std::ostream& operator<<(std::ostream& os, const InstanceInfo& info)
{
    os << "{\"instanceIdent\":[\"" << info.mInstanceIdent.mItemID.CStr() << "\",\""
       << info.mInstanceIdent.mSubjectID.CStr() << "\"," << info.mInstanceIdent.mInstance << "],\"imageID\":\""
       << info.mImageID.CStr() << "\",\"runtimeID\":\"" << info.mRuntimeID.CStr() << "\",\"nodeID\":\""
       << info.mNodeID.CStr() << "\",\"prevNodeID\":\"" << info.mPrevNodeID.CStr() << "\",\"updateItemType\":\""
       << info.mUpdateItemType.ToString().CStr() << "\",\"uid\":" << info.mUID
       << ",\"timestamp\":" << info.mTimestamp.ToUTCString().mValue.CStr()
       << "\",\"cached\":" << (info.mCached ? "true" : "false") << "}";
    return os;
}

/**
 * Stream output operator for vector of launcher::InstanceInfo.
 */
inline std::ostream& operator<<(std::ostream& os, const std::vector<InstanceInfo>& instances)
{
    os << "[";
    bool first = true;
    for (const auto& instance : instances) {
        if (!first)
            os << ",";
        os << instance;
        first = false;
    }
    os << "]";
    return os;
}

/**
 * Stream output operator for InstanceRunnerStub::NodeRunRequest.
 */
inline std::ostream& operator<<(std::ostream& os, const InstanceRunnerStub::NodeRunRequest& request)
{
    os << "{\"stopInstances\":" << request.mStopInstances << ",\"startInstances\":" << request.mStartInstances << "}";
    return os;
}

/**
 * Stream output operator for map of NodeRunRequest.
 */
inline std::ostream& operator<<(
    std::ostream& os, const std::map<std::string, InstanceRunnerStub::NodeRunRequest>& requests)
{
    os << "{";
    bool first = true;
    for (const auto& [nodeID, request] : requests) {
        if (!first)
            os << ",";
        os << "\"" << nodeID << "\":" << request;
        first = false;
    }
    os << "}";
    return os;
}

} // namespace aos::cm::launcher

// Google Test printer for std::map<std::string, InstanceRunnerStub::NodeRunRequest>
namespace testing {
namespace internal {

template <>
class UniversalPrinter<std::map<std::string, aos::cm::launcher::InstanceRunnerStub::NodeRunRequest>> {
public:
    static void Print(
        const std::map<std::string, aos::cm::launcher::InstanceRunnerStub::NodeRunRequest>& value, ::std::ostream* os)
    {
        *os << value;
    }
};

} // namespace internal
} // namespace testing

#endif // AOS_CM_LAUNCHER_TESTS_TEST_STREAM_OPERATORS_HPP_
