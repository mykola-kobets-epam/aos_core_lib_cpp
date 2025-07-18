/*
 * Copyright (C) 2025 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CM_LAUNCHER_STUBS_RESOURCEMANAGER_HPP_
#define AOS_CM_LAUNCHER_STUBS_RESOURCEMANAGER_HPP_

#include <core/cm/resourcemanager/resourcemanager.hpp>

#include <map>

namespace aos::cm::resourcemanager {

class ResourceManagerStub : public ResourceManagerItf {
public:
    void Init() { mConfigs.clear(); }

    void SetNodeConfig(const String& nodeID, const String& nodeType, const NodeConfig& cfg)
    {
        mConfigs[std::make_pair(StaticString<cIDLen>(nodeID), StaticString<cNodeTypeLen>(nodeType))] = cfg;
    }

    Error GetNodeConfig(const String& nodeID, const String& nodeType, NodeConfig& nodeConfig) override
    {
        auto it = mConfigs.find(std::make_pair(StaticString<cIDLen>(nodeID), StaticString<cNodeTypeLen>(nodeType)));
        if (it == mConfigs.end()) {
            return ErrorEnum::eNotFound;
        }
        nodeConfig = it->second;
        return ErrorEnum::eNone;
    }

private:
    std::map<std::pair<StaticString<cIDLen>, StaticString<cNodeTypeLen>>, NodeConfig> mConfigs;
};

} // namespace aos::cm::resourcemanager

#endif
