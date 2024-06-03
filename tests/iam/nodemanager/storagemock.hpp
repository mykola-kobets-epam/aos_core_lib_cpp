/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_NODEINFO_STORAGE_HPP_
#define AOS_NODEINFO_STORAGE_HPP_

#include "aos/iam/nodemanager/nodemanager.hpp"
#include <gmock/gmock.h>

namespace aos {
namespace iam {
namespace nodemanager {

class NodeInfoStorageMock : public NodeInfoStorageItf {
public:
    MOCK_METHOD(Error, SetNodeInfo, (const NodeInfo& info), (override));
    MOCK_METHOD(Error, GetNodeInfo, (const String& nodeId, NodeInfo& nodeInfo), (const, override));
    MOCK_METHOD(Error, GetAllNodeIds, (Array<StaticString<cNodeIDLen>> & ids), (const, override));
    MOCK_METHOD(Error, RemoveNodeInfo, (const String& nodeId), (override));
};

} // namespace nodemanager
} // namespace iam
} // namespace aos

#endif
