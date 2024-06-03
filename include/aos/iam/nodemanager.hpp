/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_NODEMANAGER_HPP_
#define AOS_NODEMANAGER_HPP_

#include "aos/common/types.hpp"
#include "aos/iam/config.hpp"

namespace aos::iam::nodemanager {

/** @addtogroup iam Identification and Access Manager
 *  @{
 */

/**
 * NodeInfo listener interface.
 */
class NodeInfoListenerItf {
public:
    /**
     * Node info change notification.
     *
     * @param info node info.
     */
    virtual void OnNodeInfoChange(const NodeInfo& info) = 0;

    /**
     * Node info removed notification.
     *
     * @param id id of the node been removed.
     */
    virtual void OnNodeRemoved(const String& id) = 0;

    /**
     * Destroys object instance.
     */
    virtual ~NodeInfoListenerItf() = default;
};

/**
 * Node manager interface.
 */
class NodeManagerItf {
public:
    /**
     * Updates whole information for a node.
     *
     * @param info node info.
     * @return Error.
     */
    virtual Error SetNodeInfo(const NodeInfo& info) = 0;

    /**
     * Updates node status.
     *
     * @param nodeId node identifier.
     * @param status node status.
     * @return Error.
     */
    virtual Error SetNodeStatus(const String& nodeId, NodeStatus status) = 0;

    /**
     * Returns node info.
     *
     * @param nodeId node identifier.
     * @param[out] nodeInfo result node identifier.
     * @return Error.
     */
    virtual Error GetNodeInfo(const String& nodeId, NodeInfo& nodeInfo) const = 0;

    /**
     * Returns ids for all the node in the manager.
     *
     * @param ids result node identifiers.
     * @return Error.
     */
    virtual Error GetAllNodeIds(Array<StaticString<cNodeIDLen>>& ids) const = 0;

    /**
     * Removes node info by its id.
     *
     * @param nodeId node identifier.
     * @return Error.
     */
    virtual Error RemoveNodeInfo(const String& nodeId) = 0;

    /**
     * Subscribes listener for node info updates.
     *
     * @param listener listener to subscribe.
     * @return Error.
     */
    virtual Error SubscribeNodeInfoChange(NodeInfoListenerItf& listener) = 0;

    /**
     * Destroys object instance.
     */
    virtual ~NodeManagerItf() = default;
};

/**
 * Node info storage interface.
 */
class NodeInfoStorageItf {
public:
    /**
     * Updates whole information for a node.
     *
     * @param info node info.
     * @return Error.
     */
    virtual Error SetNodeInfo(const NodeInfo& info) = 0;

    /**
     * Returns node info.
     *
     * @param nodeId node identifier.
     * @param[out] nodeInfo result node identifier.
     * @return Error.
     */
    virtual Error GetNodeInfo(const String& nodeId, NodeInfo& nodeInfo) const = 0;

    /**
     * Returns ids for all the node in the manager.
     *
     * @param ids result node identifiers.
     * @return Error.
     */
    virtual Error GetAllNodeIds(Array<StaticString<cNodeIDLen>>& ids) const = 0;

    /**
     * Removes node info by its id.
     *
     * @param nodeId node identifier.
     * @return Error.
     */
    virtual Error RemoveNodeInfo(const String& nodeId) = 0;

    /**
     * Destroys object instance.
     */
    virtual ~NodeInfoStorageItf() = default;
};

/**
 * Node manager.
 */
class NodeManager : public NodeManagerItf {
public:
    /**
     * Initializes node manager.
     *
     * @param storage node info storage.
     * @return Error.
     */
    Error Init(NodeInfoStorageItf& storage);

    /**
     * Updates whole information for a node.
     *
     * @param info node info.
     * @return Error.
     */
    Error SetNodeInfo(const NodeInfo& info) override;

    /**
     * Updates status for a node.
     *
     * @param nodeId node identifier.
     * @param status node status.
     * @return Error.
     */
    Error SetNodeStatus(const String& nodeId, NodeStatus status) override;

    /**
     * Returns node info.
     *
     * @param nodeId node identifier.
     * @param[out] nodeInfo result node identifier.
     * @return Error.
     */
    Error GetNodeInfo(const String& nodeId, NodeInfo& nodeInfo) const override;

    /**
     * Returns ids for all the node in the manager.
     *
     * @param ids result node identifiers.
     * @return Error.
     */
    Error GetAllNodeIds(Array<StaticString<cNodeIDLen>>& ids) const override;

    /**
     * Removes node info by its id.
     *
     * @param nodeId node identifier.
     * @return Error.
     */
    Error RemoveNodeInfo(const String& nodeId) override;

    /**
     * Subscribes listener for node info updates.
     *
     * @param listener listener to subscribe.
     * @return Error.
     */
    Error SubscribeNodeInfoChange(NodeInfoListenerItf& listener) override;

private:
    static constexpr auto cNodeMaxNum = AOS_CONFIG_NODEMANAGER_NODE_MAX_NUM;

    NodeInfo*       GetNodeFromCache(const String& nodeId);
    const NodeInfo* GetNodeFromCache(const String& nodeId) const;

    Error UpdateCache(const NodeInfo& nodeInfo);

    RetWithError<NodeInfo*> AddNodeInfoToCache();
    void                    NotifyNodeInfoChange(const NodeInfo& nodeInfo);

    NodeInfoStorageItf*                mStorage          = nullptr;
    NodeInfoListenerItf*               mNodeInfoListener = nullptr;
    StaticArray<NodeInfo, cNodeMaxNum> mNodeInfoCache;
};

/** @}*/

} // namespace aos::iam::nodemanager

#endif
