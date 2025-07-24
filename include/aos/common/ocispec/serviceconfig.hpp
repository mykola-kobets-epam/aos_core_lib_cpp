/*
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_SERVICECONFIG_HPP_
#define AOS_SERVICECONFIG_HPP_

#include "aos/common/ocispec/common.hpp"
#include "aos/common/tools/map.hpp"
#include "aos/common/tools/optional.hpp"
#include "aos/common/types.hpp"

namespace aos::oci {

/**
 * Balancing policy len.
 */
constexpr auto cBalancingPolicyLen = AOS_CONFIG_OCISPEC_BALANCING_POLICY_LEN;

/**
 * Max number of allowed connections.
 */
static constexpr auto cMaxNumConnections = AOS_CONFIG_NETWORKMANAGER_CONNECTIONS_PER_INSTANCE_MAX_COUNT;

/**
 * Max length of connection name.
 */
static constexpr auto cConnectionNameLen = AOS_CONFIG_NETWORKMANAGER_CONNECTION_NAME_LEN;

/**
 * Maximum number dependencies per service.
 */
static constexpr auto cMaxNumDependencies = AOS_CONFIG_MAX_NUM_SERVICE_DEPENDENCIES;

/**
 * Service quotas.
 */
struct ServiceQuotas {
    Optional<uint64_t> mCPUDMIPSLimit;
    Optional<uint64_t> mRAMLimit;
    Optional<uint64_t> mPIDsLimit;
    Optional<uint64_t> mNoFileLimit;
    Optional<uint64_t> mTmpLimit;
    Optional<uint64_t> mStateLimit;
    Optional<uint64_t> mStorageLimit;
    Optional<uint64_t> mUploadSpeed;
    Optional<uint64_t> mDownloadSpeed;
    Optional<uint64_t> mUploadLimit;
    Optional<uint64_t> mDownloadLimit;

    /**
     * Compares service quotas.
     *
     * @param quotas service quotas to compare.
     * @return bool.
     */
    bool operator==(const ServiceQuotas& quotas) const
    {
        return mCPUDMIPSLimit == quotas.mCPUDMIPSLimit && mRAMLimit == quotas.mRAMLimit
            && mPIDsLimit == quotas.mPIDsLimit && mNoFileLimit == quotas.mNoFileLimit && mTmpLimit == quotas.mTmpLimit
            && mStateLimit == quotas.mStateLimit && mStorageLimit == quotas.mStorageLimit
            && mUploadSpeed == quotas.mUploadSpeed && mDownloadSpeed == quotas.mDownloadSpeed
            && mUploadLimit == quotas.mUploadLimit && mDownloadLimit == quotas.mDownloadLimit;
    }

    /**
     * Compares service quotas.
     *
     * @param quotas service quotas to compare.
     * @return bool.
     */
    bool operator!=(const ServiceQuotas& quotas) const { return !operator==(quotas); }
};

/**
 * Requested resources.
 */
struct RequestedResources {
    Optional<uint64_t> mCPU;
    Optional<uint64_t> mRAM;
    Optional<uint64_t> mStorage;
    Optional<uint64_t> mState;

    /**
     * Compares requested resources.
     *
     * @param resources requested resources to compare.
     * @return bool.
     */
    bool operator==(const RequestedResources& resources) const
    {
        return mCPU == resources.mCPU && mRAM == resources.mRAM && mStorage == resources.mStorage
            && mState == resources.mState;
    }

    /**
     * Compares requested resources.
     *
     * @param resources requested resources to compare.
     * @return bool.
     */
    bool operator!=(const RequestedResources& resources) const { return !operator==(resources); }
};

/**
 * Service devices rules.
 */
struct ServiceDevice {
    StaticString<cDeviceNameLen>  mDevice;
    StaticString<cPermissionsLen> mPermissions;

    /**
     * Compares devices.
     *
     * @param device service device.
     * @return bool.
     */
    bool operator==(const ServiceDevice& device) const
    {
        return mDevice == device.mDevice && mPermissions == device.mPermissions;
    }

    /**
     * Compares devices.
     *
     * @param device service device.
     * @return bool.
     */
    bool operator!=(const ServiceDevice& device) const { return !operator==(device); }
};

/**
 * Dependency type enum.
 */
class DependencyTypeType {
public:
    enum class Enum {
        /**
         * At least one instance of dependency item should be successfully started,
         * if dependency item fails in runtime, current item should work with no interruption.
         */
        eStarted,
        /**
         * At least one instance of dependency item should be successfully started and healthy, if dependency item is
         * not healthy or fails in runtime, the current item should be stopped till dependency satisfies the condition
         * again.
         */
        eHealthy,
        /**
         * All instances of dependency item should be successfully completed (for one shot services/jobs).
         */
        eCompleted,
        /**
         * The current item should be started before any instance of dependency item - run, result of the current item
         * is not checked.
         */
        eBefore,
        /**
         * The current item should be started after all instances of dependency item - run, result of dependency item
         * instances are not checked.
         */
        eAfter
    };

    static const Array<const char* const> GetStrings()
    {
        static const char* const sString[] = {
            "started",
            "healthy",
            "completed",
            "before",
            "after",
        };

        return Array<const char* const>(sString, ArraySize(sString));
    };
};

using DependencyTypeEnum = DependencyTypeType::Enum;
using DependencyType     = EnumStringer<DependencyTypeType>;

/**
 * Service dependency.
 */
struct ServiceDependency {
    /**
     * Service identifier.
     */
    StaticString<cServiceIDLen> mServiceID;

    /**
     * Dependency type.
     */
    DependencyType mType = DependencyTypeEnum::eStarted;
};

/**
 * Service configuration.
 */
struct ServiceConfig {
    Time                                                                           mCreated;
    StaticString<cAuthorLen>                                                       mAuthor;
    bool                                                                           mSkipResourceLimits;
    Optional<StaticString<cHostNameLen>>                                           mHostname;
    StaticString<cBalancingPolicyLen>                                              mBalancingPolicy;
    StaticArray<StaticString<cRunnerNameLen>, cMaxNumRunners>                      mRunners;
    RunParameters                                                                  mRunParameters;
    StaticMap<StaticString<cSysctlLen>, StaticString<cSysctlLen>, cSysctlMaxCount> mSysctl;
    Duration                                                                       mOfflineTTL;
    ServiceQuotas                                                                  mQuotas;
    Optional<RequestedResources>                                                   mRequestedResources;
    StaticArray<StaticString<cConnectionNameLen>, cMaxNumConnections>              mAllowedConnections;
    StaticArray<ServiceDevice, cMaxNumNodeDevices>                                 mDevices;
    StaticArray<StaticString<cResourceNameLen>, cMaxNumNodeResources>              mResources;
    StaticArray<FunctionServicePermissions, cFuncServiceMaxCount>                  mPermissions;
    Optional<AlertRules>                                                           mAlertRules;
    StaticArray<ServiceDependency, cMaxNumDependencies>                            mDependencies;

    /**
     * Compares service config.
     *
     * @param config service config to compare.
     * @return bool.
     */
    bool operator==(const ServiceConfig& config) const
    {
        return mCreated == config.mCreated && mAuthor == config.mAuthor
            && mSkipResourceLimits == config.mSkipResourceLimits && mHostname == config.mHostname
            && mBalancingPolicy == config.mBalancingPolicy && mRunners == config.mRunners
            && mRunParameters == config.mRunParameters && mSysctl == config.mSysctl && mOfflineTTL == config.mOfflineTTL
            && mQuotas == config.mQuotas && mRequestedResources == config.mRequestedResources
            && mAllowedConnections == config.mAllowedConnections && mDevices == config.mDevices
            && mResources == config.mResources && mPermissions == config.mPermissions
            && mAlertRules == config.mAlertRules;
    }

    /**
     * Compares service config.
     *
     * @param config service config to compare.
     * @return bool.
     */
    bool operator!=(const ServiceConfig& config) const { return !operator==(config); }
};

} // namespace aos::oci

#endif
