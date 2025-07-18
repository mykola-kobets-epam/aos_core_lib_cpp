/*
 * Copyright (C) 2025 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CM_LAUNCHER_STUBS_STORAGESTATE_HPP_
#define AOS_CM_LAUNCHER_STUBS_STORAGESTATE_HPP_

#include <core/cm/storagestate/itf/storagestate.hpp>

#include <map>
#include <vector>

namespace aos::cm::storagestate {

class StorageStateStub : public StorageStateItf {
public:
    void Init()
    {
        mInstances.clear();
        mRemovedInstances.clear();
        mCleanedInstances.clear();
        mCheckSums.clear();
    }

    void SetInstanceCheckSum(const InstanceIdent& instanceIdent, const Array<uint8_t>& checkSum)
    {
        mCheckSums[instanceIdent] = std::vector<uint8_t>(checkSum.begin(), checkSum.end());
    }

    void SetTotalStateSize(size_t size) { mTotalStateSize = size; }
    void SetTotalStorageSize(size_t size) { mTotalStorageSize = size; }
    void SetIsSamePartition(bool isSamePartition) { mIsSamePartition = isSamePartition; }

    const std::vector<InstanceIdent>& GetRemovedInstances() const { return mRemovedInstances; }
    const std::vector<InstanceIdent>& GetCleanedInstances() const { return mCleanedInstances; }

    // Access to internal state for testing
    const std::map<InstanceIdent, SetupParams>&          GetInstances() const { return mInstances; }
    const std::map<InstanceIdent, std::vector<uint8_t>>& GetCheckSums() const { return mCheckSums; }

    // StorageStateItf
    Error Setup(const InstanceIdent& instanceIdent, const SetupParams& setupParams, String& storagePath,
        String& statePath) override
    {
        mInstances[instanceIdent] = setupParams;
        storagePath               = "storage_path";
        statePath                 = "state_path";
        return ErrorEnum::eNone;
    }

    Error Cleanup(const InstanceIdent& instanceIdent) override
    {
        mCleanedInstances.push_back(instanceIdent);
        return ErrorEnum::eNone;
    }

    Error Remove(const InstanceIdent& instanceIdent) override
    {
        mRemovedInstances.push_back(instanceIdent);
        return ErrorEnum::eNone;
    }

    Error GetInstanceCheckSum(const InstanceIdent& instanceIdent, Array<uint8_t>& checkSum) override
    {
        auto it = mCheckSums.find(instanceIdent);
        if (it == mCheckSums.end()) {
            return ErrorEnum::eNotFound;
        }
        checkSum.Clear();
        for (const auto& byte : it->second) {
            if (auto err = checkSum.PushBack(byte); !err.IsNone()) {
                return err;
            }
        }
        return ErrorEnum::eNone;
    }

    RetWithError<size_t> GetTotalStateSize() const override { return RetWithError<size_t>(mTotalStateSize); }
    RetWithError<size_t> GetTotalStorageSize() const override { return RetWithError<size_t>(mTotalStorageSize); }
    bool                 IsSamePartition() const override { return mIsSamePartition; }

    static constexpr uint8_t cMagicSum[] = {0x12, 0x34, 0x56, 0x78};

private:
    std::map<InstanceIdent, SetupParams>          mInstances;
    std::vector<InstanceIdent>                    mRemovedInstances;
    std::vector<InstanceIdent>                    mCleanedInstances;
    std::map<InstanceIdent, std::vector<uint8_t>> mCheckSums;
    size_t                                        mTotalStateSize   = 1024;
    size_t                                        mTotalStorageSize = 1024;
    bool                                          mIsSamePartition  = false;
};

} // namespace aos::cm::storagestate

#endif
