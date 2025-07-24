/*
 * Copyright (C) 2025 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <aos/cm/launcher/launcher.hpp>

#include "log.hpp"

namespace aos::cm::launcher {

/***********************************************************************************************************************
 * Utils
 **********************************************************************************************************************/
class ServiceIDMatcher {
public:
    ServiceIDMatcher(const String& serviceID)
        : mServiceID(&serviceID)
    {
    }

    bool operator()(const RunServiceRequest& request) { return request.mServiceID == *mServiceID; }

private:
    const String* mServiceID = nullptr;
};

ServiceIDMatcher MatchServiceID(const String& serviceID)
{
    return ServiceIDMatcher {serviceID};
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

Error DependencyResolver::Init(nodemanager::NodeManagerItf& nodeManager, imageprovider::ImageProviderItf& imageProvider,
    ReadyServicesListener& listener)
{
    LockGuard lock {mMutex};

    mNodeManager   = &nodeManager;
    mImageProvider = &imageProvider;
    mListener      = &listener;

    return ErrorEnum::eNone;
}

Error DependencyResolver::Start()
{
    LockGuard lock {mMutex};

    if (auto err = mNodeManager->SubscribeListener(*this); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return ErrorEnum::eNone;
}

Error DependencyResolver::Stop()
{
    LockGuard lock {mMutex};

    if (auto err = mNodeManager->UnsubscribeListener(*this); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return ErrorEnum::eNone;
}

Error DependencyResolver::ResolveDependencies(const Array<RunServiceRequest>& requests, bool rebalancing)
{
    LockGuard lock {mMutex};

    mAllServices = requests;
    mReadyServices.Clear();
    mDependencies.Clear();

    mRebalancing = rebalancing;

    mRunStatus.Clear();

    for (const auto& request : requests) {
        for (uint64_t i = 0; i < request.mNumInstances; ++i) {
            InstanceIdent ident = {request.mServiceID, request.mSubjectID, i};

            auto status = InstanceStatus {ident, "", InstanceRunStateEnum::ePending, Error()};
            if (auto err = mRunStatus.EmplaceBack(status); !err.IsNone()) {
                return AOS_ERROR_WRAP(err);
            }
        }

        auto serviceInfo = MakeUnique<imageprovider::ServiceInfo>(&mAllocator);
        if (auto err = mImageProvider->GetServiceInfo(request.mServiceID, *serviceInfo); !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }

        if (auto err = mDependencies.Emplace(request.mServiceID, serviceInfo->mConfig.mDependencies); !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }
    }

    // replace Before dependencies with After
    for (auto& [service, dependencies] : mDependencies) {
        const auto afterDependency
            = oci::ServiceDependency {service, oci::DependencyType(oci::DependencyTypeEnum::eAfter)};
        for (auto it = dependencies.begin(); it != dependencies.end();) {
            if (it->mType != oci::DependencyTypeEnum::eBefore) {
                it++;
                continue;
            }

            auto it2 = mDependencies.Find(it->mServiceID);
            if (auto err = it2->mSecond.PushBack(afterDependency); !err.IsNone()) {
                return AOS_ERROR_WRAP(err);
            }

            it = dependencies.Erase(it);
        }
    }

    return SendReadyServices();
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

void DependencyResolver::OnStatusChanged(const nodemanager::NodeRunInstanceStatus& status)
{
    LockGuard lock {mMutex};

    for (const auto& instance : status.mInstances) {
        auto it = mRunStatus.FindIf(
            [&instance](const InstanceStatus& item) { return item.mInstanceIdent == instance.mInstanceIdent; });

        if (it == mRunStatus.end()) {
            LOG_ERR() << "Set run status failed" << Log::Field(AOS_ERROR_WRAP(ErrorEnum::eNotFound));
        } else {
            *it = instance;
        }
    }

    SendReadyServices();
}

Error DependencyResolver::SendReadyServices()
{
    bool readyServicesChanged = false;
    for (const auto& service : mAllServices) {
        auto [ready, err] = IsServiceReadyToStart(service);
        if (!err.IsNone()) {
            return err;
        }

        const auto matchServiceID
            = [&service](const RunServiceRequest& request) { return service.mServiceID == request.mServiceID; };

        bool readySent = mReadyServices.ExistIf(matchServiceID);
        if (!ready && readySent) {
            mReadyServices.RemoveIf(matchServiceID);
            readyServicesChanged = true;
        }

        if (ready && !readySent) {
            err = mReadyServices.PushBack(service);
            if (!err.IsNone()) {
                return AOS_ERROR_WRAP(err);
            }
            readyServicesChanged = true;
        }
    }

    if (readyServicesChanged) {
        if (auto err = mListener->OnServicesReady(mReadyServices, mRebalancing); !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }
    }

    return ErrorEnum::eNone;
}

RetWithError<bool> DependencyResolver::IsServiceReadyToStart(const RunServiceRequest& request)
{
    const auto& dependencies = mDependencies.Find(request.mServiceID);
    if (dependencies == mDependencies.end()) {
        return {{}, AOS_ERROR_WRAP(ErrorEnum::eWrongState)};
    }

    for (const auto& dependency : dependencies->mSecond) {
        bool ready = false;
        switch (dependency.mType.GetValue()) {
        case oci::DependencyTypeEnum::eStarted:
            ready = IsStartingDependencyOk(request, dependency.mServiceID);
            break;
        case oci::DependencyTypeEnum::eHealthy:
            return {{}, AOS_ERROR_WRAP(ErrorEnum::eNotSupported)};
            break;
        case oci::DependencyTypeEnum::eCompleted:
            // Don't support completed dependency as there is no one shot services yet.
            return {{}, AOS_ERROR_WRAP(ErrorEnum::eNotSupported)};
        case oci::DependencyTypeEnum::eBefore:
            return {{}, AOS_ERROR_WRAP(ErrorEnum::eWrongState)};
        case oci::DependencyTypeEnum::eAfter:
            ready = IsAfterDependencyOk(request, dependency.mServiceID);
            break;
        }

        if (!ready) {
            return false;
        }
    }

    return true;
}

bool DependencyResolver::IsStartingDependencyOk(const RunServiceRequest& request, const String& serviceID)
{
    // Don't stop current service if it runs.
    if (mReadyServices.ExistIf(MatchServiceID(request.mServiceID))) {
        return true;
    }

    return mRunStatus.ExistIf([&serviceID](const InstanceStatus& status) {
        return status.mInstanceIdent.mServiceID == serviceID
            && (status.mRunState == InstanceRunStateEnum::eStarting
                || status.mRunState == InstanceRunStateEnum::eActive);
    });
}

bool DependencyResolver::IsAfterDependencyOk(const RunServiceRequest& request, const String& serviceID)
{
    (void)request;

    auto it = mAllServices.FindIf(MatchServiceID(serviceID));
    if (it == mAllServices.end()) {
        return false;
    }

    for (uint64_t i = 0; i < it->mNumInstances; ++i) {
        auto statusIt = mRunStatus.FindIf([it, i](const InstanceStatus& status) {
            return status.mInstanceIdent == InstanceIdent {it->mServiceID, it->mSubjectID, i};
        });

        if (statusIt == mRunStatus.end()) {
            return false;
        }

        if (statusIt->mRunState == InstanceRunStateEnum::ePending) {
            return false;
        }
    }

    return true;
}

} // namespace aos::cm::launcher
