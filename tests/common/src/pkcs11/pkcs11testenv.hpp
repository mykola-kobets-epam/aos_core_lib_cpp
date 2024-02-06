/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_PKCS11TESTENV_H_
#define AOS_PKCS11TESTENV_H_

#include "../log.hpp"
#include "aos/common/pkcs11/pkcs11.hpp"

namespace aos {
namespace pkcs11 {

class PKCS11TestEnv {
public:
    Error Init(const String& pin, const String& label)
    {
        setenv("SOFTHSM2_CONF", SOFTHSM_BASE_DIR "/softhsm2.conf", true);

        Log::SetCallback([](LogModule module, LogLevel level, const String& message) {
            static std::mutex           sLogMutex;
            std::lock_guard<std::mutex> lock(sLogMutex);

            std::cout << level.ToString().CStr() << " | " << module.ToString().CStr() << " | " << message.CStr()
                      << std::endl;
        });

        mLibrary = mManager.OpenLibrary(SOFTHSM2_LIB);
        if (!mLibrary) {
            return ErrorEnum::eFailed;
        }

        return InitTestToken(pin, label);
    }

    Error Deinit() { return FS::ClearDir(SOFTHSM_BASE_DIR "/tokens"); }

    RetWithError<SharedPtr<SessionContext>> OpenUserSession(const String& pin, bool login = true)
    {
        Error                     err = ErrorEnum::eNone;
        SharedPtr<SessionContext> session;

        Tie(session, err) = mLibrary->OpenSession(mSlotID, CKF_RW_SESSION | CKF_SERIAL_SESSION);
        if (!err.IsNone() || !session) {
            return {nullptr, err};
        }

        if (login) {
            err = session->Login(CKU_USER, pin);
            if (!err.IsNone()) {
                return {nullptr, err};
            }
        }

        return session;
    }

    PKCS11Manager& GetManager() { return mManager; }

    SharedPtr<LibraryContext> GetLibrary() { return mLibrary; }

    SlotID GetSlotID() const { return mSlotID; }

private:
    Error InitTestToken(const String& pin, const String& label)
    {
        Error err = ErrorEnum::eNone;

        Tie(mSlotID, err) = FindTestToken(label);

        if (err.Is(ErrorEnum::eNotFound)) {
            constexpr auto cDefaultSlotID = 0;

            err = mLibrary->InitToken(cDefaultSlotID, pin, label);
            if (!err.IsNone()) {
                return err;
            }

            Tie(mSlotID, err) = FindTestToken(label);
            if (!err.IsNone()) {
                return err;
            }

            SharedPtr<SessionContext> session;

            Tie(session, err) = mLibrary->OpenSession(mSlotID, CKF_RW_SESSION | CKF_SERIAL_SESSION);
            if (!err.IsNone()) {
                return err;
            }

            err = session->Login(CKU_SO, pin);
            if (!err.IsNone()) {
                return err;
            }

            err = session->InitPIN(pin);
            if (!err.IsNone()) {
                return err;
            }

            err = session->Logout();
        }

        return err;
    }

    RetWithError<SlotID> FindTestToken(const String& label)
    {
        constexpr auto cMaxSlotListSize = 10;

        StaticArray<SlotID, cMaxSlotListSize> slotList;

        auto err = mLibrary->GetSlotList(true, slotList);
        if (!err.IsNone()) {
            return {0, err};
        }

        for (const auto id : slotList) {
            TokenInfo tokenInfo;

            err = mLibrary->GetTokenInfo(id, tokenInfo);
            if (!err.IsNone()) {
                return {0, err};
            }

            if (tokenInfo.mLabel == label) {
                return {id, ErrorEnum::eNone};
            }
        }

        return {0, ErrorEnum::eNotFound};
    }

public:
    SlotID                    mSlotID = 0;
    PKCS11Manager             mManager;
    SharedPtr<LibraryContext> mLibrary;
};
} // namespace pkcs11
} // namespace aos

#endif
