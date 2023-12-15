/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_MOCK_HSM_HPP_
#define AOS_MOCK_HSM_HPP_

#include "aos/iam/modules/hsm.hpp"
#include <gmock/gmock.h>

namespace aos {
namespace iam {
namespace certhandler {

/**
 * StorageItf provides API to store/retrieve certificates info.
 */
class MockHSM : public HSMItf {
public:
    MOCK_METHOD(Error, SetOwner, (const String& password), (override));
    MOCK_METHOD(Error, Clear, (), (override));
    MOCK_METHOD(RetWithError<SharedPtr<crypto::PrivateKeyItf>>, CreateKey,
        (const String& password, KeyGenAlgorithm algorithm), (override));
    MOCK_METHOD(Error, ApplyCert,
        (const Array<crypto::x509::Certificate>& certChain, CertInfo& certInfo, String& password), (override));
    MOCK_METHOD(Error, RemoveCert, (const String& certURL, const String& password), (override));
    MOCK_METHOD(Error, RemoveKey, (const String& keyURL, const String& password), (override));
    MOCK_METHOD(Error, ValidateCertificates,
        (Array<StaticString<cURLLen>> & invalidCerts, Array<StaticString<cURLLen>>& invalidKeys,
            Array<CertInfo>& validCerts),
        (override));
};

} // namespace certhandler
} // namespace iam
} // namespace aos

#endif
